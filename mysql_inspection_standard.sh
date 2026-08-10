#!/usr/bin/env bash
# MySQL Inspection Collector v1.1.0-standard
# 客户侧只负责：环境检查、能力探测、只读采集、时序采样、脱敏、状态记录和打包。
# 风险判断、拓扑合并、图表和 Word 报告均由后续 Python 完成。

# 用户误用 `sh` 时自动切换到 Bash（CentOS sh=bash POSIX 模式、Debian sh=dash 都需要处理）
if [ -z "${BASH_VERSION:-}" ] || [ -n "${POSIXLY_CORRECT:-}" ] || { set -o 2>/dev/null | grep -qi '^posix.*on'; }; then
    exec bash "$0" "$@"
fi

set -o pipefail
set +e
umask 077
export LC_ALL=C
export LANG=C

COLLECTOR_VERSION="1.1.0"
SNAPSHOT_SCHEMA_VERSION="1.0"
PACKAGE_VERSION="1.0"

# 标准模式：历史 sar 最近 24 小时（若存在）+ 系统/MySQL 同步实时采样约 30 秒。
# 30 秒采样用于当前 QPS/TPS 和状态计数器差值，不替代长期监控数据。
SAR_HISTORY_HOURS=24
SAMPLE_INTERVAL=5
SAMPLE_COUNT=6
MYSQL_TIMEOUT_SECONDS=30
MIN_FREE_MB=200
TOP_N=100
OUTPUT_PARENT="/var/tmp"
CREATE_PACKAGE=1
INCLUDE_LOG_TEXT=0
LOGIN_PATH=""
PASSWORD_FILE=""
dbHost=""
dbPort=""
dbUser=""
LEGACY_PASSWORD=""

show_usage() {
cat <<'EOF'
MySQL 巡检采集器 v1.1.0（标准版）

推荐用法：
  bash mysql_inspection_standard.sh --login-path inspection --host 127.0.0.1 --port 3306 --user inspector

也可以：
  chmod +x mysql_inspection_standard.sh
  ./mysql_inspection_standard.sh --login-path inspection

认证方式（推荐顺序）：
  --login-path NAME       使用 mysql_config_editor 保存的登录配置（推荐）
  --password-file FILE    从权限为 600 的文件读取密码
  未指定时               交互式隐藏输入密码

常用参数：
  --host HOST             默认 127.0.0.1
  --port PORT             默认 3306
  --user USER             默认 root
  --output-dir DIR        默认 /var/tmp
  --no-package            不生成 tar.gz，仅保留任务目录

高级覆盖参数（默认无需调整）：
  --sample-interval SEC   默认 5 秒
  --sample-count N        默认 6 次，总时长约 30 秒
  --sar-history-hours N   默认请求最近 24 小时历史 sar
  --mysql-timeout SEC     单条 MySQL 命令超时，默认 30 秒
  --include-log-text      包含有限错误日志样本（默认关闭）

深度采样示例（约 120 秒）：
  --sample-interval 5 --sample-count 24

说明：
  1. 同一份脚本可在主库、从库、MGR/PXC 节点执行。
  2. 一个 MySQL 实例生成一个采集包；主从拓扑由后续 Python 使用多个包合并判断。
  3. 客户侧不做风险评级，不生成图表，不生成 Word。
EOF
}

has_cmd() { command -v "$1" >/dev/null 2>&1; }

iso_now() {
    date --iso-8601=seconds 2>/dev/null || date +'%Y-%m-%dT%H:%M:%S%z'
}

epoch_ms() {
    local v
    v=$(date +%s%3N 2>/dev/null)
    case "$v" in
        *N*|'') printf '%s000' "$(date +%s)" ;;
        *) printf '%s' "$v" ;;
    esac
}

monotonic_ms() {
    awk '{printf "%.0f", $1 * 1000}' /proc/uptime 2>/dev/null || epoch_ms
}

sanitize_id() {
    printf '%s' "$1" | tr -c 'A-Za-z0-9._-' '_' | sed -e 's/__*/_/g' -e 's/^_//' -e 's/_$//'
}

collect_all_ipv4() {
    if has_cmd ip; then
        ip -o -4 addr show scope global 2>/dev/null | awk '{split($4,a,"/"); if(a[1] != "127.0.0.1") print a[1]}' | sort -u | paste -sd, -
    elif has_cmd hostname; then
        hostname -I 2>/dev/null | tr ' ' '\n' | awk '/^[0-9]+([.][0-9]+){3}$/ && $0 != "127.0.0.1"' | sort -u | paste -sd, -
    fi
}

detect_primary_ipv4() {
    local v=""
    if has_cmd ip; then
        v=$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src"){print $(i+1); exit}}')
        case "$v" in 127.*) v="" ;; esac
        [ -z "$v" ] && v=$(ip -o -4 route show default 2>/dev/null | awk 'NR==1{for(i=1;i<=NF;i++) if($i=="src"){print $(i+1); exit}}')
        case "$v" in 127.*) v="" ;; esac
        [ -z "$v" ] && v=$(ip -o -4 addr show scope global 2>/dev/null | awk '{split($4,a,"/"); if(a[1] !~ /^127[.]/){print a[1]; exit}}')
    fi
    [ -z "$v" ] && v=$(collect_all_ipv4 | awk -F, '{print $1}')
    printf '%s' "${v:-unknown_ip}"
}

resolve_ipv4() {
    local host="$1" v=""
    case "$host" in 127.*|localhost|::1) printf '127.0.0.1'; return 0 ;; esac
    if printf '%s' "$host" | grep -Eq '^[0-9]+([.][0-9]+){3}$'; then printf '%s' "$host"; return 0; fi
    if has_cmd getent; then v=$(getent ahostsv4 "$host" 2>/dev/null | awk 'NR==1{print $1}'); fi
    [ -z "$v" ] && has_cmd host && v=$(host "$host" 2>/dev/null | awk '/has address/{print $NF; exit}')
    printf '%s' "$v"
}

is_local_connect_target() {
    local host="$1" resolved="$2" short fqdn ips
    case "$host" in 127.*|localhost|::1) return 0 ;; esac
    short=$(hostname -s 2>/dev/null || hostname 2>/dev/null)
    fqdn=$(hostname -f 2>/dev/null || true)
    if [ "$host" = "$short" ] || { [ -n "$fqdn" ] && [ "$host" = "$fqdn" ]; }; then return 0; fi
    ips=",$(collect_all_ipv4),"
    if [ -n "$resolved" ] && printf '%s' "$ips" | grep -Fq ",$resolved,"; then return 0; fi
    return 1
}

sanitize_text() {
    printf '%s' "${1-}" | tr '\t\r\n' '   ' | sed 's/[[:space:]][[:space:]]*/ /g'
}

json_escape() {
    local s="${1-}"
    s=${s//\\/\\\\}
    s=${s//\"/\\\"}
    s=${s//$'\n'/\\n}
    s=${s//$'\r'/\\r}
    s=${s//$'\t'/\\t}
    printf '%s' "$s"
}

json_quote() { printf '"%s"' "$(json_escape "${1-}")"; }

json_number_or_null() {
    local v="${1-}"
    if printf '%s' "$v" | grep -Eq '^-?[0-9]+([.][0-9]+)?$'; then printf '%s' "$v"; else printf 'null'; fi
}

is_uint() {
    case "${1-}" in ''|*[!0-9]*) return 1 ;; *) return 0 ;; esac
}

file_size_bytes() {
    if stat -c '%s' "$1" >/dev/null 2>&1; then stat -c '%s' "$1"
    elif stat -f '%z' "$1" >/dev/null 2>&1; then stat -f '%z' "$1"
    else wc -c < "$1" | tr -d ' '
    fi
}

sha256_file() {
    if has_cmd sha256sum; then sha256sum "$1" | awk '{print $1}'
    elif has_cmd shasum; then shasum -a 256 "$1" | awk '{print $1}'
    elif has_cmd openssl; then openssl dgst -sha256 "$1" | awk '{print $NF}'
    else printf 'UNAVAILABLE'
    fi
}

safe_relpath() { printf '%s' "${1#"$TASK_DIR"/}"; }

run_with_timeout() {
    local seconds="$1"; shift
    if has_cmd timeout; then timeout --signal=TERM --kill-after=5 "$seconds" "$@"; else "$@"; fi
}

log() {
    local level="$1"; shift
    printf '[%s] [%s] %s\n' "$(date +'%Y-%m-%d %H:%M:%S')" "$level" "$*" | tee -a "$LOG_FILE"
}

log_info() { log INFO "$@"; }
log_warn() { log WARN "$@"; }
log_error() { log ERROR "$@"; }

classify_failure() {
    local rc="$1" err_file="$2"
    if [ "$rc" -eq 124 ] || [ "$rc" -eq 137 ]; then printf 'timeout'; return; fi
    if grep -Eqi 'cannot talk to daemon|could not open connection|chronyd.*not running|chrony.*not running|daemon is not running|service.*not (running|active)|No such file or directory.*chrony|command not found.*chrony' "$err_file" 2>/dev/null; then
        printf 'not_enabled'
    elif grep -Eqi 'access denied|command denied|permission denied|requires.*privilege|you need.*privilege' "$err_file" 2>/dev/null; then
        printf 'permission_denied'
    elif grep -Eqi "doesn.t exist|unknown table|unknown system variable|unknown column|not supported|unsupported" "$err_file" 2>/dev/null; then
        printf 'unsupported'
    else
        printf 'error'
    fi
}

known_tsv_header() {
    local name
    name=$(basename "$1")
    case "$name" in
      engines.tsv) printf 'Engine\tSupport\tComment\tTransactions\tXA\tSavepoints' ;;
      replica_status.tsv) printf 'Channel_Name\tSource_Host\tSource_Port\tSource_UUID\tReplica_IO_Running\tReplica_SQL_Running\tSeconds_Behind_Source\tLast_IO_Errno\tLast_SQL_Errno\tAuto_Position' ;;
      binary_log_status.tsv) printf 'File\tPosition\tBinlog_Do_DB\tBinlog_Ignore_DB\tExecuted_Gtid_Set' ;;
      binary_logs.tsv) printf 'Log_name\tFile_size\tEncrypted' ;;
      metadata_locks_pending.tsv) printf 'OBJECT_TYPE\tOBJECT_SCHEMA\tOBJECT_NAME\tLOCK_TYPE\tLOCK_DURATION\tLOCK_STATUS\tOWNER_THREAD_ID' ;;
      data_lock_waits.tsv) printf 'ENGINE\tREQUESTING_ENGINE_TRANSACTION_ID\tBLOCKING_ENGINE_TRANSACTION_ID\tREQUESTING_THREAD_ID\tBLOCKING_THREAD_ID' ;;
      long_transactions.tsv) printf 'trx_id\ttrx_state\tduration_seconds\ttrx_rows_locked\ttrx_rows_modified\ttrx_tables_locked\ttrx_mysql_thread_id\tquery_sha256' ;;
      processlist.tsv) printf 'ID\tUSER\tHOST\tDB\tCOMMAND\tTIME\tSTATE\tSQL_SHA256' ;;
      sql_digests_top.tsv) printf 'schema_name\tDIGEST\tCOUNT_STAR\ttotal_seconds\tavg_seconds\tSUM_ROWS_EXAMINED\tSUM_ROWS_SENT\tSUM_NO_INDEX_USED\tSUM_NO_GOOD_INDEX_USED' ;;
      redundant_indexes.tsv) printf 'table_schema\ttable_name\tredundant_index_name\tredundant_index_columns\tdominant_index_name\tdominant_index_columns\tsql_drop_index' ;;
      unused_indexes.tsv) printf 'object_schema\tobject_name\tindex_name' ;;
      replication_channels.tsv) printf 'CHANNEL_NAME\tGROUP_NAME\tSOURCE_UUID\tTHREAD_ID\tSERVICE_STATE\tCOUNT_RECEIVED_HEARTBEATS\tLAST_HEARTBEAT_TIMESTAMP\tRECEIVED_TRANSACTION_SET\tLAST_ERROR_NUMBER\tLAST_ERROR_MESSAGE_SHA256\tLAST_ERROR_TIMESTAMP' ;;
      replication_workers.tsv) printf 'CHANNEL_NAME\tWORKER_ID\tTHREAD_ID\tSERVICE_STATE\tLAST_ERROR_NUMBER\tLAST_ERROR_MESSAGE_SHA256\tLAST_ERROR_TIMESTAMP\tLAST_APPLIED_TRANSACTION\tAPPLYING_TRANSACTION' ;;
      group_replication_members.tsv) printf 'CHANNEL_NAME\tMEMBER_ID\tMEMBER_HOST\tMEMBER_PORT\tMEMBER_STATE\tMEMBER_ROLE\tMEMBER_VERSION' ;;
      group_replication_stats.tsv) printf 'CHANNEL_NAME\tVIEW_ID\tMEMBER_ID\tCOUNT_TRANSACTIONS_IN_QUEUE\tCOUNT_TRANSACTIONS_CHECKED\tCOUNT_CONFLICTS_DETECTED\tCOUNT_TRANSACTIONS_ROWS_VALIDATING\tTRANSACTIONS_COMMITTED_ALL_MEMBERS\tLAST_CONFLICT_FREE_TRANSACTION' ;;
      error_log_summary.tsv) printf 'PRIO\tERROR_CODE\toccurrence_count\tfirst_seen\tlast_seen' ;;
      error_log_samples.tsv) printf 'LOGGED\tTHREAD_ID\tPRIO\tERROR_CODE\tmessage' ;;
      accounts.tsv) printf 'user\thost\tplugin\taccount_locked\tpassword_expired\tpassword_lifetime\tSuper_priv\tGrant_priv\tCreate_user_priv\tFile_priv\tShutdown_priv\tProcess_priv\tRepl_slave_priv\tRepl_client_priv' ;;
      *) return 1 ;;
    esac
}

ensure_tsv_header() {
    local file="$1" header
    [ -s "$file" ] && return 0
    header=$(known_tsv_header "$file") || return 1
    printf '%s\n' "$header" > "$file"
}

record_status() {
    local item_id="$1" category="$2" status="$3" started_at="$4" finished_at="$5" duration_ms="$6"
    local row_count="$7" exit_code="$8" output_file="$9" reason="${10-}"
    local f
    f="$STATUS_PARTS_DIR/$(sanitize_id "$item_id").tsv"
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
      "$item_id" "$category" "$status" "$started_at" "$finished_at" "$duration_ms" "$row_count" "$exit_code" \
      "$output_file" "$(sanitize_text "$reason")" > "$f"
}

capture_command() {
    local item_id="$1" category="$2" outfile="$3"; shift 3
    local start_iso end_iso start_ms end_ms rc status rows reason err
    start_iso=$(iso_now); start_ms=$(epoch_ms); err="$TMP_DIR/$(sanitize_id "$item_id").stderr"
    mkdir -p "$(dirname "$outfile")"
    "$@" > "$outfile" 2> "$err"; rc=$?
    end_iso=$(iso_now); end_ms=$(epoch_ms)
    status="ok"; reason=""
    if [ "$rc" -ne 0 ]; then
        # 部分程序（chronyc 等）把错误信息输出到 stdout 而非 stderr；
        # 当 stderr 为空时，从 outfile 借前若干字节补充到 err 用于分类。
        if [ ! -s "$err" ] && [ -s "$outfile" ]; then
            head -c 500 "$outfile" >> "$err" 2>/dev/null
        fi
        status=$(classify_failure "$rc" "$err"); reason=$(tail -n 5 "$err" 2>/dev/null | tr '\n' ' ')
    elif [ ! -s "$outfile" ]; then status="empty"; fi
    rows=$(wc -l < "$outfile" 2>/dev/null | tr -d ' '); rows=${rows:-0}
    cat "$err" >> "$MODULE_LOG_DIR/$(sanitize_id "$category").log" 2>/dev/null
    rm -f "$err"
    record_status "$item_id" "$category" "$status" "$start_iso" "$end_iso" "$((end_ms-start_ms))" "$rows" "$rc" "$(safe_relpath "$outfile")" "$reason"
    return "$rc"
}

mysql_exec() {
    run_with_timeout "$MYSQL_TIMEOUT_SECONDS" "$MYSQL_BIN" "${MYSQL_CONN_ARGS[@]}" --batch --raw "$@"
}

mysql_scalar() {
    mysql_exec -N -s -e "$1" 2>/dev/null | head -n 1 | tr -d '\r'
}

mysql_query_tsv() {
    local item_id="$1" category="$2" outfile="$3" query="$4"
    local start_iso end_iso start_ms end_ms rc status rows reason err
    start_iso=$(iso_now); start_ms=$(epoch_ms); err="$TMP_DIR/$(sanitize_id "$item_id").stderr"
    mkdir -p "$(dirname "$outfile")"
    mysql_exec --column-names -e "$query" > "$outfile" 2> "$err"; rc=$?
    end_iso=$(iso_now); end_ms=$(epoch_ms)
    status="ok"; reason=""
    if [ "$rc" -ne 0 ]; then
        status=$(classify_failure "$rc" "$err")
        reason=$(tail -n 5 "$err" 2>/dev/null | tr '\n' ' ')
        : > "$outfile"
        ensure_tsv_header "$outfile" || true
        rows=0
    else
        rows=$(awk 'END{print (NR>0?NR-1:0)}' "$outfile" 2>/dev/null); rows=${rows:-0}
        if [ "$rows" -eq 0 ]; then
            status="empty"
            # 部分客户端/SHOW 语句在空结果时不输出列名。保留注释标记，避免产生难以识别的 0 字节 TSV。
            case "$outfile" in
              *.tsv) [ -s "$outfile" ] || ensure_tsv_header "$outfile" || printf '# no rows returned; see collection_status.json\n' > "$outfile" ;;
            esac
        fi
    fi
    cat "$err" >> "$MODULE_LOG_DIR/$(sanitize_id "$category").log" 2>/dev/null
    rm -f "$err"
    record_status "$item_id" "$category" "$status" "$start_iso" "$end_iso" "$((end_ms-start_ms))" "$rows" "$rc" "$(safe_relpath "$outfile")" "$reason"
    return "$rc"
}

mysql_query_fallback() {
    local item_id="$1" category="$2" outfile="$3" primary="$4" fallback="$5"
    mysql_query_tsv "$item_id" "$category" "$outfile" "$primary"
    local rc=$?
    if [ "$rc" -ne 0 ] || [ ! -s "$outfile" ]; then
        rm -f "$STATUS_PARTS_DIR/$(sanitize_id "$item_id").tsv"
        mysql_query_tsv "$item_id" "$category" "$outfile" "$fallback"
        return $?
    fi
    return 0
}

mysql_table_exists() {
    local schema="$1" table="$2" n
    n=$(mysql_scalar "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema='${schema}' AND table_name='${table}'")
    [ "${n:-0}" -gt 0 ] 2>/dev/null
}

mysql_schema_exists() {
    local schema="$1" n
    n=$(mysql_scalar "SELECT COUNT(*) FROM information_schema.schemata WHERE schema_name='${schema}'")
    [ "${n:-0}" -gt 0 ] 2>/dev/null
}

cnf_escape() {
    local s="${1-}"
    case "$s" in *$'\n'*|*$'\r'*) return 1 ;; esac
    s=${s//\\/\\\\}; s=${s//\"/\\\"}; printf '%s' "$s"
}

redact_command_stream() {
    sed -E \
      -e 's/((--password|--passwd)(=|[[:space:]]+))[^[:space:]]+/\1<REDACTED>/Ig' \
      -e 's/(^|[[:space:]])-p[^[:space:]]+/\1-p<REDACTED>/g' \
      -e 's#(mysql|mariadb)://([^:/@]+):[^@/]+@#\1://\2:<REDACTED>@#Ig' \
      -e 's/((token|secret|access[_-]?key)(=|:))[[:graph:]]+/\1<REDACTED>/Ig'
}

run_module() {
    local module_id="$1"; shift
    local start_iso start_ms end_iso end_ms rc status reason
    start_iso=$(iso_now); start_ms=$(epoch_ms)
    log_info "开始模块: $module_id"
    "$@" >> "$MODULE_LOG_DIR/$(sanitize_id "$module_id").log" 2>&1; rc=$?
    end_iso=$(iso_now); end_ms=$(epoch_ms)
    status="ok"; reason=""
    if [ "$rc" -eq 2 ]; then status="partial"; reason="module completed partially"
    elif [ "$rc" -ne 0 ]; then status="error"; reason="module returned non-zero"; fi
    record_status "module.$module_id" "module" "$status" "$start_iso" "$end_iso" "$((end_ms-start_ms))" "0" "$rc" "logs/modules/$(sanitize_id "$module_id").log" "$reason"
    log_info "结束模块: $module_id，耗时 $((end_ms-start_ms)) ms，状态 $status"
    return "$rc"
}

start_module_bg() {
    local module_id="$1"; shift
    BG_NAMES+=("$module_id")
    BG_START_ISO+=("$(iso_now)")
    BG_START_MS+=("$(epoch_ms)")
    run_module "$module_id" "$@" &
    BG_PIDS+=("$!")
}

wait_background_modules() {
    local i rc item_file end_iso end_ms duration reason
    for ((i=0; i<${#BG_PIDS[@]}; i++)); do
        wait "${BG_PIDS[$i]}"; rc=$?
        if [ "$rc" -ne 0 ]; then
            log_warn "后台模块 ${BG_NAMES[$i]} 返回 $rc"
            item_file="$STATUS_PARTS_DIR/$(sanitize_id "module.${BG_NAMES[$i]}").tsv"
            if [ ! -s "$item_file" ]; then
                end_iso=$(iso_now); end_ms=$(epoch_ms); duration=$((end_ms-BG_START_MS[$i]))
                reason="background module terminated before status was recorded"
                record_status "module.${BG_NAMES[$i]}" "module" "error" "${BG_START_ISO[$i]}" "$end_iso" "$duration" 0 "$rc" "logs/modules/$(sanitize_id "${BG_NAMES[$i]}").log" "$reason"
            fi
        fi
    done
}

check_output_space() {
    local free_kb
    free_kb=$(df -Pk "$OUTPUT_PARENT" 2>/dev/null | awk 'NR==2{print $4}')
    if ! is_uint "$free_kb"; then log_warn "无法确认输出目录剩余空间"; return 0; fi
    if [ "$free_kb" -lt $((MIN_FREE_MB*1024)) ]; then
        printf '输出目录剩余空间不足：需要至少 %s MB，当前约 %s MB\n' "$MIN_FREE_MB" "$((free_kb/1024))" >&2
        exit 11
    fi
}

collect_system_static() {
    capture_command "system.os_release" "system.static" "$EVIDENCE_DIR/os_release.txt" bash -c 'cat /etc/os-release 2>/dev/null; uname -a; uptime 2>/dev/null' || true
    capture_command "system.time_status" "system.static" "$EVIDENCE_DIR/time_status.txt" bash -c 'printf "local_time="; date --iso-8601=seconds 2>/dev/null || date +%Y-%m-%dT%H:%M:%S%z; printf "utc_time="; date -u --iso-8601=seconds 2>/dev/null || date -u +%Y-%m-%dT%H:%M:%SZ; printf "timezone="; cat /etc/timezone 2>/dev/null || timedatectl show -p Timezone --value 2>/dev/null || date +%Z; printf "epoch_seconds="; date +%s' || true
    if has_cmd timedatectl; then capture_command "system.timedatectl" "system.static" "$EVIDENCE_DIR/timedatectl.txt" timedatectl status || true; fi
    if has_cmd chronyc; then
        capture_command "system.chronyc_tracking" "system.static" "$EVIDENCE_DIR/chronyc_tracking.txt" chronyc tracking || true
        capture_command "system.chronyc_sources" "system.static" "$EVIDENCE_DIR/chronyc_sources.txt" chronyc sources -v || true
    elif has_cmd ntpq; then
        capture_command "system.ntpq_peers" "system.static" "$EVIDENCE_DIR/ntpq_peers.txt" ntpq -pn || true
    fi
    has_cmd lscpu && capture_command "system.lscpu" "system.static" "$EVIDENCE_DIR/lscpu.txt" lscpu || record_status "system.lscpu" "system.static" "unsupported" "$(iso_now)" "$(iso_now)" 0 0 127 "" "lscpu not installed"
    has_cmd free && capture_command "system.free" "system.static" "$TABLES_DIR/memory_snapshot.tsv" free -b || true
    has_cmd df && capture_command "system.filesystems" "system.static" "$TABLES_DIR/filesystems.tsv" df -PT -x fuse.gvfsd-fuse -x fuse.gvfs-fuse-daemon || true
    has_cmd df && capture_command "system.inodes" "system.static" "$TABLES_DIR/inodes.tsv" df -Pi -x fuse.gvfsd-fuse -x fuse.gvfs-fuse-daemon || true
    has_cmd lsblk && capture_command "system.block_devices" "system.static" "$TABLES_DIR/block_devices.tsv" lsblk -b -o NAME,KNAME,TYPE,SIZE,FSTYPE,MOUNTPOINT,ROTA,SCHED,MODEL,SERIAL || true
    if has_cmd ip; then
        capture_command "system.ip_address" "system.static" "$EVIDENCE_DIR/ip_address.txt" ip -details addr show || true
        capture_command "system.ip_route" "system.static" "$EVIDENCE_DIR/ip_route.txt" ip route show table all || true
    elif has_cmd ifconfig; then
        capture_command "system.ifconfig" "system.static" "$EVIDENCE_DIR/ip_address.txt" ifconfig -a || true
    else
        record_status "system.ip_address" "system.static" "unsupported" "$(iso_now)" "$(iso_now)" 0 0 127 "" "ip/ifconfig not installed"
    fi
    has_cmd ss && capture_command "system.socket_summary" "system.static" "$EVIDENCE_DIR/socket_summary.txt" ss -s || true
    has_cmd numactl && capture_command "system.numa" "system.static" "$EVIDENCE_DIR/numa.txt" numactl --hardware || true
    has_cmd sysctl && capture_command "system.sysctl_selected" "system.static" "$TABLES_DIR/kernel_parameters.tsv" bash -c '
      for k in vm.swappiness vm.dirty_ratio vm.dirty_background_ratio vm.dirty_bytes vm.dirty_background_bytes vm.overcommit_memory vm.zone_reclaim_mode fs.file-max fs.aio-max-nr net.core.somaxconn net.ipv4.tcp_max_syn_backlog; do
        v=$(sysctl -n "$k" 2>/dev/null) && printf "%s\t%s\n" "$k" "$v"
      done
      exit 0' || true
    {
        printf 'path\tvalue\n'
        for f in /sys/kernel/mm/transparent_hugepage/enabled /sys/kernel/mm/transparent_hugepage/defrag /proc/sys/vm/nr_hugepages; do
            [ -r "$f" ] && printf '%s\t%s\n' "$f" "$(tr '\n' ' ' < "$f")"
        done
    } > "$TABLES_DIR/hugepages.tsv"
    record_status "system.hugepages" "system.static" "ok" "$(iso_now)" "$(iso_now)" 0 "$(awk 'END{print NR-1}' "$TABLES_DIR/hugepages.tsv")" 0 "tables/hugepages.tsv" ""

    if has_cmd ps; then
        ps -eo pid,ppid,user,etimes,%cpu,%mem,args 2>/dev/null | awk 'BEGIN{IGNORECASE=1} /[m]ysqld/ {print}' | redact_command_stream > "$EVIDENCE_DIR/mysql_processes.txt"
        record_status "system.mysql_processes" "system.static" "$([ -s "$EVIDENCE_DIR/mysql_processes.txt" ] && echo ok || echo empty)" "$(iso_now)" "$(iso_now)" 0 "$(wc -l < "$EVIDENCE_DIR/mysql_processes.txt")" 0 "evidence/mysql_processes.txt" ""
    fi

    collect_mycnf_allowlist
}

collect_mycnf_allowlist() {
    local defaults_file datadir basedir cnf_path="" p
    defaults_file=$(ps -eo args 2>/dev/null | grep '[m]ysqld' | grep -o -- '--defaults-file=[^ ]*' | cut -d= -f2 | head -1)
    datadir=$(mysql_scalar 'SELECT @@datadir')
    basedir=$(mysql_scalar 'SELECT @@basedir')
    local paths=()
    [ -n "$defaults_file" ] && paths+=("$defaults_file")
    [ -n "$datadir" ] && paths+=("${datadir%/}/my.cnf")
    [ -n "$basedir" ] && paths+=("${basedir%/}/etc/my.cnf" "${basedir%/}/my.cnf")
    paths+=(/etc/my.cnf /etc/mysql/my.cnf /usr/local/mysql/etc/my.cnf /usr/local/etc/my.cnf)
    for p in "${paths[@]}"; do [ -f "$p" ] && [ -r "$p" ] && { cnf_path="$p"; break; }; done
    if [ -z "$cnf_path" ]; then
        : > "$TABLES_DIR/mycnf_allowlist.tsv"
        record_status "system.mycnf_allowlist" "system.static" "empty" "$(iso_now)" "$(iso_now)" 0 0 0 "tables/mycnf_allowlist.tsv" "no readable config file found"
        return 0
    fi
    {
      printf 'parameter\tconfigured_value\n'
      awk '
        BEGIN{IGNORECASE=1; OFS="\t"}
        /^[[:space:]]*[#;]/ || /^[[:space:]]*$/ {next}
        /^[[:space:]]*\[/ {next}
        {
          line=$0; key=line; sub(/[[:space:]]*=.*/,"",key); gsub(/[[:space:]]/,"",key)
          if (key ~ /^(port|socket|basedir|datadir|tmpdir|server_id|bind_address|max_connections|back_log|open_files_limit|table_open_cache|table_definition_cache|thread_cache_size|wait_timeout|interactive_timeout|skip_name_resolve|character_set_server|collation_server|lower_case_table_names|sql_mode|transaction_isolation|default_storage_engine|performance_schema|slow_query_log|long_query_time|log_output|log_error|general_log|binlog_format|sync_binlog|binlog_expire_logs_seconds|expire_logs_days|gtid_mode|enforce_gtid_consistency|read_only|super_read_only|relay_log_recovery|innodb_buffer_pool_size|innodb_buffer_pool_instances|innodb_redo_log_capacity|innodb_log_file_size|innodb_log_files_in_group|innodb_log_buffer_size|innodb_flush_log_at_trx_commit|innodb_flush_method|innodb_io_capacity|innodb_io_capacity_max|innodb_read_io_threads|innodb_write_io_threads|innodb_page_cleaners|innodb_purge_threads|innodb_file_per_table|innodb_doublewrite|innodb_autoinc_lock_mode|tmp_table_size|max_heap_table_size|sort_buffer_size|join_buffer_size|read_buffer_size|read_rnd_buffer_size)$/) {
            val=line; sub(/^[^=]*=/,"",val); gsub(/^[[:space:]]+|[[:space:]]+$/,"",val); print key,val
          }
        }' "$cnf_path"
    } > "$TABLES_DIR/mycnf_allowlist.tsv"
    printf '%s\n' "$cnf_path" > "$EVIDENCE_DIR/mycnf_path.txt"
    record_status "system.mycnf_allowlist" "system.static" "ok" "$(iso_now)" "$(iso_now)" 0 "$(awk 'END{print NR-1}' "$TABLES_DIR/mycnf_allowlist.tsv")" 0 "tables/mycnf_allowlist.tsv" ""
}

probe_capabilities() {
    MYSQL_VERSION=$(mysql_scalar 'SELECT VERSION()')
    MYSQL_VERSION_COMMENT=$(mysql_scalar 'SELECT @@version_comment')
    MYSQL_HOSTNAME=$(mysql_scalar 'SELECT @@hostname')
    SERVER_UUID=$(mysql_scalar 'SELECT @@GLOBAL.server_uuid')
    SERVER_ID=$(mysql_scalar 'SELECT @@GLOBAL.server_id')
    MYSQL_PORT_OBSERVED=$(mysql_scalar 'SELECT @@GLOBAL.port')
    BIND_ADDRESS=$(mysql_scalar 'SELECT @@GLOBAL.bind_address')
    REPORT_HOST=$(mysql_scalar 'SELECT @@GLOBAL.report_host')
    MYSQL_FAMILY="mysql"
    if printf '%s %s' "$MYSQL_VERSION" "$MYSQL_VERSION_COMMENT" | grep -Eqi 'mariadb'; then MYSQL_FAMILY="mariadb"; fi
    MYSQL_MAJOR=$(printf '%s' "$MYSQL_VERSION" | awk -F. '{gsub(/[^0-9].*/,"",$1); print $1+0}')
    MYSQL_MINOR=$(printf '%s' "$MYSQL_VERSION" | awk -F. '{gsub(/[^0-9].*/,"",$2); print $2+0}')
    READ_ONLY=$(mysql_scalar 'SELECT @@GLOBAL.read_only')
    SUPER_READ_ONLY=$(mysql_scalar 'SELECT @@GLOBAL.super_read_only')
    LOG_BIN=$(mysql_scalar 'SELECT @@GLOBAL.log_bin')
    GTID_MODE=$(mysql_scalar 'SELECT @@GLOBAL.gtid_mode')
    PERFORMANCE_SCHEMA_ENABLED=$(mysql_scalar 'SELECT @@GLOBAL.performance_schema')
    SYS_SCHEMA_AVAILABLE=0; mysql_schema_exists sys && SYS_SCHEMA_AVAILABLE=1
    DATA_LOCKS_AVAILABLE=0; mysql_table_exists performance_schema data_locks && DATA_LOCKS_AVAILABLE=1
    DATA_LOCK_WAITS_AVAILABLE=0; mysql_table_exists performance_schema data_lock_waits && DATA_LOCK_WAITS_AVAILABLE=1
    METADATA_LOCKS_AVAILABLE=0; mysql_table_exists performance_schema metadata_locks && METADATA_LOCKS_AVAILABLE=1
    GR_MEMBERS_AVAILABLE=0; mysql_table_exists performance_schema replication_group_members && GR_MEMBERS_AVAILABLE=1
    REPL_CONN_STATUS_AVAILABLE=0; mysql_table_exists performance_schema replication_connection_status && REPL_CONN_STATUS_AVAILABLE=1
    ERROR_LOG_TABLE_AVAILABLE=0; mysql_table_exists performance_schema error_log && ERROR_LOG_TABLE_AVAILABLE=1
    WSREP_ON=$(mysql_scalar "SHOW GLOBAL VARIABLES LIKE 'wsrep_on'" | awk '{print $2}')
    [ -z "$WSREP_ON" ] && WSREP_ON="OFF"

    {
      printf 'capability\tvalue\n'
      printf 'mysql_version\t%s\n' "$MYSQL_VERSION"
      printf 'version_comment\t%s\n' "$MYSQL_VERSION_COMMENT"
      printf 'database_family\t%s\n' "$MYSQL_FAMILY"
      printf 'bind_address\t%s\n' "$BIND_ADDRESS"
      printf 'report_host\t%s\n' "$REPORT_HOST"
      printf 'performance_schema\t%s\n' "$PERFORMANCE_SCHEMA_ENABLED"
      printf 'sys_schema\t%s\n' "$SYS_SCHEMA_AVAILABLE"
      printf 'data_locks\t%s\n' "$DATA_LOCKS_AVAILABLE"
      printf 'data_lock_waits\t%s\n' "$DATA_LOCK_WAITS_AVAILABLE"
      printf 'metadata_locks\t%s\n' "$METADATA_LOCKS_AVAILABLE"
      printf 'group_replication_members\t%s\n' "$GR_MEMBERS_AVAILABLE"
      printf 'replication_connection_status\t%s\n' "$REPL_CONN_STATUS_AVAILABLE"
      printf 'performance_schema_error_log\t%s\n' "$ERROR_LOG_TABLE_AVAILABLE"
      printf 'wsrep_on\t%s\n' "$WSREP_ON"
      printf 'sar_command\t%s\n' "$HAS_SAR"
      printf 'sadf_command\t%s\n' "$HAS_SADF"
    } > "$TABLES_DIR/capabilities.tsv"
    record_status "mysql.capability_probe" "mysql.capabilities" "ok" "$(iso_now)" "$(iso_now)" 0 "$(awk 'END{print NR-1}' "$TABLES_DIR/capabilities.tsv")" 0 "tables/capabilities.tsv" ""
}

_read_cpu_stat() { awk '/^cpu /{print $2,$3,$4,$5,$6,$7,$8,$9; exit}' /proc/stat 2>/dev/null; }

append_cpu_sample() {
    local ts="$1" elapsed_ms="$2" cur user nice system idle iowait irq softirq steal total idleall dtotal didle
    cur=$(_read_cpu_stat) || return 0
    read -r user nice system idle iowait irq softirq steal <<< "$cur"
    total=$((user+nice+system+idle+iowait+irq+softirq+steal)); idleall=$((idle+iowait))
    if [ -n "${PREV_CPU_TOTAL:-}" ]; then
        dtotal=$((total-PREV_CPU_TOTAL)); didle=$((idleall-PREV_CPU_IDLE))
        awk -v ts="$ts" -v em="$elapsed_ms" -v dt="$dtotal" -v du="$((user-PREV_CPU_USER))" -v ds="$((system-PREV_CPU_SYSTEM))" -v dw="$((iowait-PREV_CPU_IOWAIT))" -v dst="$((steal-PREV_CPU_STEAL))" -v di="$didle" 'BEGIN{if(dt>0) printf "%s,%s,%.4f,%.4f,%.4f,%.4f,%.4f,%.4f\n",ts,em,du*100/dt,ds*100/dt,dw*100/dt,dst*100/dt,di*100/dt,(dt-di)*100/dt}' >> "$CPU_CSV"
    fi
    PREV_CPU_TOTAL=$total; PREV_CPU_IDLE=$idleall; PREV_CPU_USER=$user; PREV_CPU_SYSTEM=$system; PREV_CPU_IOWAIT=$iowait; PREV_CPU_STEAL=$steal
}

append_memory_sample() {
    local ts="$1" elapsed_ms="$2" vals mt ma st sf cached dirty writeback usedpct
    vals=$(awk '$1=="MemTotal:"{mt=$2}$1=="MemAvailable:"{ma=$2}$1=="SwapTotal:"{st=$2}$1=="SwapFree:"{sf=$2}$1=="Cached:"{ca=$2}$1=="Dirty:"{d=$2}$1=="Writeback:"{w=$2}END{print mt+0,ma+0,st+0,sf+0,ca+0,d+0,w+0}' /proc/meminfo 2>/dev/null)
    read -r mt ma st sf cached dirty writeback <<< "$vals"
    usedpct=$(awk -v t="$mt" -v a="$ma" 'BEGIN{if(t>0)printf "%.4f",(t-a)*100/t;else print 0}')
    printf '%s,%s,%s,%s,%s,%s,%s,%s,%s\n' "$ts" "$elapsed_ms" "$((mt*1024))" "$((ma*1024))" "$usedpct" "$((st*1024))" "$(((st-sf)*1024))" "$((cached*1024))" "$(((dirty+writeback)*1024))" >> "$MEM_CSV"
}

append_network_sample() {
    local ts="$1" elapsed_ms="$2" delta_ms="$3" p iface rx tx drx dtx
    for p in /sys/class/net/*; do
        [ -d "$p" ] || continue; iface=${p##*/}; [ "$iface" = lo ] && continue
        rx=$(cat "$p/statistics/rx_bytes" 2>/dev/null || echo 0); tx=$(cat "$p/statistics/tx_bytes" 2>/dev/null || echo 0)
        if [ -n "${PREV_NET_RX[$iface]+x}" ]; then
            drx=$((rx-PREV_NET_RX[$iface])); dtx=$((tx-PREV_NET_TX[$iface]))
            awk -v ts="$ts" -v em="$elapsed_ms" -v i="$iface" -v r="$drx" -v t="$dtx" -v dm="$delta_ms" 'BEGIN{if(dm<=0)dm=1; printf "%s,%s,%s,%.2f,%.2f,%d,%d\n",ts,em,i,r*1000/dm,t*1000/dm,r,t}' >> "$NET_CSV"
        fi
        PREV_NET_RX[$iface]=$rx; PREV_NET_TX[$iface]=$tx
    done
}

append_disk_sample() {
    local ts="$1" elapsed_ms="$2" delta_ms="$3" p dev s ri rs rt wi ws wt inflight io_ms weighted sector_size
    local dri drs drt dwi dws dwt dio dweighted
    for p in /sys/block/*; do
        [ -r "$p/stat" ] || continue; dev=${p##*/}; case "$dev" in loop*|ram*|zram*|fd*|sr*) continue;; esac
        s=$(cat "$p/stat" 2>/dev/null) || continue
        # 新内核可能在前 11 个标准字段后追加 discard/flush 字段。
        # 只提取固定位置，避免 read 的最后一个变量吞掉多个字段后参与算术运算。
        read -r ri rs rt wi ws wt inflight io_ms weighted < <(awk '{print $1,$3,$4,$5,$7,$8,$9,$10,$11}' "$p/stat" 2>/dev/null)
        for v in "$ri" "$rs" "$rt" "$wi" "$ws" "$wt" "$inflight" "$io_ms" "$weighted"; do
            case "$v" in ''|*[!0-9]*) continue 2 ;; esac
        done
        sector_size=$(cat "$p/queue/hw_sector_size" 2>/dev/null || echo 512)
        case "$sector_size" in ''|*[!0-9]*) sector_size=512 ;; esac
        if [ -n "${PREV_DISK_RSECT[$dev]+x}" ]; then
            dri=$((ri-PREV_DISK_RIOS[$dev])); drs=$((rs-PREV_DISK_RSECT[$dev])); drt=$((rt-PREV_DISK_RTICKS[$dev]))
            dwi=$((wi-PREV_DISK_WIOS[$dev])); dws=$((ws-PREV_DISK_WSECT[$dev])); dwt=$((wt-PREV_DISK_WTICKS[$dev]))
            dio=$((io_ms-PREV_DISK_IOTICKS[$dev])); dweighted=$((weighted-PREV_DISK_WEIGHTED[$dev]))
            awk -v ts="$ts" -v em="$elapsed_ms" -v d="$dev" -v dm="$delta_ms" -v bs="$sector_size" -v ri="$dri" -v rs="$drs" -v rt="$drt" -v wi="$dwi" -v ws="$dws" -v wt="$dwt" -v io="$dio" -v wq="$dweighted" 'BEGIN{if(dm<=0)dm=1; printf "%s,%s,%s,%.2f,%.2f,%.2f,%.2f,%.4f,%.4f,%.4f,%.4f\n",ts,em,d,rs*bs*1000/dm,ws*bs*1000/dm,ri*1000/dm,wi*1000/dm,(ri>0?rt/ri:0),(wi>0?wt/wi:0),io*100/dm,wq/dm}' >> "$DISK_CSV"
        fi
        PREV_DISK_RIOS[$dev]=$ri; PREV_DISK_RSECT[$dev]=$rs; PREV_DISK_RTICKS[$dev]=$rt; PREV_DISK_WIOS[$dev]=$wi; PREV_DISK_WSECT[$dev]=$ws; PREV_DISK_WTICKS[$dev]=$wt; PREV_DISK_IOTICKS[$dev]=$io_ms; PREV_DISK_WEIGHTED[$dev]=$weighted
    done
}

append_mysql_status_sample() {
    local ts="$1" elapsed_ms="$2" tmp
    tmp="$TMP_DIR/mysql_status_${elapsed_ms}.tsv"
    mysql_exec -N -s -e 'SHOW GLOBAL STATUS' > "$tmp" 2>> "$MODULE_LOG_DIR/realtime_sampling.log" || return 1
    awk -v ts="$ts" -v em="$elapsed_ms" '
      BEGIN{n=split("Uptime Questions Queries Com_select Com_insert Com_update Com_delete Com_commit Com_rollback Bytes_received Bytes_sent Threads_connected Threads_running Connections Aborted_connects Slow_queries Created_tmp_tables Created_tmp_disk_tables Opened_tables Table_open_cache_hits Table_open_cache_misses Innodb_buffer_pool_read_requests Innodb_buffer_pool_reads Innodb_buffer_pool_pages_dirty Innodb_buffer_pool_pages_total Innodb_rows_read Innodb_rows_inserted Innodb_rows_updated Innodb_rows_deleted Innodb_data_reads Innodb_data_writes Innodb_os_log_written Innodb_row_lock_waits Innodb_row_lock_time Handler_read_rnd_next Select_full_join Sort_merge_passes",k," ")}
      {v[$1]=$2}
      END{printf "%s,%s",ts,em;for(i=1;i<=n;i++)printf ",%s",(k[i] in v?v[k[i]]:"");printf "\n"}' "$tmp" >> "$MYSQL_CSV"
    rm -f "$tmp"
}

collect_realtime_samples() {
    printf 'timestamp,elapsed_ms,user_pct,system_pct,iowait_pct,steal_pct,idle_pct,busy_pct\n' > "$CPU_CSV"
    printf 'timestamp,elapsed_ms,mem_total_bytes,mem_available_bytes,mem_used_pct,swap_total_bytes,swap_used_bytes,cached_bytes,dirty_writeback_bytes\n' > "$MEM_CSV"
    printf 'timestamp,elapsed_ms,interface,rx_bytes_per_sec,tx_bytes_per_sec,rx_bytes_delta,tx_bytes_delta\n' > "$NET_CSV"
    printf 'timestamp,elapsed_ms,device,read_bytes_per_sec,write_bytes_per_sec,read_iops,write_iops,read_await_ms,write_await_ms,util_pct,avg_queue_size\n' > "$DISK_CSV"
    printf 'timestamp,elapsed_ms,Uptime,Questions,Queries,Com_select,Com_insert,Com_update,Com_delete,Com_commit,Com_rollback,Bytes_received,Bytes_sent,Threads_connected,Threads_running,Connections,Aborted_connects,Slow_queries,Created_tmp_tables,Created_tmp_disk_tables,Opened_tables,Table_open_cache_hits,Table_open_cache_misses,Innodb_buffer_pool_read_requests,Innodb_buffer_pool_reads,Innodb_buffer_pool_pages_dirty,Innodb_buffer_pool_pages_total,Innodb_rows_read,Innodb_rows_inserted,Innodb_rows_updated,Innodb_rows_deleted,Innodb_data_reads,Innodb_data_writes,Innodb_os_log_written,Innodb_row_lock_waits,Innodb_row_lock_time,Handler_read_rnd_next,Select_full_join,Sort_merge_passes\n' > "$MYSQL_CSV"

    declare -gA PREV_NET_RX PREV_NET_TX PREV_DISK_RIOS PREV_DISK_RSECT PREV_DISK_RTICKS PREV_DISK_WIOS PREV_DISK_WSECT PREV_DISK_WTICKS PREV_DISK_IOTICKS PREV_DISK_WEIGHTED
    local sampling_started_at sampling_started_ms sampling_finished_at sampling_finished_ms
    local start_mono prev_mono now_mono elapsed delta ts i mysql_fail=0
    sampling_started_at=$(iso_now); sampling_started_ms=$(epoch_ms)
    start_mono=$(monotonic_ms); prev_mono=$start_mono; ts=$(iso_now)
    append_cpu_sample "$ts" 0; append_memory_sample "$ts" 0; append_network_sample "$ts" 0 1; append_disk_sample "$ts" 0 1; append_mysql_status_sample "$ts" 0 || mysql_fail=$((mysql_fail+1))
    for ((i=1; i<=SAMPLE_COUNT; i++)); do
        sleep "$SAMPLE_INTERVAL"
        now_mono=$(monotonic_ms); elapsed=$((now_mono-start_mono)); delta=$((now_mono-prev_mono)); ts=$(iso_now)
        append_cpu_sample "$ts" "$elapsed"
        append_memory_sample "$ts" "$elapsed"
        append_network_sample "$ts" "$elapsed" "$delta"
        append_disk_sample "$ts" "$elapsed" "$delta"
        append_mysql_status_sample "$ts" "$elapsed" || mysql_fail=$((mysql_fail+1))
        prev_mono=$now_mono
        log_info "实时采样 ${i}/${SAMPLE_COUNT}"
    done
    [ "$mysql_fail" -eq 0 ] || log_warn "实时采样中 MySQL 状态读取失败 ${mysql_fail} 次"
    local mysql_points cpu_points disk_points status reason rc
    mysql_points=$(awk 'END{print (NR>0?NR-1:0)}' "$MYSQL_CSV" 2>/dev/null); mysql_points=${mysql_points:-0}
    cpu_points=$(awk 'END{print (NR>0?NR-1:0)}' "$CPU_CSV" 2>/dev/null); cpu_points=${cpu_points:-0}
    disk_points=$(awk 'END{print (NR>0?NR-1:0)}' "$DISK_CSV" 2>/dev/null); disk_points=${disk_points:-0}
    status="ok"; reason="completed ${SAMPLE_COUNT} intervals; mysql_points=${mysql_points}; cpu_points=${cpu_points}; disk_rows=${disk_points}"; rc=0
    if [ "$mysql_points" -lt $((SAMPLE_COUNT+1)) ] || [ "$cpu_points" -lt "$SAMPLE_COUNT" ]; then
        status="partial"; reason="requested ${SAMPLE_COUNT} intervals but collected mysql_points=${mysql_points}, cpu_points=${cpu_points}, disk_rows=${disk_points}; mysql_failures=${mysql_fail}"; rc=2
    elif [ "$mysql_fail" -gt 0 ]; then
        status="partial"; reason="sampling completed with ${mysql_fail} MySQL status read failures"; rc=2
    fi
    sampling_finished_at=$(iso_now); sampling_finished_ms=$(epoch_ms)
    record_status "timeseries.realtime_sampling" "timeseries" "$status" "$sampling_started_at" "$sampling_finished_at" "$((sampling_finished_ms-sampling_started_ms))" "$mysql_points" "$rc" "timeseries/" "$reason"
    return "$rc"
}

find_sar_files() {
    local d
    for d in /var/log/sa /var/log/sysstat; do
        [ -d "$d" ] || continue
        find "$d" -maxdepth 1 -type f \( -name 'sa[0-9][0-9]' -o -name 'sa[0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]' \) -mtime -2 -readable 2>/dev/null
    done | sort -u
}

collect_sadf_metric() {
    local metric_id="$1" outfile="$2"; shift 2
    local tmp="$TMP_DIR/sadf_${metric_id}.tmp" f any=0 rc=0
    : > "$outfile"
    while IFS= read -r f; do
        [ -r "$f" ] || continue
        printf '# source_file=%s\n' "$f" >> "$outfile"
        sadf -d "$f" -- "$@" >> "$outfile" 2>> "$MODULE_LOG_DIR/sar_history.log"; rc=$?
        [ "$rc" -eq 0 ] && any=1
    done < "$SAR_FILE_LIST"
    if [ "$any" -eq 1 ] && [ -s "$outfile" ]; then return 0; fi
    return 1
}

compute_sar_coverage() {
    local src="$HISTORY_DIR/sar_cpu.csv" t first_epoch="" last_epoch="" first_ts="" last_ts="" coverage_seconds=0 coverage_hours=0 status="empty"
    [ -s "$src" ] || return 0
    while IFS= read -r t; do
        [ -n "$t" ] || continue
        e=$(date -d "$t" +%s 2>/dev/null) || continue
        if [ -z "$first_epoch" ] || [ "$e" -lt "$first_epoch" ]; then first_epoch=$e; first_ts=$t; fi
        if [ -z "$last_epoch" ] || [ "$e" -gt "$last_epoch" ]; then last_epoch=$e; last_ts=$t; fi
    done < <(awk -F';' '!/^#/ && NF>=3 && $3 ~ /^[0-9][0-9][0-9][0-9]-/ {print $3}' "$src")
    if [ -n "$first_epoch" ] && [ -n "$last_epoch" ]; then
        coverage_seconds=$((last_epoch-first_epoch)); [ "$coverage_seconds" -lt 0 ] && coverage_seconds=0
        coverage_hours=$(awk -v s="$coverage_seconds" 'BEGIN{printf "%.2f",s/3600}')
        status="ok"
        [ "$coverage_seconds" -lt $((SAR_HISTORY_HOURS*3600*9/10)) ] && status="partial"
    fi
    {
      printf 'status\t%s\n' "$status"
      printf 'requested_hours\t%s\n' "$SAR_HISTORY_HOURS"
      printf 'first_timestamp\t%s\n' "$first_ts"
      printf 'last_timestamp\t%s\n' "$last_ts"
      printf 'coverage_seconds\t%s\n' "$coverage_seconds"
      printf 'coverage_hours\t%s\n' "$coverage_hours"
    } > "$HISTORY_DIR/coverage.tsv"
    {
      printf '{"schema_version":"1.0","status":%s,"requested_hours":%s,"first_timestamp":%s,"last_timestamp":%s,"coverage_seconds":%s,"coverage_hours":%s}\n' \
        "$(json_quote "$status")" "$SAR_HISTORY_HOURS" "$(json_quote "$first_ts")" "$(json_quote "$last_ts")" "$coverage_seconds" "${coverage_hours:-0}"
    } > "$HISTORY_DIR/coverage.json"
}

collect_sar_history() {
    local start_iso start_ms end_iso end_ms status reason count
    start_iso=$(iso_now); start_ms=$(epoch_ms)
    SAR_FILE_LIST="$TMP_DIR/sar_files.txt"; find_sar_files > "$SAR_FILE_LIST"
    count=$(wc -l < "$SAR_FILE_LIST" | tr -d ' ')
    if ! has_cmd sadf; then
        status="unsupported"; reason="sadf/sysstat not installed"
    elif [ "${count:-0}" -eq 0 ]; then
        status="empty"; reason="no readable sar history files found"
    else
        cp "$SAR_FILE_LIST" "$HISTORY_DIR/source_files.txt"
        collect_sadf_metric cpu "$HISTORY_DIR/sar_cpu.csv" -u ALL || true
        collect_sadf_metric memory "$HISTORY_DIR/sar_memory.csv" -r || true
        collect_sadf_metric swap "$HISTORY_DIR/sar_swap.csv" -S || true
        collect_sadf_metric load "$HISTORY_DIR/sar_load.csv" -q || true
        collect_sadf_metric disk "$HISTORY_DIR/sar_disk.csv" -d -p || true
        collect_sadf_metric network "$HISTORY_DIR/sar_network.csv" -n DEV || true
        collect_sadf_metric io "$HISTORY_DIR/sar_io.csv" -b || true
        collect_sadf_metric process "$HISTORY_DIR/sar_process.csv" -w || true
        compute_sar_coverage
        local coverage_status coverage_hours
        coverage_status=$(awk -F'\t' '$1=="status"{print $2}' "$HISTORY_DIR/coverage.tsv" 2>/dev/null)
        coverage_hours=$(awk -F'\t' '$1=="coverage_hours"{print $2}' "$HISTORY_DIR/coverage.tsv" 2>/dev/null)
        [ "$coverage_status" = "partial" ] && status="partial" || status="ok"
        reason="raw sadf data exported; approximate CPU history coverage=${coverage_hours:-unknown} hours; Python will perform final filtering and coverage calculation"
    fi
    end_iso=$(iso_now); end_ms=$(epoch_ms)
    record_status "system.sar_history" "system.history" "$status" "$start_iso" "$end_iso" "$((end_ms-start_ms))" "${count:-0}" 0 "history/" "$reason"
    return 0
}

record_skipped() {
    local item_id="$1" category="$2" status="$3" reason="$4" outfile="${5-}" output_file=""
    if [ -n "$outfile" ]; then
        mkdir -p "$(dirname "$outfile")"
        ensure_tsv_header "$outfile" || : > "$outfile"
        output_file=$(safe_relpath "$outfile")
    fi
    record_status "$item_id" "$category" "$status" "$(iso_now)" "$(iso_now)" 0 0 0 "$output_file" "$reason"
}


sanitize_tsv_columns() {
    local file="$1" wanted="$2" tmp="$file.safe"
    [ -s "$file" ] || return 0
    awk -F'\t' -v OFS='\t' -v wanted="$wanted" '
      BEGIN{n=split(wanted,w," ")}
      NR==1{
        for(i=1;i<=NF;i++){
          h=tolower($i)
          for(j=1;j<=n;j++) if(h==tolower(w[j])) keep[++k]=i
        }
        if(k==0) exit 2
        for(x=1;x<=k;x++) printf "%s%s",(x>1?OFS:""),$keep[x]
        printf "\n"; next
      }
      {
        for(x=1;x<=k;x++) printf "%s%s",(x>1?OFS:""),$keep[x]
        printf "\n"
      }' "$file" > "$tmp"
    if [ $? -eq 0 ] && [ -s "$tmp" ]; then mv "$tmp" "$file"; else rm -f "$tmp"; fi
}

collect_mysql_basic() {
    mysql_query_fallback "mysql.global_variables" "mysql.basic" "$TABLES_DIR/global_variables.tsv" \
      "SELECT VARIABLE_NAME,VARIABLE_VALUE FROM performance_schema.global_variables WHERE VARIABLE_NAME NOT LIKE '%rsa_public_key%' AND VARIABLE_NAME NOT IN ('wsrep_sst_auth') ORDER BY VARIABLE_NAME" \
      "SHOW GLOBAL VARIABLES" || true
    mysql_query_fallback "mysql.global_status" "mysql.basic" "$TABLES_DIR/global_status.tsv" \
      "SELECT VARIABLE_NAME,VARIABLE_VALUE FROM performance_schema.global_status ORDER BY VARIABLE_NAME" \
      "SHOW GLOBAL STATUS" || true
    mysql_query_tsv "mysql.engines" "mysql.basic" "$TABLES_DIR/engines.tsv" "SHOW ENGINES" || true
    mysql_query_tsv "mysql.plugins" "mysql.basic" "$TABLES_DIR/plugins.tsv" "SHOW PLUGINS" || true
    mysql_query_tsv "mysql.schemas" "mysql.basic" "$TABLES_DIR/schemas.tsv" \
      "SELECT schema_name,default_character_set_name,default_collation_name FROM information_schema.schemata ORDER BY schema_name" || true
    mysql_query_tsv "mysql.innodb_status" "mysql.basic" "$EVIDENCE_DIR/innodb_status.tsv" "SHOW ENGINE INNODB STATUS" || true
    mysql_query_tsv "mysql.open_tables" "mysql.basic" "$TABLES_DIR/open_tables.tsv" \
      "SELECT OBJECT_SCHEMA,COUNT(*) AS open_handle_count,COUNT(DISTINCT OWNER_THREAD_ID) AS owner_threads FROM performance_schema.table_handles GROUP BY OBJECT_SCHEMA ORDER BY open_handle_count DESC" || true
}

collect_mysql_capacity() {
    mysql_query_tsv "mysql.database_sizes" "mysql.capacity" "$TABLES_DIR/database_sizes.tsv" \
      "SELECT table_schema AS database_name,ROUND(SUM(data_length+index_length)/1024/1024,2) AS total_mb,ROUND(SUM(data_length)/1024/1024,2) AS data_mb,ROUND(SUM(index_length)/1024/1024,2) AS index_mb,ROUND(SUM(data_free)/1024/1024,2) AS data_free_mb,COUNT(*) AS table_count FROM information_schema.tables WHERE table_schema NOT IN ('mysql','sys','information_schema','performance_schema') GROUP BY table_schema ORDER BY SUM(data_length+index_length) DESC" || true

    mysql_query_tsv "mysql.object_counts" "mysql.capacity" "$TABLES_DIR/object_counts.tsv" \
      "SELECT table_schema,SUM(table_type='BASE TABLE') AS base_tables,SUM(table_type='VIEW') AS views,SUM(engine='InnoDB') AS innodb_tables,SUM(engine IS NULL) AS no_engine_objects FROM information_schema.tables WHERE table_schema NOT IN ('mysql','sys','information_schema','performance_schema') GROUP BY table_schema ORDER BY table_schema" || true

    mysql_query_tsv "mysql.large_tables" "mysql.capacity" "$TABLES_DIR/large_tables_top.tsv" \
      "SELECT table_schema,table_name,engine,table_rows,ROUND((data_length+index_length)/1024/1024,2) AS total_mb,ROUND(data_length/1024/1024,2) AS data_mb,ROUND(index_length/1024/1024,2) AS index_mb,ROUND(data_free/1024/1024,2) AS data_free_mb,table_collation,create_time,update_time FROM information_schema.tables WHERE table_schema NOT IN ('mysql','sys','information_schema','performance_schema') AND table_type='BASE TABLE' ORDER BY data_length+index_length DESC LIMIT ${TOP_N}" || true

    mysql_query_tsv "mysql.fragmentation" "mysql.capacity" "$TABLES_DIR/fragmentation_top.tsv" \
      "SELECT table_schema,table_name,engine,ROUND((data_length+index_length)/1024/1024,2) AS allocated_mb,ROUND(data_free/1024/1024,2) AS data_free_mb,ROUND(data_free*100/NULLIF(data_length+index_length+data_free,0),2) AS fragmentation_pct FROM information_schema.tables WHERE table_schema NOT IN ('mysql','sys','information_schema','performance_schema') AND table_type='BASE TABLE' AND (data_length+index_length+data_free)>0 ORDER BY fragmentation_pct DESC,data_free DESC LIMIT ${TOP_N}" || true

    mysql_query_tsv "mysql.no_primary_key_summary" "mysql.capacity" "$TABLES_DIR/no_primary_key_summary.tsv" \
      "SELECT COUNT(*) AS table_count,ROUND(SUM(t.data_length+t.index_length)/1024/1024,2) AS total_mb FROM information_schema.tables t LEFT JOIN information_schema.statistics s ON s.table_schema=t.table_schema AND s.table_name=t.table_name AND s.index_name='PRIMARY' WHERE t.table_schema NOT IN ('mysql','sys','information_schema','performance_schema') AND t.table_type='BASE TABLE' AND s.table_name IS NULL" || true
    mysql_query_tsv "mysql.no_primary_key" "mysql.capacity" "$TABLES_DIR/no_primary_key_top.tsv" \
      "SELECT t.table_schema,t.table_name,t.engine,t.table_rows,ROUND((t.data_length+t.index_length)/1024/1024,2) AS total_mb FROM information_schema.tables t LEFT JOIN information_schema.statistics s ON s.table_schema=t.table_schema AND s.table_name=t.table_name AND s.index_name='PRIMARY' WHERE t.table_schema NOT IN ('mysql','sys','information_schema','performance_schema') AND t.table_type='BASE TABLE' AND s.table_name IS NULL ORDER BY t.data_length+t.index_length DESC LIMIT ${TOP_N}" || true

    mysql_query_tsv "mysql.auto_increment_usage" "mysql.capacity" "$TABLES_DIR/auto_increment_usage.tsv" \
      "SELECT t.table_schema,t.table_name,c.column_name,c.column_type,t.auto_increment,CASE c.data_type WHEN 'tinyint' THEN IF(LOWER(c.column_type) LIKE '%unsigned%',255,127) WHEN 'smallint' THEN IF(LOWER(c.column_type) LIKE '%unsigned%',65535,32767) WHEN 'mediumint' THEN IF(LOWER(c.column_type) LIKE '%unsigned%',16777215,8388607) WHEN 'int' THEN IF(LOWER(c.column_type) LIKE '%unsigned%',4294967295,2147483647) WHEN 'bigint' THEN IF(LOWER(c.column_type) LIKE '%unsigned%',18446744073709551615,9223372036854775807) ELSE NULL END AS max_value,ROUND(t.auto_increment*100.0/NULLIF(CASE c.data_type WHEN 'tinyint' THEN IF(LOWER(c.column_type) LIKE '%unsigned%',255,127) WHEN 'smallint' THEN IF(LOWER(c.column_type) LIKE '%unsigned%',65535,32767) WHEN 'mediumint' THEN IF(LOWER(c.column_type) LIKE '%unsigned%',16777215,8388607) WHEN 'int' THEN IF(LOWER(c.column_type) LIKE '%unsigned%',4294967295,2147483647) WHEN 'bigint' THEN IF(LOWER(c.column_type) LIKE '%unsigned%',18446744073709551615,9223372036854775807) ELSE NULL END,0),6) AS used_pct FROM information_schema.tables t JOIN information_schema.columns c ON c.table_schema=t.table_schema AND c.table_name=t.table_name AND LOWER(c.extra) LIKE '%auto_increment%' WHERE t.auto_increment IS NOT NULL AND t.table_schema NOT IN ('mysql','sys','information_schema','performance_schema') ORDER BY used_pct DESC LIMIT ${TOP_N}" || true

    mysql_query_tsv "mysql.partition_summary" "mysql.capacity" "$TABLES_DIR/partition_summary.tsv" \
      "SELECT table_schema,table_name,COUNT(*) AS partition_count,MIN(partition_method) AS partition_method,ROUND(SUM(data_length+index_length)/1024/1024,2) AS total_mb,MAX(partition_ordinal_position) AS max_partition_ordinal FROM information_schema.partitions WHERE partition_name IS NOT NULL AND table_schema NOT IN ('mysql','sys','information_schema','performance_schema') GROUP BY table_schema,table_name ORDER BY partition_count DESC,total_mb DESC LIMIT ${TOP_N}" || true

    mysql_query_tsv "mysql.non_innodb_tables" "mysql.capacity" "$TABLES_DIR/non_innodb_tables.tsv" \
      "SELECT table_schema,table_name,engine,table_rows,ROUND((data_length+index_length)/1024/1024,2) AS total_mb FROM information_schema.tables WHERE table_schema NOT IN ('mysql','sys','information_schema','performance_schema') AND table_type='BASE TABLE' AND IFNULL(engine,'') <> 'InnoDB' ORDER BY data_length+index_length DESC LIMIT ${TOP_N}" || true
}

collect_mysql_performance() {
    mysql_query_tsv "mysql.long_transactions" "mysql.performance" "$TABLES_DIR/long_transactions.tsv" \
      "SELECT trx_id,trx_state,TIMESTAMPDIFF(SECOND,trx_started,NOW()) AS duration_seconds,trx_rows_locked,trx_rows_modified,trx_tables_locked,trx_mysql_thread_id,LEFT(IFNULL(trx_query,''),500) AS query_sample FROM information_schema.innodb_trx ORDER BY trx_started LIMIT 200" || true

    if [ "$METADATA_LOCKS_AVAILABLE" -eq 1 ]; then
        mysql_query_tsv "mysql.metadata_locks" "mysql.performance" "$TABLES_DIR/metadata_locks_pending.tsv" \
          "SELECT OBJECT_TYPE,OBJECT_SCHEMA,OBJECT_NAME,LOCK_TYPE,LOCK_DURATION,LOCK_STATUS,OWNER_THREAD_ID FROM performance_schema.metadata_locks WHERE LOCK_STATUS='PENDING' ORDER BY OBJECT_SCHEMA,OBJECT_NAME LIMIT 500" || true
    else record_skipped "mysql.metadata_locks" "mysql.performance" "unsupported" "performance_schema.metadata_locks unavailable" "$TABLES_DIR/metadata_locks_pending.tsv"; fi

    if [ "$DATA_LOCK_WAITS_AVAILABLE" -eq 1 ]; then
        mysql_query_tsv "mysql.data_lock_waits" "mysql.performance" "$TABLES_DIR/data_lock_waits.tsv" \
          "SELECT ENGINE,REQUESTING_ENGINE_TRANSACTION_ID,BLOCKING_ENGINE_TRANSACTION_ID,REQUESTING_THREAD_ID,BLOCKING_THREAD_ID FROM performance_schema.data_lock_waits LIMIT 500" || true
    else record_skipped "mysql.data_lock_waits" "mysql.performance" "unsupported" "performance_schema.data_lock_waits unavailable" "$TABLES_DIR/data_lock_waits.tsv"; fi

    mysql_query_tsv "mysql.processlist" "mysql.performance" "$TABLES_DIR/processlist.tsv" \
      "SELECT ID,USER,HOST,DB,COMMAND,TIME,STATE,LEFT(REPLACE(REPLACE(IFNULL(INFO,''),'\\n',' '),'\\r',' '),500) AS SQL_TEXT FROM information_schema.processlist ORDER BY TIME DESC LIMIT 200" || true
    mysql_query_tsv "mysql.sql_digests" "mysql.performance" "$TABLES_DIR/sql_digests_top.tsv" \
      "SELECT IFNULL(SCHEMA_NAME,'') AS schema_name,DIGEST,COUNT_STAR,ROUND(SUM_TIMER_WAIT/1000000000000,3) AS total_seconds,ROUND(AVG_TIMER_WAIT/1000000000000,6) AS avg_seconds,SUM_ROWS_EXAMINED,SUM_ROWS_SENT,SUM_NO_INDEX_USED,SUM_NO_GOOD_INDEX_USED,LEFT(REPLACE(REPLACE(DIGEST_TEXT,'\\n',' '),'\\r',' '),500) AS digest_text FROM performance_schema.events_statements_summary_by_digest WHERE DIGEST IS NOT NULL AND DIGEST_TEXT NOT LIKE '%INFORMATION_SCHEMA%' AND DIGEST_TEXT NOT LIKE '%PERFORMANCE_SCHEMA%' AND DIGEST_TEXT NOT LIKE 'SHOW %' AND DIGEST_TEXT NOT LIKE 'SELECT @@%' AND DIGEST_TEXT NOT LIKE 'SELECT IFNULL ( SCHEMA_NAME%' AND DIGEST_TEXT NOT LIKE '%`sys` .%' ORDER BY SUM_TIMER_WAIT DESC LIMIT ${TOP_N}" || true

    if [ "$SYS_SCHEMA_AVAILABLE" -eq 1 ] && mysql_table_exists sys schema_redundant_indexes; then
        mysql_query_tsv "mysql.redundant_indexes" "mysql.performance" "$TABLES_DIR/redundant_indexes.tsv" \
          "SELECT table_schema,table_name,redundant_index_name,redundant_index_columns,dominant_index_name,dominant_index_columns,sql_drop_index FROM sys.schema_redundant_indexes ORDER BY table_schema,table_name LIMIT 500" || true
    else record_skipped "mysql.redundant_indexes" "mysql.performance" "unsupported" "sys.schema_redundant_indexes unavailable" "$TABLES_DIR/redundant_indexes.tsv"; fi

    if [ "$SYS_SCHEMA_AVAILABLE" -eq 1 ] && mysql_table_exists sys schema_unused_indexes; then
        mysql_query_tsv "mysql.unused_indexes" "mysql.performance" "$TABLES_DIR/unused_indexes.tsv" \
          "SELECT object_schema,object_name,index_name FROM sys.schema_unused_indexes ORDER BY object_schema,object_name LIMIT 500" || true
    else record_skipped "mysql.unused_indexes" "mysql.performance" "unsupported" "sys.schema_unused_indexes unavailable" "$TABLES_DIR/unused_indexes.tsv"; fi

    mysql_query_tsv "mysql.table_io_top" "mysql.performance" "$TABLES_DIR/table_io_top.tsv" \
      "SELECT OBJECT_SCHEMA,OBJECT_NAME,COUNT_READ,COUNT_WRITE,ROUND(SUM_TIMER_WAIT/1000000000000,3) AS total_wait_seconds FROM performance_schema.table_io_waits_summary_by_table WHERE OBJECT_SCHEMA NOT IN ('mysql','sys','information_schema','performance_schema') ORDER BY SUM_TIMER_WAIT DESC LIMIT ${TOP_N}" || true
    mysql_query_tsv "mysql.file_io_top" "mysql.performance" "$TABLES_DIR/file_io_top.tsv" \
      "SELECT FILE_NAME,EVENT_NAME,COUNT_READ,COUNT_WRITE,SUM_NUMBER_OF_BYTES_READ,SUM_NUMBER_OF_BYTES_WRITE,ROUND(SUM_TIMER_WAIT/1000000000000,3) AS total_wait_seconds FROM performance_schema.file_summary_by_instance ORDER BY SUM_TIMER_WAIT DESC LIMIT ${TOP_N}" || true
    mysql_query_tsv "mysql.wait_events_top" "mysql.performance" "$TABLES_DIR/wait_events_top.tsv" \
      "SELECT EVENT_NAME,COUNT_STAR,ROUND(SUM_TIMER_WAIT/1000000000000,3) AS total_wait_seconds,ROUND(AVG_TIMER_WAIT/1000000000000,6) AS avg_wait_seconds FROM performance_schema.events_waits_summary_global_by_event_name WHERE COUNT_STAR>0 ORDER BY SUM_TIMER_WAIT DESC LIMIT ${TOP_N}" || true
}

collect_mysql_replication() {
    if [ "$MYSQL_FAMILY" = "mysql" ] && [ "${MYSQL_MAJOR:-0}" -ge 8 ]; then
        mysql_query_tsv "mysql.replica_status" "mysql.replication" "$TABLES_DIR/replica_status.tsv" "SHOW REPLICA STATUS" || true
    else
        mysql_query_tsv "mysql.replica_status" "mysql.replication" "$TABLES_DIR/replica_status.tsv" "SHOW SLAVE STATUS" || true
    fi
    sanitize_tsv_columns "$TABLES_DIR/replica_status.tsv" "Channel_Name Source_Host Master_Host Source_Port Master_Port Source_UUID Master_UUID Connect_Retry Source_Log_File Master_Log_File Read_Source_Log_Pos Read_Master_Log_Pos Relay_Log_File Relay_Log_Pos Relay_Source_Log_File Relay_Master_Log_File Replica_IO_Running Slave_IO_Running Replica_SQL_Running Slave_SQL_Running Replicate_Do_DB Replicate_Ignore_DB Replicate_Do_Table Replicate_Ignore_Table Replicate_Wild_Do_Table Replicate_Wild_Ignore_Table Last_Errno Last_IO_Errno Last_SQL_Errno Skip_Counter Exec_Source_Log_Pos Exec_Master_Log_Pos Relay_Log_Space Until_Condition Until_Log_File Until_Log_Pos Source_SSL_Allowed Master_SSL_Allowed Seconds_Behind_Source Seconds_Behind_Master Source_Server_Id Master_Server_Id Source_UUID Master_UUID SQL_Delay SQL_Remaining_Delay Retrieved_Gtid_Set Executed_Gtid_Set Auto_Position Replicate_Rewrite_DB"
    if [ "$LOG_BIN" = "1" ] || [ "$LOG_BIN" = "ON" ]; then
        if [ "$MYSQL_FAMILY" = "mysql" ] && { [ "${MYSQL_MAJOR:-0}" -gt 8 ] || { [ "${MYSQL_MAJOR:-0}" -eq 8 ] && [ "${MYSQL_MINOR:-0}" -ge 4 ]; }; }; then
            mysql_query_tsv "mysql.binary_log_status" "mysql.replication" "$TABLES_DIR/binary_log_status.tsv" "SHOW BINARY LOG STATUS" || true
        else
            mysql_query_tsv "mysql.binary_log_status" "mysql.replication" "$TABLES_DIR/binary_log_status.tsv" "SHOW MASTER STATUS" || true
        fi
        # GTID set may contain embedded newlines; join continuation lines
        if [ -s "$TABLES_DIR/binary_log_status.tsv" ]; then
            sed -i ':a;N;$!ba;s/,\n/, /g' "$TABLES_DIR/binary_log_status.tsv" 2>/dev/null || true
        fi
        mysql_query_tsv "mysql.binary_logs" "mysql.replication" "$TABLES_DIR/binary_logs.tsv" "SHOW BINARY LOGS" || true
    else
        record_skipped "mysql.binary_log_status" "mysql.replication" "not_applicable" "binary logging is disabled" "$TABLES_DIR/binary_log_status.tsv"
        record_skipped "mysql.binary_logs" "mysql.replication" "not_applicable" "binary logging is disabled" "$TABLES_DIR/binary_logs.tsv"
    fi

    if [ "$REPL_CONN_STATUS_AVAILABLE" -eq 1 ]; then
        if [ "$INCLUDE_LOG_TEXT" -eq 1 ]; then
            mysql_query_tsv "mysql.replication_channels" "mysql.replication" "$TABLES_DIR/replication_channels.tsv" \
              "SELECT CHANNEL_NAME,GROUP_NAME,SOURCE_UUID,THREAD_ID,SERVICE_STATE,COUNT_RECEIVED_HEARTBEATS,LAST_HEARTBEAT_TIMESTAMP,RECEIVED_TRANSACTION_SET,LAST_ERROR_NUMBER,LAST_ERROR_MESSAGE,LAST_ERROR_TIMESTAMP FROM performance_schema.replication_connection_status ORDER BY CHANNEL_NAME" || true
        else
            mysql_query_tsv "mysql.replication_channels" "mysql.replication" "$TABLES_DIR/replication_channels.tsv" \
              "SELECT CHANNEL_NAME,GROUP_NAME,SOURCE_UUID,THREAD_ID,SERVICE_STATE,COUNT_RECEIVED_HEARTBEATS,LAST_HEARTBEAT_TIMESTAMP,RECEIVED_TRANSACTION_SET,LAST_ERROR_NUMBER,CASE WHEN LAST_ERROR_MESSAGE='' THEN '' ELSE SHA2(LAST_ERROR_MESSAGE,256) END AS LAST_ERROR_MESSAGE_SHA256,LAST_ERROR_TIMESTAMP FROM performance_schema.replication_connection_status ORDER BY CHANNEL_NAME" || true
        fi
    else record_skipped "mysql.replication_channels" "mysql.replication" "unsupported" "replication_connection_status unavailable" "$TABLES_DIR/replication_channels.tsv"; fi

    if mysql_table_exists performance_schema replication_applier_status_by_worker; then
        if [ "$INCLUDE_LOG_TEXT" -eq 1 ]; then
            mysql_query_tsv "mysql.replication_workers" "mysql.replication" "$TABLES_DIR/replication_workers.tsv" \
              "SELECT CHANNEL_NAME,WORKER_ID,THREAD_ID,SERVICE_STATE,LAST_ERROR_NUMBER,LAST_ERROR_MESSAGE,LAST_ERROR_TIMESTAMP,LAST_APPLIED_TRANSACTION,APPLYING_TRANSACTION FROM performance_schema.replication_applier_status_by_worker ORDER BY CHANNEL_NAME,WORKER_ID" || true
        else
            mysql_query_tsv "mysql.replication_workers" "mysql.replication" "$TABLES_DIR/replication_workers.tsv" \
              "SELECT CHANNEL_NAME,WORKER_ID,THREAD_ID,SERVICE_STATE,LAST_ERROR_NUMBER,CASE WHEN LAST_ERROR_MESSAGE='' THEN '' ELSE SHA2(LAST_ERROR_MESSAGE,256) END AS LAST_ERROR_MESSAGE_SHA256,LAST_ERROR_TIMESTAMP,LAST_APPLIED_TRANSACTION,APPLYING_TRANSACTION FROM performance_schema.replication_applier_status_by_worker ORDER BY CHANNEL_NAME,WORKER_ID" || true
        fi
    else record_skipped "mysql.replication_workers" "mysql.replication" "unsupported" "replication_applier_status_by_worker unavailable" "$TABLES_DIR/replication_workers.tsv"; fi

    if [ "$GR_MEMBERS_AVAILABLE" -eq 1 ]; then
        mysql_query_tsv "mysql.group_replication_members" "mysql.replication" "$TABLES_DIR/group_replication_members.tsv" \
          "SELECT CHANNEL_NAME,MEMBER_ID,MEMBER_HOST,MEMBER_PORT,MEMBER_STATE,MEMBER_ROLE,MEMBER_VERSION FROM performance_schema.replication_group_members ORDER BY MEMBER_HOST,MEMBER_PORT" || true
        if mysql_table_exists performance_schema replication_group_member_stats; then
            mysql_query_tsv "mysql.group_replication_stats" "mysql.replication" "$TABLES_DIR/group_replication_stats.tsv" \
              "SELECT CHANNEL_NAME,VIEW_ID,MEMBER_ID,COUNT_TRANSACTIONS_IN_QUEUE,COUNT_TRANSACTIONS_CHECKED,COUNT_CONFLICTS_DETECTED,COUNT_TRANSACTIONS_ROWS_VALIDATING,TRANSACTIONS_COMMITTED_ALL_MEMBERS,LAST_CONFLICT_FREE_TRANSACTION FROM performance_schema.replication_group_member_stats" || true
        fi
    else record_skipped "mysql.group_replication_members" "mysql.replication" "not_applicable" "group replication tables unavailable or not enabled" "$TABLES_DIR/group_replication_members.tsv"; fi

    mysql_query_tsv "mysql.wsrep_variables" "mysql.replication" "$TABLES_DIR/wsrep_variables.tsv" "SHOW GLOBAL VARIABLES LIKE 'wsrep%'" || true
    if [ -s "$TABLES_DIR/wsrep_variables.tsv" ]; then
        awk -F'\t' 'BEGIN{OFS="\t"} NR==1 || tolower($1)!~/(auth|password|secret)/' "$TABLES_DIR/wsrep_variables.tsv" > "$TABLES_DIR/wsrep_variables.tsv.safe" && mv "$TABLES_DIR/wsrep_variables.tsv.safe" "$TABLES_DIR/wsrep_variables.tsv"
    fi
    mysql_query_tsv "mysql.wsrep_status" "mysql.replication" "$TABLES_DIR/wsrep_status.tsv" "SHOW GLOBAL STATUS LIKE 'wsrep%'" || true
}

collect_mysql_security_objects() {
    mysql_query_fallback "mysql.accounts" "mysql.security" "$TABLES_DIR/accounts.tsv" \
      "SELECT user,host,plugin,IFNULL(account_locked,'N') AS account_locked,IFNULL(password_expired,'N') AS password_expired,IFNULL(password_lifetime,'') AS password_lifetime,Super_priv,Grant_priv,Create_user_priv,File_priv,Shutdown_priv,Process_priv,Repl_slave_priv,Repl_client_priv FROM mysql.user WHERE user NOT IN ('mysql.sys','mysql.session','mysql.infoschema') ORDER BY user,host" \
      "SELECT user,host,plugin,Super_priv,Grant_priv,Create_user_priv,File_priv,Shutdown_priv,Process_priv,Repl_slave_priv,Repl_client_priv FROM mysql.user ORDER BY user,host" || true

    mysql_query_tsv "mysql.schema_privileges" "mysql.security" "$TABLES_DIR/schema_privileges.tsv" \
      "SELECT GRANTEE,TABLE_SCHEMA,PRIVILEGE_TYPE,IS_GRANTABLE FROM information_schema.schema_privileges ORDER BY GRANTEE,TABLE_SCHEMA,PRIVILEGE_TYPE LIMIT 2000" || true
    mysql_query_tsv "mysql.user_privileges" "mysql.security" "$TABLES_DIR/user_privileges.tsv" \
      "SELECT GRANTEE,PRIVILEGE_TYPE,IS_GRANTABLE FROM information_schema.user_privileges ORDER BY GRANTEE,PRIVILEGE_TYPE LIMIT 2000" || true
    mysql_query_tsv "mysql.events" "mysql.objects" "$TABLES_DIR/events.tsv" \
      "SELECT event_schema,event_name,status,event_type,interval_value,interval_field,starts,ends,last_executed,definer FROM information_schema.events ORDER BY event_schema,event_name LIMIT 1000" || true
    mysql_query_tsv "mysql.routines" "mysql.objects" "$TABLES_DIR/routines.tsv" \
      "SELECT routine_schema,routine_name,routine_type,definer,security_type,created,last_altered FROM information_schema.routines WHERE routine_schema NOT IN ('mysql','sys','information_schema','performance_schema') ORDER BY routine_schema,routine_name LIMIT 2000" || true
    mysql_query_tsv "mysql.triggers" "mysql.objects" "$TABLES_DIR/triggers.tsv" \
      "SELECT trigger_schema,trigger_name,event_manipulation,event_object_table,action_timing,definer FROM information_schema.triggers WHERE trigger_schema NOT IN ('mysql','sys','information_schema','performance_schema') ORDER BY trigger_schema,trigger_name LIMIT 2000" || true
}

collect_mysql_logs_backup() {
    local log_error_path slow_log_path general_log_path
    log_error_path=$(mysql_scalar 'SELECT @@GLOBAL.log_error')
    slow_log_path=$(mysql_scalar 'SELECT @@GLOBAL.slow_query_log_file')
    general_log_path=$(mysql_scalar 'SELECT @@GLOBAL.general_log_file')
    {
      printf 'log_type\tpath\texists\treadable\tsize_bytes\tmodified_at\n'
      local type p exists readable size mtime
      for type in error slow general; do
        case "$type" in error) p="$log_error_path";; slow) p="$slow_log_path";; general) p="$general_log_path";; esac
        exists=0; readable=0; size=""; mtime=""
        [ -n "$p" ] && [ -e "$p" ] && exists=1
        [ -n "$p" ] && [ -r "$p" ] && readable=1
        [ "$exists" -eq 1 ] && size=$(file_size_bytes "$p")
        [ "$exists" -eq 1 ] && mtime=$(stat -c '%y' "$p" 2>/dev/null || stat -f '%Sm' "$p" 2>/dev/null)
        printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$type" "$p" "$exists" "$readable" "$size" "$mtime"
      done
    } > "$TABLES_DIR/log_files.tsv"
    record_status "mysql.log_file_metadata" "mysql.logs" "ok" "$(iso_now)" "$(iso_now)" 0 3 0 "tables/log_files.tsv" ""

    if [ "$ERROR_LOG_TABLE_AVAILABLE" -eq 1 ]; then
        mysql_query_tsv "mysql.error_log_summary" "mysql.logs" "$TABLES_DIR/error_log_summary.tsv" \
          "SELECT PRIO,ERROR_CODE,COUNT(*) AS occurrence_count,MIN(LOGGED) AS first_seen,MAX(LOGGED) AS last_seen FROM performance_schema.error_log WHERE LOGGED >= NOW() - INTERVAL 24 HOUR GROUP BY PRIO,ERROR_CODE ORDER BY occurrence_count DESC LIMIT 500" || true
        if [ "$INCLUDE_LOG_TEXT" -eq 1 ]; then
            mysql_query_tsv "mysql.error_log_samples" "mysql.logs" "$TABLES_DIR/error_log_samples.tsv" \
              "SELECT LOGGED,THREAD_ID,PRIO,ERROR_CODE,LEFT(DATA,1000) AS message FROM performance_schema.error_log WHERE LOGGED >= NOW() - INTERVAL 24 HOUR ORDER BY LOGGED DESC LIMIT 500" || true
        else record_skipped "mysql.error_log_samples" "mysql.logs" "skipped" "log text disabled by default" "$TABLES_DIR/error_log_samples.tsv"; fi
    else
        record_skipped "mysql.error_log_summary" "mysql.logs" "unsupported" "performance_schema.error_log unavailable" "$TABLES_DIR/error_log_summary.tsv"
        if [ "$INCLUDE_LOG_TEXT" -eq 1 ] && [ -n "$log_error_path" ] && [ -r "$log_error_path" ]; then
            tail -n 5000 "$log_error_path" | sed -E 's/(password|passwd|pwd|token|secret)([=:])[[:graph:]]+/\1\2<REDACTED>/Ig' > "$EVIDENCE_DIR/error_log_tail.txt"
            record_status "mysql.error_log_tail" "mysql.logs" "ok" "$(iso_now)" "$(iso_now)" 0 "$(wc -l < "$EVIDENCE_DIR/error_log_tail.txt")" 0 "evidence/error_log_tail.txt" ""
        fi
    fi

    if has_cmd crontab; then
        crontab -l 2>/dev/null | redact_command_stream | grep -Ei 'mysql|maria|backup|xtrabackup|mysqldump|mydumper|binlog' > "$EVIDENCE_DIR/backup_cron.txt"
        record_status "system.backup_cron" "mysql.backup" "$([ -s "$EVIDENCE_DIR/backup_cron.txt" ] && echo ok || echo empty)" "$(iso_now)" "$(iso_now)" 0 "$(wc -l < "$EVIDENCE_DIR/backup_cron.txt")" 0 "evidence/backup_cron.txt" ""
    else record_skipped "system.backup_cron" "mysql.backup" "unsupported" "crontab command unavailable"; fi

    if has_cmd systemctl; then
        systemctl list-timers --all --no-pager 2>/dev/null | grep -Ei 'mysql|maria|backup|xtrabackup|dump' > "$EVIDENCE_DIR/backup_timers.txt"
        record_status "system.backup_timers" "mysql.backup" "$([ -s "$EVIDENCE_DIR/backup_timers.txt" ] && echo ok || echo empty)" "$(iso_now)" "$(iso_now)" 0 "$(wc -l < "$EVIDENCE_DIR/backup_timers.txt")" 0 "evidence/backup_timers.txt" ""
    fi

    ps -eo pid,user,etimes,args 2>/dev/null | grep -Ei '[x]trabackup|[m]ysqldump|[m]ydumper|[m]yloader|[m]ysqlpump|[m]ariabackup' | redact_command_stream > "$EVIDENCE_DIR/backup_processes.txt"
    record_status "system.backup_processes" "mysql.backup" "$([ -s "$EVIDENCE_DIR/backup_processes.txt" ] && echo ok || echo empty)" "$(iso_now)" "$(iso_now)" 0 "$(wc -l < "$EVIDENCE_DIR/backup_processes.txt")" 0 "evidence/backup_processes.txt" ""
}

tsv_first_value() {
    local file="$1"; shift
    [ -s "$file" ] || return 0
    awk -F'\t' -v names="$*" '
      NR==1 {n=split(names,w," "); for(i=1;i<=NF;i++) for(j=1;j<=n;j++) if(tolower($i)==tolower(w[j])) col=i; next}
      NR==2 && col>0 {print $col; exit}' "$file"
}

global_variable_value() {
    local key="$1" file="$TABLES_DIR/global_variables.tsv"
    [ -s "$file" ] || return 0
    awk -F'\t' -v k="$key" 'NR>1 && tolower($1)==tolower(k){print $2;exit}' "$file"
}

derive_role_evidence() {
    REPLICA_STATUS_PRESENT=0
    [ -s "$TABLES_DIR/replica_status.tsv" ] && [ "$(awk 'END{print NR}' "$TABLES_DIR/replica_status.tsv")" -gt 1 ] && REPLICA_STATUS_PRESENT=1
    SOURCE_HOST=$(tsv_first_value "$TABLES_DIR/replica_status.tsv" Source_Host Master_Host)
    SOURCE_PORT=$(tsv_first_value "$TABLES_DIR/replica_status.tsv" Source_Port Master_Port)
    SOURCE_UUID=$(tsv_first_value "$TABLES_DIR/replica_status.tsv" Source_UUID Master_UUID)
    REPLICA_IO_RUNNING=$(tsv_first_value "$TABLES_DIR/replica_status.tsv" Replica_IO_Running Slave_IO_Running)
    REPLICA_SQL_RUNNING=$(tsv_first_value "$TABLES_DIR/replica_status.tsv" Replica_SQL_Running Slave_SQL_Running)
    REPLICA_LAG_SECONDS=$(tsv_first_value "$TABLES_DIR/replica_status.tsv" Seconds_Behind_Source Seconds_Behind_Master)

    GR_MEMBER_ROLE=""; GR_MEMBER_STATE=""
    if [ -s "$TABLES_DIR/group_replication_members.tsv" ]; then
        GR_MEMBER_ROLE=$(awk -F'\t' -v uuid="$SERVER_UUID" '
          NR==1{for(i=1;i<=NF;i++){if(tolower($i)=="member_id")id=i;if(tolower($i)=="member_role")role=i}} NR>1&&$id==uuid{print $role;exit}' "$TABLES_DIR/group_replication_members.tsv")
        GR_MEMBER_STATE=$(awk -F'\t' -v uuid="$SERVER_UUID" '
          NR==1{for(i=1;i<=NF;i++){if(tolower($i)=="member_id")id=i;if(tolower($i)=="member_state")st=i}} NR>1&&$id==uuid{print $st;exit}' "$TABLES_DIR/group_replication_members.tsv")
    fi

    if [ -n "$GR_MEMBER_ROLE" ]; then
        case "$(printf '%s' "$GR_MEMBER_ROLE" | tr '[:lower:]' '[:upper:]')" in
          PRIMARY) ROLE_OBSERVED="mgr_primary" ;;
          SECONDARY) ROLE_OBSERVED="mgr_secondary" ;;
          *) ROLE_OBSERVED="mgr_member" ;;
        esac
        ROLE_CONFIDENCE="high"
    elif printf '%s' "$WSREP_ON" | grep -Eqi 'ON|1'; then
        ROLE_OBSERVED="pxc_or_galera_member"; ROLE_CONFIDENCE="medium"
    elif [ "$REPLICA_STATUS_PRESENT" -eq 1 ]; then
        ROLE_OBSERVED="replica"; ROLE_CONFIDENCE="high"
    elif printf '%s' "$READ_ONLY" | grep -Eqi 'ON|1'; then
        ROLE_OBSERVED="read_only_unknown"; ROLE_CONFIDENCE="medium"
    else
        ROLE_OBSERVED="standalone_or_source"; ROLE_CONFIDENCE="medium"
    fi
}

generate_collection_status_json() {
    local files
    files=$(find "$STATUS_PARTS_DIR" -type f -name '*.tsv' | sort | tr '\n' ' ')
    if [ -z "$files" ]; then
        printf '{"schema_version":"1.0","items":[],"summary":{}}\n' > "$COLLECTION_STATUS_FILE"
        return 0
    fi
    # 状态文件由采集器自身生成，文件名均已净化，不含空格。
    awk -F'\t' '
      function esc(s,   t){
        t=s; gsub(/\\/,"\\\\",t); gsub(/"/,"\\\"",t); gsub(/\r/,"\\r",t); gsub(/\n/,"\\n",t); gsub(/\t/,"\\t",t); return t
      }
      BEGIN{print "{"; print "  \"schema_version\": \"1.0\","; print "  \"items\": ["; first=1}
      NF>=9{
        if(!first) print ","; first=0
        printf "    {\"item_id\":\"%s\",\"category\":\"%s\",\"status\":\"%s\",\"started_at\":\"%s\",\"finished_at\":\"%s\",\"duration_ms\":%s,\"row_count\":%s,\"exit_code\":%s,\"output_file\":\"%s\",\"reason\":\"%s\"}",esc($1),esc($2),esc($3),esc($4),esc($5),($6~/^[0-9]+$/?$6:"null"),($7~/^[0-9]+$/?$7:"null"),($8~/^-?[0-9]+$/?$8:"null"),esc($9),esc($10)
        c[$3]++
      }
      END{
        print ""; print "  ],";
        printf "  \"summary\": {\"ok\":%d,\"empty\":%d,\"unsupported\":%d,\"not_enabled\":%d,\"not_applicable\":%d,\"permission_denied\":%d,\"timeout\":%d,\"error\":%d,\"skipped\":%d,\"partial\":%d}\n",c["ok"]+0,c["empty"]+0,c["unsupported"]+0,c["not_enabled"]+0,c["not_applicable"]+0,c["permission_denied"]+0,c["timeout"]+0,c["error"]+0,c["skipped"]+0,c["partial"]+0
        print "}"
      }' $files > "$COLLECTION_STATUS_FILE"
}

generate_snapshot_json() {
    local os_name="" kernel="" host_fqdn="" machine_id="" cpu_count="0" mem_total_kb="0" collected_end
    local actual_mysql_points actual_cpu_points actual_elapsed_ms sampling_status
    local sar_coverage_status sar_coverage_hours sar_first_timestamp sar_last_timestamp
    local host_local_time host_utc_time host_timezone ntp_synchronized
    local ok_count error_count warning_count

    [ -r /etc/os-release ] && os_name=$(awk -F= '$1=="PRETTY_NAME"{gsub(/^"|"$/,"",$2);print $2}' /etc/os-release)
    kernel=$(uname -r 2>/dev/null)
    host_fqdn=$(hostname -f 2>/dev/null || hostname 2>/dev/null)
    [ -r /etc/machine-id ] && machine_id=$(tr -d '\r\n' < /etc/machine-id)
    [ -z "$machine_id" ] && machine_id=$(printf '%s' "$host_fqdn" | sha256sum 2>/dev/null | awk '{print $1}')
    cpu_count=$(getconf _NPROCESSORS_ONLN 2>/dev/null || nproc 2>/dev/null || echo 0)
    mem_total_kb=$(awk '$1=="MemTotal:"{print $2}' /proc/meminfo 2>/dev/null)
    collected_end=$(iso_now)
    derive_role_evidence

    ok_count=$(awk -F'\t' '$3=="ok"||$3=="empty"||$3=="not_applicable"||$3=="skipped"{n++}END{print n+0}' "$STATUS_PARTS_DIR"/*.tsv 2>/dev/null)
    error_count=$(awk -F'\t' '$3=="error"||$3=="timeout"||$3=="permission_denied"{n++}END{print n+0}' "$STATUS_PARTS_DIR"/*.tsv 2>/dev/null)
    warning_count=$(awk -F'\t' '$3=="unsupported"||$3=="not_enabled"||$3=="partial"{n++}END{print n+0}' "$STATUS_PARTS_DIR"/*.tsv 2>/dev/null)

    actual_mysql_points=$(awk 'END{print (NR>0?NR-1:0)}' "$MYSQL_CSV" 2>/dev/null); actual_mysql_points=${actual_mysql_points:-0}
    actual_cpu_points=$(awk 'END{print (NR>0?NR-1:0)}' "$CPU_CSV" 2>/dev/null); actual_cpu_points=${actual_cpu_points:-0}
    actual_elapsed_ms=$(awk -F, 'NR>1{v=$2}END{print v+0}' "$MYSQL_CSV" 2>/dev/null); actual_elapsed_ms=${actual_elapsed_ms:-0}
    sampling_status=$(awk -F'\t' '$1=="timeseries.realtime_sampling"{print $3}' "$STATUS_PARTS_DIR"/*.tsv 2>/dev/null | tail -1); sampling_status=${sampling_status:-error}
    sar_coverage_status=$(awk -F'\t' '$1=="status"{print $2}' "$HISTORY_DIR/coverage.tsv" 2>/dev/null); sar_coverage_status=${sar_coverage_status:-empty}
    sar_coverage_hours=$(awk -F'\t' '$1=="coverage_hours"{print $2}' "$HISTORY_DIR/coverage.tsv" 2>/dev/null); sar_coverage_hours=${sar_coverage_hours:-0}
    sar_first_timestamp=$(awk -F'\t' '$1=="first_timestamp"{print $2}' "$HISTORY_DIR/coverage.tsv" 2>/dev/null)
    sar_last_timestamp=$(awk -F'\t' '$1=="last_timestamp"{print $2}' "$HISTORY_DIR/coverage.tsv" 2>/dev/null)
    host_local_time=$(awk -F= '$1=="local_time"{print substr($0,index($0,"=")+1)}' "$EVIDENCE_DIR/time_status.txt" 2>/dev/null)
    host_utc_time=$(awk -F= '$1=="utc_time"{print substr($0,index($0,"=")+1)}' "$EVIDENCE_DIR/time_status.txt" 2>/dev/null)
    host_timezone=$(awk -F= '$1=="timezone"{print substr($0,index($0,"=")+1)}' "$EVIDENCE_DIR/time_status.txt" 2>/dev/null)
    ntp_synchronized=$(awk -F: '/System clock synchronized/{gsub(/^[ \t]+|[ \t]+$/,"",$2);print $2}' "$EVIDENCE_DIR/timedatectl.txt" 2>/dev/null)

    {
      printf '{\n'
      printf '  "schema_version": %s,\n' "$(json_quote "$SNAPSHOT_SCHEMA_VERSION")"
      printf '  "package_version": %s,\n' "$(json_quote "$PACKAGE_VERSION")"
      printf '  "collector": {"name":"mysql_inspection","version":%s,"platform":"linux-bash","started_at":%s,"finished_at":%s},\n' \
        "$(json_quote "$COLLECTOR_VERSION")" "$(json_quote "$COLLECTION_STARTED_AT")" "$(json_quote "$collected_end")"
      printf '  "instance_identity": {"database_type":"mysql","database_family":%s,"product_comment":%s,"version":%s,"server_uuid":%s,"server_id":%s,"mysql_hostname":%s,"connect_host":%s,"connect_ip":%s,"instance_ip":%s,"bind_address":%s,"report_host":%s,"port":%s,"instance_tag":%s},\n' \
        "$(json_quote "$MYSQL_FAMILY")" "$(json_quote "$MYSQL_VERSION_COMMENT")" "$(json_quote "$MYSQL_VERSION")" "$(json_quote "$SERVER_UUID")" "$(json_quote "$SERVER_ID")" \
        "$(json_quote "$MYSQL_HOSTNAME")" "$(json_quote "$dbHost")" "$(json_quote "$TARGET_RESOLVED_IP")" "$(json_quote "$INSTANCE_ADDRESS")" "$(json_quote "$BIND_ADDRESS")" "$(json_quote "$REPORT_HOST")" "$(json_number_or_null "${MYSQL_PORT_OBSERVED:-$dbPort}")" "$(json_quote "$INSTANCE_TAG")"
      printf '  "host_identity": {"hostname":%s,"short_hostname":%s,"primary_ip":%s,"all_ipv4":%s,"database_target_is_local":%s,"machine_id":%s,"os":%s,"kernel":%s,"cpu_count":%s,"memory_total_bytes":%s},\n' \
        "$(json_quote "$host_fqdn")" "$(json_quote "$COLLECTOR_HOSTNAME")" "$(json_quote "$COLLECTOR_PRIMARY_IP")" "$(json_quote "$COLLECTOR_ALL_IPV4")" "$([ "$TARGET_IS_LOCAL" -eq 1 ] && echo true || echo false)" \
        "$(json_quote "$machine_id")" "$(json_quote "$os_name")" "$(json_quote "$kernel")" "$(json_number_or_null "$cpu_count")" "$(json_number_or_null "$(( ${mem_total_kb:-0} * 1024 ))")"
      printf '  "time_evidence": {"host_local_time":%s,"host_utc_time":%s,"timezone":%s,"ntp_synchronized":%s,"timedatectl_file":"evidence/timedatectl.txt","chrony_tracking_file":"evidence/chronyc_tracking.txt"},\n' \
        "$(json_quote "$host_local_time")" "$(json_quote "$host_utc_time")" "$(json_quote "$host_timezone")" "$(json_quote "$ntp_synchronized")"
      printf '  "role_evidence": {"role_observed":%s,"confidence":%s,"read_only":%s,"super_read_only":%s,"log_bin":%s,"gtid_mode":%s,"replica_status_present":%s,"source_host":%s,"source_port":%s,"source_uuid":%s,"replica_io_running":%s,"replica_sql_running":%s,"replica_lag_seconds":%s,"group_replication_role":%s,"group_replication_state":%s,"wsrep_on":%s},\n' \
        "$(json_quote "$ROLE_OBSERVED")" "$(json_quote "$ROLE_CONFIDENCE")" "$(json_quote "$READ_ONLY")" "$(json_quote "$SUPER_READ_ONLY")" "$(json_quote "$LOG_BIN")" "$(json_quote "$GTID_MODE")" \
        "$([ "$REPLICA_STATUS_PRESENT" -eq 1 ] && echo true || echo false)" "$(json_quote "$SOURCE_HOST")" "$(json_number_or_null "$SOURCE_PORT")" "$(json_quote "$SOURCE_UUID")" \
        "$(json_quote "$REPLICA_IO_RUNNING")" "$(json_quote "$REPLICA_SQL_RUNNING")" "$(json_number_or_null "$REPLICA_LAG_SECONDS")" "$(json_quote "$GR_MEMBER_ROLE")" "$(json_quote "$GR_MEMBER_STATE")" "$(json_quote "$WSREP_ON")"
      printf '  "capabilities": {"performance_schema":%s,"sys_schema":%s,"data_locks":%s,"data_lock_waits":%s,"metadata_locks":%s,"group_replication_members":%s,"replication_connection_status":%s,"performance_schema_error_log":%s,"sar_command":%s,"sadf_command":%s},\n' \
        "$(json_quote "$PERFORMANCE_SCHEMA_ENABLED")" "$([ "$SYS_SCHEMA_AVAILABLE" -eq 1 ] && echo true || echo false)" "$([ "$DATA_LOCKS_AVAILABLE" -eq 1 ] && echo true || echo false)" \
        "$([ "$DATA_LOCK_WAITS_AVAILABLE" -eq 1 ] && echo true || echo false)" "$([ "$METADATA_LOCKS_AVAILABLE" -eq 1 ] && echo true || echo false)" \
        "$([ "$GR_MEMBERS_AVAILABLE" -eq 1 ] && echo true || echo false)" "$([ "$REPL_CONN_STATUS_AVAILABLE" -eq 1 ] && echo true || echo false)" \
        "$([ "$ERROR_LOG_TABLE_AVAILABLE" -eq 1 ] && echo true || echo false)" "$([ "${HAS_SAR:-0}" -eq 1 ] && echo true || echo false)" "$([ "${HAS_SADF:-0}" -eq 1 ] && echo true || echo false)"
      printf '  "sampling": {"standard_mode":true,"status":%s,"interval_seconds":%s,"requested_sample_count":%s,"requested_duration_seconds":%s,"actual_mysql_points":%s,"actual_cpu_points":%s,"actual_elapsed_ms":%s,"sar_history_requested_hours":%s,"sar_history":{"status":%s,"coverage_hours":%s,"first_timestamp":%s,"last_timestamp":%s,"coverage_file":"history/coverage.json"},"realtime_files":{"cpu":"timeseries/system_cpu.csv","memory":"timeseries/system_memory.csv","disk":"timeseries/system_disk.csv","network":"timeseries/system_network.csv","mysql":"timeseries/mysql_status.csv"},"history_dir":"history"},\n' \
        "$(json_quote "$sampling_status")" "$SAMPLE_INTERVAL" "$SAMPLE_COUNT" "$((SAMPLE_INTERVAL*SAMPLE_COUNT))" "$actual_mysql_points" "$actual_cpu_points" "$actual_elapsed_ms" "$SAR_HISTORY_HOURS" "$(json_quote "$sar_coverage_status")" "$sar_coverage_hours" "$(json_quote "$sar_first_timestamp")" "$(json_quote "$sar_last_timestamp")"
      printf '  "privacy": {"sql_text_included":true,"log_text_included":%s,"full_configuration_included":false,"password_included":false},\n' \
        "$([ "$INCLUDE_LOG_TEXT" -eq 1 ] && echo true || echo false)"
      printf '  "collection_summary": {"successful_or_empty_items":%s,"warning_items":%s,"failed_items":%s,"collection_status_file":"collection_status.json"},\n' "$ok_count" "$warning_count" "$error_count"
      printf '  "artifacts": {"tables_dir":"tables","timeseries_dir":"timeseries","history_dir":"history","evidence_dir":"evidence","summary":"summary.txt","log":"logs/collection.log"}\n'
      printf '}\n'
    } > "$SNAPSHOT_FILE"
}

generate_summary() {
    local total_ms ok empty unsupported not_enabled permission timeout error skipped partial
    local actual_mysql_points actual_elapsed_ms sampling_status sar_coverage_status sar_coverage_hours sar_first sar_last
    total_ms=$(( $(epoch_ms) - COLLECTION_STARTED_MS ))
    ok=$(awk -F'\t' '$3=="ok"{n++}END{print n+0}' "$STATUS_PARTS_DIR"/*.tsv 2>/dev/null)
    empty=$(awk -F'\t' '$3=="empty"{n++}END{print n+0}' "$STATUS_PARTS_DIR"/*.tsv 2>/dev/null)
    unsupported=$(awk -F'\t' '$3=="unsupported"{n++}END{print n+0}' "$STATUS_PARTS_DIR"/*.tsv 2>/dev/null)
    not_enabled=$(awk -F'\t' '$3=="not_enabled"{n++}END{print n+0}' "$STATUS_PARTS_DIR"/*.tsv 2>/dev/null)
    permission=$(awk -F'\t' '$3=="permission_denied"{n++}END{print n+0}' "$STATUS_PARTS_DIR"/*.tsv 2>/dev/null)
    timeout=$(awk -F'\t' '$3=="timeout"{n++}END{print n+0}' "$STATUS_PARTS_DIR"/*.tsv 2>/dev/null)
    error=$(awk -F'\t' '$3=="error"{n++}END{print n+0}' "$STATUS_PARTS_DIR"/*.tsv 2>/dev/null)
    partial=$(awk -F'\t' '$3=="partial"{n++}END{print n+0}' "$STATUS_PARTS_DIR"/*.tsv 2>/dev/null)
    skipped=$(awk -F'\t' '$3=="skipped"||$3=="not_applicable"{n++}END{print n+0}' "$STATUS_PARTS_DIR"/*.tsv 2>/dev/null)
    actual_mysql_points=$(awk 'END{print (NR>0?NR-1:0)}' "$MYSQL_CSV" 2>/dev/null); actual_mysql_points=${actual_mysql_points:-0}
    actual_elapsed_ms=$(awk -F, 'NR>1{v=$2}END{print v+0}' "$MYSQL_CSV" 2>/dev/null); actual_elapsed_ms=${actual_elapsed_ms:-0}
    sampling_status=$(awk -F'\t' '$1=="timeseries.realtime_sampling"{print $3}' "$STATUS_PARTS_DIR"/*.tsv 2>/dev/null | tail -1); sampling_status=${sampling_status:-error}
    sar_coverage_status=$(awk -F'\t' '$1=="status"{print $2}' "$HISTORY_DIR/coverage.tsv" 2>/dev/null); sar_coverage_status=${sar_coverage_status:-empty}
    sar_coverage_hours=$(awk -F'\t' '$1=="coverage_hours"{print $2}' "$HISTORY_DIR/coverage.tsv" 2>/dev/null); sar_coverage_hours=${sar_coverage_hours:-0}
    sar_first=$(awk -F'\t' '$1=="first_timestamp"{print $2}' "$HISTORY_DIR/coverage.tsv" 2>/dev/null)
    sar_last=$(awk -F'\t' '$1=="last_timestamp"{print $2}' "$HISTORY_DIR/coverage.tsv" 2>/dev/null)
    {
      printf 'MySQL 巡检采集摘要\n'
      printf '====================\n'
      printf '采集器版本: %s\n' "$COLLECTOR_VERSION"
      printf '实例标识: %s\n' "$INSTANCE_TAG"
      printf 'MySQL版本: %s\n' "$MYSQL_VERSION"
      printf '数据库主机名: %s\n' "$MYSQL_HOSTNAME"
      printf '实例地址: %s:%s\n' "$INSTANCE_ADDRESS" "${MYSQL_PORT_OBSERVED:-$dbPort}"
      printf '连接地址: %s:%s\n' "$dbHost" "$dbPort"
      printf '采集主机: %s（主IP %s）\n' "$COLLECTOR_HOSTNAME" "$COLLECTOR_PRIMARY_IP"
      [ "$TARGET_IS_LOCAL" -eq 1 ] || printf '警告: 连接目标不是本机地址，系统信息属于采集器所在主机，而不一定属于数据库服务器\n'
      printf '角色观察: %s（最终拓扑由 Python 合并判断）\n' "$ROLE_OBSERVED"
      printf '采集开始: %s\n' "$COLLECTION_STARTED_AT"
      printf '总耗时: %.2f 秒\n' "$(awk -v ms="$total_ms" 'BEGIN{print ms/1000}')"
      printf '历史 sar 请求范围: 最近 %s 小时；初步状态 %s，约覆盖 %s 小时\n' "$SAR_HISTORY_HOURS" "$sar_coverage_status" "$sar_coverage_hours"
      [ -n "$sar_first" ] && printf '历史 sar 初步范围: %s ～ %s（最终精确覆盖率由 Python 计算）\n' "$sar_first" "$sar_last"
      printf '实时同步采样请求: %s 秒一次，共 %s 次，约 %s 秒\n' "$SAMPLE_INTERVAL" "$SAMPLE_COUNT" "$((SAMPLE_INTERVAL*SAMPLE_COUNT))"
      printf '实时同步采样实际: 状态 %s，MySQL 数据点 %s，实际跨度 %.2f 秒\n' "$sampling_status" "$actual_mysql_points" "$(awk -v ms="$actual_elapsed_ms" 'BEGIN{print ms/1000}')"
      printf '\n状态统计\n'
      printf '  成功: %s\n  成功但无数据: %s\n  部分成功: %s\n  不支持: %s\n  未启用: %s\n  不适用/跳过: %s\n  权限不足: %s\n  超时: %s\n  错误: %s\n' "$ok" "$empty" "$partial" "$unsupported" "$not_enabled" "$skipped" "$permission" "$timeout" "$error"
      printf '\n耗时最长的采集项（前 10）\n'
      cat "$STATUS_PARTS_DIR"/*.tsv 2>/dev/null | awk -F'\t' -v total="$total_ms" '$4!="" && $6 ~ /^[0-9]+$/ && $6>=0 && $6<=total*2' | sort -t$'\t' -k6,6nr | head -10 | awk -F'\t' '{printf "  %-45s %8.3f 秒  %s\n",$1,$6/1000,$3}'
      printf '\n非成功项\n'
      cat "$STATUS_PARTS_DIR"/*.tsv 2>/dev/null | awk -F'\t' '$3!="ok"&&$3!="empty"&&$3!="skipped"&&$3!="not_applicable"&&$3!="not_enabled"{printf "  %s: %s，%s\n",$1,$3,$10}'
      printf '\n正式数据文件\n'
      printf '  snapshot.json             实例、主机、能力和角色证据\n'
      printf '  collection_status.json    每个采集项的状态、耗时和失败原因\n'
      printf '  tables/*.tsv              静态结构化数据\n'
      printf '  timeseries/*.csv          实时同步时序（实际完成情况见 sampling/status）\n'
      printf '  history/*.csv             历史 sar/sadf 数据（若存在）\n'
      printf '  manifest.json             文件大小和 SHA256\n'
    } > "$SUMMARY_FILE"
}

security_scan() {
    local findings="$TMP_DIR/security_scan_findings.txt"
    : > "$findings"
    grep -RInE --exclude='collection.log' --exclude='manifest.json' --exclude='security_scan_findings.txt' \
      '(password[[:space:]]*=[[:space:]]*"?[^<[:space:]";]+|--password(=|[[:space:]])[^<[:space:]]+|BEGIN[[:space:]].*PRIVATE KEY|Authorization:[[:space:]]*(Basic|Bearer)[[:space:]]+[A-Za-z0-9._-]+)' \
      "$TASK_DIR" > "$findings" 2>/dev/null
    if [ -s "$findings" ]; then
        cp "$findings" "$LOG_DIR/security_scan_findings.txt"
        record_status "package.security_scan" "package" "error" "$(iso_now)" "$(iso_now)" 0 "$(wc -l < "$findings")" 1 "logs/security_scan_findings.txt" "high-confidence sensitive pattern detected; package creation blocked"
        return 1
    fi
    record_status "package.security_scan" "package" "ok" "$(iso_now)" "$(iso_now)" 0 0 0 "" ""
    return 0
}

generate_manifest() {
    local list="$TMP_DIR/manifest_files.txt" f rel first=1
    find "$TASK_DIR" -type f ! -path "$TMP_DIR/*" ! -path "$STATUS_PARTS_DIR/*" ! -name 'manifest.json' ! -name '.mysql_defaults.*.cnf' -print | sort > "$list"
    {
      printf '{\n  "package_version":%s,\n  "collector_version":%s,\n  "database_type":"mysql",\n  "instance_tag":%s,\n  "created_at":%s,\n  "files":[\n' \
        "$(json_quote "$PACKAGE_VERSION")" "$(json_quote "$COLLECTOR_VERSION")" "$(json_quote "$INSTANCE_TAG")" "$(json_quote "$(iso_now)")"
      while IFS= read -r f; do
        rel=$(safe_relpath "$f"); [ "$first" -eq 1 ] || printf ',\n'; first=0
        printf '    {"path":%s,"size_bytes":%s,"sha256":%s}' "$(json_quote "$rel")" "$(file_size_bytes "$f")" "$(json_quote "$(sha256_file "$f")")"
      done < "$list"
      printf '\n  ]\n}\n'
    } > "$MANIFEST_FILE"
}

create_package() {
    [ "$CREATE_PACKAGE" -eq 1 ] || return 0
    local parent base start_ms end_ms rc err_file
    parent=$(dirname "$TASK_DIR"); base=$(basename "$TASK_DIR"); PACKAGE_FILE="${parent}/${base}.tar.gz"
    err_file="${PACKAGE_FILE}.stderr.tmp"
    start_ms=$(epoch_ms)
    # manifest 已生成后不再修改任务目录中的任何文件，确保 SHA256 可复验。
    tar --exclude='*/.mysql_defaults.*.cnf' -C "$parent" -czf "$PACKAGE_FILE" "$base" 2> "$err_file"; rc=$?
    end_ms=$(epoch_ms)
    if [ "$rc" -eq 0 ]; then
        rm -f "$err_file"
        printf '[INFO] 回传包生成完成，耗时 %s ms: %s\n' "$((end_ms-start_ms))" "$PACKAGE_FILE"
        return 0
    fi
    printf '[ERROR] 回传包生成失败，耗时 %s ms\n' "$((end_ms-start_ms))" >&2
    cat "$err_file" >&2 2>/dev/null
    rm -f "$err_file"
    return "$rc"
}

cleanup_auth() {
    [ -n "${MYSQL_CNF:-}" ] && rm -f "$MYSQL_CNF"
    MYSQL_CNF=""
}

handle_signal() {
    cleanup_auth
    if [ -n "${BG_PIDS[*]:-}" ]; then kill "${BG_PIDS[@]}" 2>/dev/null || true; fi
    [ -n "${TASK_DIR:-}" ] && [ -d "$TASK_DIR" ] && printf 'partial\n' > "$TASK_DIR/COLLECTION_INCOMPLETE"
    exit 130
}

trap handle_signal INT TERM HUP

# -------------------- 参数与入口 --------------------
POSITIONAL=()
while [ $# -gt 0 ]; do
    case "$1" in
      -h|--help) show_usage; exit 0 ;;
      --host) dbHost="${2-}"; shift 2 ;;
      --port) dbPort="${2-}"; shift 2 ;;
      --user) dbUser="${2-}"; shift 2 ;;
      --login-path) LOGIN_PATH="${2-}"; shift 2 ;;
      --password-file) PASSWORD_FILE="${2-}"; shift 2 ;;
      --output-dir) OUTPUT_PARENT="${2-}"; shift 2 ;;
      --sample-interval) SAMPLE_INTERVAL="${2-}"; shift 2 ;;
      --sample-count) SAMPLE_COUNT="${2-}"; shift 2 ;;
      --sar-history-hours) SAR_HISTORY_HOURS="${2-}"; shift 2 ;;
      --mysql-timeout) MYSQL_TIMEOUT_SECONDS="${2-}"; shift 2 ;;
      --include-log-text) INCLUDE_LOG_TEXT=1; shift ;;
      --no-package) CREATE_PACKAGE=0; shift ;;
      --) shift; while [ $# -gt 0 ]; do POSITIONAL+=("$1"); shift; done ;;
      -*) printf '未知选项: %s\n' "$1" >&2; show_usage; exit 10 ;;
      *) POSITIONAL+=("$1"); shift ;;
    esac
done

[ -z "$dbHost" ] && [ ${#POSITIONAL[@]} -ge 1 ] && dbHost="${POSITIONAL[0]}"
[ -z "$dbPort" ] && [ ${#POSITIONAL[@]} -ge 2 ] && dbPort="${POSITIONAL[1]}"
[ -z "$dbUser" ] && [ ${#POSITIONAL[@]} -ge 3 ] && dbUser="${POSITIONAL[2]}"
[ ${#POSITIONAL[@]} -ge 4 ] && LEGACY_PASSWORD="${POSITIONAL[3]}"

dbHost="${dbHost:-127.0.0.1}"; dbPort="${dbPort:-3306}"; dbUser="${dbUser:-root}"
for n in "$dbPort" "$SAMPLE_INTERVAL" "$SAMPLE_COUNT" "$SAR_HISTORY_HOURS" "$MYSQL_TIMEOUT_SECONDS"; do is_uint "$n" || { printf '端口和时间参数必须是正整数\n' >&2; exit 10; }; done
[ "$SAMPLE_INTERVAL" -ge 1 ] && [ "$SAMPLE_COUNT" -ge 1 ] || exit 10
[ "${BASH_VERSINFO[0]:-0}" -ge 4 ] || { printf '需要 Bash 4.0 或更高版本\n' >&2; exit 10; }
has_cmd mysql || { printf '未找到 mysql 客户端\n' >&2; exit 10; }
MYSQL_BIN=$(command -v mysql)
mkdir -p "$OUTPUT_PARENT" || exit 10
check_output_space

COLLECTION_STARTED_AT=$(iso_now); COLLECTION_STARTED_MS=$(epoch_ms)
COLLECTOR_HOSTNAME=$(hostname -s 2>/dev/null || hostname 2>/dev/null || echo unknown_host)
COLLECTOR_FQDN=$(hostname -f 2>/dev/null || printf '%s' "$COLLECTOR_HOSTNAME")
COLLECTOR_ALL_IPV4=$(collect_all_ipv4)
COLLECTOR_PRIMARY_IP=$(detect_primary_ipv4)
TARGET_RESOLVED_IP=$(resolve_ipv4 "$dbHost")
TARGET_IS_LOCAL=0; is_local_connect_target "$dbHost" "$TARGET_RESOLVED_IP" && TARGET_IS_LOCAL=1
case "$dbHost" in 127.*|localhost|::1) INSTANCE_ADDRESS="$COLLECTOR_PRIMARY_IP" ;; *) INSTANCE_ADDRESS="${TARGET_RESOLVED_IP:-$dbHost}" ;; esac
qctime=$(date +'%Y%m%d_%H%M%S'); pre_tag=$(sanitize_id "${COLLECTOR_HOSTNAME}_${INSTANCE_ADDRESS}_${dbPort}")
TASK_DIR="${OUTPUT_PARENT%/}/mysql_inspection_v1_${pre_tag}_${qctime}"
TABLES_DIR="$TASK_DIR/tables"; TIMESERIES_DIR="$TASK_DIR/timeseries"; HISTORY_DIR="$TASK_DIR/history"; EVIDENCE_DIR="$TASK_DIR/evidence"
LOG_DIR="$TASK_DIR/logs"; MODULE_LOG_DIR="$LOG_DIR/modules"; TMP_DIR="$TASK_DIR/.tmp"; STATUS_PARTS_DIR="$TASK_DIR/.status_parts"
mkdir -p "$TABLES_DIR" "$TIMESERIES_DIR" "$HISTORY_DIR" "$EVIDENCE_DIR" "$MODULE_LOG_DIR" "$TMP_DIR" "$STATUS_PARTS_DIR" || exit 10
LOG_FILE="$LOG_DIR/collection.log"; SNAPSHOT_FILE="$TASK_DIR/snapshot.json"; COLLECTION_STATUS_FILE="$TASK_DIR/collection_status.json"
SUMMARY_FILE="$TASK_DIR/summary.txt"; MANIFEST_FILE="$TASK_DIR/manifest.json"
CPU_CSV="$TIMESERIES_DIR/system_cpu.csv"; MEM_CSV="$TIMESERIES_DIR/system_memory.csv"; NET_CSV="$TIMESERIES_DIR/system_network.csv"; DISK_CSV="$TIMESERIES_DIR/system_disk.csv"; MYSQL_CSV="$TIMESERIES_DIR/mysql_status.csv"
: > "$LOG_FILE"
BG_PIDS=(); BG_NAMES=(); BG_START_ISO=(); BG_START_MS=(); FINALIZED=0; MYSQL_CNF=""; MYSQL_CONN_ARGS=()
HAS_SAR=0; has_cmd sar && HAS_SAR=1
HAS_SADF=0; has_cmd sadf && HAS_SADF=1

log_info "MySQL 巡检采集器 v${COLLECTOR_VERSION} 启动"
log_info "目标实例 ${dbHost}:${dbPort}，标准实时采样约 $((SAMPLE_INTERVAL*SAMPLE_COUNT)) 秒"
log_info "采集主机 ${COLLECTOR_HOSTNAME}，主IP ${COLLECTOR_PRIMARY_IP}，输出标识 ${pre_tag}"
[ "$TARGET_IS_LOCAL" -eq 1 ] || log_warn "连接目标 ${dbHost} 看起来不是本机；系统数据属于采集器主机 ${COLLECTOR_HOSTNAME}"

if [ -n "$LOGIN_PATH" ]; then
    MYSQL_CONN_ARGS+=("--login-path=$LOGIN_PATH" "--host=$dbHost" "--port=$dbPort" "--user=$dbUser")
else
    PASS=""
    if [ -n "$PASSWORD_FILE" ]; then
        [ -r "$PASSWORD_FILE" ] || { printf '无法读取密码文件\n' >&2; exit 10; }
        if has_cmd stat; then
            mode=$(stat -c '%a' "$PASSWORD_FILE" 2>/dev/null); [ -n "$mode" ] && [ "$mode" -gt 600 ] 2>/dev/null && log_warn "密码文件权限建议设置为 600"
        fi
        PASS=$(head -n 1 "$PASSWORD_FILE")
    elif [ -n "$LEGACY_PASSWORD" ]; then
        PASS="$LEGACY_PASSWORD"; log_warn "检测到命令行密码，建议改用 --login-path"
    else
        printf 'Please input your DB Password: '
        if [ -t 0 ]; then stty -echo 2>/dev/null; IFS= read -r PASS; stty echo 2>/dev/null; printf '\n'; else IFS= read -r PASS; fi
    fi
    escaped=$(cnf_escape "$PASS") || { printf '密码包含换行，无法安全处理\n' >&2; exit 10; }
    MYSQL_CNF=$(mktemp "$TMP_DIR/.mysql_defaults.XXXXXX.cnf") || exit 10
    chmod 600 "$MYSQL_CNF"
    {
      printf '[client]\n'; printf 'host=%s\n' "$dbHost"; printf 'port=%s\n' "$dbPort"; printf 'user=%s\n' "$dbUser"; printf 'password="%s"\n' "$escaped"; printf 'protocol=tcp\n'
    } > "$MYSQL_CNF"
    MYSQL_CONN_ARGS+=("--defaults-extra-file=$MYSQL_CNF")
    PASS=""; escaped=""; LEGACY_PASSWORD=""
fi

conn_err="$TMP_DIR/connect.stderr"
mysql_exec -N -s -e 'SELECT 1' > /dev/null 2> "$conn_err"; rc=$?
if [ "$rc" -ne 0 ]; then
    log_error "MySQL 连接失败"
    cleanup_auth
    sed -E 's/(password=)[^ ]+/\1<REDACTED>/Ig' "$conn_err" >&2
    exit 20
fi
rm -f "$conn_err"

run_module "mysql.capabilities" probe_capabilities
INSTANCE_TAG=$(sanitize_id "${MYSQL_HOSTNAME:-$COLLECTOR_HOSTNAME}_${INSTANCE_ADDRESS}_${MYSQL_PORT_OBSERVED:-$dbPort}")
log_info "实例标识: $INSTANCE_TAG，版本: $MYSQL_VERSION"

# 实时时序、历史 sar、系统静态信息并行；MySQL SQL 组串行执行，避免对生产库造成过高并发。
start_module_bg "realtime_sampling" collect_realtime_samples
start_module_bg "sar_history" collect_sar_history
start_module_bg "system_static" collect_system_static

run_module "mysql_basic" collect_mysql_basic
run_module "mysql_capacity" collect_mysql_capacity
run_module "mysql_performance" collect_mysql_performance
run_module "mysql_replication" collect_mysql_replication
run_module "mysql_security_objects" collect_mysql_security_objects
run_module "mysql_logs_backup" collect_mysql_logs_backup
wait_background_modules

derive_role_evidence
cleanup_auth

# 生成结构化状态和快照；敏感扫描通过后才允许打包。
generate_collection_status_json
generate_snapshot_json
generate_summary
if security_scan; then
    generate_collection_status_json
    generate_snapshot_json
    generate_summary
    generate_manifest
    rm -rf "$TMP_DIR" "$STATUS_PARTS_DIR"
    create_package || log_warn "回传包生成失败，可直接回传任务目录"
else
    generate_collection_status_json
    generate_snapshot_json
    generate_summary
    log_error "敏感信息扫描未通过，已阻止打包；请查看 logs/security_scan_findings.txt"
    rm -rf "$TMP_DIR" "$STATUS_PARTS_DIR"
fi

FINALIZED=1

printf '\n采集完成\n'
printf '任务目录: %s\n' "$TASK_DIR"
printf '实例角色观察: %s（最终拓扑由 Python 判断）\n' "$ROLE_OBSERVED"
printf '状态明细: %s\n' "$COLLECTION_STATUS_FILE"
printf '摘要: %s\n' "$SUMMARY_FILE"
[ -n "${PACKAGE_FILE:-}" ] && [ -f "$PACKAGE_FILE" ] && printf '回传包: %s\n' "$PACKAGE_FILE"
exit 0

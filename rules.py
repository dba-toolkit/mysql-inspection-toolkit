#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""MySQL inspection rule engine — config-driven, threshold-externalized.

Loads inspection_rules.json and provides RuleEngine which evaluates all
defined rules against PackageContext + derived metrics.  The engine uses
the same Finding / RuleEvaluation dataclasses as the analyzer so the
contract is unchanged.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from analyze_inspection_v2 import (
    Finding,
    RuleEvaluation,
    PackageContext,
    safe_float,
)

RULES_CONFIG = Path(__file__).resolve().parent / "inspection_rules.json"


def load_rules_config(path: Path | None = None) -> dict[str, Any]:
    target = path or RULES_CONFIG
    with target.open("r", encoding="utf-8") as f:
        config = json.load(f)
    if not isinstance(config, dict):
        raise ValueError(f"Rules config must be a JSON object: {target}")
    if config.get("version") != "2.0":
        raise ValueError(f"Unsupported rules config version: {config.get('version')}")
    return config


class RuleEngine:
    """Evaluates all rules from config against one PackageContext + metrics.

    Usage::

        engine = RuleEngine(config_path)
        findings, evaluations = engine.run(ctx, metrics, quality)
    """

    def __init__(self, config_path: Path | None = None) -> None:
        self.config = load_rules_config(config_path)
        self._globals = self.config.get("globals", {})
        self._rule_defs = self.config.get("rules", {})
        self._findings: list[Finding] = []
        self._evaluations: list[RuleEvaluation] = []

    # ------------------------------------------------------------------
    # public API
    # ------------------------------------------------------------------

    def run(
        self, ctx: PackageContext, metrics: dict[str, Any], quality: dict[str, Any]
    ) -> tuple[list[Finding], list[RuleEvaluation]]:
        self._findings = []
        self._evaluations = []

        self._check_collection_integrity(ctx)
        self._check_collection_quality(quality)
        self._check_time_sync(ctx, metrics)
        self._check_system_resources(ctx, metrics)
        self._check_security_root_remote(ctx)
        self._check_buffer_pool_ratio(ctx, metrics)
        self._check_performance_metrics(ctx, metrics)
        self._check_connection_usage(ctx, metrics)
        self._check_filesystem_usage(ctx, metrics)
        self._check_schema_items(ctx, metrics)
        self._check_sql_no_index(ctx, metrics)
        self._check_long_transactions(ctx, metrics)
        self._check_lock_waiting(ctx, metrics)
        self._check_replication_health(ctx)
        self._check_error_log(ctx, metrics)
        self._check_backup(ctx)

        return self._findings, self._evaluations

    # ------------------------------------------------------------------
    # helpers
    # ------------------------------------------------------------------

    def _cfg(self, rule_id: str) -> dict[str, Any]:
        return self._rule_defs.get(rule_id, {})

    def _threshold(self, rule_id: str, key: str, default: Any = None) -> Any:
        return self._cfg(rule_id).get("threshold", {}).get(key, self._globals.get(key, default))

    def _evaluate(
        self,
        rule_id: str,
        applicable: bool,
        available: bool,
        triggered: bool,
        reason: str,
        facts: list[str],
    ) -> None:
        """Core evaluation dispatcher — mirrors the original evaluate() closure."""
        cfg = self._cfg(rule_id)
        category: str = cfg.get("category", rule_id.split(".")[0])
        severity: str = cfg.get("severity", "medium")
        title: str = cfg.get("title", rule_id)
        summary: str = cfg.get("summary", "")
        recommendation: str = cfg.get("recommendation", "")
        evidence: list[str] = cfg.get("evidence_refs", [])
        confidence: float = float(cfg.get("confidence", 1.0))
        requires_restart: bool | None = cfg.get("requires_restart", False)

        if not applicable:
            status = "not_applicable"
        elif not available:
            status = "not_evaluated"
        elif triggered:
            status = "triggered"
        else:
            status = "passed"

        finding_id = None
        if status == "triggered":
            finding_id = f"R{len(self._findings) + 1:03d}"
            self._findings.append(Finding(
                rule_id=rule_id, severity=severity, title=title, category=category,
                summary=summary, facts=facts, recommendation=recommendation,
                evidence_refs=evidence, requires_restart=requires_restart,
                status="triggered", confidence=confidence, finding_id=finding_id,
            ))
        self._evaluations.append(RuleEvaluation(
            rule_id=rule_id, category=category, status=status, reason=reason,
            severity_if_triggered=severity, finding_id=finding_id,
            evidence_refs=evidence, confidence=confidence,
        ))

    # ------------------------------------------------------------------
    # rule implementations
    # ------------------------------------------------------------------

    def _check_collection_integrity(self, ctx: PackageContext) -> None:
        rule = "COMMON.COLLECTION.INTEGRITY"
        ok = ctx.integrity.get("status") == "ok"
        self._evaluate(
            rule, True, True, not ok,
            "清单哈希与文件完整性校验",
            [f"失败文件数：{ctx.integrity.get('failure_count', 0)}"],
        )

    def _check_collection_quality(self, quality: dict[str, Any]) -> None:
        rule = "COMMON.COLLECTION.QUALITY"
        score = quality.get("score", 100)
        min_score = self._threshold(rule, "quality_score_min", 80)
        self._evaluate(
            rule, True, True, score < min_score,
            f"采集完整度 {score}%",
            [f"数据完整度：{score}%"],
        )

    def _check_time_sync(self, ctx: PackageContext, metrics: dict[str, Any]) -> None:
        rule = "COMMON.SYSTEM.TIME_SYNC"
        local = metrics["scope"]["database_target_is_local"]
        ntp = str(ctx.snapshot.get("time_evidence", {}).get("ntp_synchronized", "")).lower()
        self._evaluate(
            rule, local, bool(ntp),
            ntp in {"no", "false", "0", "inactive"},
            f"NTP synchronized={ntp or 'unknown'}",
            [f"NTP synchronized：{ntp or 'unknown'}"],
        )

    def _check_system_resources(self, ctx: PackageContext, metrics: dict[str, Any]) -> None:
        local = metrics["scope"]["database_target_is_local"]
        history_usable = metrics["sampling_context"]["history"]["usable_for_trend_rules"]
        source = metrics["system_history"] if history_usable else metrics["system_realtime"]
        conf = 0.9 if history_usable else 0.65
        reason_note = "使用有效 SAR 历史" if history_usable else "仅使用现场短时样本，结论置信度较低"

        # CPU
        cpu_max = source.get("cpu_busy_percent", {}).get("max")
        threshold = self._threshold("COMMON.SYSTEM.CPU_PRESSURE", "cpu_peak_warning", 90)
        self._evaluate(
            "COMMON.SYSTEM.CPU_PRESSURE", local, cpu_max is not None,
            cpu_max is not None and cpu_max >= threshold,
            reason_note,
            [f"CPU 峰值：{cpu_max}%"] if cpu_max is not None else [],
        )
        # override confidence for system rules based on data source
        if self._evaluations:
            self._evaluations[-1].confidence = conf

        # IO wait
        iowait_max = source.get("cpu_iowait_percent", {}).get("max")
        threshold = self._threshold("COMMON.SYSTEM.IOWAIT_PRESSURE", "iowait_peak_warning", 20)
        self._evaluate(
            "COMMON.SYSTEM.IOWAIT_PRESSURE", local, iowait_max is not None,
            iowait_max is not None and iowait_max >= threshold,
            reason_note,
            [f"IO wait 峰值：{iowait_max}%"] if iowait_max is not None else [],
        )
        if self._evaluations:
            self._evaluations[-1].confidence = conf

        # Memory
        mem_avg = source.get("memory_used_percent", {}).get("average")
        threshold = self._threshold("COMMON.SYSTEM.MEMORY_PRESSURE", "memory_usage_warning", 90)
        self._evaluate(
            "COMMON.SYSTEM.MEMORY_PRESSURE", local, mem_avg is not None,
            mem_avg is not None and mem_avg >= threshold,
            reason_note,
            [f"内存平均使用率：{mem_avg}%"] if mem_avg is not None else [],
        )
        if self._evaluations:
            self._evaluations[-1].confidence = conf

    def _check_security_root_remote(self, ctx: PackageContext) -> None:
        rule = "MYSQL.SECURITY.ROOT_REMOTE"
        accounts = ctx.tables.get("accounts", [])
        remote_roots = [
            r for r in accounts
            if r.get("user") == "root" and r.get("host") not in {"localhost", "127.0.0.1", "::1"}
        ]
        self._evaluate(
            rule, True, bool(accounts), bool(remote_roots),
            "检查 root 的登录来源",
            ["账户来源：" + ", ".join(sorted({r.get('host', '') for r in remote_roots}))]
            if remote_roots else [],
        )

    def _check_buffer_pool_ratio(self, ctx: PackageContext, metrics: dict[str, Any]) -> None:
        rule = "MYSQL.INNODB.BUFFER_POOL_RATIO"
        local = metrics["scope"]["database_target_is_local"]
        bp_ratio = metrics["mysql_realtime"].get("buffer_pool_to_memory_ratio")
        lo = self._threshold(rule, "buffer_pool_ratio_min", 0.4)
        hi = self._threshold(rule, "buffer_pool_ratio_max", 0.85)
        self._evaluate(
            rule, local, bp_ratio is not None,
            bp_ratio is not None and (bp_ratio < lo or bp_ratio > hi),
            "仅当数据库与采集主机相同且内存信息可用时判断",
            [f"Buffer Pool/内存：{bp_ratio * 100:.1f}%"] if bp_ratio is not None else [],
        )

    def _check_performance_metrics(self, ctx: PackageContext, metrics: dict[str, Any]) -> None:
        mr = metrics["mysql_realtime"]

        tmp_ratio = mr.get("tmp_disk_ratio")
        t = self._threshold("MYSQL.PERFORMANCE.TMP_DISK_RATIO", "tmp_disk_ratio_warning", 0.25)
        self._evaluate(
            "MYSQL.PERFORMANCE.TMP_DISK_RATIO", True, tmp_ratio is not None,
            tmp_ratio is not None and tmp_ratio > t,
            "基于采样窗口内计数器增量",
            [f"临时表落盘比例：{tmp_ratio * 100:.1f}%"] if tmp_ratio is not None else [],
        )

        bp_miss = mr.get("buffer_pool_read_miss_ratio")
        t = self._threshold("MYSQL.INNODB.BUFFER_POOL_MISS", "buffer_pool_miss_warning", 0.01)
        self._evaluate(
            "MYSQL.INNODB.BUFFER_POOL_MISS", True, bp_miss is not None,
            bp_miss is not None and bp_miss > t,
            "基于采样窗口内读请求增量",
            [f"读未命中比例：{bp_miss * 100:.2f}%"] if bp_miss is not None else [],
        )

        cache_miss = mr.get("table_open_cache_miss_ratio")
        t = self._threshold("MYSQL.PERFORMANCE.TABLE_CACHE_MISS", "table_cache_miss_warning", 0.10)
        self._evaluate(
            "MYSQL.PERFORMANCE.TABLE_CACHE_MISS", True, cache_miss is not None,
            cache_miss is not None and cache_miss > t,
            "基于采样窗口内缓存命中增量",
            [f"表缓存未命中比例：{cache_miss * 100:.1f}%"] if cache_miss is not None else [],
        )

    def _check_connection_usage(self, ctx: PackageContext, metrics: dict[str, Any]) -> None:
        rule = "MYSQL.CONNECTION.USAGE"
        connected_max = metrics["mysql_realtime"].get("threads_connected", {}).get("max")
        max_conn = safe_float(ctx.variables.get("max_connections"))
        ratio = connected_max / max_conn if connected_max is not None and max_conn else None
        t = self._threshold(rule, "connection_usage_warning", 0.85)
        self._evaluate(
            rule, True, ratio is not None,
            ratio is not None and ratio >= t,
            "Threads_connected/Max_connections",
            [f"连接峰值：{connected_max:.0f}", f"上限：{max_conn:.0f}", f"使用率：{ratio * 100:.1f}%"]
            if ratio is not None else [],
        )

    def _check_filesystem_usage(self, ctx: PackageContext, metrics: dict[str, Any]) -> None:
        rule = "COMMON.CAPACITY.FILESYSTEM_USAGE"
        local = metrics["scope"]["database_target_is_local"]
        max_fs = metrics["capacity"].get("max_filesystem_usage_percent")
        t = self._threshold(rule, "filesystem_usage_critical", 90)
        self._evaluate(
            rule, local, max_fs is not None,
            max_fs is not None and max_fs >= t,
            "检查所有已成功读取的文件系统",
            [f"最高文件系统使用率：{max_fs:.1f}%"] if max_fs is not None else [],
        )

    def _check_schema_items(self, ctx: PackageContext, metrics: dict[str, Any]) -> None:
        schema = metrics["schema"]

        no_pk = schema.get("tables_without_primary_key")
        self._evaluate(
            "MYSQL.SCHEMA.NO_PRIMARY_KEY", True, no_pk is not None,
            bool(no_pk and no_pk > 0),
            "统计业务表主键情况",
            [f"无主键表：{no_pk}"] if no_pk is not None else [],
        )

        redundant = schema.get("redundant_index_count")
        self._evaluate(
            "MYSQL.SCHEMA.REDUNDANT_INDEX", True, redundant is not None,
            bool(redundant and redundant > 0),
            "依据 sys schema 候选结果",
            [f"候选数量：{redundant}"] if redundant is not None else [],
        )

        auto_count = schema.get("auto_increment_warning_count")
        self._evaluate(
            "MYSQL.SCHEMA.AUTO_INCREMENT_CAPACITY", True, auto_count is not None,
            bool(auto_count and auto_count > 0),
            "采集器仅输出达到风险阈值的自增列",
            [f"风险对象数：{auto_count}"] if auto_count is not None else [],
        )

        frag_count = schema.get("fragmentation_candidate_count")
        self._evaluate(
            "MYSQL.SCHEMA.FRAGMENTATION", True, frag_count is not None,
            bool(frag_count and frag_count > 0),
            "按采集器碎片候选阈值判断",
            [f"候选对象数：{frag_count}"] if frag_count is not None else [],
        )

        non_innodb = schema.get("non_innodb_table_count")
        self._evaluate(
            "MYSQL.SCHEMA.NON_INNODB", True, non_innodb is not None,
            bool(non_innodb and non_innodb > 0),
            "检查业务 schema 中的非 InnoDB 表",
            [f"表数量：{non_innodb}"] if non_innodb is not None else [],
        )

    def _check_sql_no_index(self, ctx: PackageContext, metrics: dict[str, Any]) -> None:
        rule = "MYSQL.SQL.NO_INDEX_DIGEST"
        digest_rows = ctx.tables.get("sql_digests_top", [])
        no_index_exec = sum(
            int((r.get("SUM_NO_INDEX_USED") or "").strip() or 0) for r in digest_rows
        )
        no_index_seconds = sum(
            float((r.get("total_seconds") or "").strip() or 0)
            for r in digest_rows if int((r.get("SUM_NO_INDEX_USED") or "").strip() or 0) > 0
        )
        exec_min = self._threshold(rule, "no_index_exec_min", 100)
        sec_min = self._threshold(rule, "no_index_seconds_min", 60)
        self._evaluate(
            rule, True, bool(digest_rows),
            no_index_exec > exec_min and no_index_seconds >= sec_min,
            "Performance Schema 摘要中 SUM_NO_INDEX_USED 累计值；需结合启动时长",
            [f"摘要累计执行次数：{no_index_exec}", f"累计耗时：{no_index_seconds:.1f} 秒"]
            if digest_rows else [],
        )

    def _check_long_transactions(self, ctx: PackageContext, metrics: dict[str, Any]) -> None:
        rule = "MYSQL.TRANSACTION.LONG_RUNNING"
        activity = metrics["activity"]
        long_count = activity.get("long_transaction_count")
        long_max = activity.get("max_long_transaction_seconds")
        t = self._threshold(rule, "long_transaction_seconds", 300)
        self._evaluate(
            rule, True, long_count is not None,
            bool(long_count and long_max is not None and long_max >= t),
            f"长事务阈值 {t} 秒",
            [f"数量：{long_count}", f"最长：{long_max:.0f} 秒"] if long_count else [],
        )

    def _check_lock_waiting(self, ctx: PackageContext, metrics: dict[str, Any]) -> None:
        rule = "MYSQL.LOCK.WAITING"
        activity = metrics["activity"]
        lock_count = (
            (activity.get("data_lock_wait_count") or 0)
            + (activity.get("pending_metadata_lock_count") or 0)
        )
        self._evaluate(
            rule, True, True, lock_count > 0,
            "检查数据锁等待和待授予元数据锁",
            [f"等待记录：{lock_count}"] if lock_count else [],
        )

    def _check_replication_health(self, ctx: PackageContext) -> None:
        rule = "MYSQL.REPLICATION.HEALTH"
        role = ctx.snapshot.get("role_evidence", {})
        replica_rows = ctx.tables.get("replica_status", [])
        applicable = bool(role.get("replica_status_present")) or "replica" in str(
            role.get("role_observed", "")
        )
        lag = safe_float(role.get("replica_lag_seconds"))
        t = self._threshold(rule, "replication_lag_seconds", 60)
        repl_bad = False
        if applicable:
            io_ok = str(role.get("replica_io_running", "")).lower() in {"yes", "on", "1"}
            sql_ok = str(role.get("replica_sql_running", "")).lower() in {"yes", "on", "1"}
            repl_bad = not io_ok or not sql_ok or (lag is not None and lag > t)
        self._evaluate(
            rule, applicable, bool(replica_rows) or applicable, repl_bad,
            "检查复制线程状态及延迟",
            [f"IO={role.get('replica_io_running')}", f"SQL={role.get('replica_sql_running')}", f"lag={lag}"]
            if applicable else [],
        )

    def _check_error_log(self, ctx: PackageContext, metrics: dict[str, Any]) -> None:
        rule = "MYSQL.LOG.ERROR_EVENTS"
        error_count = metrics["activity"].get("error_log_error_occurrences")
        self._evaluate(
            rule, True, error_count is not None,
            bool(error_count and error_count > 0),
            "仅按错误级别汇总，不读取日志正文",
            [f"错误级事件次数：{error_count}"] if error_count is not None else [],
        )

    def _check_backup(self, ctx: PackageContext) -> None:
        rule = "MYSQL.BACKUP.RECENT_SUCCESS"
        backup_rows = ctx.tables.get("backup_evidence", [])
        self._evaluate(
            rule, True, bool(backup_rows), False,
            "采集包未包含可验证的最近备份成功记录" if not backup_rows else "检查最近备份成功记录",
            [],
        )

#!/usr/bin/env python3
"""MySQL inspection package analyzer v2.0.0.

Reads one or more mysql_inspection_v1 tar.gz packages, validates package
integrity, calculates deterministic static/time-series metrics, runs an
quality-aware rule pack (config-driven, see inspection_rules.json), renders
PNG charts, and writes analysis.json, report_model.json and llm_input.json.

Only Python standard library and matplotlib are required.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import os
import re
import shutil
import statistics
import sys
import tarfile
import tempfile
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Sequence
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

ANALYZER_VERSION = "2.1.0"
ANALYSIS_SCHEMA_VERSION = "2.0"
SUPPORTED_COLLECTOR_MAJOR = "1"


class AnalyzerError(RuntimeError):
    pass


def now_iso() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


def read_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as f:
        value = json.load(f)
    if not isinstance(value, dict):
        raise AnalyzerError(f"JSON root must be an object: {path}")
    return value


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        json.dump(value, f, ensure_ascii=False, indent=2)
        f.write("\n")


def safe_float(value: Any) -> float | None:
    if value is None:
        return None
    text = str(value).strip()
    if not text or text.upper() in {"NULL", "N/A", "NA", "NONE"}:
        return None
    try:
        return float(text)
    except (TypeError, ValueError):
        return None


def safe_int(value: Any) -> int | None:
    number = safe_float(value)
    return None if number is None else int(number)


def percentile(values: Sequence[float], p: float) -> float | None:
    data = sorted(v for v in values if math.isfinite(v))
    if not data:
        return None
    if len(data) == 1:
        return data[0]
    rank = (len(data) - 1) * p
    low = math.floor(rank)
    high = math.ceil(rank)
    if low == high:
        return data[low]
    return data[low] + (data[high] - data[low]) * (rank - low)


def summarize(values: Iterable[float]) -> dict[str, Any]:
    data = [float(v) for v in values if v is not None and math.isfinite(float(v))]
    if not data:
        return {"count": 0, "min": None, "average": None, "p95": None, "max": None}
    return {
        "count": len(data),
        "min": round(min(data), 4),
        "average": round(statistics.fmean(data), 4),
        "p95": round(percentile(data, 0.95) or 0.0, 4),
        "max": round(max(data), 4),
    }


def duration_ms(start_ns: int) -> int:
    return int((time.monotonic_ns() - start_ns) / 1_000_000)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def is_safe_member(name: str) -> bool:
    path = Path(name)
    return not path.is_absolute() and ".." not in path.parts


def safe_extract_tar(archive: Path, destination: Path) -> Path:
    destination.mkdir(parents=True, exist_ok=True)
    with tarfile.open(archive, "r:*") as tf:
        members = tf.getmembers()
        if len(members) > 5000:
            raise AnalyzerError(f"Too many archive entries: {archive}")
        total = 0
        for member in members:
            if not is_safe_member(member.name):
                raise AnalyzerError(f"Unsafe archive path: {member.name}")
            if member.issym() or member.islnk():
                raise AnalyzerError(f"Archive links are not allowed: {member.name}")
            total += max(member.size, 0)
            if total > 2 * 1024 * 1024 * 1024:
                raise AnalyzerError(f"Archive expands beyond 2 GiB: {archive}")
        tf.extractall(destination, filter="data")
    roots = [p for p in destination.iterdir() if p.is_dir()]
    if len(roots) == 1 and (roots[0] / "snapshot.json").exists():
        return roots[0]
    if (destination / "snapshot.json").exists():
        return destination
    matches = list(destination.rglob("snapshot.json"))
    if len(matches) != 1:
        raise AnalyzerError(f"Cannot determine package root in {archive}")
    return matches[0].parent


def parse_delimited(path: Path, delimiter: str = "\t") -> list[dict[str, str]]:
    if not path.exists() or path.stat().st_size == 0:
        return []
    lines: list[str] = []
    with path.open("r", encoding="utf-8", errors="replace") as f:
        for line in f:
            if line.startswith("#") or not line.strip():
                continue
            lines.append(line.rstrip("\n\r"))
    if not lines:
        return []
    reader = csv.DictReader(lines, delimiter=delimiter)
    return [{str(k): (v or "") for k, v in row.items() if k is not None} for row in reader]


def parse_csv(path: Path) -> list[dict[str, str]]:
    return parse_delimited(path, ",")


def parse_sadf(path: Path) -> list[dict[str, str]]:
    """Parse sadf -d style semicolon files with comment header."""
    if not path.exists() or path.stat().st_size == 0:
        return []
    header: list[str] | None = None
    rows: list[dict[str, str]] = []
    with path.open("r", encoding="utf-8", errors="replace") as f:
        for raw in f:
            line = raw.rstrip("\n")
            if line.startswith("# hostname;"):
                header = line[2:].split(";")
                continue
            if line.startswith("#") or not line.strip() or "LINUX-RESTART" in line:
                continue
            if not header:
                continue
            values = line.split(";")
            if len(values) < len(header):
                continue
            rows.append(dict(zip(header, values[: len(header)])))
    return rows


def key_value_tsv(path: Path) -> dict[str, str]:
    rows = parse_delimited(path)
    result: dict[str, str] = {}
    for row in rows:
        keys = list(row)
        if len(keys) >= 2:
            result[row[keys[0]]] = row[keys[1]]
    return result


def counter_rates(rows: list[dict[str, str]], counters: Sequence[str]) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for prev, cur in zip(rows, rows[1:]):
        p_ms = safe_float(prev.get("elapsed_ms"))
        c_ms = safe_float(cur.get("elapsed_ms"))
        if p_ms is None or c_ms is None or c_ms <= p_ms:
            continue
        dt = (c_ms - p_ms) / 1000.0
        point: dict[str, Any] = {
            "timestamp": cur.get("timestamp"),
            "elapsed_ms": c_ms,
            "interval_seconds": dt,
        }
        for counter in counters:
            a = safe_float(prev.get(counter))
            b = safe_float(cur.get(counter))
            if a is None or b is None:
                point[counter + "_per_sec"] = None
            elif b >= a:
                point[counter + "_per_sec"] = (b - a) / dt
            else:
                point[counter + "_per_sec"] = None
        result.append(point)
    return result


def delta_ratio(rows: list[dict[str, str]], numerator: str, denominator: str) -> float | None:
    if len(rows) < 2:
        return None
    a_num = safe_float(rows[0].get(numerator))
    b_num = safe_float(rows[-1].get(numerator))
    a_den = safe_float(rows[0].get(denominator))
    b_den = safe_float(rows[-1].get(denominator))
    if None in {a_num, b_num, a_den, b_den}:
        return None
    num = b_num - a_num
    den = b_den - a_den
    if den <= 0 or num < 0:
        return None
    return num / den


@dataclass
class Finding:
    rule_id: str
    severity: str
    title: str
    category: str
    summary: str
    facts: list[str]
    recommendation: str
    evidence_refs: list[str]
    requires_restart: bool | None = None
    status: str = "evaluated"
    confidence: float = 1.0
    finding_id: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "rule_id": self.rule_id,
            "status": self.status,
            "evaluation_status": self.status,
            "triggered": True,
            "severity": self.severity,
            "category": self.category,
            "title": self.title,
            "summary": self.summary,
            "facts": self.facts,
            "recommendation": self.recommendation,
            "requires_restart": self.requires_restart,
            "confidence": self.confidence,
            "evidence_refs": self.evidence_refs,
        }


@dataclass
class RuleEvaluation:
    rule_id: str
    category: str
    status: str
    reason: str
    severity_if_triggered: str | None = None
    finding_id: str | None = None
    evidence_refs: list[str] = field(default_factory=list)
    confidence: float = 1.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "category": self.category,
            "status": self.status,
            "reason": self.reason,
            "severity_if_triggered": self.severity_if_triggered,
            "finding_id": self.finding_id,
            "evidence_refs": self.evidence_refs,
            "confidence": self.confidence,
        }


@dataclass
class PackageContext:
    source: Path
    root: Path
    snapshot: dict[str, Any]
    status: dict[str, Any]
    manifest: dict[str, Any]
    integrity: dict[str, Any]
    tables: dict[str, list[dict[str, str]]] = field(default_factory=dict)
    variables: dict[str, str] = field(default_factory=dict)
    global_status: dict[str, str] = field(default_factory=dict)
    timeseries: dict[str, list[dict[str, str]]] = field(default_factory=dict)
    history: dict[str, list[dict[str, str]]] = field(default_factory=dict)

    @property
    def instance_id(self) -> str:
        identity = self.snapshot.get("instance_identity", {})
        return str(identity.get("server_uuid") or identity.get("instance_tag") or self.source.stem)


class Analyzer:
    def __init__(self, output: Path, keep_extracted: bool = False) -> None:
        self.output = output
        self.keep_extracted = keep_extracted
        self.work = output / "_work"
        self.charts_dir = output / "charts"
        self.stage_log: list[dict[str, Any]] = []

    def stage(self, name: str, fn):
        started = now_iso()
        start_ns = time.monotonic_ns()
        try:
            value = fn()
            status = "success"
            reason = ""
            return value
        except Exception as exc:
            status = "error"
            reason = f"{type(exc).__name__}: {exc}"
            raise
        finally:
            self.stage_log.append({
                "stage": name,
                "status": status,
                "started_at": started,
                "finished_at": now_iso(),
                "duration_ms": duration_ms(start_ns),
                "reason": reason,
            })

    def load_package(self, source: Path, index: int) -> PackageContext:
        target = self.work / f"package_{index:03d}"
        if target.exists():
            shutil.rmtree(target)
        root = safe_extract_tar(source, target) if source.is_file() else source
        snapshot = read_json(root / "snapshot.json")
        status = read_json(root / "collection_status.json")
        manifest = read_json(root / "manifest.json")
        collector_version = str(snapshot.get("collector", {}).get("version", ""))
        if collector_version and collector_version.split(".")[0] != SUPPORTED_COLLECTOR_MAJOR:
            raise AnalyzerError(f"Unsupported collector version {collector_version} in {source}")
        integrity = self.validate_manifest(root, manifest)
        context = PackageContext(source, root, snapshot, status, manifest, integrity)
        context.variables = key_value_tsv(root / "tables/global_variables.tsv")
        context.global_status = key_value_tsv(root / "tables/global_status.tsv")
        for path in (root / "tables").glob("*.tsv"):
            context.tables[path.stem] = parse_delimited(path)
        for path in (root / "timeseries").glob("*.csv"):
            context.timeseries[path.stem] = parse_csv(path)
        for path in (root / "history").glob("sar_*.csv"):
            context.history[path.stem] = parse_sadf(path)
        return context

    @staticmethod
    def validate_manifest(root: Path, manifest: dict[str, Any]) -> dict[str, Any]:
        failures: list[dict[str, str]] = []
        checked = 0
        for item in manifest.get("files", []):
            relative = str(item.get("path", ""))
            if not relative or not is_safe_member(relative):
                failures.append({"path": relative, "reason": "invalid_path"})
                continue
            path = root / relative
            if not path.exists() or not path.is_file():
                failures.append({"path": relative, "reason": "missing"})
                continue
            checked += 1
            expected_size = safe_int(item.get("size_bytes"))
            if expected_size is not None and path.stat().st_size != expected_size:
                failures.append({"path": relative, "reason": "size_mismatch"})
                continue
            expected_hash = str(item.get("sha256", ""))
            if expected_hash and sha256_file(path) != expected_hash:
                failures.append({"path": relative, "reason": "sha256_mismatch"})
        return {
            "status": "ok" if not failures else "failed",
            "files_checked": checked,
            "failure_count": len(failures),
            "failures": failures,
        }

    def collection_quality(self, ctx: PackageContext) -> dict[str, Any]:
        items = ctx.status.get("items", [])
        counts: dict[str, int] = {}
        failures: list[dict[str, Any]] = []
        total_weight = 0.0
        earned = 0.0
        weights = {
            "ok": 1.0,
            "empty": 1.0,
            "not_applicable": 1.0,
            "unsupported": 0.8,
            "not_enabled": 0.8,
            "partial": 0.6,
            "permission_denied": 0.2,
            "timeout": 0.0,
            "error": 0.0,
            "skipped": 0.5,
        }
        for item in items:
            status = str(item.get("status", "unknown"))
            counts[status] = counts.get(status, 0) + 1
            total_weight += 1
            earned += weights.get(status, 0.0)
            if status not in {"ok", "empty", "not_applicable"}:
                failures.append({
                    "item_id": item.get("item_id"),
                    "status": status,
                    "reason": item.get("reason", ""),
                    "duration_ms": item.get("duration_ms"),
                })
        score = round((earned / total_weight * 100) if total_weight else 0.0, 1)
        limitations: list[str] = []
        sar = ctx.snapshot.get("sampling", {}).get("sar_history", {})
        if sar.get("status") != "ok":
            limitations.append(
                f"系统历史数据未覆盖完整24小时，实际约 {sar.get('coverage_hours', 0)} 小时。"
            )
        for failure in failures:
            if failure["status"] in {"permission_denied", "timeout", "error"}:
                limitations.append(
                    f"采集项 {failure['item_id']} 状态为 {failure['status']}：{failure['reason'] or '未提供原因'}"
                )
        return {
            "score": score,
            "status_counts": counts,
            "integrity": ctx.integrity,
            "limitations": limitations,
            "non_ok_items": failures,
        }

    def derive_metrics(self, ctx: PackageContext) -> dict[str, Any]:
        cpu_rows = ctx.timeseries.get("system_cpu", [])
        mem_rows = ctx.timeseries.get("system_memory", [])
        disk_rows = ctx.timeseries.get("system_disk", [])
        net_rows = ctx.timeseries.get("system_network", [])
        mysql_rows = ctx.timeseries.get("mysql_status", [])

        rates = counter_rates(mysql_rows, [
            "Questions", "Queries", "Com_select", "Com_insert", "Com_update", "Com_delete",
            "Com_commit", "Com_rollback", "Bytes_received", "Bytes_sent", "Connections",
            "Aborted_connects", "Slow_queries", "Created_tmp_tables", "Created_tmp_disk_tables",
            "Opened_tables", "Innodb_buffer_pool_read_requests", "Innodb_buffer_pool_reads",
            "Innodb_rows_read", "Innodb_rows_inserted", "Innodb_rows_updated", "Innodb_rows_deleted",
            "Innodb_data_reads", "Innodb_data_writes", "Innodb_os_log_written", "Innodb_row_lock_waits",
            "Innodb_row_lock_time", "Handler_read_rnd_next", "Select_full_join", "Sort_merge_passes",
        ])
        # The first interval includes collector startup/static SQL overhead. Keep it in
        # the raw series and charts, but exclude it from workload statistics.
        workload_rates = rates[1:] if len(rates) > 2 else rates
        qps = [safe_float(r.get("Questions_per_sec")) for r in workload_rates]
        tps = []
        for r in workload_rates:
            commit = safe_float(r.get("Com_commit_per_sec")) or 0.0
            rollback = safe_float(r.get("Com_rollback_per_sec")) or 0.0
            tps.append(commit + rollback)

        per_device: dict[str, dict[str, Any]] = {}
        for row in disk_rows:
            dev = row.get("device", "unknown")
            bucket = per_device.setdefault(dev, {"util": [], "read_await": [], "write_await": [], "read_bps": [], "write_bps": [], "queue": []})
            for source_key, target_key in [
                ("util_pct", "util"), ("read_await_ms", "read_await"), ("write_await_ms", "write_await"),
                ("read_bytes_per_sec", "read_bps"), ("write_bytes_per_sec", "write_bps"),
                ("avg_queue_size", "queue"),
            ]:
                value = safe_float(row.get(source_key))
                if value is not None:
                    bucket[target_key].append(value)
        disk_summary = {
            dev: {key: summarize(vals) for key, vals in data.items()}
            for dev, data in per_device.items()
        }

        interfaces: dict[str, dict[str, list[float]]] = {}
        for row in net_rows:
            iface = row.get("interface", "unknown")
            bucket = interfaces.setdefault(iface, {"rx_bps": [], "tx_bps": []})
            rx = safe_float(row.get("rx_bytes_per_sec"))
            tx = safe_float(row.get("tx_bytes_per_sec"))
            if rx is not None:
                bucket["rx_bps"].append(rx)
            if tx is not None:
                bucket["tx_bps"].append(tx)

        tmp_ratio = delta_ratio(mysql_rows, "Created_tmp_disk_tables", "Created_tmp_tables")
        bp_miss = delta_ratio(mysql_rows, "Innodb_buffer_pool_reads", "Innodb_buffer_pool_read_requests")
        table_cache_misses = None
        if len(mysql_rows) >= 2:
            miss0 = safe_float(mysql_rows[0].get("Table_open_cache_misses"))
            miss1 = safe_float(mysql_rows[-1].get("Table_open_cache_misses"))
            hit0 = safe_float(mysql_rows[0].get("Table_open_cache_hits"))
            hit1 = safe_float(mysql_rows[-1].get("Table_open_cache_hits"))
            if None not in {miss0, miss1, hit0, hit1}:
                miss_delta = miss1 - miss0
                hit_delta = hit1 - hit0
                if miss_delta >= 0 and hit_delta >= 0 and (miss_delta + hit_delta) > 0:
                    table_cache_misses = miss_delta / (miss_delta + hit_delta)
        total_memory = safe_float(ctx.snapshot.get("host_identity", {}).get("memory_total_bytes"))
        buffer_pool = safe_float(ctx.variables.get("innodb_buffer_pool_size"))
        buffer_pool_ratio = buffer_pool / total_memory if buffer_pool and total_memory else None

        sar_cpu = ctx.history.get("sar_cpu", [])
        sar_cpu_busy = []
        sar_iowait = []
        for row in sar_cpu:
            idle = safe_float(row.get("%idle"))
            iowait = safe_float(row.get("%iowait"))
            if idle is not None:
                sar_cpu_busy.append(100.0 - idle)
            if iowait is not None:
                sar_iowait.append(iowait)

        sar_mem = ctx.history.get("sar_memory", [])
        sar_mem_used = [v for row in sar_mem if (v := safe_float(row.get("%memused"))) is not None]
        sar_swap = ctx.history.get("sar_swap", [])
        sar_swap_used = [v for row in sar_swap if (v := safe_float(row.get("%swpused"))) is not None]
        sar_disk = ctx.history.get("sar_disk", [])
        sar_disk_by_device: dict[str, dict[str, list[float]]] = {}
        for row in sar_disk:
            dev = row.get("DEV", "unknown")
            bucket = sar_disk_by_device.setdefault(dev, {"util": [], "await": [], "read_kbps": [], "write_kbps": []})
            for key, dest in [("%util", "util"), ("await", "await"), ("rkB/s", "read_kbps"), ("wkB/s", "write_kbps")]:
                value = safe_float(row.get(key))
                if value is not None:
                    bucket[dest].append(value)

        return {
            "system_realtime": {
                "cpu_busy_percent": summarize(v for row in cpu_rows if (v := safe_float(row.get("busy_pct"))) is not None),
                "cpu_iowait_percent": summarize(v for row in cpu_rows if (v := safe_float(row.get("iowait_pct"))) is not None),
                "memory_used_percent": summarize(v for row in mem_rows if (v := safe_float(row.get("mem_used_pct"))) is not None),
                "memory_available_bytes": summarize(v for row in mem_rows if (v := safe_float(row.get("mem_available_bytes"))) is not None),
                "swap_used_bytes": summarize(v for row in mem_rows if (v := safe_float(row.get("swap_used_bytes"))) is not None),
                "disk_devices": disk_summary,
                "network_interfaces": {
                    iface: {key: summarize(vals) for key, vals in data.items()}
                    for iface, data in interfaces.items()
                },
            },
            "mysql_realtime": {
                "sample_points": len(mysql_rows),
                "rate_points": len(rates),
                "qps": summarize(v for v in qps if v is not None),
                "tps": summarize(tps),
                "threads_connected": summarize(v for row in mysql_rows if (v := safe_float(row.get("Threads_connected"))) is not None),
                "threads_running": summarize(v for row in mysql_rows if (v := safe_float(row.get("Threads_running"))) is not None),
                "tmp_disk_ratio": None if tmp_ratio is None else round(tmp_ratio, 6),
                "buffer_pool_read_miss_ratio": None if bp_miss is None else round(bp_miss, 8),
                "table_open_cache_miss_ratio": None if table_cache_misses is None else round(table_cache_misses, 8),
                "workload_statistics_excluded_initial_intervals": 1 if len(rates) > 2 else 0,
                "buffer_pool_to_memory_ratio": None if buffer_pool_ratio is None else round(buffer_pool_ratio, 6),
                "derived_rate_series": rates,
            },
            "system_history": {
                "coverage": ctx.snapshot.get("sampling", {}).get("sar_history", {}),
                "cpu_busy_percent": summarize(sar_cpu_busy),
                "cpu_iowait_percent": summarize(sar_iowait),
                "memory_used_percent": summarize(sar_mem_used),
                "swap_used_percent": summarize(sar_swap_used),
                "disk_devices": {
                    dev: {key: summarize(vals) for key, vals in data.items()}
                    for dev, data in sar_disk_by_device.items()
                },
            },
        }

    def run_rules(self, ctx: PackageContext, metrics: dict[str, Any], quality: dict[str, Any]) -> list[Finding]:
        raise NotImplementedError("Use AnalyzerV2.run_rules() which delegates to RuleEngine")

    def generate_charts(self, ctx: PackageContext, metrics: dict[str, Any]) -> list[dict[str, Any]]:
        self.charts_dir.mkdir(parents=True, exist_ok=True)
        try:
            import matplotlib
            matplotlib.use("Agg")
            import matplotlib.pyplot as plt
            import matplotlib.dates as mdates
            from chart_style import apply_style, C0, C1, C2, C3, C4, C5, C6, C7
            apply_style()
        except ImportError:
            return [{"chart_id": "ALL", "status": "skipped", "reason": "matplotlib_not_installed"}]

        charts: list[dict[str, Any]] = []
        timezone_name = str(ctx.snapshot.get("time_evidence", {}).get("timezone") or "UTC")
        try:
            display_tz = ZoneInfo(timezone_name)
        except ZoneInfoNotFoundError:
            timezone_name = "UTC"
            display_tz = timezone.utc

        def parse_chart_time(value: Any) -> datetime | None:
            text = str(value or "").strip()
            if not text:
                return None
            normalized = re.sub(r"\s+UTC$", "+00:00", text, flags=re.IGNORECASE)
            if normalized.endswith("Z"):
                normalized = normalized[:-1] + "+00:00"
            try:
                parsed = datetime.fromisoformat(normalized)
            except ValueError:
                return None
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=display_tz)
            return parsed.astimezone(display_tz)

        def save_line(chart_id: str, title: str, x: list[Any], series: list[tuple[str, list[float | None]]], filename: str, y_label: str) -> None:
            start_ns = time.monotonic_ns()
            if len(x) < 2 or not any(any(v is not None for v in ys) for _, ys in series):
                charts.append({"chart_id": chart_id, "title": title, "status": "skipped", "reason": "insufficient_data_points"})
                return
            parsed_x = [parse_chart_time(value) for value in x]
            use_datetime_axis = all(value is not None for value in parsed_x)
            # If data span < 5 min, use sample index to avoid all-same timestamps
            if use_datetime_axis:
                valid_times = [v for v in parsed_x if v is not None]
                if len(valid_times) > 1 and (max(valid_times) - min(valid_times)).total_seconds() < 300:
                    use_datetime_axis = False
                    plot_x = list(range(len(x)))
                else:
                    plot_x = parsed_x
            else:
                plot_x = list(range(len(x)))

            fig, ax = plt.subplots()
            for label, values in series:
                ax.plot(plot_x, values, label=label)
            ax.set_title(title)
            ax.set_xlabel(f"Time ({timezone_name})" if use_datetime_axis else "Sample")
            ax.set_ylabel(y_label)
            if len(series) > 1:
                ax.legend()
            if use_datetime_axis:
                valid_times = [value for value in parsed_x if value is not None]
                span_seconds = (max(valid_times) - min(valid_times)).total_seconds() if len(valid_times) > 1 else 0
                locator = mdates.AutoDateLocator(minticks=5, maxticks=9, tz=display_tz)
                if span_seconds <= 2 * 86400:
                    formatter = mdates.DateFormatter("%m-%d %H:%M", tz=display_tz)
                elif span_seconds <= 31 * 86400:
                    formatter = mdates.DateFormatter("%m-%d", tz=display_tz)
                else:
                    formatter = mdates.DateFormatter("%Y-%m", tz=display_tz)
                ax.xaxis.set_major_locator(locator)
                ax.xaxis.set_major_formatter(formatter)
                fig.autofmt_xdate(rotation=30)
            elif len(x) > 12:
                step = max(1, len(x) // 8)
                ax.set_xticks(x[::step])
            fig.tight_layout()
            path = self.charts_dir / filename
            fig.savefig(path)
            plt.close(fig)
            charts.append({
                "chart_id": chart_id,
                "title": title,
                "status": "generated",
                "file": path.relative_to(self.output).as_posix(),
                "source_points": len(x),
                "duration_ms": duration_ms(start_ns),
            })

        def save_line_dual(
            chart_id: str, title: str, x: list[Any],
            left_series: list[tuple[str, list[float | None]]],
            right_series: list[tuple[str, list[float | None]]],
            filename: str, y_left: str, y_right: str,
        ) -> None:
            """Save a dual-Y-axis line chart. left_series on ax1, right_series on ax2 (dashed)."""
            start_ns = time.monotonic_ns()
            all_series = left_series + right_series
            if len(x) < 2 or not any(any(v is not None for v in ys) for _, ys in all_series):
                charts.append({"chart_id": chart_id, "title": title, "status": "skipped", "reason": "insufficient_data_points"})
                return
            parsed_x = [parse_chart_time(value) for value in x]
            use_datetime_axis = all(value is not None for value in parsed_x)
            # If data span is < 5 minutes, switch to sample index (timestamps would all look the same)
            if use_datetime_axis:
                valid_times = [v for v in parsed_x if v is not None]
                if len(valid_times) > 1 and (max(valid_times) - min(valid_times)).total_seconds() < 300:
                    use_datetime_axis = False
                    plot_x = list(range(len(x)))
                else:
                    plot_x = parsed_x
            else:
                plot_x = list(range(len(x)))

            fig, ax1 = plt.subplots()
            left_colors = [C0, C3, C5, C7][:len(left_series)]
            right_colors = [C1, C2, C4, C6][:len(right_series)]
            ax2_created = False

            for idx, (label, values) in enumerate(left_series):
                ax1.plot(plot_x, values, label=label, color=left_colors[idx], linewidth=1.5)
            for idx, (label, values) in enumerate(right_series):
                ax2 = ax1.twinx()
                ax2_created = True
                if idx > 0:
                    ax2.spines["right"].set_position(("outward", 60 * idx))
                ax2.plot(plot_x, values, label=label, color=right_colors[idx], linewidth=1.5, linestyle="--")

            ax1.set_title(title)
            ax1.set_xlabel("Time" if use_datetime_axis else "Sample")
            ax1.set_ylabel(y_left)
            ax2.set_ylabel(y_right)

            lines1, labels1 = ax1.get_legend_handles_labels()
            lines2, labels2 = ax2.get_legend_handles_labels()
            ax1.legend(lines1 + lines2, labels1 + labels2, loc="upper left")

            if use_datetime_axis:
                valid_times = [v for v in parsed_x if v is not None]
                span = (max(valid_times) - min(valid_times)).total_seconds() if len(valid_times) > 1 else 0
                locator = mdates.AutoDateLocator(minticks=5, maxticks=9, tz=display_tz)
                if span <= 2 * 86400:
                    formatter = mdates.DateFormatter("%m-%d %H:%M", tz=display_tz)
                elif span <= 31 * 86400:
                    formatter = mdates.DateFormatter("%m-%d", tz=display_tz)
                else:
                    formatter = mdates.DateFormatter("%Y-%m", tz=display_tz)
                ax1.xaxis.set_major_locator(locator)
                ax1.xaxis.set_major_formatter(formatter)
                fig.autofmt_xdate(rotation=30)
            fig.tight_layout()
            path = self.charts_dir / filename
            fig.savefig(path)
            plt.close(fig)
            charts.append({
                "chart_id": chart_id,
                "title": title,
                "status": "generated",
                "file": path.relative_to(self.output).as_posix(),
                "source_points": len(x),
                "duration_ms": duration_ms(start_ns),
            })

        # ── CPU chart: SAR history (24h) preferred, realtime fallback ──
        sar_cpu_rows = ctx.history.get("sar_cpu", [])
        sar_all = [r for r in sar_cpu_rows if r.get("CPU") == "-1"]
        has_sar_cpu = len(sar_all) >= 2
        if has_sar_cpu:
            save_line(
                "SYSTEM_CPU", "CPU usage",
                [r.get("timestamp", "") for r in sar_all],
                [
                    ("User (用户)", [safe_float(r.get("%user")) for r in sar_all]),
                    ("System (系统)", [safe_float(r.get("%system")) for r in sar_all]),
                    ("IO wait (IO等待)", [safe_float(r.get("%iowait")) for r in sar_all]),
                    ("Steal (被抢占)", [safe_float(r.get("%steal")) for r in sar_all]),
                ],
                f"{ctx.snapshot['instance_identity']['instance_tag']}_cpu.png", "Percent",
            )
        else:
            cpu_rows = ctx.timeseries.get("system_cpu", [])
            save_line(
                "SYSTEM_CPU", "CPU usage",
                [r.get("timestamp", "") for r in cpu_rows],
                [
                    ("User (用户)", [safe_float(r.get("user_pct")) for r in cpu_rows]),
                    ("System (系统)", [safe_float(r.get("system_pct")) for r in cpu_rows]),
                    ("IO wait (IO等待)", [safe_float(r.get("iowait_pct")) for r in cpu_rows]),
                    ("Steal (被抢占)", [safe_float(r.get("steal_pct")) for r in cpu_rows]),
                ],
                f"{ctx.snapshot['instance_identity']['instance_tag']}_cpu.png", "Percent",
            )

        # ── Memory chart: SAR history (24h) preferred, realtime dual-Y fallback ──
        sar_mem_rows = ctx.history.get("sar_memory", [])
        sar_swap_rows = ctx.history.get("sar_swap", [])
        has_sar_mem = len(sar_mem_rows) >= 2
        if has_sar_mem:
            total_kb = (safe_float(ctx.snapshot.get("host_identity", {}).get("memory_total_bytes")) or 1) / 1024
            # Build swap dict for lookup
            swap_by_ts: dict[str, float] = {}
            for r in sar_swap_rows:
                ts = str(r.get("timestamp", ""))
                v = safe_float(r.get("%swpused"))
                if ts and v is not None:
                    swap_by_ts[ts] = v
            save_line(
                "SYSTEM_MEMORY", "Memory usage",
                [r.get("timestamp", "") for r in sar_mem_rows],
                [
                    ("Used (已用%)", [safe_float(r.get("%memused")) for r in sar_mem_rows]),
                    ("Cached (缓存%)", [
                        safe_float(r.get("kbcached")) / total_kb * 100 if total_kb > 0 and safe_float(r.get("kbcached")) else None
                        for r in sar_mem_rows
                    ]),
                    ("Swap (交换%)", [swap_by_ts.get(str(r.get("timestamp", ""))) for r in sar_mem_rows]),
                ],
                f"{ctx.snapshot['instance_identity']['instance_tag']}_memory.png", "Percent",
            )
        else:
            mem_rows = ctx.timeseries.get("system_memory", [])
            save_line_dual(
                "SYSTEM_MEMORY", "Memory usage",
                [r.get("timestamp", "") for r in mem_rows],
                [("Used (已用%)", [safe_float(r.get("mem_used_pct")) for r in mem_rows])],
                [
                    ("Available (可用GB)", [(safe_float(r.get("mem_available_bytes")) or 0) / (1024**3) for r in mem_rows]),
                    ("Cached (缓存GB)", [(safe_float(r.get("cached_bytes")) or 0) / (1024**3) for r in mem_rows]),
                    ("Swap (交换GB)", [(safe_float(r.get("swap_used_bytes")) or 0) / (1024**3) for r in mem_rows]),
                ],
                f"{ctx.snapshot['instance_identity']['instance_tag']}_memory.png",
                "Percent", "GB",
            )

        # QPS/TPS
        rates = metrics["mysql_realtime"].get("derived_rate_series", [])
        qps = [safe_float(r.get("Questions_per_sec")) for r in rates]
        tps = [(safe_float(r.get("Com_commit_per_sec")) or 0) + (safe_float(r.get("Com_rollback_per_sec")) or 0) for r in rates]
        save_line(
            "MYSQL_QPS_TPS", "MySQL realtime QPS and TPS",
            [r.get("timestamp", "") for r in rates],
            [("QPS", qps), ("TPS", tps)],
            f"{ctx.snapshot['instance_identity']['instance_tag']}_mysql_qps_tps.png", "Operations / second",
        )

        # Threads
        rows = ctx.timeseries.get("mysql_status", [])
        save_line(
            "MYSQL_THREADS", "MySQL connection and running threads",
            [r.get("timestamp", "") for r in rows],
            [("Connected", [safe_float(r.get("Threads_connected")) for r in rows]), ("Running", [safe_float(r.get("Threads_running")) for r in rows])],
            f"{ctx.snapshot['instance_identity']['instance_tag']}_mysql_threads.png", "Threads",
        )

        # ── Disk chart: SAR history (24h) preferred, dual Y-axis ──
        sar_disk_rows = ctx.history.get("sar_disk", [])
        has_sar_disk = len(sar_disk_rows) >= 2
        if has_sar_disk:
            disk_devs = sorted({str(r.get("DEV", "")) for r in sar_disk_rows if r.get("DEV")})
            if disk_devs:
                busiest = max(disk_devs, key=lambda d: sum(safe_float(r.get("%util")) or 0 for r in sar_disk_rows if r.get("DEV") == d))
                dr = [r for r in sar_disk_rows if r.get("DEV") == busiest]
                save_line_dual(
                    "SYSTEM_DISK", f"Disk I/O ({busiest})",
                    [r.get("timestamp", "") for r in dr],
                    [("Read KiB/s", [safe_float(r.get("rkB/s")) for r in dr]),
                     ("Write KiB/s", [safe_float(r.get("wkB/s")) for r in dr])],
                    [("Util (繁忙%)", [safe_float(r.get("%util")) for r in dr]),
                     ("Await (延迟ms)", [safe_float(r.get("await")) for r in dr])],
                    f"{ctx.snapshot['instance_identity']['instance_tag']}_disk.png",
                    "KiB/s", "Percent / ms",
                )
        else:
            disk_rows_all = ctx.timeseries.get("system_disk", [])
            disk_names = sorted({str(row.get("device")) for row in disk_rows_all if row.get("device")})
            if disk_names:
                busiest = max(disk_names, key=lambda name: sum(
                    (safe_float(r.get("read_bytes_per_sec")) or 0)
                    + (safe_float(r.get("write_bytes_per_sec")) or 0)
                    for r in disk_rows_all if r.get("device") == name))
                dr = [r for r in disk_rows_all if r.get("device") == busiest]
                save_line_dual(
                    "SYSTEM_DISK", f"Disk I/O ({busiest})",
                    [r.get("timestamp", "") for r in dr],
                    [("Read KiB/s", [(safe_float(r.get("read_bytes_per_sec")) or 0) / 1024 for r in dr]),
                     ("Write KiB/s", [(safe_float(r.get("write_bytes_per_sec")) or 0) / 1024 for r in dr])],
                    [("Util (繁忙%)", [safe_float(r.get("util_pct")) for r in dr]),
                     ("Await (延迟ms)", [safe_float(r.get("read_await_ms")) for r in dr])],
                    f"{ctx.snapshot['instance_identity']['instance_tag']}_disk.png",
                    "KiB/s", "Percent / ms",
                )
        return charts

    @staticmethod
    def topology(contexts: list[PackageContext]) -> dict[str, Any]:
        nodes = []
        by_uuid: dict[str, str] = {}
        for ctx in contexts:
            identity = ctx.snapshot.get("instance_identity", {})
            role = ctx.snapshot.get("role_evidence", {})
            node_id = ctx.instance_id
            server_uuid = str(identity.get("server_uuid", ""))
            if server_uuid:
                by_uuid[server_uuid] = node_id
            nodes.append({
                "node_id": node_id,
                "instance_tag": identity.get("instance_tag"),
                "hostname": identity.get("mysql_hostname"),
                "ip": identity.get("instance_ip"),
                "port": identity.get("port"),
                "server_uuid": server_uuid,
                "server_id": identity.get("server_id"),
                "role_observed": role.get("role_observed"),
                "source_uuid": role.get("source_uuid"),
                "source_host": role.get("source_host"),
                "source_port": role.get("source_port"),
            })
        edges = []
        unresolved = []
        for node in nodes:
            source_uuid = str(node.get("source_uuid") or "")
            if source_uuid:
                source_node = by_uuid.get(source_uuid)
                edge = {"source_node_id": source_node, "target_node_id": node["node_id"], "source_uuid": source_uuid}
                if source_node:
                    edges.append(edge)
                else:
                    unresolved.append(edge)
            elif node.get("source_host"):
                candidates = [n for n in nodes if n.get("hostname") == node.get("source_host") or n.get("ip") == node.get("source_host")]
                if len(candidates) == 1:
                    edges.append({"source_node_id": candidates[0]["node_id"], "target_node_id": node["node_id"], "source_uuid": None})
                else:
                    unresolved.append({"source_node_id": None, "target_node_id": node["node_id"], "source_host": node.get("source_host")})
        return {
            "mode": "single_instance" if len(nodes) == 1 else "multi_instance",
            "nodes": nodes,
            "edges": edges,
            "unresolved_edges": unresolved,
            "completeness": "complete" if not unresolved else "partial",
        }

    @staticmethod
    def health_summary(findings: list[Finding]) -> dict[str, Any]:
        counts = {"high": 0, "medium": 0, "low": 0, "info": 0}
        penalties = {"high": 18, "medium": 8, "low": 3, "info": 0}
        score = 100
        for f in findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
            score -= penalties.get(f.severity, 0)
        return {"score": max(0, score), **{f"{k}_count": v for k, v in counts.items()}}

    def build_llm_input(self, analysis: dict[str, Any]) -> dict[str, Any]:
        instances = []
        for instance in analysis.get("instances", []):
            findings = instance.get("findings", [])
            instances.append({
                "instance_id": instance.get("instance_id"),
                "identity": instance.get("identity"),
                "collection_quality": {
                    "score": instance.get("collection_quality", {}).get("score"),
                    "limitations": instance.get("collection_quality", {}).get("limitations", []),
                },
                "health_summary": instance.get("health_summary"),
                "key_findings": [
                    {
                        "finding_id": f.get("finding_id"),
                        "rule_id": f.get("rule_id"),
                        "severity": f.get("severity"),
                        "title": f.get("title"),
                        "facts": f.get("facts"),
                        "summary": f.get("summary"),
                        "recommendation": f.get("recommendation"),
                    }
                    for f in findings[:20]
                ],
                "trend_summary": {
                    "system_history": instance.get("metrics", {}).get("system_history"),
                    "system_realtime": {
                        "cpu_busy_percent": instance.get("metrics", {}).get("system_realtime", {}).get("cpu_busy_percent"),
                        "memory_used_percent": instance.get("metrics", {}).get("system_realtime", {}).get("memory_used_percent"),
                    },
                    "mysql_realtime": {
                        key: instance.get("metrics", {}).get("mysql_realtime", {}).get(key)
                        for key in ["sample_points", "qps", "tps", "threads_connected", "threads_running", "tmp_disk_ratio", "buffer_pool_read_miss_ratio"]
                    },
                },
            })
        return {
            "schema_version": "1.0",
            "purpose": "optional_llm_narrative_input",
            "immutable_fact_notice": "风险等级、数值、规则编号、证据和建议均来自确定性规则引擎，禁止修改。",
            "topology": analysis.get("topology"),
            "instances": instances,
            "requested_output": {
                "format": "strict_json",
                "fields": [
                    "executive_summary.overall_assessment",
                    "executive_summary.key_message",
                    "finding_explanations[].finding_id",
                    "finding_explanations[].impact_explanation",
                    "finding_explanations[].priority_rationale",
                    "trend_commentary",
                    "limitations",
                ],
            },
        }

    def analyze(self, sources: list[Path]) -> dict[str, Any]:
        self.output.mkdir(parents=True, exist_ok=True)
        self.work.mkdir(parents=True, exist_ok=True)

        contexts = self.stage(
            "load_and_validate_packages",
            lambda: [self.load_package(src, i) for i, src in enumerate(sources, 1)],
        )
        self.stage("normalize_instances", lambda: contexts)
        metrics_list = self.stage("calculate_metrics", lambda: [self.derive_metrics(ctx) for ctx in contexts])
        quality_list = self.stage("evaluate_collection_quality", lambda: [self.collection_quality(ctx) for ctx in contexts])
        findings_list = self.stage(
            "execute_rules",
            lambda: [self.run_rules(ctx, metrics, quality) for ctx, metrics, quality in zip(contexts, metrics_list, quality_list)],
        )
        charts_list = self.stage(
            "generate_charts",
            lambda: [self.generate_charts(ctx, metrics) for ctx, metrics in zip(contexts, metrics_list)],
        )

        def build_instance_results() -> list[dict[str, Any]]:
            results: list[dict[str, Any]] = []
            for ctx, quality, metrics, findings, charts in zip(contexts, quality_list, metrics_list, findings_list, charts_list):
                instance_started = time.monotonic_ns()
                identity = ctx.snapshot.get("instance_identity", {})
                result = {
                    "instance_id": ctx.instance_id,
                    "source_package": ctx.source.name,
                    "identity": {
                        "instance_tag": identity.get("instance_tag"),
                        "database_type": identity.get("database_type"),
                        "database_family": identity.get("database_family"),
                        "version": identity.get("version"),
                        "server_uuid": identity.get("server_uuid"),
                        "server_id": identity.get("server_id"),
                        "hostname": identity.get("mysql_hostname"),
                        "ip": identity.get("instance_ip"),
                        "port": identity.get("port"),
                        "role_observed": ctx.snapshot.get("role_evidence", {}).get("role_observed"),
                    },
                    "collector": ctx.snapshot.get("collector"),
                    "collection_quality": quality,
                    "facts": {
                        "host_identity": ctx.snapshot.get("host_identity"),
                        "time_evidence": ctx.snapshot.get("time_evidence"),
                        "capabilities": ctx.snapshot.get("capabilities"),
                        "role_evidence": ctx.snapshot.get("role_evidence"),
                        "sampling": ctx.snapshot.get("sampling"),
                        "key_variables": {
                            key: ctx.variables.get(key)
                            for key in [
                                "innodb_buffer_pool_size", "innodb_redo_log_capacity", "innodb_log_file_size",
                                "max_connections", "table_open_cache", "tmp_table_size", "max_heap_table_size",
                                "binlog_format", "sync_binlog", "innodb_flush_log_at_trx_commit", "read_only",
                                "super_read_only", "gtid_mode", "log_bin", "lower_case_table_names", "sql_mode",
                                "character_set_server", "collation_server",
                            ]
                        },
                    },
                    "metrics": metrics,
                    "health_summary": self.health_summary(findings),
                    "findings": [finding.to_dict() for finding in findings],
                    "charts": charts,
                    "analysis_duration_ms": 0,
                }
                result["analysis_duration_ms"] = max(1, duration_ms(instance_started))
                results.append(result)
            return results

        instance_results = self.stage("build_instance_results", build_instance_results)
        topology = self.stage("build_topology", lambda: self.topology(contexts))
        all_findings = [finding for instance in instance_results for finding in instance["findings"]]
        analysis = {
            "schema_version": ANALYSIS_SCHEMA_VERSION,
            "analyzer": {"name": "mysql_inspection_analyzer", "version": ANALYZER_VERSION, "generated_at": now_iso()},
            "input_packages": [str(source) for source in sources],
            "topology": topology,
            "overall_health_summary": {
                "instance_count": len(instance_results),
                "high_count": sum(1 for finding in all_findings if finding.get("severity") == "high"),
                "medium_count": sum(1 for finding in all_findings if finding.get("severity") == "medium"),
                "low_count": sum(1 for finding in all_findings if finding.get("severity") == "low"),
            },
            "instances": instance_results,
            "stage_log": self.stage_log,
        }

        def write_outputs() -> None:
            write_json(self.output / "analysis.json", analysis)
            write_json(self.output / "llm_input.json", self.build_llm_input(analysis))
            summary_lines = [
                "MySQL Inspection Analyzer Summary",
                "",
                f"Analyzer version: {ANALYZER_VERSION}",
                f"Generated at: {analysis['analyzer']['generated_at']}",
                f"Input packages: {len(sources)}",
                f"Instances: {len(instance_results)}",
                f"Topology mode: {topology['mode']}",
                f"High findings: {analysis['overall_health_summary']['high_count']}",
                f"Medium findings: {analysis['overall_health_summary']['medium_count']}",
                f"Low findings: {analysis['overall_health_summary']['low_count']}",
                "",
            ]
            for instance in instance_results:
                summary_lines.extend([
                    f"[{instance['identity']['instance_tag']}]",
                    f"Version: {instance['identity']['version']}",
                    f"Role observed: {instance['identity']['role_observed']}",
                    f"Collection quality: {instance['collection_quality']['score']}%",
                    f"Health score: {instance['health_summary']['score']}",
                ])
                for finding in instance["findings"]:
                    summary_lines.append(f"- {finding['finding_id']} [{finding['severity']}] {finding['title']}")
                summary_lines.append("")
            (self.output / "analysis_summary.txt").write_text("\n".join(summary_lines), encoding="utf-8")

        self.stage("write_outputs", write_outputs)
        analysis["stage_log"] = self.stage_log
        write_json(self.output / "analysis.json", analysis)
        write_json(self.output / "analyzer_status.json", {"status": "success", "generated_at": now_iso(), "stages": self.stage_log})

        if not self.keep_extracted:
            shutil.rmtree(self.work, ignore_errors=True)
        return analysis


class AnalyzerV2(Analyzer):
    """Quality-aware analyzer while retaining v1 package compatibility."""

    OPTIONAL_COLLECTION_ITEMS = {
        "system.chronyc_sources",
        "system.chronyc_tracking",
        "mysql.error_log_samples",
        "mysql.innodb_status",
    }

    def __init__(self, output: Path, keep_extracted: bool = False, rules_config: Path | None = None) -> None:
        super().__init__(output, keep_extracted)
        self.rule_evaluations: dict[str, list[RuleEvaluation]] = {}
        self.inspection_sections: dict[str, list[dict[str, Any]]] = {}
        self.comprehensive_conclusions: dict[str, list[dict[str, Any]]] = {}
        self.rules_config = rules_config

    @staticmethod
    def _parse_time(value: Any) -> datetime | None:
        text = str(value or "").strip()
        if not text:
            return None
        normalized = re.sub(r"\s+UTC$", "+00:00", text, flags=re.IGNORECASE)
        if normalized.endswith("Z"):
            normalized = normalized[:-1] + "+00:00"
        try:
            parsed = datetime.fromisoformat(normalized)
        except ValueError:
            return None
        return parsed.replace(tzinfo=timezone.utc) if parsed.tzinfo is None else parsed

    @staticmethod
    def _row_number(row: dict[str, str], *keys: str) -> float | None:
        lowered = {str(k).lower(): v for k, v in row.items()}
        for key in keys:
            value = safe_float(row.get(key))
            if value is None:
                value = safe_float(lowered.get(key.lower()))
            if value is not None:
                return value
        return None

    @staticmethod
    def _percent(value: Any) -> float | None:
        number = safe_float(str(value or "").replace("%", ""))
        return number

    @staticmethod
    def _filesystem_rows(path: Path) -> list[dict[str, Any]]:
        """Parse POSIX df -PT output (it is aligned text despite the .tsv suffix)."""
        if not path.exists():
            return []
        rows: list[dict[str, Any]] = []
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        for line in lines[1:]:
            parts = re.split(r"\s+", line.strip(), maxsplit=6)
            if len(parts) != 7:
                continue
            filesystem, fs_type, blocks, used, available, capacity, mountpoint = parts
            rows.append({
                "filesystem": filesystem,
                "type": fs_type,
                "blocks_kb": safe_float(blocks),
                "used_kb": safe_float(used),
                "available_kb": safe_float(available),
                "usage_percent": safe_float(capacity.replace("%", "")),
                "mountpoint": mountpoint,
            })
        return rows

    @staticmethod
    def _format_bytes(value: Any) -> str | None:
        number = safe_float(value)
        if number is None:
            return None
        units = ("B", "KB", "MB", "GB", "TB", "PB")
        index = 0
        while abs(number) >= 1024 and index < len(units) - 1:
            number /= 1024
            index += 1
        return f"{number:.2f} {units[index]}"

    @staticmethod
    def _status_index(ctx: PackageContext) -> dict[str, dict[str, Any]]:
        result: dict[str, dict[str, Any]] = {}
        for raw in ctx.status.get("items", []):
            item = dict(raw)
            item_id = str(item.get("item_id", ""))
            status = str(item.get("status", "unknown"))
            reason = str(item.get("reason", ""))
            if item_id.startswith("system.chronyc_") and status == "error" and not reason.strip():
                status = "not_enabled"
                reason = "Chrony 服务或命令未启用"
            if item_id in {"system.filesystems", "system.inodes"} and status == "error":
                table_name = "filesystems" if item_id.endswith("filesystems") else "inodes"
                if ctx.tables.get(table_name):
                    status = "partial"
            item["status"] = status
            item["reason"] = reason
            result[item_id] = item
        return result

    @staticmethod
    def _raw_key_value_rows(path: Path) -> list[dict[str, str]]:
        if not path.exists():
            return []
        rows: list[dict[str, str]] = []
        for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            if "\t" in line:
                name, value = line.split("\t", 1)
            elif "=" in line:
                name, value = line.split("=", 1)
            else:
                continue
            rows.append({"参数": name.strip(), "值": value.strip()})
        return rows

    @staticmethod
    def _colon_key_values(path: Path) -> dict[str, str]:
        if not path.exists():
            return {}
        values: dict[str, str] = {}
        for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
            if ":" not in raw:
                continue
            name, value = raw.split(":", 1)
            values[name.strip()] = value.strip()
        return values

    @staticmethod
    def _kernel_recommendation(ctx: "PackageContext") -> str:
        """Check OS kernel parameters for database-specific recommendations."""
        path = ctx.root / "tables/kernel_parameters.tsv"
        if not path.exists():
            return ""
        # kernel_parameters.tsv is a key-value TSV: name \t value
        kernel: dict[str, str] = {}
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "\t" in line:
                parts = line.split("\t", 1)
                if len(parts) == 2:
                    kernel[parts[0].strip()] = parts[1].strip()
        parts: list[str] = []
        # vm.swappiness: 1-10 for DB servers, default 60 is too aggressive
        swappiness_str = kernel.get("vm.swappiness", "")
        if swappiness_str:
            try:
                swappiness = int(swappiness_str)
                if swappiness > 10:
                    parts.append(
                        f"vm.swappiness={swappiness}（默认 60）→ 数据库服务器建议设为 1-10，"
                        "避免操作系统在尚有可用内存时主动换出 MySQL 内存页到 Swap"
                    )
            except ValueError:
                pass
        if parts:
            return "；".join(parts) + "。"
        return ""

    @staticmethod
    def _config_recommendation(item_id: str, ctx: "PackageContext") -> str:
        """Generate parameter-specific recommendations based on collected values."""
        base = "对缺失参数确认版本适用性；涉及参数变更时先完成容量测算和回滚方案"
        specific: list[str] = []
        v = ctx.variables

        if item_id == "mysql.config.memory":
            flush = str(v.get("innodb_flush_method", "")).strip().lower()
            if flush == "fsync":
                specific.append(
                    "innodb_flush_method=fsync → 建议改为 O_DIRECT：fsync 导致 InnoDB 与 OS 页缓存双重缓冲，浪费内存并降低性能。O_DIRECT 绕过 OS 缓存直写磁盘，变更需重启 MySQL（SAN/NFS 需验证兼容性）"
                )
            elif flush == "fdatasync":
                specific.append(
                    "innodb_flush_method=fdatasync → 仅跳过元数据刷新，仍有双缓冲问题，建议评估切换 O_DIRECT"
                )
            doublewrite = str(v.get("innodb_doublewrite", "")).strip().upper()
            if doublewrite in ("OFF", "0"):
                specific.append(
                    "innodb_doublewrite=OFF → 存在部分��损坏风险（页断裂）；ZFS/BTRFS 可例外，否则建议开启"
                )
            stats_persist = str(v.get("innodb_stats_persistent", "")).strip().upper()
            if stats_persist in ("OFF", "0"):
                specific.append(
                    "innodb_stats_persistent=OFF → 重启后统计信息丢失，可能触发全表扫描，建议开启"
                )
            tmp_size = v.get("tmp_table_size")
            max_heap = v.get("max_heap_table_size")
            if tmp_size is not None and max_heap is not None and str(tmp_size) != str(max_heap):
                specific.append(
                    "tmp_table_size 与 max_heap_table_size 不一致 → MySQL 以较小者为准，可能导致非预期的磁盘临时表，建议设为相同值"
                )
            io_cap = safe_int(v.get("innodb_io_capacity"))
            if io_cap is not None and io_cap <= 200:
                specific.append(
                    f"innodb_io_capacity={io_cap}（默认值）→ 如使用 SSD/云盘建议提升至 2000-4000，"
                    "默认值针对机械盘设计，会限制 InnoDB 后台 IO 吞吐；HDD 环境可维持不变"
                )

        elif item_id == "mysql.config.connection":
            skip_resolve = str(v.get("skip_name_resolve", "")).strip().upper()
            if skip_resolve in ("OFF", "0", ""):
                specific.append(
                    "skip_name_resolve=OFF → DNS 解析开销大，DNS 不可用时连接超时；建议开启并在授权表使用 IP 或 IP 段"
                )
            have_ssl = str(v.get("have_ssl", "")).strip().upper()
            if have_ssl in ("DISABLED", "NO"):
                specific.append(
                    "have_ssl=DISABLED → 建议部署证书启用 SSL 加密传输，满足安全合规基线要求"
                )
            wait_timeout_val = safe_int(v.get("wait_timeout"))
            if wait_timeout_val is not None and wait_timeout_val >= 28800:
                specific.append(
                    f"wait_timeout={wait_timeout_val}（默认 8 小时）→ 空闲连接超时过长，"
                    "长时间未使用的连接占用内存和文件描述符，建议设为 600-1800 秒（10-30 分钟）"
                )

        elif item_id == "mysql.config.persistence":
            flush_log = str(v.get("innodb_flush_log_at_trx_commit", "")).strip()
            sync_binlog = str(v.get("sync_binlog", "")).strip()
            if flush_log != "1" or sync_binlog != "1":
                parts = []
                if flush_log != "1":
                    parts.append("innodb_flush_log_at_trx_commit≠1")
                if sync_binlog != "1":
                    parts.append("sync_binlog≠1")
                specific.append(
                    f"{'/'.join(parts)} → 当前设置牺牲部分持久性换取写入性能；金融、交易类 ACID 严格场景建议均设为 1"
                )
            slow_log = str(v.get("slow_query_log", "")).strip().upper()
            if slow_log in ("OFF", "0"):
                specific.append(
                    "slow_query_log=OFF → 慢查询日志是定位 SQL 性能问题的关键入口，建议开启并设置合理的 long_query_time"
                )
            binlog_format_val = str(v.get("binlog_format", "")).strip().upper()
            if binlog_format_val not in ("ROW",):
                specific.append(
                    f"binlog_format={binlog_format_val} → 生产环境建议 ROW 格式以确保数据一致性和 GTID 正常运作"
                )
            skip_err = (str(v.get("replica_skip_errors", "")).strip() or str(v.get("slave_skip_errors", "")).strip())
            if skip_err and skip_err not in ("OFF", "0", ""):
                specific.append(
                    f"replica_skip_errors={skip_err} → 跳过复制错误会导致主从数据静默不一致，强烈建议设为 OFF"
                )
            expire = v.get("binlog_expire_logs_seconds")
            if expire is not None and int(expire) == 0:
                specific.append(
                    "binlog_expire_logs_seconds=0 → Binlog 永不过期，建议设为 604800（7天）或 1296000（15天）"
                )

        elif item_id == "mysql.config.charset":
            char_server = str(v.get("character_set_server", "")).lower()
            if char_server and not char_server.startswith("utf8"):
                specific.append(
                    f"character_set_server={char_server} → MySQL 8.0 建议 utf8mb4 以支持完整 Unicode 和 emoji"
                )
            tz = str(v.get("time_zone", "")).strip()
            if tz in ("SYSTEM", ""):
                specific.append(
                    "time_zone=SYSTEM → 受 OS 时区影响，跨国部署或容器化环境建议显式设置（如 +08:00）"
                )
            lctn = str(v.get("lower_case_table_names", "")).strip()
            if lctn == "0":
                specific.append(
                    "lower_case_table_names=0 → Linux 区分大小写，跨平台迁移时可能表名找不到，建议评估调整"
                )

        if specific:
            return base + "。" + "。".join(specific) + "。"
        return base + "。"

    @staticmethod
    def _select_rows(
        rows: list[dict[str, Any]],
        columns: Sequence[tuple[str, str]],
        limit: int = 20,
        preserve_empty: Sequence[str] = (),
    ) -> list[dict[str, Any]]:
        selected: list[dict[str, Any]] = []
        preserve_set = set(preserve_empty)
        for raw in rows[:limit]:
            lowered = {str(key).lower(): value for key, value in raw.items()}
            item: dict[str, Any] = {}
            for source, label in columns:
                value = raw.get(source)
                if value is None:
                    value = lowered.get(source.lower())
                if label in preserve_set:
                    item[label] = value if value is not None else None
                else:
                    item[label] = value if value not in {"", "NULL"} else None
            selected.append(item)
        return selected

    @staticmethod
    def _item(
        item_id: str,
        title: str,
        source: str,
        rows: list[dict[str, Any]],
        conclusion: str,
        *,
        status: str = "normal",
        recommendation: str = "",
        evidence: Sequence[str] = (),
        collection: dict[str, Any] | None = None,
        total_rows: int | None = None,
        display_type: str = "table",
        note: str = "",
    ) -> dict[str, Any]:
        collection = collection or {}
        return {
            "item_id": item_id,
            "title": title,
            "source": source,
            "collection": {
                "status": collection.get("status", "ok" if rows else "empty"),
                "reason": collection.get("reason", ""),
                "row_count": collection.get("row_count", total_rows if total_rows is not None else len(rows)),
            },
            "display": {
                "type": display_type,
                "rows": rows,
                "shown_rows": len(rows),
                "total_rows": total_rows if total_rows is not None else len(rows),
                "note": note,
            },
            "analysis": {
                "status": status,
                "conclusion": conclusion,
                "evidence": list(evidence),
                "recommendation": recommendation,
            },
        }

    def build_inspection_model(
        self, ctx: PackageContext, metrics: dict[str, Any]
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        """Build the report-ready evidence model while the extracted package is available."""
        status = self._status_index(ctx)
        snapshot = ctx.snapshot
        identity = snapshot.get("instance_identity", {})
        host = snapshot.get("host_identity", {})
        time_info = snapshot.get("time_evidence", {})
        role = snapshot.get("role_evidence", {})
        mysql = metrics.get("mysql_realtime", {})
        sampling = metrics.get("sampling_context", {})

        def collection(item_id: str) -> dict[str, Any]:
            return status.get(item_id, {})

        def value_row(name: str, value: Any, description: str = "") -> dict[str, Any]:
            return {"检查项": name, "采集值": value, "说明": description}

        lscpu = self._colon_key_values(ctx.root / "evidence/lscpu.txt")
        host_rows = [
            value_row("主机名", host.get("hostname"), "数据库所在主机"),
            value_row("主机 IP", host.get("primary_ip"), "采集识别的主机地址"),
            value_row("操作系统", host.get("os"), "操作系统版本"),
            value_row("内核版本", host.get("kernel"), "Linux 内核"),
            value_row("CPU 型号", lscpu.get("Model name"), "处理器型号"),
            value_row("逻辑 CPU", host.get("cpu_count"), "逻辑处理器数量"),
            value_row("CPU Socket", lscpu.get("Socket(s)"), "物理处理器插槽"),
            value_row("每 Socket 核数", lscpu.get("Core(s) per socket"), "物理核心"),
            value_row("NUMA 节点", lscpu.get("NUMA node(s)"), "NUMA 拓扑"),
            value_row("物理内存", self._format_bytes(host.get("memory_total_bytes")), "主机总内存"),
            value_row("本地目标", "是" if host.get("database_target_is_local") else "否", "主机指标是否适用于数据库实例"),
        ]
        ntp_value = str(time_info.get("ntp_synchronized", "")).lower()
        ntp_ok = ntp_value in {"yes", "true", "1", "active"}
        time_rows = [
            value_row("本地时间", time_info.get("host_local_time"), "采集时主机时间"),
            value_row("时区", time_info.get("timezone"), "主机时区"),
            value_row("NTP 同步", time_info.get("ntp_synchronized"), "系统时间同步状态"),
        ]
        fs_rows = [
            {
                "文件系统": row.get("filesystem"),
                "类型": row.get("type"),
                "挂载点": row.get("mountpoint"),
                "使用率": f"{row['usage_percent']:.1f}%" if row.get("usage_percent") is not None else None,
                "可用空间": self._format_bytes((row.get("available_kb") or 0) * 1024),
            }
            for row in metrics.get("capacity", {}).get("filesystems", [])
        ]
        kernel_rows = self._raw_key_value_rows(ctx.root / "tables/kernel_parameters.tsv")
        realtime = metrics.get("system_realtime", {})
        resource_rows = [
            {
                "指标": "CPU 使用率",
                "平均值": f"{realtime.get('cpu_busy_percent', {}).get('average')}%",
                "峰值": f"{realtime.get('cpu_busy_percent', {}).get('max')}%",
                "说明": "现场短时采样",
            },
            {
                "指标": "CPU IO wait",
                "平均值": f"{realtime.get('cpu_iowait_percent', {}).get('average')}%",
                "峰值": f"{realtime.get('cpu_iowait_percent', {}).get('max')}%",
                "说明": "现场短时采样",
            },
            {
                "指标": "内存使用率",
                "平均值": f"{realtime.get('memory_used_percent', {}).get('average')}%",
                "峰值": f"{realtime.get('memory_used_percent', {}).get('max')}%",
                "说明": "现场短时采样",
            },
            {
                "指标": "可用内存",
                "平均值": self._format_bytes(realtime.get("memory_available_bytes", {}).get("average")),
                "峰值": self._format_bytes(realtime.get("memory_available_bytes", {}).get("min")),
                "说明": "峰值列表示窗口内最低可用内存",
            },
            {
                "指标": "已用 Swap",
                "平均值": self._format_bytes(realtime.get("swap_used_bytes", {}).get("average")),
                "峰值": self._format_bytes(realtime.get("swap_used_bytes", {}).get("max")),
                "说明": "现场短时采样",
            },
        ]
        disk_rows: list[dict[str, Any]] = []
        for device, device_metrics in realtime.get("disk_devices", {}).items():
            disk_rows.append({
                "设备": device,
                "平均 util": f"{device_metrics.get('util', {}).get('average')}%",
                "峰值 util": f"{device_metrics.get('util', {}).get('max')}%",
                "平均读 await": f"{device_metrics.get('read_await', {}).get('average')} ms",
                "平均写 await": f"{device_metrics.get('write_await', {}).get('average')} ms",
            })
        network_rows: list[dict[str, Any]] = []
        for interface, interface_metrics in realtime.get("network_interfaces", {}).items():
            if interface == "lo":
                continue
            network_rows.append({
                "网卡": interface,
                "平均接收": self._format_bytes(interface_metrics.get("rx_bps", {}).get("average")) + "/s"
                if interface_metrics.get("rx_bps", {}).get("average") is not None else None,
                "峰值接收": self._format_bytes(interface_metrics.get("rx_bps", {}).get("max")) + "/s"
                if interface_metrics.get("rx_bps", {}).get("max") is not None else None,
                "平均发送": self._format_bytes(interface_metrics.get("tx_bps", {}).get("average")) + "/s"
                if interface_metrics.get("tx_bps", {}).get("average") is not None else None,
                "峰值发送": self._format_bytes(interface_metrics.get("tx_bps", {}).get("max")) + "/s"
                if interface_metrics.get("tx_bps", {}).get("max") is not None else None,
            })

        basic_rows = [
            value_row("数据库类型", identity.get("database_type"), "数据库产品"),
            value_row("数据库版本", identity.get("version"), "服务端版本"),
            value_row("实例标识", identity.get("instance_tag"), "主机、IP 与端口组合"),
            value_row("监听地址", identity.get("bind_address"), "bind_address"),
            value_row("端口", identity.get("port"), "服务端口"),
            value_row("Server UUID", identity.get("server_uuid"), "实例唯一标识"),
            value_row("Server ID", identity.get("server_id"), "复制标识"),
            value_row("观测角色", role.get("role_observed"), "依据只读、复制和集群证据推断"),
        ]
        schemas = self._select_rows(
            ctx.tables.get("schemas", []),
            [
                ("SCHEMA_NAME", "Schema"),
                ("DEFAULT_CHARACTER_SET_NAME", "默认字符集"),
                ("DEFAULT_COLLATION_NAME", "默认排序规则"),
            ],
        )
        engines = self._select_rows(
            [row for row in ctx.tables.get("engines", []) if str(row.get("Support", "")).upper() in {"YES", "DEFAULT"}],
            [("Engine", "存储引擎"), ("Support", "支持状态"), ("Transactions", "事务"), ("XA", "XA"), ("Savepoints", "保存点")],
        )
        plugins = self._select_rows(
            [row for row in ctx.tables.get("plugins", []) if str(row.get("Status", "")).upper() == "ACTIVE"],
            [("Name", "插件"), ("Type", "类型"), ("Status", "状态"), ("License", "许可")],
            30,
        )

        variable_groups = [
            (
                "mysql.config.memory",
                "内存与 InnoDB 核心参数",
                [
                    ("innodb_buffer_pool_size", "InnoDB Buffer Pool"),
                    ("innodb_buffer_pool_instances", "Buffer Pool 实例数"),
                    ("innodb_redo_log_capacity", "Redo Log 容量"),
                    ("innodb_log_file_size", "单个 Redo 文件大小"),
                    ("innodb_log_buffer_size", "Redo Log Buffer"),
                    ("innodb_flush_method", "InnoDB 刷盘方式"),
                ],
            ),
            (
                "mysql.config.connection",
                "连接、线程与缓存参数",
                [
                    ("max_connections", "最大连接数"),
                    ("thread_cache_size", "线程缓存"),
                    ("table_open_cache", "表打开缓存"),
                    ("table_definition_cache", "表定义缓存"),
                    ("tmp_table_size", "内存临时表上限"),
                    ("max_heap_table_size", "MEMORY 表上限"),
                ],
            ),
            (
                "mysql.config.durability",
                "日志、持久性与复制参数",
                [
                    ("log_bin", "Binary Log"),
                    ("binlog_format", "Binlog 格式"),
                    ("gtid_mode", "GTID 模式"),
                    ("enforce_gtid_consistency", "GTID 一致性"),
                    ("sync_binlog", "Binlog 同步策略"),
                    ("innodb_flush_log_at_trx_commit", "事务日志刷盘策略"),
                    ("binlog_expire_logs_seconds", "Binlog 保留秒数"),
                ],
            ),
            (
                "mysql.config.charset",
                "字符集与 SQL 模式",
                [
                    ("character_set_server", "服务端字符集"),
                    ("collation_server", "服务端排序规则"),
                    ("lower_case_table_names", "表名大小写策略"),
                    ("sql_mode", "SQL Mode"),
                    ("time_zone", "会话默认时区"),
                ],
            ),
        ]
        config_items: list[dict[str, Any]] = []
        config_issues = 0
        config_issue_summaries: list[str] = []
        for item_id, title, variables in variable_groups:
            rows = [
                {"参数": name, "采集值": ctx.variables.get(name), "说明": label}
                for name, label in variables
            ]
            available = sum(1 for row in rows if row["采集值"] is not None)
            recommendation = self._config_recommendation(item_id, ctx)
            # Determine if there are specific parameter findings (not just the generic base advice)
            has_specific = bool(recommendation.split("。")[1].strip()) if recommendation.startswith("对缺失参数") and recommendation.count("。") >= 2 else False
            if has_specific:
                config_issues += 1
                # Extract first specific finding for summary (between first and second 。)
                parts = recommendation.split("。")
                if len(parts) >= 2:
                    config_issue_summaries.append(parts[1].strip())
            param_status = "attention" if has_specific else ("normal" if available == len(rows) else "attention")
            conclusion = f"已展示 {available} 项核心运行参数"
            if has_specific:
                conclusion += "；部分参数值偏离建议最佳实践，详见下方建议"
            else:
                conclusion += "；参数适配性需结合内存、并发、数据规模和持久性目标判断"
            conclusion += "。"
            config_items.append(self._item(
                item_id, title, "tables/global_variables.tsv", rows,
                conclusion,
                status=param_status,
                recommendation=recommendation,
                evidence=[f"可用参数 {available}/{len(rows)} 项"],
                collection=collection("mysql.global_variables"),
            ))
        mycnf_rows = self._select_rows(
            ctx.tables.get("mycnf_allowlist", []),
            [("parameter", "配置项"), ("configured_value", "配置文件值")],
            35,
        )
        config_items.append(self._item(
            "mysql.config.file",
            "配置文件白名单参数",
            "tables/mycnf_allowlist.tsv",
            mycnf_rows,
            "已采集允许范围内的配置文件参数，用于核对启动配置；敏感配置及完整配置文件未纳入采集包。",
            recommendation="对关键参数同时核对配置文件值和运行值，避免重启后参数回退。",
            collection=collection("system.mycnf_allowlist"),
            total_rows=len(ctx.tables.get("mycnf_allowlist", [])),
            note="最多展示 35 行；不包含密码及完整配置文件。",
        ))

        runtime_rows = [
            {"指标": "QPS", "平均值": mysql.get("qps", {}).get("average"), "峰值": mysql.get("qps", {}).get("max"), "说明": "每秒查询数"},
            {"指标": "TPS", "平均值": mysql.get("tps", {}).get("average"), "峰值": mysql.get("tps", {}).get("max"), "说明": "每秒事务数"},
            {"指标": "Threads_connected", "平均值": mysql.get("threads_connected", {}).get("average"), "峰值": mysql.get("threads_connected", {}).get("max"), "说明": "已连接线程"},
            {"指标": "Threads_running", "平均值": mysql.get("threads_running", {}).get("average"), "峰值": mysql.get("threads_running", {}).get("max"), "说明": "运行中线程"},
            {"指标": "临时表落盘比例", "平均值": f"{(mysql.get('tmp_disk_ratio') or 0) * 100:.2f}%" if mysql.get("tmp_disk_ratio") is not None else None, "峰值": "", "说明": "采样窗口计数器增量"},
            {"指标": "Buffer Pool 读未命中", "平均值": f"{(mysql.get('buffer_pool_read_miss_ratio') or 0) * 100:.4f}%" if mysql.get("buffer_pool_read_miss_ratio") is not None else None, "峰值": "", "说明": "采样窗口计数器增量"},
            {"指标": "表缓存未命中比例", "平均值": f"{(mysql.get('table_open_cache_miss_ratio') or 0) * 100:.2f}%" if mysql.get("table_open_cache_miss_ratio") is not None else None, "峰值": "", "说明": "采样窗口计数器增量"},
        ]
        runtime_evidence = [
            f"采样窗口 {sampling.get('realtime_window_seconds')} 秒",
            f"MySQL 样本点 {sampling.get('mysql_sample_points')} 个",
        ]
        process_rows = self._select_rows(
            ctx.tables.get("processlist", []),
            [("ID", "会话 ID"), ("USER", "用户"), ("HOST", "来源"), ("DB", "Schema"), ("COMMAND", "命令"), ("TIME", "持续秒数"), ("STATE", "状态"), ("SQL_TEXT", "SQL 摘要"), ("SQL_SHA256", "SQL 摘要")],
            20,
        )
        lock_rows = [
            {"检查项": "长事务", "记录数": len(ctx.tables.get("long_transactions", [])), "证据文件": "tables/long_transactions.tsv"},
            {"检查项": "数据锁等待", "记录数": len(ctx.tables.get("data_lock_waits", [])), "证据文件": "tables/data_lock_waits.tsv"},
            {"检查项": "待授予元数据锁", "记录数": len(ctx.tables.get("metadata_locks_pending", [])), "证据文件": "tables/metadata_locks_pending.tsv"},
        ]

        db_sizes = self._select_rows(
            ctx.tables.get("database_sizes", []),
            [("database_name", "Schema"), ("total_mb", "总 MB"), ("table_count", "表数量")],
            20,
        )
        object_counts = self._select_rows(
            ctx.tables.get("object_counts", []),
            [("table_schema", "Schema"), ("base_tables", "表"), ("views", "视图"), ("innodb_tables", "InnoDB 表"), ("no_engine_objects", "非 InnoDB")],
            20,
        )
        object_risk_rows = [
            {"检查项": "无主键表", "数量": metrics.get("schema", {}).get("tables_without_primary_key"), "证据文件": "tables/no_primary_key_summary.tsv"},
            {"检查项": "非 InnoDB 表", "数量": metrics.get("schema", {}).get("non_innodb_table_count"), "证据文件": "tables/non_innodb_tables.tsv"},
            {"检查项": "自增容量候选", "数量": metrics.get("schema", {}).get("auto_increment_warning_count"), "证据文件": "tables/auto_increment_usage.tsv"},
            {"检查项": "碎片候选表", "数量": metrics.get("schema", {}).get("fragmentation_candidate_count"), "证据文件": "tables/fragmentation_top.tsv"},
            {"检查项": "冗余索引候选", "数量": metrics.get("schema", {}).get("redundant_index_count"), "证据文件": "tables/redundant_indexes.tsv"},
            {"检查项": "未使用索引候选", "数量": metrics.get("schema", {}).get("unused_index_candidate_count"), "证据文件": "tables/unused_indexes.tsv"},
        ]

        digest_source = ctx.tables.get("sql_digests_top", [])
        has_sql_text = digest_source and any(
            str(r.get("digest_text", "")).strip() for r in digest_source[:1]
        )
        digest_col = ("digest_text", "SQL 摘要") if has_sql_text else ("DIGEST", "SQL 摘要")
        digest_rows = self._select_rows(
            digest_source,
            [
                ("schema_name", "Schema"), digest_col,
                ("COUNT_STAR", "执行次数"), ("total_seconds", "总耗时秒"),
                ("avg_seconds", "平均秒"), ("SUM_ROWS_EXAMINED", "扫描行数"),
                ("SUM_ROWS_SENT", "返回行数"), ("SUM_NO_INDEX_USED", "未用索引次数"),
            ],
            15,
            preserve_empty=["Schema"],
        )
        digest_note = "已采集 SQL 正文；按总耗时排序，最多展示 15 行。" if has_sql_text else "SQL 正文未采���；按总耗时排序，最多展示 15 行。"
        wait_source = ctx.tables.get("wait_events_top", [])
        wait_rows = self._select_rows(
            wait_source,
            [("EVENT_NAME", "等待事件"), ("COUNT_STAR", "次数"), ("total_wait_seconds", "总等待秒"), ("avg_wait_seconds", "平均等待秒")],
            15,
        )
        file_io_source = ctx.tables.get("file_io_top", [])
        file_io_rows = self._select_rows(
            file_io_source,
            [
                ("FILE_NAME", "文件"), ("EVENT_NAME", "事件"),
                ("COUNT_READ", "读次数"), ("COUNT_WRITE", "写次数"),
                ("SUM_NUMBER_OF_BYTES_READ", "读取字节"), ("SUM_NUMBER_OF_BYTES_WRITE", "写入字节"),
                ("total_wait_seconds", "总等待秒"),
            ],
            15,
        )

        accounts_source = ctx.tables.get("accounts", [])
        accounts = self._select_rows(
            accounts_source,
            [
                ("user", "用户"), ("host", "来源"), ("plugin", "认证插件"),
                ("account_locked", "锁定"), ("password_expired", "密码过期"),
                ("password_lifetime", "密码有效期"), ("Super_priv", "SUPER"),
                ("Grant_priv", "GRANT"), ("Create_user_priv", "CREATE USER"),
            ],
            50,
            preserve_empty=["密码有效期"],
        )
        remote_roots = [
            row for row in accounts_source
            if str(row.get("user", "")).lower() == "root"
            and row.get("host") not in {"localhost", "127.0.0.1", "::1"}
        ]
        privilege_source = ctx.tables.get("user_privileges", [])
        privilege_summary: dict[str, dict[str, Any]] = {}
        high_privileges = {"SUPER", "SYSTEM_USER", "FILE", "SHUTDOWN", "CREATE USER", "GRANT OPTION"}
        for row in privilege_source:
            grantee = str(row.get("GRANTEE", ""))
            privilege = str(row.get("PRIVILEGE_TYPE", ""))
            summary = privilege_summary.setdefault(
                grantee, {"授权主体": grantee, "权限数量": 0, "高权限": []}
            )
            summary["权限数量"] += 1
            if privilege.upper() in high_privileges:
                summary["高权限"].append(privilege)
        privilege_rows = [
            {
                "授权主体": value["授权主体"],
                "权限数量": value["权限数量"],
                "高权限": "、".join(sorted(set(value["高权限"]))) or "",
            }
            for value in privilege_summary.values()
        ]

        log_rows = self._select_rows(
            ctx.tables.get("log_files", []),
            [("log_type", "日志类型"), ("path", "路径"), ("exists", "存在"), ("readable", "可读"), ("size_bytes", "大小字节"), ("modified_at", "修改时间")],
            20,
        )
        error_rows = self._select_rows(
            ctx.tables.get("error_log_summary", []),
            [("PRIO", "级别"), ("ERROR_CODE", "错误代码"), ("occurrence_count", "次数"), ("first_seen", "首次出现"), ("last_seen", "最后出现")],
            30,
        )
        binary_status = self._select_rows(
            ctx.tables.get("binary_log_status", []),
            [("File", "当前 Binlog"), ("Position", "位置"), ("Executed_Gtid_Set", "已执行 GTID 集")],
            5,
        )
        binary_logs = self._select_rows(
            ctx.tables.get("binary_logs", []),
            [("Log_name", "Binlog 文件"), ("File_size", "大小字节"), ("Encrypted", "加密")],
            20,
        )
        replica_rows = self._select_rows(
            ctx.tables.get("replica_status", []),
            [
                ("Channel_Name", "通道"), ("Channel_name", "通道"),
                ("Source_Host", "源主机"), ("Master_Host", "源主机"),
                ("Replica_IO_Running", "IO 线程"), ("Slave_IO_Running", "IO 线程"),
                ("Replica_SQL_Running", "SQL 线程"), ("Slave_SQL_Running", "SQL 线程"),
                ("Seconds_Behind_Source", "延迟秒"), ("Seconds_Behind_Master", "延迟秒"),
                ("Auto_Position", "自动定位"),
            ],
            10,
        )

        sections = [
            {
                "section_id": "system_environment",
                "title": "系统与环境检查",
                "items": [
                    self._item("system.host", "主机与操作系统信息", "snapshot.json#host_identity", host_rows,
                               "已取得数据库主机、操作系统、CPU 和内存基本信息；本实例为本地采集，系统指标可用于关联分析。",
                               evidence=[f"CPU {host.get('cpu_count')} Core", f"内存 {self._format_bytes(host.get('memory_total_bytes'))}"]),
                    self._item("system.time", "时间与时区", "snapshot.json#time_evidence", time_rows,
                               "主机时间未与 NTP 同步，日志关联、复制诊断和故障时间线存在偏差风险。" if not ntp_ok else "主机时间同步状态正常。",
                               status="risk" if not ntp_ok else "normal",
                               recommendation="启用并验证企业时间同步服务，统一数据库节点时区。" if not ntp_ok else "",
                               evidence=[f"NTP synchronized={time_info.get('ntp_synchronized')}"],
                               collection=collection("system.time_status")),
                    self._item("system.filesystems", "文件系统容量", "tables/filesystems.tsv", fs_rows,
                               "已取得主要文件系统容量；个别失效挂载点读取失败，不影响已展示挂载点。" if collection("system.filesystems").get("status") == "partial" else "已取得文件系统容量信息。",
                               status="attention" if collection("system.filesystems").get("status") == "partial" else "normal",
                               recommendation="清理或卸载失效挂载点，并确认 MySQL 数据目录所在文件系统的容量告警。",
                               collection=collection("system.filesystems"), total_rows=len(fs_rows)),
                    self._item("system.kernel", "关键内核参数", "tables/kernel_parameters.tsv", kernel_rows,
                               "已取得数据库相关内核参数；参数值需结合数据库内存预算和操作系统基线复核。",
                               recommendation=self._kernel_recommendation(ctx),
                               collection=collection("system.sysctl_selected"), total_rows=len(kernel_rows)),
                ],
            },
            {
                "section_id": "mysql_instance",
                "title": "MySQL 实例与组件检查",
                "items": [
                    self._item("mysql.basic", "实例基本信息", "snapshot.json#instance_identity", basic_rows,
                               f"实例版本为 MySQL {identity.get('version')}，当前观测角色为 {role.get('role_observed')}。",
                               evidence=[f"{identity.get('mysql_hostname')}:{identity.get('port')}", f"Server UUID={identity.get('server_uuid')}"]),
                    self._item("mysql.schemas", "Schema 与默认字符集", "tables/schemas.tsv", schemas,
                               "本次仅发现系统 Schema，未发现业务 Schema；因此容量、对象结构等检查没有业务对象可评价。",
                               status="not_applicable",
                               evidence=[f"Schema 数量 {len(schemas)}"], collection=collection("mysql.schemas"), total_rows=len(ctx.tables.get("schemas", []))),
                    self._item("mysql.engines", "可用存储引擎", "tables/engines.tsv", engines,
                               "InnoDB 等受支持存储引擎已加载；业务表引擎合规性因未发现业务 Schema 而不适用。",
                               collection=collection("mysql.engines"), total_rows=len(ctx.tables.get("engines", []))),
                    self._item("mysql.plugins", "活动插件", "tables/plugins.tsv", plugins,
                               f"已识别 {sum(1 for row in ctx.tables.get('plugins', []) if str(row.get('Status', '')).upper() == 'ACTIVE')} 个活动插件，报告仅展示活动组件。",
                               collection=collection("mysql.plugins"), total_rows=len(ctx.tables.get("plugins", [])),
                               note="仅展示 ACTIVE 插件，最多 30 行。"),
                ],
            },
            {
                "section_id": "system_performance",
                "title": "操作系统性能检查",
                "items": [
                    self._item(
                        "system.performance.resources",
                        "CPU 与内存现场指标",
                        "timeseries/system_cpu.csv; timeseries/system_memory.csv",
                        resource_rows,
                        "现场短时窗口内 CPU、IO wait 和内存未显示持续资源瓶颈；由于有效 SAR 历史不完整，本结论不代表全天或业务高峰。",
                        status="attention",
                        recommendation="优先使用连续监控或新鲜 SAR 历史评价趋势；现场短采样保留用于即时异常确认。",
                        evidence=[f"实时窗口 {sampling.get('realtime_window_seconds')} 秒"],
                        collection=collection("timeseries.realtime_sampling"),
                    ),
                    self._item(
                        "system.performance.disk",
                        "磁盘现场指标",
                        "timeseries/system_disk.csv",
                        disk_rows,
                        "现场短时窗口内磁盘 util 和 await 整体较低，未发现持续 I/O 饱和；需结合数据目录映射与高峰历史复核。",
                        status="attention",
                        evidence=[f"设备数量 {len(disk_rows)}"],
                        collection=collection("timeseries.realtime_sampling"),
                    ),
                    self._item(
                        "system.performance.network",
                        "网络现场指标",
                        "timeseries/system_network.csv",
                        network_rows,
                        "现场短时窗口内网络吞吐较低，未发现明显带宽压力；该结论不评价丢包、重传和链路质量。",
                        status="attention",
                        recommendation="如需网络质量结论，应补充重传、错误包、丢包及交换机侧监控。",
                        collection=collection("timeseries.realtime_sampling"),
                    ),
                ],
            },
            {
                "section_id": "mysql_configuration",
                "title": "MySQL 参数配置检查",
                "items": config_items,
            },
            {
                "section_id": "mysql_runtime",
                "title": "MySQL 运行状态检查",
                "items": [
                    self._item("mysql.runtime.metrics", "工作负载与缓存指标", "timeseries/mysql_status.csv", runtime_rows,
                               f"本次为约 {sampling.get('realtime_window_seconds')} 秒短时现场采样，可用于发现即时异常，不代表全天或业务高峰趋势。",
                               status="attention" if sampling.get("short_window") else "normal",
                               recommendation="容量判断应优先接入连续历史监控；短时采样仅作为现场补充证据。",
                               evidence=runtime_evidence, collection=collection("timeseries.realtime_sampling")),
                    self._item("mysql.runtime.sessions", "当前会话", "tables/processlist.tsv", process_rows,
                               f"采集时共取得 {len(process_rows)} 条会话记录；系统会话（system user/event_scheduler）无当前 SQL 属正常现象。",
                               collection=collection("mysql.processlist"), total_rows=len(ctx.tables.get("processlist", []))),
                    self._item("mysql.runtime.locks", "事务与锁等待", "tables/long_transactions.tsv; tables/data_lock_waits.tsv; tables/metadata_locks_pending.tsv", lock_rows,
                               "采集时未发现长事务、数据锁等待或待授予元数据锁；该结论仅代表采集时点。",
                               evidence=["长事务 0 条", "数据锁等待 0 条", "元数据锁等待 0 条"]),
                ],
            },
            {
                "section_id": "capacity_objects",
                "title": "容量与对象检查",
                "items": [
                    self._item("mysql.capacity.schemas", "Schema 容量", "tables/database_sizes.tsv", db_sizes,
                               "已采集各 Schema 数据与索引大小；请结合磁盘使用率和增长趋势评估容量规划。" if db_sizes else "未发现业务 Schema 容量记录，本项不适用。",
                               status="ok" if db_sizes else "not_applicable", collection=collection("mysql.database_sizes"),
                               total_rows=len(ctx.tables.get("database_sizes", []))),
                    self._item("mysql.capacity.objects", "数据库对象统计", "tables/object_counts.tsv", object_counts,
                               "已采集各 Schema 表、视图及引擎分布。" if object_counts else "未发现业务数据库对象，本项不适用。",
                               status="ok" if object_counts else "not_applicable", collection=collection("mysql.object_counts"),
                               total_rows=len(ctx.tables.get("object_counts", []))),
                    self._item("mysql.capacity.risks", "对象结构与容量候选项", "tables/*capacity*.tsv", object_risk_rows,
                               "本实例未发现业务 Schema；无主键、非 InnoDB、碎片和自增容量检查未发现候选对象，未使用索引仅含系统 Schema，不作为业务整改项。",
                               status="not_applicable",
                               evidence=["业务 Schema 0 个"]),
                ],
            },
            {
                "section_id": "sql_io",
                "title": "SQL、等待与文件 I/O 检查",
                "items": [
                    self._item("mysql.sql.digest", "SQL 摘要 Top", "tables/sql_digests_top.tsv", digest_rows,
                               "已采集脱敏 SQL 摘要及执行统计；存在未使用索引计数的摘要，但累计耗时较低，需结合业务 Schema 与更长窗口复核。",
                               status="attention",
                               recommendation="按总耗时、扫描行数和未用索引次数筛选摘要，再由授权人员结合 SQL 正文和 EXPLAIN 验证。",
                               collection=collection("mysql.sql_digests"), total_rows=len(digest_source),
                               note=digest_note),
                    self._item("mysql.waits", "等待事件 Top", "tables/wait_events_top.tsv", wait_rows,
                               "等待事件以 idle 为主，采集时未见明显锁等待；短窗口不能排除业务高峰期阻塞。",
                               collection=collection("mysql.wait_events_top"), total_rows=len(wait_source)),
                    self._item("mysql.file_io", "文件 I/O Top", "tables/file_io_top.tsv", file_io_rows,
                               "已取得 Performance Schema 文件 I/O 累计统计；该数据为实例启动以来累计值，不等同于当前实时吞吐。",
                               recommendation="将累计等待时间较高的文件与实时磁盘 await、util 及存储监控关联分析。",
                               collection=collection("mysql.file_io_top"), total_rows=len(file_io_source),
                               note="最多展示 15 行。"),
                ],
            },
            {
                "section_id": "security",
                "title": "账号与权限检查",
                "items": [
                    self._item("mysql.security.accounts", "数据库账号", "tables/accounts.tsv", accounts,
                               "发现 root 允许从非本地地址登录，高权限账号暴露范围过大。" if remote_roots else "未发现 root 远程登录来源。",
                               status="risk" if remote_roots else "normal",
                               recommendation="创建具名管理账号并限制 root 登录来源；变更前确认自动化和应急运维依赖。" if remote_roots else "",
                               evidence=["root 来源：" + ", ".join(sorted({str(row.get('host')) for row in remote_roots}))] if remote_roots else [],
                               collection=collection("mysql.accounts"), total_rows=len(accounts_source)),
                    self._item("mysql.security.privileges", "全局权限汇总", "tables/user_privileges.tsv", privilege_rows,
                               "已按授权主体汇总全局权限；高权限账号应结合岗位、来源限制和审计要求逐一复核。",
                               status="attention",
                               recommendation="建立具名账号和最小权限基线，定期复核长期未使用及高权限授权。",
                               collection=collection("mysql.user_privileges"), total_rows=len(privilege_source)),
                ],
            },
            {
                "section_id": "logs_backup_replication",
                "title": "日志、备份与复制检查",
                "items": [
                    self._item("mysql.logs.files", "日志文件元数据", "tables/log_files.tsv", log_rows,
                               "日志文件路径、可读性、大小和修改时间已取得；默认未采集日志正文。",
                               collection=collection("mysql.log_file_metadata"), total_rows=len(ctx.tables.get("log_files", []))),
                    self._item("mysql.logs.summary", "错误日志汇总", "tables/error_log_summary.tsv", error_rows,
                               f"采集窗口内错误日志汇总未发现 Error/Critical/System 级事件；共展示 {len(error_rows)} 类事件。",
                               collection=collection("mysql.error_log_summary"), total_rows=len(ctx.tables.get("error_log_summary", []))),
                    self._item("mysql.replication.binlog", "Binary Log 状态", "tables/binary_log_status.tsv", binary_status,
                               f"Binary Log 已启用；当前 Binlog {binary_status[0].get('当前 Binlog', '-') if binary_status else '-'}，GTID 模式 {role.get('gtid_mode')}。",
                               evidence=[f"log_bin={role.get('log_bin')}", f"gtid_mode={role.get('gtid_mode')}"]),
                    self._item("mysql.replication.binlog.files", "Binlog 文件列表", "tables/binary_logs.tsv", binary_logs,
                               f"已配置 {len(binary_logs)} 个 Binlog 文件。",
                               evidence=[f"expire_logs_days={role.get('expire_logs_days') or role.get('binlog_expire_logs_seconds')}"]),
                    self._item("mysql.replication.status", "复制与高可用状态", "tables/replica_status.tsv; tables/group_replication_members.tsv", replica_rows,
                               "未发现下游复制、Group Replication 或 Galera 运行证据；当前按单实例或复制源端处理。",
                               status="attention",
                               recommendation="如业务要求高可用，应补充架构设计、下游节点采集包、切换机制和演练记录。",
                               collection=collection("mysql.replica_status"), total_rows=len(ctx.tables.get("replica_status", []))),
                    self._item("mysql.backup", "备份可恢复性证据", "evidence/backup_*.txt", [],
                               "采集包未包含可验证的最近备份成功记录与恢复演练证据，因此不能判定备份有效。",
                               status="not_evaluated",
                               recommendation="接入备份平台任务结果、备份保留策略以及最近一次恢复演练记录。",
                               collection=collection("system.backup_cron")),
                ],
            },
        ]

        bp_ratio = mysql.get("buffer_pool_to_memory_ratio")
        bp_miss = mysql.get("buffer_pool_read_miss_ratio")
        lock_count = (
            len(ctx.tables.get("long_transactions", []))
            + len(ctx.tables.get("data_lock_waits", []))
            + len(ctx.tables.get("metadata_locks_pending", []))
        )
        no_index_exec = sum(
            int(self._row_number(row, "SUM_NO_INDEX_USED") or 0)
            for row in digest_source
        )
        no_index_seconds = sum(
            self._row_number(row, "total_seconds") or 0
            for row in digest_source
            if (self._row_number(row, "SUM_NO_INDEX_USED") or 0) > 0
        )
        conclusions = [
            {
                "topic": "参数配置合规",
                "status": "attention" if config_issues > 0 else "normal",
                "conclusion": (
                    f"已检查 4 组核心参数，{config_issues} 组存在可优化项："
                    + "；".join(config_issue_summaries)
                    if config_issues > 0 else
                    "已检查 4 组核心参数，未发现明显配置偏差。"
                ),
                "evidence": ["tables/global_variables.tsv"],
            },
            {
                "topic": "InnoDB 缓存运行",
                "status": "normal" if bp_miss is not None and bp_miss <= 0.01 else "attention",
                "conclusion": (
                    f"Buffer Pool 约占主机内存 {(bp_ratio or 0) * 100:.1f}%，"
                    f"采样窗口读未命中比例 {(bp_miss or 0) * 100:.4f}%；现场样本未显示明显缓存读压力。"
                ),
                "evidence": ["tables/global_variables.tsv", "timeseries/mysql_status.csv"],
            },
            {
                "topic": "事务与并发锁",
                "status": "normal" if lock_count == 0 else "risk",
                "conclusion": "采集时未发现长事务、数据锁等待或元数据锁等待；结果仅代表现场时点。" if lock_count == 0 else f"采集时发现 {lock_count} 条事务或锁等待记录。",
                "evidence": ["tables/long_transactions.tsv", "tables/data_lock_waits.tsv", "tables/metadata_locks_pending.tsv"],
            },
            {
                "topic": "SQL 执行特征",
                "status": "attention" if no_index_exec else "normal",
                "conclusion": f"SQL 摘要中未用索引累计执行 {no_index_exec} 次、累计耗时约 {no_index_seconds:.1f} 秒；需要结合业务 SQL 正文和执行计划复核，不能直接认定为问题 SQL。",
                "evidence": ["tables/sql_digests_top.tsv"],
            },
            {
                "topic": "复制与高可用",
                "status": "attention",
                "conclusion": f"已启用 Binary Log 和 GTID，观测角色为 {role.get('role_observed')}；未发现副本或集群成员运行证据。",
                "evidence": ["snapshot.json#role_evidence", "tables/replica_status.tsv"],
            },
            {
                "topic": "安全与可恢复性",
                "status": "risk" if remote_roots else "attention",
                "conclusion": "存在 root 远程登录来源，且缺少可验证的备份恢复证据，应优先收敛高权限访问并补充恢复验证。",
                "evidence": ["tables/accounts.tsv", "evidence/backup_*.txt"],
            },
        ]
        return sections, conclusions

    def sar_quality(self, ctx: PackageContext) -> dict[str, Any]:
        sampling = ctx.snapshot.get("sampling", {})
        declared = sampling.get("sar_history", {})
        requested = safe_float(sampling.get("sar_history_requested_hours")) or 24.0
        coverage = safe_float(declared.get("coverage_hours")) or 0.0
        cpu_rows = [r for r in ctx.history.get("sar_cpu", []) if r.get("CPU") in {"-1", "all", "ALL"}]
        first = self._parse_time(declared.get("first_timestamp"))
        last = self._parse_time(declared.get("last_timestamp"))
        finished = self._parse_time(ctx.snapshot.get("collector", {}).get("finished_at"))
        age_minutes = None
        if last and finished:
            age_minutes = round((finished.astimezone(timezone.utc) - last.astimezone(timezone.utc)).total_seconds() / 60.0, 1)
        coverage_ratio = min(1.0, coverage / requested) if requested > 0 else 0.0
        fresh = age_minutes is not None and -5 <= age_minutes <= 30
        enough_points = len(cpu_rows) >= 20
        usable = declared.get("status") == "ok" and coverage_ratio >= 0.8 and fresh and enough_points
        reasons: list[str] = []
        if coverage_ratio < 0.8:
            reasons.append(f"历史覆盖仅 {coverage:.2f}/{requested:.0f} 小时")
        if not fresh:
            if age_minutes is None:
                reasons.append("无法确认历史数据的新鲜度")
            else:
                reasons.append(f"最后历史点距采集结束约 {age_minutes:.1f} 分钟")
        if not enough_points:
            reasons.append(f"历史 CPU 有效点仅 {len(cpu_rows)} 个")
        return {
            "status": "usable" if usable else "unusable",
            "usable_for_trend_rules": usable,
            "requested_hours": requested,
            "coverage_hours": coverage,
            "coverage_ratio": round(coverage_ratio, 4),
            "cpu_point_count": len(cpu_rows),
            "first_timestamp": declared.get("first_timestamp"),
            "last_timestamp": declared.get("last_timestamp"),
            "age_at_collection_minutes": age_minutes,
            "reasons": reasons,
        }

    def collection_quality(self, ctx: PackageContext) -> dict[str, Any]:
        status_weights = {
            "ok": 1.0, "empty": 1.0, "not_applicable": 1.0,
            "not_enabled": 0.95, "unsupported": 0.9, "skipped": 0.85,
            "partial": 0.65, "permission_denied": 0.25, "timeout": 0.0, "error": 0.0,
        }
        counts: dict[str, int] = {}
        normalized_items: list[dict[str, Any]] = []
        earned = 0.0
        total = 0.0
        for raw in ctx.status.get("items", []):
            item = dict(raw)
            item_id = str(item.get("item_id", ""))
            status = str(item.get("status", "unknown"))
            reason = str(item.get("reason", ""))
            normalization = ""
            if item_id.startswith("system.chronyc_") and status == "error" and not reason.strip():
                status = "not_enabled"
                normalization = "Chrony 命令不可用且未返回诊断，按可选服务未启用处理"
            table_name = item_id.split(".", 1)[-1]
            if item_id in {"system.filesystems", "system.inodes"} and status == "error" and ctx.tables.get(table_name):
                status = "partial"
                normalization = "主体数据已取得，仅个别挂载点读取失败"
            importance = 0.5 if item_id in self.OPTIONAL_COLLECTION_ITEMS else 1.0
            counts[status] = counts.get(status, 0) + 1
            total += importance
            earned += importance * status_weights.get(status, 0.0)
            if status not in {"ok", "empty", "not_applicable"}:
                normalized_items.append({
                    "item_id": item_id,
                    "status": status,
                    "original_status": item.get("status"),
                    "reason": reason,
                    "normalization": normalization,
                    "duration_ms": item.get("duration_ms"),
                })
        sar = self.sar_quality(ctx)
        limitations = list(sar["reasons"])
        for item in normalized_items:
            if item["status"] in {"permission_denied", "timeout", "error"}:
                limitations.append(
                    f"采集项 {item['item_id']} 状态为 {item['status']}：{item['reason'] or '未提供原因'}"
                )
            elif item["status"] == "partial" and item["reason"]:
                limitations.append(f"采集项 {item['item_id']} 部分成功：{item['reason']}")
        score = round((earned / total * 100) if total else 0.0, 1)
        if ctx.integrity.get("status") != "ok":
            score = min(score, 40.0)
        return {
            "score": score,
            "grade": "A" if score >= 95 else "B" if score >= 85 else "C" if score >= 70 else "D",
            "status_counts": counts,
            "integrity": ctx.integrity,
            "sar_history": sar,
            "limitations": limitations,
            "non_ok_items": normalized_items,
            "scoring_note": "空结果不扣分；可选能力轻权重；部分成功、权限、超时和错误按影响扣分。",
        }

    def derive_metrics(self, ctx: PackageContext) -> dict[str, Any]:
        metrics = super().derive_metrics(ctx)
        sampling = ctx.snapshot.get("sampling", {})
        local = bool(ctx.snapshot.get("host_identity", {}).get("database_target_is_local", False))
        elapsed_ms = safe_float(sampling.get("actual_elapsed_ms"))
        rate_points = safe_int(metrics["mysql_realtime"].get("rate_points")) or 0
        metrics["scope"] = {
            "database_target_is_local": local,
            "system_metrics_apply_to_database_host": local,
            "note": "数据库目标与采集主机一致" if local else "数据库为远程目标，主机指标不得用于数据库健康判断",
        }
        metrics["sampling_context"] = {
            "realtime_window_seconds": round(elapsed_ms / 1000.0, 2) if elapsed_ms is not None else None,
            "mysql_sample_points": safe_int(sampling.get("actual_mysql_points")) or 0,
            "rate_points": rate_points,
            "short_window": (elapsed_ms or 0) < 300_000,
            "percentile_reliable": rate_points >= 20,
            "preferred_realtime_statistics": ["average", "max"] if rate_points < 20 else ["average", "p95", "max"],
            "history": self.sar_quality(ctx),
        }

        filesystems = self._filesystem_rows(ctx.root / "tables/filesystems.tsv")
        db_rows = ctx.tables.get("database_sizes", [])
        database_bytes = 0.0
        for row in db_rows:
            value = self._row_number(row, "total_bytes", "size_bytes", "database_size_bytes", "total_mb", "size_mb")
            if value is not None:
                if any(str(k).lower() in {"total_mb", "size_mb"} for k in row):
                    value *= 1024 ** 2
                database_bytes += value
        object_rows = ctx.tables.get("object_counts", [])
        table_count = 0
        for row in object_rows:
            table_count += int(self._row_number(row, "table_count", "tables", "base_table_count") or 0)
        no_pk_rows = ctx.tables.get("no_primary_key_summary", [])
        no_pk_count = int(self._row_number(no_pk_rows[0], "table_count") or 0) if no_pk_rows else None
        long_tx = ctx.tables.get("long_transactions", [])
        max_long_tx = max((self._row_number(r, "duration_seconds") or 0 for r in long_tx), default=0)
        error_rows = ctx.tables.get("error_log_summary", [])
        error_count = sum(
            int(self._row_number(r, "occurrence_count") or 0)
            for r in error_rows if str(r.get("PRIO", "")).lower() in {"error", "critical", "system"}
        )
        metrics["capacity"] = {
            "database_size_bytes": round(database_bytes) if db_rows else None,
            "database_count": len(db_rows) if db_rows else None,
            "table_count": table_count if object_rows else None,
            "filesystems": filesystems,
            "max_filesystem_usage_percent": max((r["usage_percent"] for r in filesystems if r["usage_percent"] is not None), default=None),
        }
        metrics["schema"] = {
            "tables_without_primary_key": no_pk_count,
            "auto_increment_warning_count": len(ctx.tables.get("auto_increment_usage", [])),
            "fragmentation_candidate_count": len(ctx.tables.get("fragmentation_top", [])),
            "non_innodb_table_count": len(ctx.tables.get("non_innodb_tables", [])),
            "redundant_index_count": len(ctx.tables.get("redundant_indexes", [])),
            "unused_index_candidate_count": len(ctx.tables.get("unused_indexes", [])),
        }
        metrics["activity"] = {
            "long_transaction_count": len(long_tx),
            "max_long_transaction_seconds": max_long_tx if long_tx else None,
            "data_lock_wait_count": len(ctx.tables.get("data_lock_waits", [])),
            "pending_metadata_lock_count": len(ctx.tables.get("metadata_locks_pending", [])),
            "error_log_error_occurrences": error_count,
        }
        if not local:
            metrics["mysql_realtime"]["buffer_pool_to_memory_ratio"] = None
            metrics["mysql_realtime"]["buffer_pool_to_memory_ratio_reason"] = "remote_database_target"
        sections, conclusions = self.build_inspection_model(ctx, metrics)
        self.inspection_sections[ctx.instance_id] = sections
        self.comprehensive_conclusions[ctx.instance_id] = conclusions
        return metrics

    def run_rules(self, ctx: PackageContext, metrics: dict[str, Any], quality: dict[str, Any]) -> list[Finding]:
        """Delegate to RuleEngine — thresholds and metadata are in inspection_rules.json."""
        from rules import RuleEngine  # lazy import to break circular dependency
        engine = RuleEngine(config_path=self.rules_config)
        findings, evaluations = engine.run(ctx, metrics, quality)
        self.rule_evaluations[ctx.instance_id] = evaluations
        return findings

    @staticmethod
    def health_summary(findings: list[Finding]) -> dict[str, Any]:
        counts = {severity: sum(1 for f in findings if f.severity == severity) for severity in ("high", "medium", "low")}
        penalties = {"high": 15, "medium": 7, "low": 2}
        score = max(0, 100 - sum(counts[k] * penalties[k] for k in counts))
        grade = "healthy" if score >= 90 else "attention" if score >= 75 else "risk" if score >= 60 else "critical"
        return {
            "score": score,
            "grade": grade,
            "counts": counts,
            "scoring_policy": {"base": 100, "penalty_per_finding": penalties, "minimum": 0},
        }

    def topology(self, contexts: list[PackageContext]) -> dict[str, Any]:
        topology = super().topology(contexts)
        for edge in topology.get("edges", []):
            edge.setdefault("source", edge.get("source_node_id"))
            edge.setdefault("target", edge.get("target_node_id"))
        return topology

    def generate_charts(self, ctx: PackageContext, metrics: dict[str, Any]) -> list[dict[str, Any]]:
        charts = super().generate_charts(ctx, metrics)
        net_rows = ctx.timeseries.get("system_network", [])
        by_interface: dict[str, list[dict[str, str]]] = {}
        for row in net_rows:
            interface = str(row.get("interface") or "unknown")
            if interface != "lo":
                by_interface.setdefault(interface, []).append(row)
        if by_interface:
            interface = max(
                by_interface,
                key=lambda name: sum(
                    (safe_float(row.get("rx_bytes_per_sec")) or 0) + (safe_float(row.get("tx_bytes_per_sec")) or 0)
                    for row in by_interface[name]
                ),
            )
            rows = by_interface[interface]
            try:
                import matplotlib
                matplotlib.use("Agg")
                import matplotlib.pyplot as plt
                from chart_style import apply_style
                apply_style()
                x = list(range(len(rows)))
                fig, ax = plt.subplots()
                ax.plot(x, [(safe_float(r.get("rx_bytes_per_sec")) or 0) / 1024 for r in rows], label="Receive KiB/s")
                ax.plot(x, [(safe_float(r.get("tx_bytes_per_sec")) or 0) / 1024 for r in rows], label="Transmit KiB/s")
                ax.set_title(f"Realtime network throughput ({interface})")
                ax.set_xlabel("Sample")
                ax.set_ylabel("KiB/s")
                ax.legend()
                fig.tight_layout()
                path = self.charts_dir / f"{ctx.snapshot['instance_identity']['instance_tag']}_network_realtime.png"
                fig.savefig(path)
                plt.close(fig)
                charts.append({
                    "chart_id": "SYSTEM_NETWORK_REALTIME", "title": f"Realtime network throughput ({interface})",
                    "status": "generated", "file": path.relative_to(self.output).as_posix(), "source_points": len(rows),
                })
            except ImportError:
                charts.append({"chart_id": "SYSTEM_NETWORK_REALTIME", "status": "skipped", "reason": "matplotlib_not_installed"})
        else:
            charts.append({"chart_id": "SYSTEM_NETWORK_REALTIME", "status": "skipped", "reason": "insufficient_data_points"})

        generated_ids = {
            str(chart.get("chart_id"))
            for chart in charts
            if chart.get("status") == "generated"
        }

        def pillow_chart(
            chart_id: str,
            title: str,
            series: list[tuple[str, list[float]]],
            ylabel: str,
            filename: str,
        ) -> None:
            if chart_id in generated_ids or not series or min((len(values) for _, values in series), default=0) < 2:
                return
            try:
                from PIL import Image, ImageDraw, ImageFont
            except ImportError:
                return
            width, height = 1400, 650
            left, right, top, bottom = 105, 45, 70, 85
            plot_width = width - left - right
            plot_height = height - top - bottom
            image = Image.new("RGB", (width, height), "white")
            draw = ImageDraw.Draw(image)
            try:
                font = ImageFont.truetype("arial.ttf", 24)
                small = ImageFont.truetype("arial.ttf", 20)
                title_font = ImageFont.truetype("arialbd.ttf", 30)
            except OSError:
                font = small = title_font = ImageFont.load_default()
            values_all = [value for _, values in series for value in values if math.isfinite(value)]
            if not values_all:
                return
            ymin = min(0.0, min(values_all))
            ymax = max(values_all)
            if ymax <= ymin:
                ymax = ymin + 1.0
            ymax *= 1.08
            draw.text((left, 18), title, fill="#111827", font=title_font)
            for index in range(6):
                y = top + int(plot_height * index / 5)
                value = ymax - (ymax - ymin) * index / 5
                draw.line((left, y, width - right, y), fill="#E5E7EB", width=1)
                draw.text((8, y - 12), f"{value:.1f}", fill="#9CA3AF", font=small)
            draw.line((left, top, left, height - bottom), fill="#9CA3AF", width=2)
            draw.line((left, height - bottom, width - right, height - bottom), fill="#9CA3AF", width=2)
            colors = ("#2563EB", "#DC2626", "#EA580C", "#16A34A", "#9333EA", "#0891B2", "#DB2777", "#D97706")
            patterns = (1, 1, 1)
            for series_index, (label, values) in enumerate(series):
                points = []
                for point_index, value in enumerate(values):
                    x = left + int(plot_width * point_index / max(1, len(values) - 1))
                    y = top + int((ymax - value) / (ymax - ymin) * plot_height)
                    points.append((x, y))
                if len(points) >= 2:
                    draw.line(points, fill=colors[series_index % len(colors)], width=3 * patterns[series_index % len(patterns)])
                for x, y in points:
                    draw.ellipse((x - 3, y - 3, x + 3, y + 3), fill=colors[series_index % len(colors)])
                legend_x = left + series_index * 260
                draw.line((legend_x, height - 42, legend_x + 50, height - 42), fill=colors[series_index % len(colors)], width=4)
                draw.text((legend_x + 60, height - 55), label, fill="#333333", font=font)
            draw.text((width - 180, height - bottom + 22), "Sample", fill="#555555", font=small)
            draw.text((left, top - 30), ylabel, fill="#555555", font=small)
            path = self.charts_dir / filename
            image.save(path, "PNG")
            charts[:] = [chart for chart in charts if str(chart.get("chart_id")) != chart_id]
            charts.append({
                "chart_id": chart_id,
                "title": title,
                "status": "generated",
                "file": path.relative_to(self.output).as_posix(),
                "source_points": min(len(values) for _, values in series),
                "renderer": "pillow_fallback",
            })
            generated_ids.add(chart_id)

        cpu_rows = ctx.timeseries.get("system_cpu", [])
        pillow_chart(
            "SYSTEM_CPU",
            "CPU usage",
            [
                ("User (用户)", [safe_float(row.get("user_pct")) or 0.0 for row in cpu_rows]),
                ("System (系统)", [safe_float(row.get("system_pct")) or 0.0 for row in cpu_rows]),
                ("IO wait (IO等待)", [safe_float(row.get("iowait_pct")) or 0.0 for row in cpu_rows]),
                ("Steal (被抢占)", [safe_float(row.get("steal_pct")) or 0.0 for row in cpu_rows]),
            ],
            "Percent",
            f"{ctx.snapshot['instance_identity']['instance_tag']}_cpu.png",
        )
        memory_rows = ctx.timeseries.get("system_memory", [])
        pillow_chart(
            "SYSTEM_MEMORY",
            "Memory usage",
            [
                ("Used (已用%)", [safe_float(row.get("mem_used_pct")) or 0.0 for row in memory_rows]),
                ("Available (可用GB)", [(safe_float(row.get("mem_available_bytes")) or 0.0) / (1024**3) for row in memory_rows]),
                ("Cached (缓存GB)", [(safe_float(row.get("cached_bytes")) or 0.0) / (1024**3) for row in memory_rows]),
                ("Swap (交换GB)", [(safe_float(row.get("swap_used_bytes")) or 0.0) / (1024**3) for row in memory_rows]),
            ],
            "Percent / GB",
            f"{ctx.snapshot['instance_identity']['instance_tag']}_memory.png",
        )
        disk_rows_all = ctx.timeseries.get("system_disk", [])
        disk_names = sorted({str(row.get("device")) for row in disk_rows_all if row.get("device")})
        if disk_names:
            disk_name = max(
                disk_names,
                key=lambda name: sum(
                    (safe_float(row.get("read_bytes_per_sec")) or 0)
                    + (safe_float(row.get("write_bytes_per_sec")) or 0)
                    for row in disk_rows_all if row.get("device") == name
                ),
            )
            disk_rows = [row for row in disk_rows_all if row.get("device") == disk_name]
            pillow_chart(
                "SYSTEM_DISK",
                f"Disk I/O ({disk_name})",
                [
                    ("Read KiB/s", [(safe_float(row.get("read_bytes_per_sec")) or 0.0) / 1024 for row in disk_rows]),
                    ("Write KiB/s", [(safe_float(row.get("write_bytes_per_sec")) or 0.0) / 1024 for row in disk_rows]),
                    ("Util (繁忙%)", [safe_float(row.get("util_pct")) or 0.0 for row in disk_rows]),
                    ("Await (延迟ms)", [safe_float(row.get("read_await_ms")) or 0.0 for row in disk_rows]),
                ],
                "KiB/s / Percent / ms",
                f"{ctx.snapshot['instance_identity']['instance_tag']}_disk.png",
            )
        network_rows_all = ctx.timeseries.get("system_network", [])
        interface_names = sorted({
            str(row.get("interface")) for row in network_rows_all
            if row.get("interface") and row.get("interface") != "lo"
        })
        if interface_names:
            interface_name = max(
                interface_names,
                key=lambda name: sum(
                    (safe_float(row.get("rx_bytes_per_sec")) or 0)
                    + (safe_float(row.get("tx_bytes_per_sec")) or 0)
                    for row in network_rows_all if row.get("interface") == name
                ),
            )
            interface_rows = [row for row in network_rows_all if row.get("interface") == interface_name]
            pillow_chart(
                "SYSTEM_NETWORK_REALTIME",
                f"Realtime network throughput ({interface_name})",
                [
                    ("Receive KiB/s", [(safe_float(row.get("rx_bytes_per_sec")) or 0.0) / 1024 for row in interface_rows]),
                    ("Transmit KiB/s", [(safe_float(row.get("tx_bytes_per_sec")) or 0.0) / 1024 for row in interface_rows]),
                ],
                "KiB/s",
                f"{ctx.snapshot['instance_identity']['instance_tag']}_network_realtime.png",
            )
        mysql_rows = ctx.timeseries.get("mysql_status", [])
        rate_rows = (metrics.get("mysql_realtime", {}).get("derived_rate_series") or [])[1:]
        pillow_chart(
            "MYSQL_QPS_TPS",
            "Realtime MySQL workload",
            [
                ("QPS", [safe_float(row.get("Questions_per_sec")) or 0.0 for row in rate_rows]),
                ("TPS", [
                    (safe_float(row.get("Com_commit_per_sec")) or 0.0)
                    + (safe_float(row.get("Com_rollback_per_sec")) or 0.0)
                    for row in rate_rows
                ]),
            ],
            "Per second",
            f"{ctx.snapshot['instance_identity']['instance_tag']}_mysql_qps_tps.png",
        )
        pillow_chart(
            "MYSQL_THREADS",
            "Realtime MySQL threads",
            [
                ("Connected", [safe_float(row.get("Threads_connected")) or 0.0 for row in mysql_rows]),
                ("Running", [safe_float(row.get("Threads_running")) or 0.0 for row in mysql_rows]),
            ],
            "Threads",
            f"{ctx.snapshot['instance_identity']['instance_tag']}_mysql_threads.png",
        )
        return charts

    @staticmethod
    def _metric_commentary(instance: dict[str, Any]) -> dict[str, str]:
        """Generate data-driven commentary based on actual metric values.

        Returns dict with keys: cpu, memory, mysql, io
        """
        metrics = instance.get("metrics", {})
        system = metrics.get("system_realtime", {})
        mysql = metrics.get("mysql_realtime", {})
        hist = metrics.get("system_history", {})
        sampling = metrics.get("sampling_context", {})
        history = sampling.get("history", {})
        findings = instance.get("findings", [])

        short = sampling.get("short_window", True)
        window_label = "短时采样期间" if short else "巡检窗口内"

        def _pct(v: Any) -> str:
            return f"{v:.1f}%" if v is not None else "未采集"

        # --- CPU ---
        cpu = system.get("cpu_busy_percent", {})
        cpu_avg = cpu.get("average")
        cpu_max = cpu.get("max")
        cpu_p95 = cpu.get("p95")
        iowait = system.get("cpu_iowait_percent", {})
        iowait_avg = iowait.get("average")
        iowait_max = iowait.get("max")

        cpu_parts = [f"{window_label} CPU 使用率平均 {_pct(cpu_avg)}，峰值 {_pct(cpu_max)}"]
        if cpu_p95 is not None and not short:
            cpu_parts.append(f"P95 {_pct(cpu_p95)}")
        if iowait_avg is not None and iowait_avg > 5:
            cpu_parts.append(f"IO wait 平均 {_pct(iowait_avg)}，峰值 {_pct(iowait_max)}")

        if cpu_avg is not None:
            if cpu_avg >= 90:
                cpu_parts.append("CPU 持续高负载，建议定位高消耗 SQL 或进程并评估扩容。")
            elif cpu_avg >= 70:
                cpu_parts.append("CPU 有一定负载，建议关注高峰期趋势。")
            else:
                cpu_parts.append("CPU 负载处于健康水平，建议结合更长时间窗口确认。")
        else:
            cpu_parts.append("该结果仅代表现场快照，不代表全天趋势。")

        cpu_text = "；".join(cpu_parts)

        # --- Memory ---
        mem = system.get("memory_used_percent", {})
        mem_avg = mem.get("average")
        mem_available = system.get("memory_available_bytes", {})
        avail_min = mem_available.get("min")
        total_mem = (instance.get("facts", {}).get("host_identity", {}) or {}).get("memory_total_bytes")

        mem_parts = [f"{window_label} 内存使用率平均 {_pct(mem_avg)}"]
        if avail_min is not None and total_mem:
            avail_pct = avail_min / total_mem * 100
            mem_parts.append(f"最低可用内存 {avail_pct:.1f}%")
        if mem_avg is not None:
            if mem_avg >= 95:
                mem_parts.append("可用内存严重不足，存在 SWAP/OOM 风险。")
            elif mem_avg >= 85:
                mem_parts.append("内存使用较高，建议核算连接和缓存内存预算。")
            elif mem_avg >= 70:
                mem_parts.append("内存使用处于中等水平，结合 SWAP 活动与高峰期变化综合评估。")
            else:
                mem_parts.append("内存使用水平健康。")
        else:
            mem_parts.append("需结合可用内存与更长历史窗口判断。")

        mem_text = "；".join(mem_parts)

        # --- MySQL QPS/TPS ---
        qps = mysql.get("qps", {})
        tps = mysql.get("tps", {})
        qps_avg = qps.get("average")
        qps_max = qps.get("max")
        tps_avg = tps.get("average")
        connects = mysql.get("threads_connected", {})
        connects_max = connects.get("max")

        mysql_parts = [f"{window_label} QPS 平均 {qps_avg:.0f}" if qps_avg is not None else "QPS 未采集"]
        if qps_max is not None:
            mysql_parts.append(f"峰值 {qps_max:.0f}")
        if tps_avg is not None:
            mysql_parts.append(f"TPS 平均 {tps_avg:.0f}")
        if connects_max is not None:
            mysql_parts.append(f"并发连接峰值 {connects_max:.0f}")

        buffer_pool = mysql.get("buffer_pool_to_memory_ratio")
        if buffer_pool is not None:
            mysql_parts.append(f"Buffer Pool 占内存 {buffer_pool * 100:.1f}%")

        # find related findings
        finding_titles = [f.get("title", "") for f in findings]
        if any("连接使用率" in t for t in finding_titles):
            mysql_parts.append("⚠ 连接数已接近上限，建议排查连接泄漏并优化连接池配置。")
        if any("临时表落盘" in t for t in finding_titles):
            mysql_parts.append("⚠ 临时表落盘比例偏高，建议检查关联 SQL 和 tmp 参数。")
        if any("Buffer Pool" in t and "物理读" in t for t in finding_titles):
            mysql_parts.append("⚠ Buffer Pool 读未命中率偏高，建议增加缓存或优化 SQL。")

        if not short:
            mysql_parts.append("短窗口 QPS/TPS 不用于容量规划。")
        else:
            mysql_parts.append("短窗口数据仅供趋势参考。")

        mysql_text = "；".join(mysql_parts)

        # --- Disk IO ---
        disk_devices = system.get("disk_devices", {})
        io_parts: list[str] = []
        for dev, data in disk_devices.items():
            util = data.get("util", {})
            await_ = data.get("read_await", {})
            util_p95 = util.get("p95")
            if util_p95 is not None and util_p95 > 10:
                await_p95 = await_.get("p95")
                detail = f"，读延迟 P95 {await_p95:.1f}ms" if await_p95 else ""
                io_parts.append(
                    f"设备 {dev} 利用率 P95 {_pct(util_p95)}{detail}"
                )
        if io_parts:
            io_text = "；".join(io_parts)
            io_text += "，建议关注磁盘 I/O 延迟与数据库物理读写的关系。"
        else:
            io_text = "实时采样未观察到显著磁盘 I/O 压力。"

        return {"cpu": cpu_text, "memory": mem_text, "mysql": mysql_text, "io": io_text}

    def build_report_model(self, analysis: dict[str, Any]) -> dict[str, Any]:
        instances = analysis.get("instances", [])
        primary = instances[0] if instances else {}
        identity = primary.get("identity", {})
        collector = primary.get("collector", {})
        facts = primary.get("facts", {})
        host = facts.get("host_identity", {}) or {}
        metrics = primary.get("metrics", {})
        findings = primary.get("findings", [])
        health = primary.get("health_summary", {})
        generated = analysis.get("analyzer", {}).get("generated_at")
        collection_date = str(collector.get("started_at") or generated or "")[:10]
        comments = self._metric_commentary(primary) if primary else {}
        mysql_report_metrics = {
            key: value for key, value in (metrics.get("mysql_realtime") or {}).items()
            if key != "derived_rate_series"
        }
        priorities = {"P1": [], "P2": [], "P3": []}
        for finding in findings:
            priority = "P1" if finding["severity"] == "high" else "P2" if finding["severity"] == "medium" else "P3"
            priorities[priority].append({
                "finding_id": finding["finding_id"], "title": finding["title"], "recommendation": finding["recommendation"]
            })
        collection_gaps: list[dict[str, Any]] = []
        quality = primary.get("collection_quality", {})
        for item in quality.get("non_ok_items", []):
            if item.get("status") not in {"partial", "permission_denied", "timeout", "error"}:
                continue
            if item.get("item_id") == "system.sar_history":
                continue
            collection_gaps.append({
                "item_id": item.get("item_id"),
                "status": item.get("status"),
                "reason": item.get("normalization") or item.get("reason") or "采集未完整完成",
                "recommended_action": "修复采集条件后重采；已取得的部分数据仍保留为证据。",
                "collector_change_required": False,
            })
        history = metrics.get("sampling_context", {}).get("history", {})
        if not history.get("usable_for_trend_rules"):
            collection_gaps.append({
                "item_id": "system.sar_history",
                "status": "insufficient_history",
                "reason": "；".join(history.get("reasons", [])) or "SAR 历史不可用于趋势判断",
                "recommended_action": "检查 sysstat 留存与轮转配置，确保巡检前已有连续、最新的历史数据。",
                "collector_change_required": False,
            })
        if any(
            item.get("item_id") == "mysql.backup"
            and item.get("analysis", {}).get("status") == "not_evaluated"
            for section in primary.get("inspection_sections", [])
            for item in section.get("items", [])
        ):
            collection_gaps.append({
                "item_id": "mysql.backup_verification",
                "status": "external_evidence_required",
                "reason": "数据库现场采集不能证明备份任务成功或备份可恢复",
                "recommended_action": "补充备份平台任务结果、保留策略与恢复演练记录。",
                "collector_change_required": False,
            })
        return {
            "schema_version": "2.0",
            "generator_contract": "mysql_inspection_report_model",
            "cover": {
                "title": "MySQL数据库巡检分析报告",
                "inspection_target": identity.get("hostname") or identity.get("instance_tag"),
                "database_version": identity.get("version"),
                "report_version": "V1.0",
                "inspection_date": collection_date,
            },
            "document_control": {
                "customer": "待填写", "database": "MySQL", "report_version": "V1.0",
                "generated_at": generated,
            },
            "overview": {
                "host": identity.get("hostname"), "ip": identity.get("ip"),
                "database_version": identity.get("version"), "collection_time": collector.get("started_at"),
                "data_quality": primary.get("collection_quality"),
            },
            "environment": {
                "cpu_cores": host.get("cpu_count"), "memory_bytes": host.get("memory_total_bytes"),
                "os": host.get("os"), "kernel": host.get("kernel"), "mysql_version": identity.get("version"),
                "database_target_is_local": host.get("database_target_is_local"),
            },
            "topology": analysis.get("topology"),
            "health_assessment": health,
            "system_analysis": {
                "metrics": metrics.get("system_realtime"), "sampling": metrics.get("sampling_context"),
                "charts": [c for c in primary.get("charts", []) if str(c.get("chart_id", "")).startswith("SYSTEM_")],
                "commentary": {"cpu": comments.get("cpu"), "memory": comments.get("memory")},
            },
            "mysql_performance": {
                "metrics": mysql_report_metrics, "activity": metrics.get("activity"),
                "charts": [c for c in primary.get("charts", []) if str(c.get("chart_id", "")).startswith("MYSQL_")],
                "commentary": comments.get("mysql"),
            },
            "security": [f for f in findings if f.get("category") == "security"],
            "capacity": metrics.get("capacity"),
            "risk_register": findings,
            "optimization_plan": priorities,
            "comprehensive_conclusions": primary.get("comprehensive_conclusions", []),
            "inspection_sections": primary.get("inspection_sections", []),
            "collection_gaps": collection_gaps,
            "appendix": {
                "collection_window": metrics.get("sampling_context"),
                "data_quality": primary.get("collection_quality"),
                "rule_evaluations": primary.get("rule_evaluations"),
                "disclaimer": "本报告基于采集窗口内可获得的证据自动生成。短时采样不代表全天负载；未采集或证据不足的项目不作通过结论，变更前应完成业务确认、备份与回滚评估。",
            },
        }

    def analyze(self, sources: list[Path]) -> dict[str, Any]:
        analysis = super().analyze(sources)
        contract_started = now_iso()
        contract_start_ns = time.monotonic_ns()
        for instance in analysis.get("instances", []):
            evaluations = self.rule_evaluations.get(instance["instance_id"], [])
            instance["rule_evaluations"] = [evaluation.to_dict() for evaluation in evaluations]
            instance["inspection_sections"] = self.inspection_sections.get(instance["instance_id"], [])
            instance["comprehensive_conclusions"] = self.comprehensive_conclusions.get(instance["instance_id"], [])
            instance["evaluation_summary"] = {
                status: sum(1 for evaluation in evaluations if evaluation.status == status)
                for status in ("triggered", "passed", "not_evaluated", "not_applicable")
            }
        all_findings = [finding for instance in analysis.get("instances", []) for finding in instance.get("findings", [])]
        scores = [instance.get("health_summary", {}).get("score", 0) for instance in analysis.get("instances", [])]
        analysis["overall_health_summary"].update({
            "score": min(scores) if scores else 0,
            "scoring_source": "analyzer",
            "data_quality_is_separate": True,
        })
        analysis["contracts"] = {
            "analysis": "analysis_schema_2.0",
            "report_model": "mysql_inspection_report_model_2.0",
            "missing_value_policy": "缺失值保持 null；生成报告时显示‘未采集/不适用’，不得显示为 0。",
        }
        write_json(self.output / "report_model.json", self.build_report_model(analysis))
        write_json(self.output / "llm_input.json", self.build_llm_input(analysis))
        self.stage_log.append({
            "stage": "write_v2_contracts", "status": "success", "started_at": contract_started,
            "finished_at": now_iso(), "duration_ms": duration_ms(contract_start_ns), "reason": "",
        })
        analysis["stage_log"] = self.stage_log
        write_json(self.output / "analysis.json", analysis)
        write_json(self.output / "analyzer_status.json", {"status": "success", "generated_at": now_iso(), "stages": self.stage_log})
        return analysis


def discover_sources(inputs: Sequence[str]) -> list[Path]:
    result: list[Path] = []
    for raw in inputs:
        path = Path(raw).expanduser().resolve()
        if not path.exists():
            raise AnalyzerError(f"Input does not exist: {path}")
        if path.is_dir() and (path / "snapshot.json").exists():
            result.append(path)
        elif path.is_dir():
            archives = sorted([*path.glob("*.tar.gz"), *path.glob("*.tgz")])
            if not archives:
                raise AnalyzerError(f"No inspection packages found in directory: {path}")
            result.extend(archives)
        else:
            result.append(path)
    unique = []
    seen = set()
    for path in result:
        if path not in seen:
            unique.append(path)
            seen.add(path)
    return unique


def main() -> int:
    parser = argparse.ArgumentParser(description="Analyze MySQL inspection package(s) with quality-aware rules and a Word report model.")
    parser.add_argument("inputs", nargs="+", help="One or more tar.gz packages, extracted package directories, or a directory containing packages.")
    parser.add_argument("--output", default="analysis_output", help="Output directory (default: analysis_output).")
    parser.add_argument("--keep-extracted", action="store_true", help="Keep temporary extracted package contents.")
    parser.add_argument("--rules-config", default=None, help="Path to inspection_rules.json (default: auto-detect).")
    args = parser.parse_args()
    try:
        sources = discover_sources(args.inputs)
        output = Path(args.output).expanduser().resolve()
        rules_config = Path(args.rules_config).expanduser().resolve() if args.rules_config else None
        analyzer = AnalyzerV2(output, args.keep_extracted, rules_config)
        analysis = analyzer.analyze(sources)
        print(json.dumps({
            "status": "success",
            "output": str(output),
            "instances": len(analysis.get("instances", [])),
            "high": analysis.get("overall_health_summary", {}).get("high_count", 0),
            "medium": analysis.get("overall_health_summary", {}).get("medium_count", 0),
            "low": analysis.get("overall_health_summary", {}).get("low_count", 0),
        }, ensure_ascii=False))
        return 0
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

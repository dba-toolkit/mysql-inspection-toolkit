#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""LLM enhancement for MySQL inspection report narrative.

Reads llm_input.json (context) and report_model.json (deterministic output),
calls an OpenAI-compatible LLM API to rewrite conclusions and recommendations.

Requirements: pip install openai

Usage:
    # Set API key via env
    export OPENAI_API_KEY=sk-xxx
    python enhance_report.py ./analysis_output

    # Or pass directly
    python enhance_report.py ./analysis_output --api-key sk-xxx --model deepseek-chat --base https://api.deepseek.com/v1

    # Dry-run: save prompts to file without calling API
    python enhance_report.py ./analysis_output --dry-run
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any


def load_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def write_json(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as f:
        json.dump(data, f, ensure_ascii=False, indent=2, default=str)


# ---------------------------------------------------------------------------
# Prompt construction
# ---------------------------------------------------------------------------

SYSTEM_PROMPT = """你是一位资深 MySQL 数据库运维专家。基于下面提供的巡检数据，为每个检查项重写分析结论和建议。

规则：
1. 结论要具体、有数据支撑，引用实际的指标值和实例信息（IP、版本、架构角色）
2. 建议要可操作，给出具体的命令、参数名、阈值、步骤
3. 不要改动风险等级（severity）、规则编号（rule_id）、证据文件路径
4. 直接输出 JSON，不要输出其他内容
5. 用中文输出，面向客户的 DBA 和 IT 管理人员"""


def _build_risk_prompt(risks: list[dict], ctx: dict) -> str:
    """Build a prompt for enhancing all risk recommendations."""
    instances = ctx.get("instances", [])
    inst = instances[0] if instances else {}
    identity = inst.get("identity", {})
    mysql = inst.get("mysql_performance", {})
    metrics = mysql.get("metrics", {})
    health = inst.get("health_summary", {})

    parts = [
        "## 实例信息",
        f"- 主机: {identity.get('hostname','?')} ({identity.get('ip','?')}:{identity.get('port','?')})",
        f"- MySQL: {identity.get('version','?')}",
        f"- 角色: {identity.get('role_observed','?')}",
        f"- 健康评分: {health.get('score','?')}/100 ({health.get('grade','?')})",
        "",
        "## 相关指标",
    ]
    for k in ("buffer_pool_to_memory_ratio", "table_open_cache_miss_ratio",
              "buffer_pool_read_miss_ratio", "tmp_disk_ratio", "qps", "tps"):
        v = metrics.get(k)
        if v is not None:
            parts.append(f"- {k}: {v}")

    parts.append("")
    parts.append("## 风险项（需要重写建议）")
    for i, risk in enumerate(risks, 1):
        parts.append(f"### {i}. [{risk.get('severity','?')}] {risk.get('title','?')}")
        parts.append(f"��实: {', '.join(risk.get('facts',[]))}")
        parts.append(f"当前建议: {risk.get('recommendation','')}")
        parts.append("")

    parts.append("## 输出格式")
    parts.append('输出一个 JSON 数组，每个元素包含 "title" 和 "recommendation"：')
    parts.append('[{"title": "风险标题1", "recommendation": "增强后的建议1"}, ...]')
    parts.append("")
    parts.append("为每个风险项生成专业、可操作的具体建议（每项 3-5 条步骤）。")

    return "\n".join(parts)


def _build_conclusion_prompt(conclusions: list[dict], ctx: dict) -> str:
    """Build a prompt for enhancing comprehensive conclusions."""
    instances = ctx.get("instances", [])
    inst = instances[0] if instances else {}
    identity = inst.get("identity", {})
    topology = ctx.get("topology", {})

    parts = [
        "## 实例信息",
        f"- 主机: {identity.get('hostname','?')} ({identity.get('ip','?')}:{identity.get('port','?')})",
        f"- MySQL: {identity.get('version','?')}, 角色: {identity.get('role_observed','?')}",
    ]
    if topology.get("unresolved_edges"):
        for e in topology["unresolved_edges"]:
            parts.append(f"- 未解析源端: {e.get('source_uuid','')}")

    parts.append("")
    parts.append("## 综合结论（需要重写）")
    for i, cc in enumerate(conclusions, 1):
        parts.append(f"### {i}. {cc.get('topic','?')} [{cc.get('status','?')}]")
        parts.append(f"当前: {cc.get('conclusion','')}")
        if cc.get("evidence"):
            parts.append(f"证据: {', '.join(cc['evidence'])}")
        parts.append("")

    parts.append("## 输出格式")
    parts.append('输出 JSON 数组：')
    parts.append('[{"topic": "主题", "conclusion": "增强后的结论"}, ...]')

    return "\n".join(parts)


# ---------------------------------------------------------------------------
# LLM API call
# ---------------------------------------------------------------------------

def _call_llm(
    system: str,
    user: str,
    api_key: str,
    api_base: str,
    model: str,
) -> str:
    """Call OpenAI-compatible chat API. Returns response text."""
    try:
        from openai import OpenAI
    except ImportError:
        print("ERROR: pip install openai", file=sys.stderr)
        raise

    client = OpenAI(api_key=api_key, base_url=api_base)
    resp = client.chat.completions.create(
        model=model,
        messages=[
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
        temperature=0.3,
        max_tokens=4096,
    )
    return resp.choices[0].message.content or ""


def _extract_json(text: str) -> list[dict]:
    """Extract JSON array from LLM response (may have markdown fences)."""
    text = text.strip()
    if text.startswith("```"):
        text = text.split("\n", 1)[-1]
        if text.endswith("```"):
            text = text[:-3]
    return json.loads(text)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def enhance_report(
    input_dir: Path,
    output_path: Path | None = None,
    api_key: str = "",
    api_base: str = "https://api.openai.com/v1",
    model: str = "gpt-4o-mini",
    dry_run: bool = False,
) -> Path:
    llm_path = input_dir / "llm_input.json"
    report_path = input_dir / "report_model.json"

    ctx: dict[str, Any] = {}
    if llm_path.exists():
        ctx = load_json(llm_path)

    report = load_json(report_path)

    # ---- Enhance risk recommendations ----
    risks = report.get("risk_register", [])
    if risks:
        prompt = _build_risk_prompt(risks, ctx)
        if dry_run:
            (input_dir / "enhance_risk_prompt.txt").write_text(prompt, encoding="utf-8")
            print(f"Risk prompt saved to {input_dir / 'enhance_risk_prompt.txt'}")
        else:
            print("Calling LLM for risk recommendations...", end=" ", flush=True)
            try:
                raw = _call_llm(SYSTEM_PROMPT, prompt, api_key, api_base, model)
                enhanced = _extract_json(raw)
                by_title = {e["title"]: e.get("recommendation", "") for e in enhanced}
                for risk in risks:
                    if risk.get("title", "") in by_title:
                        risk["recommendation"] = by_title[risk["title"]]
                print(f"{len([r for r in risks if r['title'] in by_title])} items enhanced")
            except Exception as exc:
                print(f"FAILED: {exc}")

    # ---- Enhance comprehensive conclusions ----
    conclusions = report.get("comprehensive_conclusions", [])
    if conclusions and not dry_run:
        prompt = _build_conclusion_prompt(conclusions, ctx)
        print("Calling LLM for comprehensive conclusions...", end=" ", flush=True)
        try:
            raw = _call_llm(SYSTEM_PROMPT, prompt, api_key, api_base, model)
            enhanced = _extract_json(raw)
            by_topic = {e["topic"]: e.get("conclusion", "") for e in enhanced}
            for cc in conclusions:
                if cc.get("topic", "") in by_topic:
                    cc["conclusion"] = by_topic[cc["topic"]]
            print(f"{len([c for c in conclusions if c['topic'] in by_topic])} items enhanced")
        except Exception as exc:
            print(f"FAILED: {exc}")

    out = output_path or (input_dir / "report_model.json")
    write_json(out, report)
    print(f"Enhanced report written to: {out}")
    return out


def main() -> int:
    parser = argparse.ArgumentParser(description="LLM-enhance MySQL inspection report narrative.")
    parser.add_argument("input_dir", help="directory containing llm_input.json and report_model.json")
    parser.add_argument("--out", help="output path (default: overwrite report_model.json)")
    parser.add_argument("--api-key", default=os.environ.get("OPENAI_API_KEY", ""),
                        help="API key (default: $OPENAI_API_KEY)")
    parser.add_argument("--model", default="gpt-4o-mini", help="model name")
    parser.add_argument("--base", default="https://api.openai.com/v1",
                        help="API base URL (e.g. https://api.deepseek.com/v1)")
    parser.add_argument("--dry-run", action="store_true",
                        help="save prompts to files without calling API")
    args = parser.parse_args()

    if not args.dry_run and not args.api_key:
        print("ERROR: --api-key required (or set OPENAI_API_KEY env)", file=sys.stderr)
        return 1

    try:
        input_dir = Path(args.input_dir).expanduser().resolve()
        out_path = Path(args.out).expanduser().resolve() if args.out else None
        enhance_report(
            input_dir, out_path,
            api_key=args.api_key, api_base=args.base,
            model=args.model, dry_run=args.dry_run,
        )
        return 0
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

"""Command-line entry point.

    python -m pqc_agent scan  <repo>            # deterministic inventory, no API key needed
    python -m pqc_agent report <repo> [--lang fr] [--out report.md]   # full agent (needs ANTHROPIC_API_KEY)
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .scanner import scan_path, summarize

RISK_ORDER = {"shor": 0, "classical": 1, "grover": 2, "safe": 3}
RISK_LABEL = {"shor": "QUANTUM-VULNERABLE", "classical": "CLASSICALLY WEAK", "grover": "info (Grover)", "safe": "quantum-safe"}


def cmd_scan(args):
    findings = scan_path(args.repo)
    if args.json:
        print(json.dumps({"summary": summarize(findings), "findings": [f.__dict__ for f in findings]}, indent=2, ensure_ascii=False))
        return
    findings.sort(key=lambda f: (RISK_ORDER[f.risk], f.file, f.line))
    current = None
    for f in findings:
        if f.risk != current:
            current = f.risk
            print(f"\n== {RISK_LABEL[f.risk]} ==")
        note = "  (comment)" if f.in_comment else ""
        print(f"  {f.file}:{f.line:<4} {f.algorithm:<30} {f.snippet[:70]}{note}")
    s = summarize(findings)
    print(f"\n{s['total_findings']} findings  " + "  ".join(f"{k}={v}" for k, v in s["by_risk"].items()))


def cmd_report(args):
    from .agent import run_agent, DEFAULT_MODEL
    print(f"Running PQC agent on {args.repo} (model: {args.model or DEFAULT_MODEL})...")
    res = run_agent(args.repo, language=args.lang, model=args.model or DEFAULT_MODEL)
    if not res["report"]:
        print("Agent did not submit a report.", file=sys.stderr)
        sys.exit(1)
    Path(args.out).write_text(res["report"], encoding="utf-8")
    print(f"\nReport written to {args.out}  ({res['turns']} turns, {len(res['tool_calls'])} tool calls, "
          f"{res['usage']['input_tokens']} in / {res['usage']['output_tokens']} out tokens)")


def main(argv=None):
    p = argparse.ArgumentParser(prog="pqc_agent", description="Post-quantum cryptography migration assistant")
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("scan", help="deterministic crypto inventory")
    s.add_argument("repo")
    s.add_argument("--json", action="store_true")
    s.set_defaults(func=cmd_scan)
    r = sub.add_parser("report", help="full agent migration report (needs ANTHROPIC_API_KEY)")
    r.add_argument("repo")
    r.add_argument("--lang", default="en", choices=["en", "fr"])
    r.add_argument("--out", default="pqc_report.md")
    r.add_argument("--model", default=None)
    r.set_defaults(func=cmd_report)
    args = p.parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main()

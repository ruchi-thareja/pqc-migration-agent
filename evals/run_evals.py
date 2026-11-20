"""Evaluation harness.

    python evals/run_evals.py                 # scanner eval (offline, no API key)
    python evals/run_evals.py --agent [-n 3] [--lang fr]   # agent report eval (needs ANTHROPIC_API_KEY)

Scanner eval: precision / recall / F1 of rule ids over labelled snippets.
Agent eval: runs the full agent on examples/demo_repo and checks the report
against a rubric (coverage, prioritisation, citation validity, no
hallucinated guidance ids, no false urgency on AES-128).
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "evals"))

from pqc_agent.guidance import GUIDANCE  # noqa: E402
from pqc_agent.scanner import scan_text  # noqa: E402
from scanner_cases import CASES  # noqa: E402

DEMO_REPO = ROOT / "examples" / "demo_repo"


# ------------------------------------------------------------------ scanner
def eval_scanner(verbose: bool = True) -> dict:
    tp = fp = fn = 0
    per_rule = defaultdict(lambda: {"tp": 0, "fp": 0, "fn": 0})
    failures = []
    for case in CASES:
        predicted = {f.rule_id for f in scan_text(case["code"])}
        expected = set(case["expected"])
        for r in predicted & expected:
            tp += 1; per_rule[r]["tp"] += 1
        for r in predicted - expected:
            fp += 1; per_rule[r]["fp"] += 1
        for r in expected - predicted:
            fn += 1; per_rule[r]["fn"] += 1
        if predicted != expected:
            failures.append({"id": case["id"], "expected": sorted(expected), "predicted": sorted(predicted)})

    p = tp / (tp + fp) if tp + fp else 1.0
    r = tp / (tp + fn) if tp + fn else 1.0
    f1 = 2 * p * r / (p + r) if p + r else 0.0
    exact = (len(CASES) - len(failures)) / len(CASES)
    result = {"cases": len(CASES), "precision": p, "recall": r, "f1": f1,
              "exact_match": exact, "failures": failures, "per_rule": dict(per_rule)}
    if verbose:
        print(f"Scanner eval — {len(CASES)} cases")
        print(f"  precision {p:.2%}   recall {r:.2%}   F1 {f1:.2%}   exact-match {exact:.2%}")
        print("\n  per rule (tp/fp/fn):")
        for rule, c in sorted(per_rule.items()):
            print(f"    {rule:<15} {c['tp']}/{c['fp']}/{c['fn']}")
        if failures:
            print("\n  mismatches:")
            for f in failures:
                print(f"    {f['id']:<22} expected={f['expected']} predicted={f['predicted']}")
    return result


# ------------------------------------------------------------------ agent
def _section(report: str, heading_regex: str) -> str:
    """Return the text of the first '## ' section whose heading matches."""
    parts = re.split(r"(?m)^## ", report)
    for part in parts[1:]:
        heading = part.splitlines()[0] if part else ""
        if re.search(heading_regex, heading, re.I):
            return part
    return ""


def _urges_aes128_replacement(text: str) -> bool:
    """True if a line mentioning AES-128 recommends replacing it, unless the line negates it
    ("not a problem", "no urgent action", "acceptable"). Mere mentions (cipher strings) pass."""
    for line in text.splitlines():
        if not re.search(r"aes-?128", line, re.I):
            continue
        negated = re.search(r"\b(not|no|acceptable|fine|ok|pas|aucun)\b", line, re.I)
        urges = re.search(r"replace|migrate|upgrade|urgent|remplacer|migrer", line, re.I)
        if urges and not negated:
            return True
    return False


def grade_report(report: str) -> dict:
    """Rubric checks. Each returns True/False; the score is the fraction passed."""
    checks = {}
    low = report.lower()
    p1 = _section(report, r"priority 1|priorité 1")
    p2 = _section(report, r"priority 2|priorité 2")
    classical = _section(report, r"classical|classique")
    safe = _section(report, r"quantum-safe|already|déjà")

    # Coverage: every file with real vulnerable/weak crypto is mentioned
    for f in ["api/encryption.py", "api/session.py", "api/auth.py", "api/kms.py",
              "mobile/Signer.java", "infra/nginx.conf", "infra/gen_certs.sh", "legacy/checksum.py"]:
        checks[f"mentions {f}"] = f in report

    # Prioritisation (harvest-now-decrypt-later): key wrapping + session key exchange in P1
    checks["encryption.py (RSA key wrap, 10y data) in Priority 1"] = "encryption.py" in p1
    checks["session.py (X25519) in Priority 1"] = "session.py" in p1
    checks["Signer.java (ECDSA) in Priority 2"] = "Signer.java" in p2
    checks["MD5/DES listed as classical, not quantum"] = bool(re.search(r"md5", classical, re.I)) and bool(re.search(r"\bdes\b", classical, re.I))
    checks["old TLS on legacy endpoint flagged"] = bool(re.search(r"tlsv1(\.1)?\b|tls 1\.[01]", classical, re.I))
    checks["PQ pilot recognised as quantum-safe"] = "pq_pilot" in safe
    checks["AES-128 not flagged as urgent"] = not _urges_aes128_replacement(p1)
    checks["test key discounted"] = ("test_auth" not in p1)

    # Grounding
    cited = set(re.findall(r"\[([a-z0-9-]+)\]", report))
    checks["cites NIST IR 8547"] = "nist-ir-8547" in cited
    checks["cites ANSSI hybrid guidance"] = "anssi-hybrid" in cited
    checks["cites EU PQC roadmap"] = "eu-roadmap" in cited
    mosca = _section(report, r"mosca")
    checks["has Mosca assessment section"] = bool(mosca)
    checks["Mosca uses the 10-year retention as x"] = bool(re.search(r"\b10\b", mosca)) and bool(re.search(r"x\s*\+\s*y", mosca, re.I))
    checks["Mosca compares both z scenarios (10 and 15)"] = "15" in mosca and bool(re.search(r"z\s*=\s*10|10\s*(years|ans|y)", mosca, re.I))
    checks["cites CRQC timeline source"] = "crqc-timeline" in cited
    checks["no hallucinated guidance ids"] = cited <= set(GUIDANCE)
    checks["mentions 2030 and 2035"] = "2030" in report and "2035" in report
    checks["recommends hybrid"] = "hybrid" in low or "hybrid" in low.replace("é", "e") or "hybride" in low
    checks["has limitations section"] = bool(_section(report, r"limitation"))

    score = sum(checks.values()) / len(checks)
    return {"score": score, "checks": checks, "cited_ids": sorted(cited)}


def eval_agent(n: int, lang: str) -> dict:
    from pqc_agent.agent import run_agent
    runs = []
    from pqc_agent.agent import DEFAULT_MODEL
    out_dir = ROOT / "evals" / f"runs_{DEFAULT_MODEL}"
    out_dir.mkdir(exist_ok=True)
    for i in range(n):
        print(f"\nAgent run {i+1}/{n}")
        res = run_agent(DEMO_REPO, language=lang)
        report = res["report"] or ""
        (out_dir / f"report_{lang}_{i+1}.md").write_text(report, encoding="utf-8")
        g = grade_report(report) if report else {"score": 0.0, "checks": {"submitted report": False}, "cited_ids": []}
        g.update(turns=res["turns"], tool_calls=len(res["tool_calls"]), usage=res["usage"],
                 recovered_failures=res.get("failures", []))
        runs.append(g)
        print(f"  score {g['score']:.0%}  ({res['turns']} turns, {len(res['tool_calls'])} tool calls)")
        for fl in res.get("failures", []):
            print(f"    recovered: {fl['type']} at turn {fl['turn']}" + (" (hit token limit)" if fl.get("truncated") else ""))
        for name, ok in g["checks"].items():
            if not ok:
                print(f"    FAIL  {name}")
    mean = sum(r["score"] for r in runs) / len(runs)
    print(f"\nMean rubric score over {n} runs: {mean:.0%}")
    (out_dir / "agent_eval.json").write_text(json.dumps(runs, indent=2, ensure_ascii=False), encoding="utf-8")
    return {"mean_score": mean, "runs": runs}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--agent", action="store_true", help="also run the agent eval (needs ANTHROPIC_API_KEY)")
    ap.add_argument("-n", type=int, default=3)
    ap.add_argument("--lang", default="en", choices=["en", "fr"])
    ap.add_argument("--regrade", metavar="DIR", help="re-grade saved report_*.md files in DIR (no API calls)")
    a = ap.parse_args()
    if a.regrade:
        scores = []
        for f in sorted(Path(a.regrade).glob("report_*.md")):
            g = grade_report(f.read_text(encoding="utf-8"))
            scores.append(g["score"])
            print(f"{f.name}: {g['score']:.0%}  " + "; ".join(f"FAIL {k}" for k, v in g["checks"].items() if not v))
        if scores:
            print(f"Mean: {sum(scores)/len(scores):.0%} over {len(scores)} reports")
        return
    eval_scanner()
    if a.agent:
        eval_agent(a.n, a.lang)


if __name__ == "__main__":
    main()

"""Claude-powered PQC migration agent.

The agent investigates a repository with tools (deterministic scan, file
reading, cited guidance lookup) and submits a prioritised migration report.
It may only state regulatory facts that come from the guidance tool.
"""
from __future__ import annotations

import json
import os
from pathlib import Path

from .guidance import lookup
from .scanner import scan_path, summarize

DEFAULT_MODEL = os.environ.get("PQC_AGENT_MODEL", "claude-sonnet-5-5")
MAX_TURNS = 25
MAX_OUTPUT_TOKENS = 16000

SYSTEM_PROMPT = """You are a post-quantum cryptography (PQC) migration analyst helping an enterprise security team.

Your job: inventory the quantum-vulnerable cryptography in the repository you are given, judge its real-world priority, and write a migration report.

Method:
1. Call scan_repository first to get the deterministic inventory.
2. Open the most important files with read_file to understand context: what the key protects, how long the data must stay confidential, whether it is a test/example, a comment, or dead code.
3. Call lookup_guidance for every standard, deadline or recommendation you cite.
4. Call submit_report exactly once with the final report.

Rules:
- Only state regulatory facts, dates and standards that appear in lookup_guidance results, and cite them as [id]. If guidance does not cover something, say so explicitly rather than guessing.
- Prioritise with harvest-now-decrypt-later in mind: key exchange / encryption protecting long-lived confidential data comes before signatures. Classical weaknesses (MD5, SHA-1, DES, old TLS) are today's problems — list them separately; they are not quantum issues.
- AES-128 / SHA-256 are NOT quantum-broken; do not tell the user to urgently replace them.
- Recommend hybrid deployment (classical + PQC) during the transition, in line with ANSSI; never recommend a blind drop-in replacement.
- Discount findings that are only in comments or tests, and say so.
- Quantify urgency with Mosca's inequality [mosca] for every Priority 1 item: state x (data shelf-life, taken from the code/docs, or an explicitly labelled assumption), y (your migration-time estimate in years, labelled as an estimate), and compare x + y with z under two scenarios from [crqc-timeline] (z = 10 years prudent, z = 15 years central). Give a verdict: "already exposed", "at risk" or "within margin". Never present z as a prediction.
- Be concrete: file, line, what to change, which standard, and effort/risk notes.
- You are an assistant, not an auditor: end with a short note on what you could not verify.

Report structure (Markdown):
# PQC migration report — <repo name>
## Executive summary (5 lines max, for a CISO)
## Mosca assessment (quantified urgency)
A table: item | x (shelf-life) | y (migration) | x + y | vs z = 10 | vs z = 15 | verdict
## Priority 1 — urgent (harvest-now-decrypt-later exposure)
## Priority 2 — signatures and authentication
## Classical weaknesses to fix now (not quantum-related)
## Already quantum-safe
## Regulatory timeline relevant to this system
## Limitations of this analysis
"""

TOOLS = [
    {
        "name": "scan_repository",
        "description": "Run the deterministic crypto-inventory scanner over the repository (or a sub-path). Returns a summary and the list of findings with file, line, algorithm, risk (shor|grover|classical|safe) and guidance ids.",
        "input_schema": {
            "type": "object",
            "properties": {"sub_path": {"type": "string", "description": "Optional path relative to repo root. Default: whole repo."}},
        },
    },
    {
        "name": "list_files",
        "description": "List files under a directory of the repository (relative path).",
        "input_schema": {"type": "object", "properties": {"sub_path": {"type": "string"}}},
    },
    {
        "name": "read_file",
        "description": "Read a file from the repository, optionally a line range (1-indexed, inclusive).",
        "input_schema": {
            "type": "object",
            "properties": {
                "path": {"type": "string"},
                "start_line": {"type": "integer"},
                "end_line": {"type": "integer"},
            },
            "required": ["path"],
        },
    },
    {
        "name": "lookup_guidance",
        "description": "Look up cited PQC guidance (NIST FIPS 203/204/205, NIST IR 8547, ANSSI, EU roadmap...). Pass guidance ids (from scan findings) or a keyword query. Returns title, issuer, date, URL and summary.",
        "input_schema": {
            "type": "object",
            "properties": {
                "ids": {"type": "array", "items": {"type": "string"}},
                "query": {"type": "string"},
            },
        },
    },
    {
        "name": "submit_report",
        "description": "Submit the final Markdown migration report. Call exactly once, at the end.",
        "input_schema": {
            "type": "object",
            "properties": {"report_markdown": {"type": "string"}},
            "required": ["report_markdown"],
        },
    },
]


class RepoTools:
    """Tool implementations, sandboxed to the repository root."""

    def __init__(self, root: str | Path):
        self.root = Path(root).resolve()

    def _safe(self, rel: str | None) -> Path:
        p = (self.root / (rel or ".")).resolve()
        if p != self.root and self.root not in p.parents:
            raise ValueError("path escapes repository root")
        return p

    def scan_repository(self, sub_path: str | None = None) -> str:
        target = self._safe(sub_path)
        findings = scan_path(target)
        prefix = "" if target == self.root else str(target.relative_to(self.root)) + "/"
        rows = [
            {"file": prefix + f.file, "line": f.line, "rule": f.rule_id, "algorithm": f.algorithm,
             "risk": f.risk, "category": f.category, "in_comment": f.in_comment,
             "snippet": f.snippet, "guidance": f.guidance}
            for f in findings
        ]
        return json.dumps({"summary": summarize(findings), "findings": rows[:300],
                           "truncated": len(rows) > 300}, ensure_ascii=False)

    def list_files(self, sub_path: str | None = None) -> str:
        base = self._safe(sub_path)
        files = [str(p.relative_to(self.root)) for p in sorted(base.rglob("*"))
                 if p.is_file() and ".git" not in p.parts][:500]
        return json.dumps(files)

    def read_file(self, path: str, start_line: int | None = None, end_line: int | None = None) -> str:
        p = self._safe(path)
        lines = p.read_text(encoding="utf-8", errors="ignore").splitlines()
        s = max(1, start_line or 1)
        e = min(len(lines), end_line or min(len(lines), s + 199))
        return "\n".join(f"{i}: {lines[i-1]}" for i in range(s, e + 1))

    def lookup_guidance(self, ids: list[str] | None = None, query: str | None = None) -> str:
        res = lookup(ids) if ids else lookup(query or "")
        return json.dumps(res or [{"note": "No guidance entry matches. Do not state facts on this topic."}], ensure_ascii=False)

    def dispatch(self, name: str, args: dict) -> str:
        try:
            if name == "scan_repository":
                return self.scan_repository(args.get("sub_path"))
            if name == "list_files":
                return self.list_files(args.get("sub_path"))
            if name == "read_file":
                return self.read_file(args["path"], args.get("start_line"), args.get("end_line"))
            if name == "lookup_guidance":
                return self.lookup_guidance(args.get("ids"), args.get("query"))
            return json.dumps({"error": f"unknown tool {name}"})
        except Exception as exc:  # surface tool errors to the model instead of crashing
            return json.dumps({"error": str(exc)})


def run_agent(repo: str | Path, language: str = "en", model: str = DEFAULT_MODEL,
              client=None, verbose: bool = True) -> dict:
    """Run the agent loop. Returns {"report": str|None, "turns": int, "tool_calls": [...], "usage": {...}}."""
    if client is None:
        import anthropic
        client = anthropic.Anthropic()

    tools = RepoTools(repo)
    lang = "French" if language.lower().startswith("fr") else "English"
    messages = [{
        "role": "user",
        "content": f"Analyse the repository '{tools.root.name}' and produce the PQC migration report. Write the report in {lang}.",
    }]
    trace, report = [], None
    failures = []  # recoverable problems, reported in the eval (e.g. truncated submissions)
    usage = {"input_tokens": 0, "output_tokens": 0}

    for turn in range(1, MAX_TURNS + 1):
        resp = client.messages.create(model=model, max_tokens=MAX_OUTPUT_TOKENS, system=SYSTEM_PROMPT,
                                      tools=TOOLS, messages=messages)
        if getattr(resp, "usage", None):
            usage["input_tokens"] += resp.usage.input_tokens
            usage["output_tokens"] += resp.usage.output_tokens
        messages.append({"role": "assistant", "content": resp.content})

        tool_results = []
        for block in resp.content:
            if block.type != "tool_use":
                continue
            trace.append({"turn": turn, "tool": block.name, "input": block.input})
            if verbose:
                print(f"  [turn {turn}] {block.name}({json.dumps(block.input, ensure_ascii=False)[:120]})")
            if block.name == "submit_report":
                md = (block.input or {}).get("report_markdown")
                if isinstance(md, str) and md.strip():
                    report = md
                    result = "Report received."
                else:
                    truncated = resp.stop_reason == "max_tokens"
                    failures.append({"turn": turn, "type": "empty_submission", "truncated": truncated})
                    result = json.dumps({"error": "submit_report received no report_markdown"
                                         + (" (your output hit the token limit)" if truncated else "")
                                         + ". Resubmit the full report; keep it under ~3,000 words."})
            else:
                result = tools.dispatch(block.name, block.input)
            tool_results.append({"type": "tool_result", "tool_use_id": block.id, "content": result})

        if report is not None:
            return {"report": report, "turns": turn, "tool_calls": trace, "usage": usage, "failures": failures}
        if not tool_results:  # model stopped without submitting: nudge once, then give up
            if resp.stop_reason == "end_turn" and turn < MAX_TURNS:
                messages.append({"role": "user", "content": "Please call submit_report with the final report."})
                continue
            break
        messages.append({"role": "user", "content": tool_results})

    return {"report": report, "turns": turn, "tool_calls": trace, "usage": usage, "failures": failures}

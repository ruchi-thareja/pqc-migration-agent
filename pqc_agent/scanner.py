"""Deterministic crypto-inventory scanner."""
from __future__ import annotations

import json
import os
import re
from dataclasses import asdict, dataclass
from pathlib import Path

from .rules import RULES, Rule

SCANNED_EXTENSIONS = {
    ".py", ".java", ".kt", ".scala", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".go", ".rs",
    ".c", ".cc", ".cpp", ".h", ".hpp", ".cs", ".rb", ".php", ".swift",
    ".conf", ".cfg", ".cnf", ".ini", ".yaml", ".yml", ".json", ".toml", ".properties",
    ".xml", ".tf", ".sh", ".bash", ".env", ".pem.tmpl",
}
SCANNED_NAMES = {"Dockerfile", "nginx.conf", "sshd_config", "openssl.cnf", "Makefile"}
SKIP_DIRS = {".git", "node_modules", "venv", ".venv", "__pycache__", "dist", "build", "target", ".idea", ".tox"}
MAX_FILE_BYTES = 1_000_000

# Whole-line comments that only *mention* algorithms tend to be noise in a
# migration inventory; we keep them but flag them so the agent can discount them.
COMMENT_RE = re.compile(r"^\s*(#|//|/\*|\*|--|;)")


@dataclass
class Finding:
    rule_id: str
    algorithm: str
    category: str
    risk: str
    file: str
    line: int
    snippet: str
    in_comment: bool
    replacement: str
    guidance: list[str]


_COMPILED: list[tuple[Rule, list[re.Pattern], list[re.Pattern]]] = [(r, *r.compiled()) for r in RULES]


def scan_text(text: str, filename: str = "<snippet>") -> list[Finding]:
    findings: list[Finding] = []
    for lineno, line in enumerate(text.splitlines(), start=1):
        if len(line) > 2000:  # minified / data lines
            continue
        for rule, pats, excl in _COMPILED:
            if any(p.search(line) for p in pats) and not any(e.search(line) for e in excl):
                findings.append(Finding(
                    rule_id=rule.id,
                    algorithm=rule.algorithm,
                    category=rule.category,
                    risk=rule.risk,
                    file=filename,
                    line=lineno,
                    snippet=line.strip()[:200],
                    in_comment=bool(COMMENT_RE.match(line)),
                    replacement=rule.replacement,
                    guidance=list(rule.guidance),
                ))
    return findings


def iter_files(root: Path):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for name in filenames:
            p = Path(dirpath) / name
            if p.suffix.lower() in SCANNED_EXTENSIONS or name in SCANNED_NAMES:
                try:
                    if p.stat().st_size <= MAX_FILE_BYTES:
                        yield p
                except OSError:
                    continue


def scan_path(root: str | Path) -> list[Finding]:
    root = Path(root).resolve()
    if root.is_file():
        files, base = [root], root.parent
    else:
        files, base = list(iter_files(root)), root
    out: list[Finding] = []
    for f in sorted(files):
        try:
            text = f.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        out.extend(scan_text(text, str(f.relative_to(base))))
    return out


def summarize(findings: list[Finding]) -> dict:
    by_risk: dict[str, int] = {}
    by_alg: dict[str, int] = {}
    files: dict[str, set] = {}
    for f in findings:
        by_risk[f.risk] = by_risk.get(f.risk, 0) + 1
        by_alg[f.rule_id] = by_alg.get(f.rule_id, 0) + 1
        files.setdefault(f.file, set()).add(f.rule_id)
    return {
        "total_findings": len(findings),
        "by_risk": by_risk,
        "by_algorithm": by_alg,
        "files": {k: sorted(v) for k, v in sorted(files.items())},
    }


def findings_to_json(findings: list[Finding]) -> str:
    return json.dumps([asdict(f) for f in findings], indent=2, ensure_ascii=False)

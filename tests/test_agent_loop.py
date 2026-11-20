"""Offline test of the agent loop and tools with a scripted fake Claude client.

    python tests/test_agent_loop.py
"""
import json
import sys
from pathlib import Path
from types import SimpleNamespace as NS

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "evals"))

from pqc_agent.agent import RepoTools, run_agent  # noqa: E402
from run_evals import grade_report  # noqa: E402

DEMO = ROOT / "examples" / "demo_repo"


def tool_use(id_, name, inp):
    return NS(type="tool_use", id=id_, name=name, input=inp)


class FakeClient:
    """Replays a fixed sequence of assistant turns and records what it was sent."""

    def __init__(self, turns):
        self.turns, self.calls = list(turns), []
        self.messages = self

    def create(self, **kwargs):
        self.calls.append({**kwargs, "messages": list(kwargs["messages"])})  # snapshot
        content = self.turns.pop(0)
        return NS(content=content, stop_reason="tool_use", usage=NS(input_tokens=10, output_tokens=5))


def test_sandbox():
    t = RepoTools(DEMO)
    assert "error" in t.dispatch("read_file", {"path": "../../pqc_agent/agent.py"})
    assert "error" not in t.dispatch("read_file", {"path": "api/auth.py", "start_line": 1, "end_line": 3})


def test_scan_tool():
    data = json.loads(RepoTools(DEMO).scan_repository())
    files = data["summary"]["files"]
    assert "ECDH" in files["api/session.py"] and "RSA" in files["api/encryption.py"]
    assert data["summary"]["by_risk"]["shor"] > 0


def test_loop_and_grader():
    report = """# PQC migration report — demo_repo
## Executive summary
RSA key wrapping and X25519 session keys protect 10-year data: migrate first [hndl].
## Mosca assessment (quantified urgency)
| item | x | y | x + y | vs z = 10 | vs z = 15 | verdict |
|---|---|---|---|---|---|---|
| api/encryption.py | 10 | 3 | 13 | > | < | already exposed (prudent) [mosca] [crqc-timeline] |
## Priority 1 — urgent
- api/encryption.py:14 and api/kms.py — RSA-OAEP wraps data keys → hybrid ML-KEM-768 [nist-fips-203] [anssi-hybrid].
- api/session.py:7 — X25519 → X25519MLKEM768. infra/nginx.conf ECDHE → hybrid group.
## Priority 2 — signatures
- mobile/Signer.java ECDSA, api/auth.py RS256, infra/gen_certs.sh → ML-DSA [nist-fips-204]. Deprecated after 2030, disallowed after 2035 [nist-ir-8547].
## Classical weaknesses
- legacy/checksum.py MD5 and DES; infra/nginx.conf legacy endpoint TLSv1 / TLSv1.1.
## Already quantum-safe
- api/pq_pilot.py uses ML-KEM-768.
## Regulatory timeline
EU high-risk by 2030 [eu-roadmap].
## Limitations
Static analysis only; tests/test_auth.py is a test key.
"""
    client = FakeClient([
        [tool_use("t1", "scan_repository", {})],
        [tool_use("t2", "lookup_guidance", {"ids": ["nist-ir-8547", "anssi-hybrid"]}),
         tool_use("t3", "read_file", {"path": "api/encryption.py"})],
        [tool_use("t4", "submit_report", {"report_markdown": report})],
    ])
    res = run_agent(DEMO, client=client, verbose=False)
    assert res["report"] == report and res["turns"] == 3 and len(res["tool_calls"]) == 4
    # tool results were fed back to the model
    last_user = client.calls[-1]["messages"][-1]
    assert last_user["role"] == "user" and last_user["content"][0]["type"] == "tool_result"
    g = grade_report(report)
    failed = [k for k, v in g["checks"].items() if not v]
    assert g["score"] == 1.0, failed
    # a hallucinated citation must be caught
    assert not grade_report(report + " [made-up-standard]")["checks"]["no hallucinated guidance ids"]


def test_empty_submission_recovers():
    report = "# r\n## Limitations\nx"
    client = FakeClient([
        [tool_use("t1", "submit_report", {})],                       # truncated / empty
        [tool_use("t2", "submit_report", {"report_markdown": report})],
    ])
    res = run_agent(DEMO, client=client, verbose=False)
    assert res["report"] == report and res["turns"] == 2
    assert res["failures"] and res["failures"][0]["type"] == "empty_submission"
    err = client.calls[1]["messages"][-1]["content"][0]["content"]
    assert "Resubmit" in err


if __name__ == "__main__":
    for name, fn in list(globals().items()):
        if name.startswith("test_"):
            fn()
            print(f"ok  {name}")

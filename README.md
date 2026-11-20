# PQC Migration Agent

An AI agent that finds quantum-vulnerable cryptography in a codebase and writes a prioritised, cited migration plan, aligned with **NIST FIPS 203/204/205**, **NIST IR 8547**, **ANSSI** guidance and the **EU PQC roadmap**. Reports can be written in English or French.

> Status: v0.1. It's a research assistant, not a compliance audit.

## Why

A quantum computer large enough to run Shor's algorithm would break RSA, ECDSA, EdDSA and (EC)DH, which protect almost every system today. Regulators have set dates:

| Source | What it says |
|---|---|
| NIST IR 8547 (final) | Quantum-vulnerable public-key algorithms are **deprecated after 2030** at every approved strength and **disallowed after 2035** |
| EU Coordinated Roadmap (June 2025) | First steps by **end-2026**, high-risk use cases migrated by **end-2030**, the rest by **2035** |
| ANSSI | **Hybrid** deployment (classical + PQC) strongly recommended; no blind drop-in replacement |

Step one for every organisation is a **crypto inventory**. This tool automates it, then uses Claude to do the part a regex can't: work out what each key actually protects, rank the findings by real exposure, and turn them into a plan.

## How it works

```
repo ──► deterministic scanner ──► findings (file, line, algorithm, risk)
                                         │
                     Claude agent  ◄─────┘
                       tools: scan_repository · list_files · read_file · lookup_guidance · submit_report
                         │
                         ▼
             Markdown migration report (EN/FR), every regulatory claim cited [guidance-id]
```

- **Scanner** (`pqc_agent/rules.py`, `scanner.py`): transparent regex rules for Python, Java, JS/TS, Go, C#, shell, and nginx/OpenSSL/SSH configs. It sorts each finding into one of four buckets:
  - `shor`: quantum-vulnerable, must migrate
  - `classical`: weak today (MD5, SHA-1, DES, TLS < 1.2)
  - `grover`: informational (AES-128)
  - `safe`: ML-KEM / ML-DSA / hybrid already in place
- **Agent** (`pqc_agent/agent.py`): a tool-use loop on the Claude API.
  - It reads files to understand context: whether it's a test key, how long the data is retained, whether the code is a comment or dead code.
  - It prioritises with *harvest-now-decrypt-later* in mind: key exchange and encryption come before signatures.
  - It may only state facts returned by `lookup_guidance`, the curated and cited knowledge base in `pqc_agent/guidance.py`.
  - All file access is sandboxed to the repository.
- **Mosca's inequality**: for each urgent finding, the agent works out *x* (how long the data must stay secret, read from the code) + *y* (estimated migration time) and compares it with *z* (years until a quantum computer can break it) under two scenarios. The z scenarios come from the GRI/evolutionQ 2025 expert survey, with Gidney's 2025 estimate of under a million noisy qubits for RSA-2048 as background. So instead of a vague "urgent", the report says "already exposed" with numbers behind it.
- **Evals** (`evals/`): see below.

## Quick start

```bash
pip3 install -r requirements.txt

# 1. Inventory only (no API key needed)
python3 -m pqc_agent scan examples/demo_repo

# 2. Full agent report
export ANTHROPIC_API_KEY=...
python3 -m pqc_agent report examples/demo_repo --lang fr --out rapport_pqc.md
```

`examples/demo_repo` is a fictional payments API with the kinds of things you find in real code:
- RSA-OAEP key wrapping for 10-year KYC data
- X25519 session keys
- RS256 JWTs
- ECDSA on mobile
- a legacy TLS 1.0 endpoint, MD5 and DES
- a test-only key
- an ML-KEM pilot that is already quantum-safe

## Evaluation

```bash
python3 evals/run_evals.py              # scanner eval, offline
python3 evals/run_evals.py --agent -n 3 # agent rubric eval (needs API key)
python3 tests/test_agent_loop.py        # offline loop test with a scripted fake client
```

**Scanner eval** (`evals/scanner_cases.py`): 43 labelled snippets in 7 languages/config formats, including hard negatives (AES-256, SHA-256, HMAC, bcrypt, TLS 1.2/1.3 configs, hybrid groups like `X25519MLKEM768`).

| precision | recall | F1 | exact match |
|---|---|---|---|
| 97.3% | 100% | 98.6% | 97.7% |

The one known false positive: `createECDH('prime256v1')` also triggers the ECDSA rule, because the curve name alone doesn't say whether it's used for signing or key exchange. That's the kind of call the agent layer is there to make.

*Caveat:* the rules and the cases were written together, so these numbers are optimistic. The next step is a held-out set built from real open-source repos.

**Agent eval** (`evals/run_evals.py --agent`) grades each report against a 27-check rubric:
- **Coverage:** every vulnerable file is mentioned.
- **Prioritisation:**
  - RSA key wrapping and X25519 in Priority 1, ECDSA in Priority 2
  - AES-128 *not* flagged as urgent
  - the test key discounted
- **Classical vs quantum:** MD5/DES and old TLS kept separate from quantum issues.
- **Grounding:**
  - cites NIST IR 8547, ANSSI and the EU roadmap
  - **no hallucinated guidance ids**
  - mentions the 2030/2035 dates
  - has a limitations section
- **Mosca:** has the assessment table, uses the 10-year retention as x, compares both z scenarios, cites the source.

It runs N times to measure consistency, because the agent is non-deterministic. Reports and scores are saved in `evals/runs_<model>/`. Use `python3 evals/run_evals.py --regrade <dir>` to re-score saved reports without API calls.

### Results: Sonnet 5.5 vs Haiku 5.5 (Nov 2026, 3 runs each on `examples/demo_repo`)

| | Sonnet 5.5 | Haiku 5.5 |
|---|---|---|
| Rubric score (27 checks) | 100% / 100% / 100% | 100% / 100% / 100% |
| Turns per run | 3 / 3 / 3 | 4 / 4 / 5 |
| Input tokens per run | 21.5k (identical every run) | 31k / 31k / 54k |
| Output tokens per run | 6.3k – 6.6k | 10.7k / 10.7k / 15.6k |
| Robustness | no failures | once submitted an empty report (ran out of output tokens inside the tool call); now recovered automatically |
| Cost per report | _TBD_ | _TBD_ |

Total spend for all development and eval runs, about 10 full reports: **$0.49**.

What the results show:
- **Both models pass every rubric check, so the rubric has saturated.** It can no longer tell them apart. Next step: a model-graded quality eval.
- **Sonnet was fully consistent.** It read all 11 relevant files and looked up guidance in parallel in a single turn, every run. Its input tokens were identical across runs, so cost is predictable.
- **Haiku is cheaper per token but used 1.5–2.5× more tokens**, needed more turns and varied more between runs. So the cheaper model is not proportionally cheaper.
- **Haiku once ran out of output budget while writing the report inside the tool call.** The agent now detects an empty submission, tells the model why, and asks for a shorter resubmission. Recovered failures are logged in the eval results.
- **Two eval findings came from checking the evals themselves:**
  - A first grader version flagged correct reports that mentioned AES-128 in Priority 1 only to say it was *not* a problem. The check now fails only if a report recommends replacing it.
  - In an early run, the agent spotted a false positive in the scanner (`ssl_ecdh_curve` tagged as ECDSA). That is the deterministic + LLM design working as intended.

## Design choices

- **Deterministic scanner + LLM judgement.** The regex layer is cheap, auditable and doesn't miss obvious cases. The LLM adds context and prioritisation instead of being trusted to find everything.
- **Closed-book regulation.** Getting regulatory facts wrong is costly, so the agent can only cite the curated knowledge base, and the eval checks for invented citations. Updating guidance means editing one file.
- **Hybrid by default**, following ANSSI. The report never recommends replacing classical crypto outright.

## Deploying in an enterprise (not implemented)

Run the scanner in CI on every merge request. Run the agent on a schedule, using Claude through **AWS Bedrock** or **Google Vertex AI** so code stays in the company's cloud tenancy. Push findings to the security team's ticketing system, and feed the inventory into the organisation's CBOM (Cryptographic Bill of Materials).

## Roadmap

- Crypto-agility score: is the algorithm hard-coded or configurable?
- Quantum resource estimates by algorithm (RSA vs ECC), explaining why bigger RSA keys don't help.
- Future module: QKD deployment checks (decoy-state parameter validation), as a separate tool with its own tests, based on my VeriQloud work.
- Held-out scanner eval set built from real open-source repositories.
- Model-graded quality eval (LLM-as-judge), since the rubric now saturates.
- Prompt caching for the system prompt and tool definitions, with a before/after cost comparison.

## Limitations

- Static, line-level pattern matching: crypto hidden behind wrappers, in binaries, HSM configs or third-party services isn't seen.
- The knowledge base was last reviewed in Nov 2026. Guidance changes fast, so check sources before relying on a date.
- Not legal or compliance advice.

## Author

Ruchi Thareja — M2 Quantum Information (Sorbonne Université); research on decoy-state QKD at VeriQloud.

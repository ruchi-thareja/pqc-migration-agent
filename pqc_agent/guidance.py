"""Curated, cited guidance the agent is allowed to rely on.

Summaries are written in our own words. Each entry carries its source URL so
every claim in a generated report can be traced. Keep this file up to date:
it is the agent's only source of regulatory facts (last reviewed Nov 2026).
"""
from __future__ import annotations

GUIDANCE: dict[str, dict] = {
    "nist-fips-203": {
        "title": "NIST FIPS 203 — ML-KEM (Module-Lattice Key-Encapsulation Mechanism)",
        "issuer": "NIST", "date": "2024-08",
        "url": "https://csrc.nist.gov/pubs/fips/203/final",
        "summary": "Standardised post-quantum KEM (derived from CRYSTALS-Kyber). Parameter sets ML-KEM-512/768/1024; ML-KEM-768 is the common default. Replaces RSA key transport and (EC)DH key agreement.",
    },
    "nist-fips-204": {
        "title": "NIST FIPS 204 — ML-DSA (Module-Lattice Digital Signature Algorithm)",
        "issuer": "NIST", "date": "2024-08",
        "url": "https://csrc.nist.gov/pubs/fips/204/final",
        "summary": "Standardised post-quantum signature (derived from CRYSTALS-Dilithium). General-purpose replacement for RSA, ECDSA and EdDSA signatures.",
    },
    "nist-fips-205": {
        "title": "NIST FIPS 205 — SLH-DSA (Stateless Hash-Based Digital Signature Algorithm)",
        "issuer": "NIST", "date": "2024-08",
        "url": "https://csrc.nist.gov/pubs/fips/205/final",
        "summary": "Hash-based signature (derived from SPHINCS+). Conservative security assumptions, larger signatures and slower; suited to firmware/code signing and long-lived roots of trust.",
    },
    "nist-ir-8547": {
        "title": "NIST IR 8547 — Transition to Post-Quantum Cryptography Standards (final)",
        "issuer": "NIST", "date": "2026",
        "url": "https://csrc.nist.gov/pubs/ir/8547/final",
        "summary": "Final transition timeline: all quantum-vulnerable public-key algorithms (RSA, ECDSA, EdDSA, finite-field DH, ECDH, MQV, RSA key establishment) are deprecated after 2030 at every approved security strength and disallowed after 2035. Unlike the 2024 draft, RSA-3072, P-256 and Ed25519 are no longer spared until 2035. 'Deprecated' means still usable only if the data owner accepts the risk. Symmetric primitives (AES, SHA-2/SHA-3) are not on this public-key deprecation schedule.",
    },
    "anssi-hybrid": {
        "title": "ANSSI — position on the PQC transition (2022, 2023 follow-up) and PQC FAQ",
        "issuer": "ANSSI (France)", "date": "2023-12 / FAQ ongoing",
        "url": "https://cyber.gouv.fr/enjeux-technologiques/cryptographie-post-quantique/faq-pqc/",
        "summary": "ANSSI strongly recommends hybridation — combining a post-quantum algorithm with a well-studied classical one — wherever post-quantum protection is needed, in the short and medium term, and advises against drop-in replacement of classical by post-quantum. Priority for products protecting confidentiality beyond 2030 or likely still in use after 2030. ML-KEM is endorsed for key establishment (FrodoKEM as a conservative alternative). ANSSI's PQC recommendations are not, so far, a regulatory obligation.",
    },
    "anssi-tls13": {
        "title": "ANSSI technical sheet — Post-quantum transition of TLS 1.3",
        "issuer": "ANSSI (France)", "date": "2025-2026",
        "url": "https://messervices.cyber.gouv.fr/documents-guides/transition_post_quantique_tls_1_3.pdf",
        "summary": "Guidance for hybrid key exchange and hybrid signature authentication in TLS 1.3. TLS 1.3 is the base for post-quantum migration of web traffic; older TLS versions should be removed first.",
    },
    "anssi-ipsec": {
        "title": "ANSSI technical sheet FT-117 — Post-quantum transition of IPsec",
        "issuer": "ANSSI (France)", "date": "2026-02",
        "url": "https://messervices.cyber.gouv.fr/documents-guides/transition_post_quantique_ipsec.pdf",
        "summary": "Options for IPsec/IKEv2: post-quantum security via pre-shared keys, or hybrid key exchange and hybrid signature authentication.",
    },
    "eu-roadmap": {
        "title": "EU Coordinated Implementation Roadmap for the Transition to PQC (Part 1)",
        "issuer": "EU NIS Cooperation Group / European Commission", "date": "2025-06-23",
        "url": "https://digital-strategy.ec.europa.eu/en/library/coordinated-implementation-roadmap-transition-post-quantum-cryptography",
        "summary": "Follows the Commission's April 2024 PQC Recommendation. Milestones: first steps (inventory, risk assessment, pilots) by end of 2026; high-risk use cases (e.g. critical infrastructure such as energy, health, finance, transport) migrated as soon as possible and no later than end of 2030 — quantum-vulnerable public-key mechanisms should not be used stand-alone there after 2030; medium- and low-risk use cases by 2035.",
    },
    "hndl": {
        "title": "Harvest-now-decrypt-later (prioritisation principle)",
        "issuer": "Common to NIST, ANSSI and EU guidance", "date": "-",
        "url": "https://digital-strategy.ec.europa.eu/en/policies/post-quantum-cryptography",
        "summary": "Encrypted traffic recorded today can be decrypted once a quantum computer exists. Key exchange / encryption protecting data with long confidentiality lifetimes is therefore more urgent than signatures, which only need replacing before a quantum computer can forge them.",
    },
    "grover-symmetric": {
        "title": "Symmetric cryptography and Grover's algorithm",
        "issuer": "NIST IR 8547", "date": "2026",
        "url": "https://csrc.nist.gov/pubs/ir/8547/final",
        "summary": "Grover gives only a quadratic speed-up; AES and SHA-2/SHA-3 are not on NIST's quantum deprecation schedule. AES-128 remains acceptable; AES-256 is a conservative choice for very long-lived secrets. Not a migration priority.",
    },
    "classical-weak": {
        "title": "Classically weak primitives (independent of quantum)",
        "issuer": "General cryptographic practice", "date": "-",
        "url": "https://csrc.nist.gov/projects/hash-functions",
        "summary": "MD5 and SHA-1 have practical collision attacks; DES/3DES/RC4 and TLS < 1.2 are deprecated. These are today's problems, not quantum ones — fix them first, as part of the same crypto-inventory effort.",
    },
    "mosca": {
        "title": "Mosca's inequality (quantum-risk urgency framework)",
        "issuer": "M. Mosca; used in GRI/evolutionQ Quantum Threat Timeline reports", "date": "-",
        "url": "https://globalriskinstitute.org/publication/quantum-threat-timeline-report-2025b/",
        "summary": "Let x = how long the data must stay confidential (shelf-life), y = how long the migration will take, z = years until a cryptographically relevant quantum computer (CRQC) exists. If x + y > z, data protected today with quantum-vulnerable crypto will be exposed before its shelf-life ends: the organisation is already late. Applies to confidentiality (key exchange / encryption); for signatures the relevant x is how long a signature must remain trustworthy.",
    },
    "crqc-timeline": {
        "title": "Estimates of when a CRQC may exist (z in Mosca's inequality)",
        "issuer": "Global Risk Institute & evolutionQ (Quantum Threat Timeline Report 2025); C. Gidney, Google Quantum AI (arXiv:2505.15917)", "date": "2025-2026",
        "url": "https://globalriskinstitute.org/publication/quantum-threat-timeline-report-2025b/",
        "summary": "Expert survey (26 experts): a CRQC is 'quite possible' within 10 years (28-49% averaged probability) and 'likely' within 15 years (51-70%). Resource estimate: Gidney (May 2025, https://arxiv.org/abs/2505.15917) shows RSA-2048 could be factored in under a week with under one million noisy qubits, assuming 0.1% gate error, 1 microsecond surface-code cycle and nearest-neighbour connectivity - a 20x reduction from the 2019 estimate of 20 million qubits. These are estimates with wide uncertainty, not predictions; use z = 10 years as a prudent scenario and z = 15 years as a central scenario.",
    },
}


def lookup(ids_or_query: str | list[str]) -> list[dict]:
    """Return guidance entries by id list, or by keyword search over titles/summaries."""
    if isinstance(ids_or_query, list):
        return [{"id": i, **GUIDANCE[i]} for i in ids_or_query if i in GUIDANCE]
    q = ids_or_query.lower().strip()
    if q in GUIDANCE:
        return [{"id": q, **GUIDANCE[q]}]
    terms = [t for t in q.replace("-", " ").split() if len(t) > 2]
    scored = []
    for k, v in GUIDANCE.items():
        hay = (k + " " + v["title"] + " " + v["summary"]).lower()
        s = sum(hay.count(t) for t in terms)
        if s:
            scored.append((s, k))
    scored.sort(reverse=True)
    return [{"id": k, **GUIDANCE[k]} for _, k in scored[:4]]

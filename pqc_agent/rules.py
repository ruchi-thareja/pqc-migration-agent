"""Detection rules for cryptography usage, grouped by quantum risk.

Each rule is a set of regexes over single source lines. Rules are deliberately
simple and transparent: the deterministic scanner gives the agent a reliable
inventory, and the LLM layer does the judgement (context, priority, migration).

Risk levels
-----------
- "shor"      : public-key crypto broken by a large quantum computer (Shor).
                Must migrate to ML-KEM / ML-DSA / SLH-DSA (hybrid per ANSSI).
- "grover"    : symmetric primitive only weakened by Grover; usually fine,
                informational only.
- "classical" : already weak today, independent of quantum (MD5, SHA-1, DES...).
- "safe"      : post-quantum or hybrid mechanism detected (positive signal).
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field


@dataclass(frozen=True)
class Rule:
    id: str
    algorithm: str
    category: str          # key-exchange | signature | encryption | hash | symmetric | protocol | pqc
    risk: str              # shor | grover | classical | safe
    patterns: tuple[str, ...]
    exclude: tuple[str, ...] = field(default_factory=tuple)
    replacement: str = ""
    guidance: tuple[str, ...] = field(default_factory=tuple)

    def compiled(self):
        return [re.compile(p) for p in self.patterns], [re.compile(p) for p in self.exclude]


# Lines mentioning PQC/hybrid mechanisms: suppress classical findings on the same line
# (e.g. "X25519MLKEM768" is a hybrid group, not a vulnerable X25519 use).
HYBRID_MARKERS = (r"(?i)mlkem|ml-kem|ml_kem|kyber|frodo",)

RULES: tuple[Rule, ...] = (
    # ---------------- Shor-vulnerable public-key ----------------
    Rule(
        id="RSA",
        algorithm="RSA",
        category="encryption/signature",
        risk="shor",
        patterns=(
            r"\brsa\.generate_private_key\b",
            r"\bRSA\.(generate|import_key|importKey|new)\b",
            r"KeyPairGenerator\.getInstance\(\s*\"RSA\"",
            r"Cipher\.getInstance\(\s*\"RSA",
            r"generateKeyPair(Sync)?\(\s*['\"]rsa['\"]",
            r"\brsa\.(GenerateKey|EncryptOAEP|EncryptPKCS1v15|SignPKCS1v15|SignPSS)\b",
            r"\bopenssl\s+genrsa\b",
            r"-newkey\s+rsa:",
            r"\bPKCS1_(OAEP|v1_5)\b",
            r"\bSHA\d+with(RSA|RSAandMGF1)\b",
            r"['\"](RS|PS)(256|384|512)['\"]",
            r"\bRSA_(PKCS1|generate_key)\b",
            r"\bssh-keygen\b.*-t\s+rsa\b",
            r"\bkey_algorithm\s*=\s*['\"]RSA",
            r"\bRSACryptoServiceProvider\b",
            r"\b(EC)?DHE[-_]RSA\b",
            r"\bpadding\.(OAEP|PKCS1v15|PSS)\b",
            r"\bimport\s+RSA\b",
            r"['\"]RSA-OAEP(-256)?['\"]",
        ),
        exclude=HYBRID_MARKERS,
        replacement="ML-KEM (FIPS 203) for encryption/key transport; ML-DSA (FIPS 204) or SLH-DSA (FIPS 205) for signatures — deployed in hybrid mode with the classical algorithm during transition (ANSSI).",
        guidance=("nist-ir-8547", "eu-roadmap", "mosca", "crqc-timeline", "nist-fips-203", "nist-fips-204", "anssi-hybrid"),
    ),
    Rule(
        id="ECDSA",
        algorithm="ECDSA / ECC keys",
        category="signature",
        risk="shor",
        patterns=(
            r"\bec\.generate_private_key\b",
            r"\bec\.ECDSA\b",
            r"\becdsa\.(SigningKey|GenerateKey|Sign|SignASN1|Verify)\b",
            r"KeyPairGenerator\.getInstance\(\s*\"EC\"",
            r"\bSHA\d+withECDSA\b",
            r"generateKeyPair(Sync)?\(\s*['\"]ec['\"]",
            r"\belliptic\.P(224|256|384|521)\(\)",
            r"\b(prime256v1|secp256r1|secp384r1|secp521r1|secp256k1|SECP256R1|SECP384R1|SECP256K1)\b",
            r"['\"]ES(256|384|512)K?['\"]",
            r"-newkey\s+ec\b",
            r"\bopenssl\s+ecparam\b",
            r"\bssh-keygen\b.*-t\s+ecdsa\b",
            r"\bECDsa\b",
        ),
        exclude=HYBRID_MARKERS,
        replacement="ML-DSA (FIPS 204) or SLH-DSA (FIPS 205), in hybrid/composite mode with the classical signature during transition.",
        guidance=("nist-ir-8547", "eu-roadmap", "mosca", "crqc-timeline", "nist-fips-204", "nist-fips-205", "anssi-hybrid"),
    ),
    Rule(
        id="EDDSA",
        algorithm="EdDSA (Ed25519/Ed448)",
        category="signature",
        risk="shor",
        patterns=(
            r"\b[Ee]d(25519|448)\b",
            r"\bed25519\.",
            r"\bEd25519PrivateKey\b",
            r"['\"]EdDSA['\"]",
            r"\bssh-keygen\b.*-t\s+ed25519\b",
        ),
        exclude=HYBRID_MARKERS,
        replacement="ML-DSA (FIPS 204) or SLH-DSA (FIPS 205), hybrid with Ed25519 during transition.",
        guidance=("nist-ir-8547", "eu-roadmap", "mosca", "crqc-timeline", "nist-fips-204", "anssi-hybrid"),
    ),
    Rule(
        id="ECDH",
        algorithm="ECDH / X25519 key exchange",
        category="key-exchange",
        risk="shor",
        patterns=(
            r"\b[Xx](25519|448)\b",
            r"\bx25519\.",
            r"\bX25519PrivateKey\b",
            r"\bec\.ECDH\(\)",
            r"\bECDH\b",
            r"\bcreateECDH\b",
            r"\becdh\.P(256|384|521)\(\)",
            r"\bECDHE[-_]",
            r"\bssl_ecdh_curve\b",
            r"KeyAgreement\.getInstance\(\s*\"(ECDH|XDH|X25519)\"",
        ),
        exclude=HYBRID_MARKERS,
        replacement="Hybrid key exchange X25519MLKEM768 (ML-KEM-768 + X25519) — the urgent priority because of harvest-now-decrypt-later.",
        guidance=("nist-ir-8547", "eu-roadmap", "mosca", "crqc-timeline", "nist-fips-203", "anssi-hybrid", "anssi-tls13", "hndl"),
    ),
    Rule(
        id="DH",
        algorithm="Finite-field Diffie-Hellman",
        category="key-exchange",
        risk="shor",
        patterns=(
            r"\bdh\.generate_parameters\b",
            r"\bcreateDiffieHellman\b",
            r"\bDiffieHellman\b",
            r"KeyPairGenerator\.getInstance\(\s*\"DH\"",
            r"KeyAgreement\.getInstance\(\s*\"DH\"",
            r"\bopenssl\s+dhparam\b",
            r"\bssl_dhparam\b",
            r"\bDHE[-_]RSA\b",
            r"\bmodp(1024|1536|2048|3072|4096)\b",
        ),
        exclude=HYBRID_MARKERS,
        replacement="ML-KEM (FIPS 203) in hybrid mode; for IPsec/IKEv2 follow ANSSI's IPsec transition sheet.",
        guidance=("nist-ir-8547", "eu-roadmap", "mosca", "crqc-timeline", "nist-fips-203", "anssi-hybrid", "anssi-ipsec", "hndl"),
    ),
    Rule(
        id="DSA",
        algorithm="DSA",
        category="signature",
        risk="shor",
        patterns=(
            r"\bdsa\.generate_private_key\b",
            r"KeyPairGenerator\.getInstance\(\s*\"DSA\"",
            r"\bSHA\d+withDSA\b",
            r"\bDSA\.generate\b",
            r"\bssh-keygen\b.*-t\s+dsa\b",
        ),
        exclude=HYBRID_MARKERS,
        replacement="ML-DSA (FIPS 204). DSA is also legacy classically — remove it.",
        guidance=("nist-ir-8547", "eu-roadmap", "mosca", "crqc-timeline", "nist-fips-204"),
    ),
    # ---------------- Classically weak (not a quantum issue) ----------------
    Rule(
        id="MD5",
        algorithm="MD5",
        category="hash",
        risk="classical",
        patterns=(r"\bmd5\b", r"\bMD5\b", r"hashlib\.md5", r"MessageDigest\.getInstance\(\s*\"MD5\""),
        replacement="SHA-256 / SHA-3. Classically broken — fix regardless of quantum.",
        guidance=("classical-weak",),
    ),
    Rule(
        id="SHA1",
        algorithm="SHA-1",
        category="hash",
        risk="classical",
        patterns=(r"hashlib\.sha1\b", r"\bSHA-?1\b(?!\d)", r"MessageDigest\.getInstance\(\s*\"SHA-?1\"", r"createHash\(\s*['\"]sha1['\"]", r"\bsha1\.(New|Sum)\b", r"\bSHA1with"),
        replacement="SHA-256 / SHA-3. Collision attacks exist today.",
        guidance=("classical-weak",),
    ),
    Rule(
        id="WEAK_SYMMETRIC",
        algorithm="DES / 3DES / RC4",
        category="symmetric",
        risk="classical",
        patterns=(r"\b(DESede|TripleDES|3DES|DES3)\b", r"\bDES\.new\b", r"Cipher\.getInstance\(\s*\"DES", r"\bRC4\b", r"\bARC4\b", r"['\"]des-ede3", r"['\"]rc4['\"]"),
        replacement="AES-256-GCM or ChaCha20-Poly1305.",
        guidance=("classical-weak",),
    ),
    Rule(
        id="OLD_TLS",
        algorithm="TLS 1.0 / 1.1 or SSL",
        category="protocol",
        risk="classical",
        patterns=(r"\bTLSv1(\.1)?\b(?!\.[23])", r"\bSSLv[23]\b", r"PROTOCOL_TLSv1(_1)?\b", r"\bTLSv1_(0|1)\b"),
        replacement="TLS 1.3 only (prerequisite for hybrid PQ key exchange).",
        guidance=("anssi-tls13", "classical-weak"),
    ),
    # ---------------- Grover (informational) ----------------
    Rule(
        id="AES128",
        algorithm="AES-128",
        category="symmetric",
        risk="grover",
        patterns=(r"\bAES[-_]?128\b", r"\baes-128-", r"\bAES128\b"),
        replacement="Not urgent: NIST does not deprecate AES-128 for quantum. AES-256 gives extra margin for long-lived secrets.",
        guidance=("grover-symmetric",),
    ),
    # ---------------- Positive signals ----------------
    Rule(
        id="PQC",
        algorithm="Post-quantum / hybrid mechanism",
        category="pqc",
        risk="safe",
        patterns=(
            r"(?i)\bml[-_]?kem",
            r"(?i)\bml[-_]?dsa",
            r"(?i)\bslh[-_]?dsa",
            r"(?i)\bkyber",
            r"(?i)\bdilithium",
            r"(?i)\bsphincs",
            r"(?i)\bfrodokem",
            r"(?i)X25519MLKEM768",
            r"\boqs\.",
        ),
        replacement="Already quantum-safe (check hybrid mode and parameter set).",
        guidance=("nist-fips-203", "nist-fips-204", "anssi-hybrid"),
    ),
)

RULES_BY_ID = {r.id: r for r in RULES}

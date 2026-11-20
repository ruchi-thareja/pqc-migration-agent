"""End-to-end session keys between mobile app and API."""
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

def derive_session_key(peer_public):
    eph = X25519PrivateKey.generate()
    shared = eph.exchange(peer_public)
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"payflow").derive(shared)

"""Pilot: hybrid post-quantum key exchange (ML-KEM-768 + X25519) with liboqs."""
import oqs

def pq_keypair():
    kem = oqs.KeyEncapsulation("ML-KEM-768")
    return kem, kem.generate_keypair()

TLS_GROUPS = "X25519MLKEM768"

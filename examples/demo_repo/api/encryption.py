"""Envelope encryption for customer IBANs and KYC documents (10-year retention)."""
import os
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def encrypt_record(data: bytes, kms_public_key) -> dict:
    dek = AESGCM.generate_key(bit_length=256)          # AES-256-GCM data key
    nonce = os.urandom(12)
    ciphertext = AESGCM(dek).encrypt(nonce, data, None)
    # Wrap the data key with the KMS RSA key
    wrapped = kms_public_key.encrypt(
        dek,
        padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
    )
    return {"ct": ciphertext, "nonce": nonce, "wrapped_dek": wrapped, "alg": "RSA-OAEP-256"}

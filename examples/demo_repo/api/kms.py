from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

def load_kms_key(pem: bytes):
    return PKCS1_OAEP.new(RSA.import_key(pem))

import hashlib
from Crypto.Cipher import DES

def file_fingerprint(path):
    return hashlib.md5(open(path, "rb").read()).hexdigest()

def decrypt_archive(key, blob):
    return DES.new(key, DES.MODE_ECB).decrypt(blob)

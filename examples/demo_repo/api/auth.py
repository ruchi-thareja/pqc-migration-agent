"""JWT authentication for the PayFlow API."""
import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

# Signing key for access tokens (rotated yearly)
_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

def issue_token(user_id: str) -> str:
    return jwt.encode({"sub": user_id}, _private_key, algorithm="RS256")

def verify_token(token: str, public_key) -> dict:
    return jwt.decode(token, public_key, algorithms=["RS256"])

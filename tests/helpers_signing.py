# SPDX-License-Identifier: PolyForm-Shield-1.0.0
"""TEST-ONLY Ed25519 helpers. The real signing service lives in the private control-plane repo."""
import base64
import json

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def generate():
    key = Ed25519PrivateKey.generate()
    priv = key.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
    pub = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return base64.b64encode(priv).decode(), base64.b64encode(pub).decode()


def sign_message(message: dict, private_b64: str, kid: str) -> dict:
    key = Ed25519PrivateKey.from_private_bytes(base64.b64decode(private_b64))
    body = {**{k: v for k, v in message.items() if k not in ("sig", "kid")}, "kid": kid}
    raw = key.sign(json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode())
    return {**body, "sig": "ed25519:" + base64.b64encode(raw).decode()}

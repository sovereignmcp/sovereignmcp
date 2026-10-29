# SPDX-License-Identifier: PolyForm-Shield-1.0.0
"""Generate a DEV Ed25519 keypair for trying cloud mode with examples/mock_cloud.py.
Production keys are made and held by your control plane (KMS), never by this script."""
import base64

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

key = Ed25519PrivateKey.generate()
priv = key.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
pub = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
print("MOCK_SIGNING_KEY (mock cloud only):\n  " + base64.b64encode(priv).decode())
print("\nSOVEREIGN_CLOUD_PUBKEYS (set on the gateway):\n  k1:" + base64.b64encode(pub).decode())

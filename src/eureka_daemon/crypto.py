import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.exceptions import InvalidSignature
import json
import base64

class EurekaCrypto:
    """
    Handles Ed25519 identity generation, signing, and verification 
    for the Eureka Protocol.
    """
    def __init__(self, private_key_hex=None):
        if private_key_hex:
            self.private_key = ed25519.Ed25519PrivateKey.from_private_bytes(
                bytes.fromhex(private_key_hex)
            )
        else:
            self.private_key = ed25519.Ed25519PrivateKey.generate()
        
        self.public_key = self.private_key.public_key()
        self.public_key_bytes = self.public_key.public_bytes_raw()
        self.private_key_bytes = self.private_key.private_bytes_raw()

    def get_public_key_hex(self):
        return self.public_key_bytes.hex()

    def sign_data(self, data: bytes) -> str:
        """Signs bytes and returns a base64 encoded signature."""
        signature = self.private_key.sign(data)
        return base64.b64encode(signature).decode('utf-8')

    @staticmethod
    def verify_signature(public_key_hex: str, signature_base64: str, data: bytes) -> bool:
        """Verifies a base64 encoded signature against a hex public key."""
        try:
            pub_key = ed25519.Ed25519PublicKey.from_public_bytes(
                bytes.fromhex(public_key_hex)
            )
            signature = base64.b64decode(signature_base64)
            pub_key.verify(signature, data)
            return True
        except (InvalidSignature, Exception):
            return False

    def sign_json(self, payload: dict) -> str:
        """Helper to sign a JSON-serializable dictionary."""
        canonical_data = json.dumps(payload, sort_keys=True).encode('utf-8')
        return self.sign_data(canonical_data)

    @staticmethod
    def verify_json(public_key_hex: str, signature_base64: str, payload: dict) -> bool:
        """Helper to verify a signature against a JSON dictionary."""
        canonical_data = json.dumps(payload, sort_keys=True).encode('utf-8')
        return EurekaCrypto.verify_signature(public_key_hex, signature_base64, canonical_data)

if __name__ == "__main__":
    # Quick unit test for the crypto module
    crypto = EurekaCrypto()
    msg = b"Eureka Protocol Handshake Test"
    sig = crypto.sign_data(msg)
    print(f"Public Key: {crypto.get_public_key_hex()}")
    print(f"Signature: {sig}")
    is_valid = EurekaCrypto.verify_signature(crypto.get_public_key_hex(), sig, msg)
    print(f"Verification Success: {is_valid}")

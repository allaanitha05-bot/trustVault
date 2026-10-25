import os
import json
import hashlib
import base64
from typing import Dict, Any, Tuple
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Master key derivation or fallback 32-byte key
DEFAULT_MASTER_KEY = b"TrustVault-AES256-SecretKey-2026!" # 32 bytes

def derive_tenant_key(tenant_id: str, master_key: bytes = DEFAULT_MASTER_KEY) -> bytes:
    """
    Derives a unique 256-bit AES key per tenant using SHA-256.
    Ensures cryptographic isolation across tenants.
    """
    h = hashlib.sha256()
    h.update(master_key)
    h.update(tenant_id.encode("utf-8"))
    return h.digest()

def encrypt_file_data(data: bytes, tenant_id: str) -> Tuple[bytes, str]:
    """
    Encrypts file data using AES-256-GCM.
    Returns:
        (encrypted_bytes_with_nonce, sha256_checksum_of_plaintext)
    """
    key = derive_tenant_key(tenant_id)
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)  # 96-bit nonce for AES-GCM
    ciphertext = aesgcm.encrypt(nonce, data, associated_data=tenant_id.encode("utf-8"))
    
    # Prepend 12-byte nonce to ciphertext
    encrypted_payload = nonce + ciphertext
    plaintext_sha256 = hashlib.sha256(data).hexdigest()
    
    return encrypted_payload, plaintext_sha256

def decrypt_file_data(encrypted_payload: bytes, tenant_id: str) -> bytes:
    """
    Decrypts AES-256-GCM encrypted file payload with tenant key and nonce.
    """
    if len(encrypted_payload) < 28: # 12 bytes nonce + 16 bytes GCM tag
        raise ValueError("Payload is corrupted or too short")
        
    nonce = encrypted_payload[:12]
    ciphertext = encrypted_payload[12:]
    key = derive_tenant_key(tenant_id)
    aesgcm = AESGCM(key)
    
    decrypted_data = aesgcm.decrypt(nonce, ciphertext, associated_data=tenant_id.encode("utf-8"))
    return decrypted_data

def hash_passcode(passcode: str, salt: str = "tv_salt_") -> str:
    """Hashes a share passcode using salted SHA-256."""
    return hashlib.sha256(f"{salt}{passcode}".encode("utf-8")).hexdigest()

def verify_passcode(passcode: str, hashed: str, salt: str = "tv_salt_") -> bool:
    """Verifies a share passcode against its hash."""
    return hash_passcode(passcode, salt) == hashed

def compute_audit_hash(
    prev_hash: str,
    index: int,
    timestamp: str,
    tenant_id: str,
    actor_id: str,
    action: str,
    resource_id: str,
    details: Dict[str, Any]
) -> str:
    """
    Computes canonical SHA-256 hash for an audit record, enforcing hash-chain integrity.
    H_i = SHA-256(prev_hash || index || timestamp || tenant_id || actor_id || action || resource_id || canonical_json(details))
    """
    canonical_details = json.dumps(details, sort_keys=True, separators=(',', ':'))
    payload = f"{prev_hash}|{index}|{timestamp}|{tenant_id}|{actor_id}|{action}|{resource_id}|{canonical_details}"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()

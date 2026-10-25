import os
import unittest
import gc
from pathlib import Path

from app.crypto import (
    encrypt_file_data, decrypt_file_data,
    hash_passcode, verify_passcode, compute_audit_hash
)
from app.models import ActionType, Classification, Role
from app.rbac import has_permission, require_permission
from app.storage import StorageManager, GENESIS_HASH

class TestTrustVaultCore(unittest.TestCase):

    def setUp(self):
        self.test_db = Path("data/test_tv_suite.db")
        self.test_blobs = Path("data/test_tv_blobs")
        if self.test_db.exists():
            self.test_db.unlink(missing_ok=True)
        self.mgr = StorageManager(db_path=self.test_db, blob_dir=self.test_blobs)

    def tearDown(self):
        del self.mgr
        gc.collect()
        try:
            self.test_db.unlink(missing_ok=True)
            for f in self.test_blobs.glob("*"):
                f.unlink(missing_ok=True)
            self.test_blobs.rmdir()
        except Exception:
            pass

    def test_aes_256_gcm_encryption_and_tenant_isolation(self):
        """Verifies AES-256-GCM encryption, decryption, and tenant key isolation."""
        secret_data = b"CONFIDENTIAL FINANCIAL RECORD Q3: $42,500,000 EBITDA"
        tenant_a = "tenant-acme"
        tenant_b = "tenant-cyber"

        # Encrypt for Tenant A
        encrypted_payload, checksum = encrypt_file_data(secret_data, tenant_a)
        self.assertGreater(len(encrypted_payload), len(secret_data))
        self.assertIsNotNone(checksum)

        # Decrypt with Tenant A -> Success
        decrypted = decrypt_file_data(encrypted_payload, tenant_a)
        self.assertEqual(decrypted, secret_data)

        # Decrypt with Tenant B -> MUST FAIL (cryptographic tenant isolation)
        with self.assertRaises(Exception):
            decrypt_file_data(encrypted_payload, tenant_b)

    def test_passcode_protection(self):
        """Verifies passcode hashing and validation."""
        code = "UltraSecretVaultPass2026!"
        hashed = hash_passcode(code)
        self.assertTrue(verify_passcode(code, hashed))
        self.assertFalse(verify_passcode("WrongPassword", hashed))

    def test_audit_hash_chain_and_tamper_detection(self):
        """Verifies that tampering with an audit block breaks the cryptographic chain."""
        tenant_id = "tenant-test"
        self.mgr._ensure_genesis_block(tenant_id)

        # Initial chain verification -> Valid
        initial_check = self.mgr.verify_ledger_integrity(tenant_id)
        self.assertTrue(initial_check.is_valid)
        self.assertEqual(initial_check.total_records, 1)

        # Append 2 audit records
        self.mgr.append_audit_log(
            tenant_id=tenant_id,
            actor_id="user-1",
            actor_name="Test User 1",
            actor_role="ADMIN",
            action=ActionType.DOC_UPLOAD,
            resource_id="doc-1",
            resource_name="spec.pdf",
            ip_address="10.0.0.1",
            user_agent="unittest",
            details={"size": 1024}
        )

        self.mgr.append_audit_log(
            tenant_id=tenant_id,
            actor_id="user-2",
            actor_name="Test User 2",
            actor_role="COMPLIANCE_OFFICER",
            action=ActionType.DOC_VIEW,
            resource_id="doc-1",
            resource_name="spec.pdf",
            ip_address="10.0.0.2",
            user_agent="unittest",
            details={"mode": "preview"}
        )

        # Verify chain with 3 records
        check_3 = self.mgr.verify_ledger_integrity(tenant_id)
        self.assertTrue(check_3.is_valid)
        self.assertEqual(check_3.total_records, 3)

        # Simulate a raw database tampering attack
        tampered_idx = self.mgr.simulate_tampering_for_demo(tenant_id)
        self.assertIsNotNone(tampered_idx)

        # Verify ledger -> MUST DETECT TAMPERING!
        tamper_check = self.mgr.verify_ledger_integrity(tenant_id)
        self.assertFalse(tamper_check.is_valid)
        self.assertEqual(tamper_check.tampered_index, tampered_idx)

        # Repair ledger -> Restores validity
        self.mgr.repair_tampering_for_demo(tenant_id)
        repair_check = self.mgr.verify_ledger_integrity(tenant_id)
        self.assertTrue(repair_check.is_valid)

    def test_document_lifecycle_and_shares(self):
        """Tests uploading, reading, sharing, and revoking a document."""
        tenant_id = "tenant-acme"
        content = b"TOP SECRET: Propulsion blueprint v1"
        
        doc = self.mgr.save_document(
            tenant_id=tenant_id,
            filename="blueprint.txt",
            mime_type="text/plain",
            data=content,
            classification=Classification.TOP_SECRET,
            tags=["defense", "propulsion"],
            actor_id="user-acme-admin",
            actor_name="Alice Sterling"
        )
        self.assertEqual(doc.filename, "blueprint.txt")
        self.assertEqual(doc.file_size, len(content))

        # Read document bytes back (decryption verification)
        decrypted_bytes, meta = self.mgr.read_document_bytes(doc.id, tenant_id)
        self.assertEqual(decrypted_bytes, content)
        self.assertEqual(meta.id, doc.id)

        # Create time-limited share
        share = self.mgr.create_share_link(
            tenant_id=tenant_id,
            document_id=doc.id,
            document_name=doc.filename,
            created_by_id="user-acme-admin",
            created_by_name="Alice Sterling",
            expires_at=None,
            max_views=5,
            allow_download=False,
            passcode="Passcode123"
        )
        self.assertTrue(share.has_password)
        self.assertFalse(share.allow_download)

        # Retrieve by token
        fetched = self.mgr.get_share_by_token(share.token)
        self.assertIsNotNone(fetched)
        self.assertEqual(fetched.id, share.id)

        # Increment views
        new_views = self.mgr.increment_share_views(share.id)
        self.assertEqual(new_views, 1)

        # Revoke share
        revoked = self.mgr.revoke_share(share.id, tenant_id)
        self.assertTrue(revoked)
        revoked_share = self.mgr.get_share_by_token(share.token)
        self.assertTrue(revoked_share.is_revoked)

    def test_rbac_policies(self):
        """Tests RBAC permission rules across all 4 built-in roles."""
        # Admin has full privileges
        self.assertTrue(has_permission(Role.ADMIN, "CAN_UPLOAD_DOC"))
        self.assertTrue(has_permission(Role.ADMIN, "CAN_DELETE_DOC"))
        self.assertTrue(has_permission(Role.ADMIN, "CAN_CREATE_SHARE"))
        self.assertTrue(has_permission(Role.ADMIN, "CAN_VIEW_AUDIT_LOGS"))
        self.assertTrue(has_permission(Role.ADMIN, "CAN_VERIFY_AUDIT_CHAIN"))
        self.assertTrue(has_permission(Role.ADMIN, "CAN_SIMULATE_TAMPER"))

        # Compliance Officer: Audit & verify allowed, upload denied
        self.assertTrue(has_permission(Role.COMPLIANCE_OFFICER, "CAN_VIEW_AUDIT_LOGS"))
        self.assertTrue(has_permission(Role.COMPLIANCE_OFFICER, "CAN_VERIFY_AUDIT_CHAIN"))
        self.assertFalse(has_permission(Role.COMPLIANCE_OFFICER, "CAN_UPLOAD_DOC"))
        self.assertFalse(has_permission(Role.COMPLIANCE_OFFICER, "CAN_CREATE_SHARE"))

        # Document Manager: Upload & share allowed, audit view denied
        self.assertTrue(has_permission(Role.DOCUMENT_MANAGER, "CAN_UPLOAD_DOC"))
        self.assertTrue(has_permission(Role.DOCUMENT_MANAGER, "CAN_CREATE_SHARE"))
        self.assertFalse(has_permission(Role.DOCUMENT_MANAGER, "CAN_VIEW_AUDIT_LOGS"))

        # Viewer: Read-only, upload and audit denied
        self.assertTrue(has_permission(Role.VIEWER, "CAN_VIEW_DOC"))
        self.assertFalse(has_permission(Role.VIEWER, "CAN_UPLOAD_DOC"))
        self.assertFalse(has_permission(Role.VIEWER, "CAN_VIEW_AUDIT_LOGS"))


if __name__ == "__main__":
    unittest.main()

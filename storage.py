import os
import json
import sqlite3
import uuid
from datetime import datetime, timezone
from typing import List, Optional, Tuple, Dict, Any
from pathlib import Path

from app.models import (
    Tenant, User, Role, Classification, DocumentMetadata,
    ShareLink, AuditRecord, ActionType, AuditVerificationResult
)
from app.crypto import (
    encrypt_file_data, decrypt_file_data, compute_audit_hash,
    hash_passcode, verify_passcode
)

DB_PATH = Path("data/trustvault.db")
BLOB_DIR = Path("data/vault/encrypted_blobs")
GENESIS_HASH = "0" * 64

class StorageManager:
    def __init__(self, db_path: Path = DB_PATH, blob_dir: Path = BLOB_DIR):
        self.db_path = db_path
        self.blob_dir = blob_dir
        self.blob_dir.mkdir(parents=True, exist_ok=True)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()
        self._seed_initial_data()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path), timeout=15)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self):
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS tenants (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                description TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
            """)
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id TEXT PRIMARY KEY,
                tenant_id TEXT NOT NULL,
                email TEXT NOT NULL,
                full_name TEXT NOT NULL,
                role TEXT NOT NULL,
                avatar_color TEXT NOT NULL,
                FOREIGN KEY (tenant_id) REFERENCES tenants (id)
            )
            """)
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS documents (
                id TEXT PRIMARY KEY,
                tenant_id TEXT NOT NULL,
                filename TEXT NOT NULL,
                original_name TEXT NOT NULL,
                mime_type TEXT NOT NULL,
                file_size INTEGER NOT NULL,
                classification TEXT NOT NULL,
                tags TEXT NOT NULL,
                plaintext_sha256 TEXT NOT NULL,
                storage_path TEXT NOT NULL,
                uploaded_by_id TEXT NOT NULL,
                uploaded_by_name TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                FOREIGN KEY (tenant_id) REFERENCES tenants (id)
            )
            """)
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS share_links (
                id TEXT PRIMARY KEY,
                token TEXT UNIQUE NOT NULL,
                tenant_id TEXT NOT NULL,
                document_id TEXT NOT NULL,
                document_name TEXT NOT NULL,
                created_by_id TEXT NOT NULL,
                created_by_name TEXT NOT NULL,
                created_at TEXT NOT NULL,
                expires_at TEXT,
                max_views INTEGER,
                current_views INTEGER DEFAULT 0,
                allow_download INTEGER DEFAULT 1,
                is_revoked INTEGER DEFAULT 0,
                has_password INTEGER DEFAULT 0,
                passcode_hash TEXT,
                FOREIGN KEY (tenant_id) REFERENCES tenants (id),
                FOREIGN KEY (document_id) REFERENCES documents (id)
            )
            """)
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS audit_records (
                index_num INTEGER NOT NULL,
                id TEXT PRIMARY KEY,
                timestamp TEXT NOT NULL,
                tenant_id TEXT NOT NULL,
                actor_id TEXT NOT NULL,
                actor_name TEXT NOT NULL,
                actor_role TEXT NOT NULL,
                action TEXT NOT NULL,
                resource_id TEXT NOT NULL,
                resource_name TEXT NOT NULL,
                ip_address TEXT NOT NULL,
                user_agent TEXT NOT NULL,
                details TEXT NOT NULL,
                prev_hash TEXT NOT NULL,
                hash TEXT NOT NULL,
                FOREIGN KEY (tenant_id) REFERENCES tenants (id)
            )
            """)
            conn.commit()

    def _seed_initial_data(self):
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM tenants")
            if cursor.fetchone()[0] == 0:
                # Tenants
                now = datetime.now(timezone.utc).isoformat()
                tenants = [
                    ("tenant-acme", "Acme Aerospace Corp", "Defense & commercial avionics documentation", now),
                    ("tenant-cyber", "CyberShield Global", "Cybersecurity compliance & incident disclosures", now),
                    ("tenant-fintech", "Apex Financial Group", "Mergers, acquisitions & financial audits", now)
                ]
                cursor.executemany("INSERT INTO tenants VALUES (?, ?, ?, ?)", tenants)

                # Users
                users = [
                    # Acme Users
                    ("user-acme-admin", "tenant-acme", "alice.admin@acme.com", "Alice Sterling", "ADMIN", "#4f46e5"),
                    ("user-acme-comp", "tenant-acme", "bob.compliance@acme.com", "Bob Vance", "COMPLIANCE_OFFICER", "#059669"),
                    ("user-acme-mgr", "tenant-acme", "charlie.pm@acme.com", "Charlie Hayes", "DOCUMENT_MANAGER", "#d97706"),
                    ("user-acme-view", "tenant-acme", "diana.audit@acme.com", "Diana Prince", "VIEWER", "#64748b"),

                    # CyberShield Users
                    ("user-cyber-admin", "tenant-cyber", "elena.sec@cybershield.io", "Elena Rostova", "ADMIN", "#dc2626"),
                    ("user-cyber-mgr", "tenant-cyber", "marcus.ops@cybershield.io", "Marcus Reed", "DOCUMENT_MANAGER", "#7c3aed"),
                ]
                cursor.executemany("INSERT INTO users VALUES (?, ?, ?, ?, ?, ?)", users)
                conn.commit()

        # Initialize Genesis blocks for seeded tenants
        for t_id in ["tenant-acme", "tenant-cyber", "tenant-fintech"]:
            self._ensure_genesis_block(t_id)

        # Seed sample documents for demonstration
        self._seed_sample_documents()

    def _ensure_genesis_block(self, tenant_id: str):
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM audit_records WHERE tenant_id = ?", (tenant_id,))
            if cursor.fetchone()[0] == 0:
                now = datetime.now(timezone.utc).isoformat()
                rec_id = f"audit-genesis-{tenant_id}"
                details = {"event": "Genesis Block Initialized", "system": "TrustVault 1.0"}
                h = compute_audit_hash(
                    prev_hash=GENESIS_HASH,
                    index=0,
                    timestamp=now,
                    tenant_id=tenant_id,
                    actor_id="SYSTEM",
                    action="AUDIT_VERIFY",
                    resource_id=tenant_id,
                    details=details
                )
                cursor.execute("""
                INSERT INTO audit_records 
                (index_num, id, timestamp, tenant_id, actor_id, actor_name, actor_role, action, resource_id, resource_name, ip_address, user_agent, details, prev_hash, hash)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    0, rec_id, now, tenant_id, "SYSTEM", "TrustVault System", "SYSTEM",
                    "AUDIT_VERIFY", tenant_id, "Cryptographic Ledger Genesis", "127.0.0.1", "Internal",
                    json.dumps(details), GENESIS_HASH, h
                ))
                conn.commit()

    def _seed_sample_documents(self):
        should_seed = False
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM documents WHERE tenant_id = 'tenant-acme'")
            if cursor.fetchone()[0] == 0:
                should_seed = True
                sample_text = (
                    "ACME AEROSPACE CORPORATION - CONFIDENTIAL PROJECT BLUEPRINT\n"
                    "==========================================================\n"
                    "Project: HyperSonic Sub-orbital Propulsion Architecture v4.2\n"
                    "Security Classification: TOP SECRET // COMPLIANCE STRICT\n"
                    "Status: Active Patent Verification\n\n"
                    "1. EXECUTIVE OVERVIEW\n"
                    "This document contains proprietary mathematical and thermal barrier\n"
                    "specifications for cryogenic propulsion turbines. Unauthorized\n"
                    "distribution, mirroring, or extraction is strictly prohibited under\n"
                    "federal and international defense trade regulations.\n\n"
                    "2. ENCRYPTION SPECIFICATIONS\n"
                    "- Data at Rest: AES-256-GCM hardware accelerated\n"
                    "- Key Derivation: Tenant-scoped PBKDF2/SHA256\n"
                    "- Audit Chaining: SHA-256 linear Merkle ledger\n"
                    "- Dynamic Watermarking: Enforced on all external previews\n\n"
                    "3. REVISION HISTORY & COMPLIANCE SIGN-OFF\n"
                    "- Rev 4.2 Approved by Dr. H. Vance (Chief Propulsion Engineer)\n"
                    "- Compliance Verified by Bob Vance (ISO-27001 Auditor)\n"
                ).encode("utf-8")

                encrypted_blob, sha256_hash = encrypt_file_data(sample_text, "tenant-acme")
                doc_id = "doc-acme-sample-01"
                storage_filename = f"{doc_id}.enc"
                blob_path = self.blob_dir / storage_filename
                blob_path.write_bytes(encrypted_blob)

                now = datetime.now(timezone.utc).isoformat()
                cursor.execute("""
                INSERT INTO documents VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    doc_id, "tenant-acme", "Hypersonic_Propulsion_v4.2.txt", "Hypersonic_Propulsion_v4.2.txt",
                    "text/plain", len(sample_text), "TOP_SECRET",
                    json.dumps(["engineering", "propulsion", "classified"]),
                    sha256_hash, str(blob_path), "user-acme-admin", "Alice Sterling", now, now
                ))
                conn.commit()

        # Append audit log OUTSIDE the connection block to prevent SQLite nested transaction deadlocks
        if should_seed:
            self.append_audit_log(
                tenant_id="tenant-acme",
                actor_id="user-acme-admin",
                actor_name="Alice Sterling",
                actor_role="ADMIN",
                action=ActionType.DOC_UPLOAD,
                resource_id=doc_id,
                resource_name="Hypersonic_Propulsion_v4.2.txt",
                ip_address="192.168.1.104",
                user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
                details={"file_size": len(sample_text), "classification": "TOP_SECRET", "sha256": sha256_hash}
            )

    # ------------------ TENANTS & USERS ------------------
    def get_tenants(self) -> List[Tenant]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM tenants ORDER BY name ASC")
            return [Tenant(**dict(row)) for row in cursor.fetchall()]

    def get_tenant(self, tenant_id: str) -> Optional[Tenant]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM tenants WHERE id = ?", (tenant_id,))
            row = cursor.fetchone()
            return Tenant(**dict(row)) if row else None

    def get_users_by_tenant(self, tenant_id: str) -> List[User]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM users WHERE tenant_id = ?", (tenant_id,))
            return [User(**dict(row)) for row in cursor.fetchall()]

    def get_user(self, user_id: str) -> Optional[User]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
            row = cursor.fetchone()
            return User(**dict(row)) if row else None

    # ------------------ DOCUMENTS ------------------
    def list_documents(self, tenant_id: str) -> List[DocumentMetadata]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM documents WHERE tenant_id = ? ORDER BY created_at DESC", (tenant_id,))
            results = []
            for row in cursor.fetchall():
                d = dict(row)
                d["tags"] = json.loads(d["tags"])
                results.append(DocumentMetadata(**d))
            return results

    def get_document(self, document_id: str, tenant_id: str) -> Optional[DocumentMetadata]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM documents WHERE id = ? AND tenant_id = ?", (document_id, tenant_id))
            row = cursor.fetchone()
            if not row:
                return None
            d = dict(row)
            d["tags"] = json.loads(d["tags"])
            return DocumentMetadata(**d)

    def save_document(
        self,
        tenant_id: str,
        filename: str,
        mime_type: str,
        data: bytes,
        classification: Classification,
        tags: List[str],
        actor_id: str,
        actor_name: str
    ) -> DocumentMetadata:
        doc_id = f"doc-{uuid.uuid4().hex[:12]}"
        now = datetime.now(timezone.utc).isoformat()
        
        # Encrypt with AES-256-GCM
        encrypted_payload, sha256_hash = encrypt_file_data(data, tenant_id)
        storage_filename = f"{doc_id}.enc"
        blob_path = self.blob_dir / storage_filename
        blob_path.write_bytes(encrypted_payload)

        doc_meta = DocumentMetadata(
            id=doc_id,
            tenant_id=tenant_id,
            filename=filename,
            original_name=filename,
            mime_type=mime_type or "application/octet-stream",
            file_size=len(data),
            classification=classification,
            tags=tags,
            plaintext_sha256=sha256_hash,
            storage_path=str(blob_path),
            uploaded_by_id=actor_id,
            uploaded_by_name=actor_name,
            created_at=now,
            updated_at=now
        )

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
            INSERT INTO documents VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                doc_meta.id, doc_meta.tenant_id, doc_meta.filename, doc_meta.original_name,
                doc_meta.mime_type, doc_meta.file_size, doc_meta.classification.value,
                json.dumps(doc_meta.tags), doc_meta.plaintext_sha256, doc_meta.storage_path,
                doc_meta.uploaded_by_id, doc_meta.uploaded_by_name, doc_meta.created_at, doc_meta.updated_at
            ))
            conn.commit()

        return doc_meta

    def read_document_bytes(self, document_id: str, tenant_id: str) -> Tuple[bytes, DocumentMetadata]:
        doc = self.get_document(document_id, tenant_id)
        if not doc:
            raise ValueError("Document not found or access denied")
        blob_path = Path(doc.storage_path)
        if not blob_path.exists():
            raise FileNotFoundError("Underlying encrypted payload is missing from vault")
        
        encrypted_payload = blob_path.read_bytes()
        decrypted_bytes = decrypt_file_data(encrypted_payload, tenant_id)
        return decrypted_bytes, doc

    def delete_document(self, document_id: str, tenant_id: str) -> bool:
        doc = self.get_document(document_id, tenant_id)
        if not doc:
            return False
        
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM share_links WHERE document_id = ? AND tenant_id = ?", (document_id, tenant_id))
            cursor.execute("DELETE FROM documents WHERE id = ? AND tenant_id = ?", (document_id, tenant_id))
            conn.commit()

        # Delete physical blob file
        try:
            Path(doc.storage_path).unlink(missing_ok=True)
        except Exception:
            pass
        return True

    # ------------------ SHARES ------------------
    def create_share_link(
        self,
        tenant_id: str,
        document_id: str,
        document_name: str,
        created_by_id: str,
        created_by_name: str,
        expires_at: Optional[str] = None,
        max_views: Optional[int] = None,
        allow_download: bool = True,
        passcode: Optional[str] = None
    ) -> ShareLink:
        share_id = f"share-{uuid.uuid4().hex[:12]}"
        token = uuid.uuid4().hex
        now = datetime.now(timezone.utc).isoformat()
        has_password = bool(passcode and passcode.strip())
        passcode_hash = hash_passcode(passcode.strip()) if has_password else None

        share = ShareLink(
            id=share_id,
            token=token,
            tenant_id=tenant_id,
            document_id=document_id,
            document_name=document_name,
            created_by_id=created_by_id,
            created_by_name=created_by_name,
            created_at=now,
            expires_at=expires_at,
            max_views=max_views,
            current_views=0,
            allow_download=allow_download,
            is_revoked=False,
            has_password=has_password,
            passcode_hash=passcode_hash
        )

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
            INSERT INTO share_links VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                share.id, share.token, share.tenant_id, share.document_id, share.document_name,
                share.created_by_id, share.created_by_name, share.created_at, share.expires_at,
                share.max_views, share.current_views, 1 if share.allow_download else 0,
                0, 1 if share.has_password else 0, share.passcode_hash
            ))
            conn.commit()

        return share

    def list_shares(self, tenant_id: str) -> List[ShareLink]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM share_links WHERE tenant_id = ? ORDER BY created_at DESC", (tenant_id,))
            results = []
            for row in cursor.fetchall():
                d = dict(row)
                d["allow_download"] = bool(d["allow_download"])
                d["is_revoked"] = bool(d["is_revoked"])
                d["has_password"] = bool(d["has_password"])
                results.append(ShareLink(**d))
            return results

    def get_share_by_token(self, token: str) -> Optional[ShareLink]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM share_links WHERE token = ?", (token,))
            row = cursor.fetchone()
            if not row:
                return None
            d = dict(row)
            d["allow_download"] = bool(d["allow_download"])
            d["is_revoked"] = bool(d["is_revoked"])
            d["has_password"] = bool(d["has_password"])
            return ShareLink(**d)

    def revoke_share(self, share_id: str, tenant_id: str) -> bool:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("UPDATE share_links SET is_revoked = 1 WHERE id = ? AND tenant_id = ?", (share_id, tenant_id))
            conn.commit()
            return cursor.rowcount > 0

    def increment_share_views(self, share_id: str) -> int:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("UPDATE share_links SET current_views = current_views + 1 WHERE id = ?", (share_id,))
            conn.commit()
            cursor.execute("SELECT current_views FROM share_links WHERE id = ?", (share_id,))
            row = cursor.fetchone()
            return row[0] if row else 0

    # ------------------ CRYPTOGRAPHIC AUDIT TRAIL ------------------
    def append_audit_log(
        self,
        tenant_id: str,
        actor_id: str,
        actor_name: str,
        actor_role: str,
        action: ActionType,
        resource_id: str,
        resource_name: str,
        ip_address: str,
        user_agent: str,
        details: Dict[str, Any]
    ) -> AuditRecord:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            # Fetch the latest record for this tenant
            cursor.execute("""
            SELECT index_num, hash FROM audit_records 
            WHERE tenant_id = ? 
            ORDER BY index_num DESC LIMIT 1
            """, (tenant_id,))
            last_record = cursor.fetchone()
            
            if last_record:
                next_index = last_record["index_num"] + 1
                prev_hash = last_record["hash"]
            else:
                next_index = 0
                prev_hash = GENESIS_HASH

            now = datetime.now(timezone.utc).isoformat()
            record_id = f"audit-{uuid.uuid4().hex[:12]}"
            
            action_val = action.value if hasattr(action, "value") else str(action)
            action_enum = ActionType(action_val) if action_val in ActionType.__members__.values() else ActionType.DOC_VIEW

            # Cryptographic hash chaining: H_i = SHA-256(prev_hash || index || timestamp || ...)
            computed_hash = compute_audit_hash(
                prev_hash=prev_hash,
                index=next_index,
                timestamp=now,
                tenant_id=tenant_id,
                actor_id=actor_id,
                action=action_val,
                resource_id=resource_id,
                details=details
            )

            record = AuditRecord(
                index=next_index,
                id=record_id,
                timestamp=now,
                tenant_id=tenant_id,
                actor_id=actor_id,
                actor_name=actor_name,
                actor_role=actor_role,
                action=action_enum,
                resource_id=resource_id,
                resource_name=resource_name,
                ip_address=ip_address,
                user_agent=user_agent,
                details=details,
                prev_hash=prev_hash,
                hash=computed_hash
            )

            cursor.execute("""
            INSERT INTO audit_records 
            (index_num, id, timestamp, tenant_id, actor_id, actor_name, actor_role, action, resource_id, resource_name, ip_address, user_agent, details, prev_hash, hash)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                record.index, record.id, record.timestamp, record.tenant_id,
                record.actor_id, record.actor_name, record.actor_role, action_val,
                record.resource_id, record.resource_name, record.ip_address, record.user_agent,
                json.dumps(record.details), record.prev_hash, record.hash
            ))
            conn.commit()
            return record

    def get_audit_trail(self, tenant_id: str, limit: int = 100) -> List[AuditRecord]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
            SELECT * FROM audit_records 
            WHERE tenant_id = ? 
            ORDER BY index_num DESC LIMIT ?
            """, (tenant_id, limit))
            results = []
            for row in cursor.fetchall():
                d = dict(row)
                d["index"] = d.pop("index_num")
                d["details"] = json.loads(d["details"])
                results.append(AuditRecord(**d))
            return results

    def verify_ledger_integrity(self, tenant_id: str) -> AuditVerificationResult:
        """
        Traverses the full audit hash-chain for a tenant from index 0 to head.
        Recomputes SHA-256 for each block and validates link to prev_hash.
        Returns detailed integrity status or flags the exact index where tampering occurred.
        """
        now = datetime.now(timezone.utc).isoformat()
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
            SELECT * FROM audit_records 
            WHERE tenant_id = ? 
            ORDER BY index_num ASC
            """, (tenant_id,))
            rows = cursor.fetchall()

            if not rows:
                return AuditVerificationResult(
                    is_valid=True,
                    total_records=0,
                    genesis_hash=GENESIS_HASH,
                    latest_hash=GENESIS_HASH,
                    verified_at=now
                )

            expected_prev_hash = GENESIS_HASH
            for i, row in enumerate(rows):
                idx = row["index_num"]
                prev_h = row["prev_hash"]
                stored_h = row["hash"]
                details_dict = json.loads(row["details"])

                # Check 1: Prev hash link matches expected
                if prev_h != expected_prev_hash:
                    return AuditVerificationResult(
                        is_valid=False,
                        total_records=len(rows),
                        genesis_hash=rows[0]["hash"],
                        latest_hash=rows[-1]["hash"],
                        tampered_index=idx,
                        error_message=f"Hash chain broken at index {idx}: previous hash '{prev_h[:12]}...' does not match prior block hash '{expected_prev_hash[:12]}...'",
                        verified_at=now
                    )

                # Check 2: Recomputed hash matches stored hash
                recomputed_h = compute_audit_hash(
                    prev_hash=prev_h,
                    index=idx,
                    timestamp=row["timestamp"],
                    tenant_id=row["tenant_id"],
                    actor_id=row["actor_id"],
                    action=row["action"],
                    resource_id=row["resource_id"],
                    details=details_dict
                )

                if recomputed_h != stored_h:
                    return AuditVerificationResult(
                        is_valid=False,
                        total_records=len(rows),
                        genesis_hash=rows[0]["hash"],
                        latest_hash=rows[-1]["hash"],
                        tampered_index=idx,
                        error_message=f"Cryptographic hash mismatch at index {idx}! Data contents were altered after signature.",
                        verified_at=now
                    )

                expected_prev_hash = stored_h

            return AuditVerificationResult(
                is_valid=True,
                total_records=len(rows),
                genesis_hash=rows[0]["hash"],
                latest_hash=rows[-1]["hash"],
                verified_at=now
            )

    def simulate_tampering_for_demo(self, tenant_id: str) -> Optional[int]:
        """
        Simulates an unauthorized database tampering attack by mutating details of an existing audit entry
        WITHOUT updating the hash chain. This demonstrates TrustVault's tamper detection.
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
            SELECT index_num, id, details FROM audit_records 
            WHERE tenant_id = ? AND index_num > 0 
            ORDER BY index_num DESC LIMIT 1
            """, (tenant_id,))
            row = cursor.fetchone()
            if not row:
                return None
            
            idx = row["index_num"]
            rec_id = row["id"]
            details = json.loads(row["details"])
            details["__TAMPERED_BY_ATTACKER__"] = "Unauthorized direct SQL edit without cryptographic resigning"

            cursor.execute("""
            UPDATE audit_records 
            SET details = ? 
            WHERE id = ?
            """, (json.dumps(details), rec_id))
            conn.commit()
            return idx

    def repair_tampering_for_demo(self, tenant_id: str):
        """
        Repairs the chain by recomputing hashes from genesis to head.
        Used to reset demo state after tamper simulation.
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
            SELECT * FROM audit_records 
            WHERE tenant_id = ? 
            ORDER BY index_num ASC
            """, (tenant_id,))
            rows = cursor.fetchall()
            
            expected_prev = GENESIS_HASH
            for row in rows:
                idx = row["index_num"]
                rec_id = row["id"]
                details = json.loads(row["details"])
                if "__TAMPERED_BY_ATTACKER__" in details:
                    del details["__TAMPERED_BY_ATTACKER__"]

                new_h = compute_audit_hash(
                    prev_hash=expected_prev,
                    index=idx,
                    timestamp=row["timestamp"],
                    tenant_id=row["tenant_id"],
                    actor_id=row["actor_id"],
                    action=row["action"],
                    resource_id=row["resource_id"],
                    details=details
                )
                cursor.execute("""
                UPDATE audit_records 
                SET prev_hash = ?, hash = ?, details = ?
                WHERE id = ?
                """, (expected_prev, new_h, json.dumps(details), rec_id))
                expected_prev = new_h

            conn.commit()

storage = StorageManager()

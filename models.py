from enum import Enum
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field
from datetime import datetime

class Role(str, Enum):
    ADMIN = "ADMIN"
    COMPLIANCE_OFFICER = "COMPLIANCE_OFFICER"
    DOCUMENT_MANAGER = "DOCUMENT_MANAGER"
    VIEWER = "VIEWER"

class Classification(str, Enum):
    PUBLIC = "PUBLIC"
    INTERNAL = "INTERNAL"
    CONFIDENTIAL = "CONFIDENTIAL"
    RESTRICTED = "RESTRICTED"
    TOP_SECRET = "TOP_SECRET"

class ActionType(str, Enum):
    DOC_UPLOAD = "DOC_UPLOAD"
    DOC_VIEW = "DOC_VIEW"
    DOC_DOWNLOAD = "DOC_DOWNLOAD"
    DOC_DELETE = "DOC_DELETE"
    SHARE_CREATE = "SHARE_CREATE"
    SHARE_ACCESS = "SHARE_ACCESS"
    SHARE_REVOKE = "SHARE_REVOKE"
    SHARE_FAIL_PASSWORD = "SHARE_FAIL_PASSWORD"
    AUDIT_VERIFY = "AUDIT_VERIFY"
    AUDIT_EXPORT = "AUDIT_EXPORT"
    USER_SWITCH = "USER_SWITCH"

class Tenant(BaseModel):
    id: str
    name: str
    description: str
    created_at: str

class User(BaseModel):
    id: str
    tenant_id: str
    email: str
    full_name: str
    role: Role
    avatar_color: str = "#2563eb"

class DocumentMetadata(BaseModel):
    id: str
    tenant_id: str
    filename: str
    original_name: str
    mime_type: str
    file_size: int
    classification: Classification
    tags: List[str] = []
    plaintext_sha256: str
    storage_path: str
    uploaded_by_id: str
    uploaded_by_name: str
    created_at: str
    updated_at: str

class ShareLink(BaseModel):
    id: str
    token: str
    tenant_id: str
    document_id: str
    document_name: str
    created_by_id: str
    created_by_name: str
    created_at: str
    expires_at: Optional[str] = None
    max_views: Optional[int] = None
    current_views: int = 0
    allow_download: bool = True
    is_revoked: bool = False
    has_password: bool = False
    passcode_hash: Optional[str] = None

class AuditRecord(BaseModel):
    index: int
    id: str
    timestamp: str
    tenant_id: str
    actor_id: str
    actor_name: str
    actor_role: str
    action: ActionType
    resource_id: str
    resource_name: str
    ip_address: str
    user_agent: str
    details: Dict[str, Any] = {}
    prev_hash: str
    hash: str

class CreateShareRequest(BaseModel):
    document_id: str
    expires_in_hours: Optional[int] = None
    max_views: Optional[int] = None
    allow_download: bool = True
    passcode: Optional[str] = None

class ShareAccessRequest(BaseModel):
    passcode: Optional[str] = None

class AuditVerificationResult(BaseModel):
    is_valid: bool
    total_records: int
    genesis_hash: str
    latest_hash: str
    tampered_index: Optional[int] = None
    error_message: Optional[str] = None
    verified_at: str

from fastapi import HTTPException, status
from app.models import Role, User

PERMISSIONS = {
    Role.ADMIN: {
        "CAN_UPLOAD_DOC",
        "CAN_DELETE_DOC",
        "CAN_VIEW_DOC",
        "CAN_DOWNLOAD_DOC",
        "CAN_CREATE_SHARE",
        "CAN_REVOKE_SHARE",
        "CAN_VIEW_AUDIT_LOGS",
        "CAN_VERIFY_AUDIT_CHAIN",
        "CAN_EXPORT_AUDIT_LOGS",
        "CAN_SIMULATE_TAMPER",
    },
    Role.COMPLIANCE_OFFICER: {
        "CAN_VIEW_DOC",
        "CAN_DOWNLOAD_DOC",
        "CAN_VIEW_AUDIT_LOGS",
        "CAN_VERIFY_AUDIT_CHAIN",
        "CAN_EXPORT_AUDIT_LOGS",
        "CAN_REVOKE_SHARE", # Compliance can revoke suspicious shares
    },
    Role.DOCUMENT_MANAGER: {
        "CAN_UPLOAD_DOC",
        "CAN_DELETE_DOC",
        "CAN_VIEW_DOC",
        "CAN_DOWNLOAD_DOC",
        "CAN_CREATE_SHARE",
        "CAN_REVOKE_SHARE",
    },
    Role.VIEWER: {
        "CAN_VIEW_DOC",
        "CAN_DOWNLOAD_DOC",
    }
}

def has_permission(role: Role, permission: str) -> bool:
    """Checks if a given role has the requested permission."""
    return permission in PERMISSIONS.get(role, set())

def require_permission(user: User, permission: str):
    """Enforces permission check or raises HTTP 403 Forbidden."""
    if not has_permission(user.role, permission):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Access Denied: Role '{user.role.value}' lacks required permission '{permission}'."
        )

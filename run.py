import sys
import socket
import uvicorn

def is_port_in_use(port: int, host: str = "127.0.0.1") -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        return s.connect_ex((host, port)) == 0

def find_available_port(start_port: int = 8000, max_attempts: int = 20) -> int:
    port = start_port
    while port < start_port + max_attempts:
        if not is_port_in_use(port):
            return port
        port += 1
    return start_port

def print_banner(host: str, port: int):
    base_url = f"http://{host}:{port}"
    print("=" * 68)
    print("  🛡️  TRUSTVAULT — SECURE MULTI-TENANT DOCUMENT VAULT  🛡️")
    print("=" * 68)
    print(f"  ▸ Web Dashboard:        {base_url}/")
    print(f"  ▸ Interactive API Docs: {base_url}/docs")
    print(f"  ▸ Encryption:           AES-256-GCM (Hardware-accelerated)")
    print(f"  ▸ Audit Ledger:         Tamper-Evident SHA-256 Linear Merkle Chain")
    print("--------------------------------------------------------------------")
    print("  Pre-seeded Organizations & Personas for RBAC Demonstration:")
    print("  • Acme Aerospace Corp (Acme)")
    print("    - Alice Sterling   [ADMIN]              - Full Control & Audit Verification")
    print("    - Bob Vance        [COMPLIANCE_OFFICER] - Read-Only Docs, Full Ledger Inspection")
    print("    - Charlie Hayes    [DOCUMENT_MANAGER]   - Upload, Classify & Create Shares")
    print("    - Diana Prince     [VIEWER]             - Watermarked Preview & Download Only")
    print("  • CyberShield Global")
    print("    - Elena Rostova    [ADMIN]")
    print("    - Marcus Reed      [DOCUMENT_MANAGER]")
    print("=" * 68)
    print("  Press Ctrl+C to stop the TrustVault server.\n")

if __name__ == "__main__":
    host = "127.0.0.1"
    port = find_available_port(8000)
    print_banner(host, port)
    uvicorn.run("app.main:app", host=host, port=port, reload=False, log_level="info")

# TrustVault — Secure Multi-Tenant Document Sharing Platform

TrustVault is a secure, multi-tenant document-sharing platform that enables companies to upload, share, and manage confidential documents with role-based access control (RBAC), at-rest AES-256-GCM encryption, dynamic anti-leak watermarking, and a real tamper-evident cryptographic audit ledger.

---

## 🌟 Key Features

### 1. Multi-Tenant Cryptographic Isolation
- **Tenant-Scoped Architecture:** Every document, share link, and audit record is strictly bound to an organization (`tenant_id`).
- **Derived Cryptographic Keys:** Each tenant's documents are encrypted at rest with a 256-bit AES key derived independently via SHA-256/PBKDF2. Decrypting Tenant A's documents using Tenant B's keys is mathematically impossible.

### 2. Role-Based Access Control (RBAC)
TrustVault provides 4 enterprise roles with granular privilege enforcement:

| Role | Upload & Classify | View / Preview | Download Decrypted | Create Shares | Revoke Shares | Inspect Audit Trail | Verify Ledger Integrity |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Admin** (Alice) | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **Compliance Officer** (Bob) | ❌ | ✅ | ✅ | ❌ | ✅ *(Emergency)* | ✅ *(Full)* | ✅ *(Signed Reports)* |
| **Document Manager** (Charlie)| ✅ | ✅ | ✅ | ✅ | ✅ | ❌ | ❌ |
| **Viewer** (Diana) | ❌ | ✅ *(Watermarked)*| ✅ | ❌ | ❌ | ❌ | ❌ |

> **Live Demo Feature:** The web dashboard includes an instant persona switcher in the header to evaluate RBAC restrictions in real time.

### 3. Time-Bound, Protected Document Sharing
- **Expiring Links:** Configure links to expire automatically after 1 hour, 24 hours, 7 days, or upon revocation.
- **Access Limits:** Enforce maximum view counts (e.g. self-destruct after 3 views).
- **Passcode Protection:** Optional salted SHA-256 passcodes required before decryption.
- **View-Only Mode:** Disable file downloads for sensitive files.
- **Instant Revocation:** One-click revocation immediately invalidates public links across all sessions.

### 4. Dynamic Anti-Leak Watermarking
- Confidential documents previewed internally or via external links render with diagonal, semi-transparent watermark overlays containing:
  - Viewer email / identifier
  - Client IP address
  - Timestamp of access
  - Confidentiality classification warning
- Deters screen capturing, photography, and unauthorized distribution.

### 5. Real, Tamper-Evident Cryptographic Audit Trail
Unlike standard database logging where records can be silently updated or deleted by database administrators:
- **Append-Only Linear Hash Chain:**
  Each audit block $i$ is sealed with a SHA-256 digest:
  $$H_i = \text{SHA-256}(H_{i-1} \parallel \text{Index} \parallel \text{Timestamp} \parallel \text{Tenant} \parallel \text{Actor} \parallel \text{Action} \parallel \text{Resource} \parallel \text{Details})$$
  Genesis blocks are initialized with $H_0 = 0^{64}$.
- **Instant Integrity Verification:** Traverses the entire ledger from genesis to head, re-calculating cryptographic proofs.
- **Built-In Attack Simulation (Demo):** Test the tamper detection live! Click **"Simulate Tampering Attack"** in the dashboard to secretly corrupt raw SQL data. Running ledger verification triggers an immediate cryptographic alarm pinpointing the exact modified block index.
- **Compliance Export:** Export signed audit reports in JSON or CSV format.

---

## 🚀 Quickstart

### Prerequisites
- Python 3.10+ (Python 3.12 verified)

### 1. Launch the Platform
```powershell
python run.py
```
This automatically finds an available port and starts the server:
- **Web Dashboard:** [http://127.0.0.1:8000/](http://127.0.0.1:8000/)
- **Interactive Swagger API Docs:** [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)

### 2. Pre-Seeded Demonstration Accounts

| Organization | User Persona | Role | Capabilities |
| :--- | :--- | :--- | :--- |
| **Acme Aerospace Corp** | **Alice Sterling** | `ADMIN` | Full control, upload, sharing, audit verification |
| Acme Aerospace Corp | **Bob Vance** | `COMPLIANCE_OFFICER` | Read-only docs, full audit trail, compliance exports |
| Acme Aerospace Corp | **Charlie Hayes** | `DOCUMENT_MANAGER` | Upload, classify, generate & revoke share links |
| Acme Aerospace Corp | **Diana Prince** | `VIEWER` | Watermarked preview, download only |
| **CyberShield Global** | **Elena Rostova** | `ADMIN` | Isolated CyberShield tenant administration |
| CyberShield Global | **Marcus Reed** | `DOCUMENT_MANAGER` | CyberShield document management |

---

## 🧪 Automated Test Suite

Run the unit test suite covering AES-256-GCM encryption, cross-tenant isolation, RBAC policies, and tamper-evident hash chaining:

```powershell
python -m unittest tests/test_trustvault.py
```

Expected output:
```
.....
----------------------------------------------------------------------
Ran 5 tests in 0.559s

OK
```

---

## 📁 Project Structure

```
trustVault/
├── app/
│   ├── __init__.py
│   ├── main.py              # FastAPI server, static file mounting & routes
│   ├── models.py            # Pydantic schemas (Tenant, User, Document, Share, Audit)
│   ├── storage.py           # SQLite persistence, AES-GCM blob storage, audit ledger
│   ├── crypto.py            # AES-256-GCM encryption, PBKDF2 keys, SHA-256 hash chaining
│   ├── rbac.py              # Role-Based Access Control policies & permission guards
│   ├── api/
│   │   ├── auth.py          # Tenant & Persona context resolution
│   │   ├── documents.py     # Document upload, download, preview & deletion
│   │   ├── shares.py        # Expiring share link generation & public viewer
│   │   └── audit.py         # Audit trail inspection, verification & tamper simulation
│   └── static/
│       ├── index.html       # Enterprise dashboard SPA (Tailwind CSS)
│       ├── share.html       # Public confidential document recipient page
│       ├── app.js           # Frontend reactive state & dynamic watermarking
│       └── styles.css       # Watermark layout & theme styles
├── data/
│   ├── trustvault.db        # Persistent relational state
│   └── vault/
│       └── encrypted_blobs/ # AES-256-GCM encrypted document blobs
├── tests/
│   └── test_trustvault.py   # Unit & integration test suite
├── run.py                   # Self-contained application runner
└── README.md                # Project documentation & security guide
```

---

## 🔒 Security Architecture Highlights

1. **At-Rest Zero Plaintext:** Documents are never written to disk in unencrypted form. Nonces (12 bytes) are uniquely generated per file.
2. **Deterministic Tamper Detection:** Any alteration of audit records breaks the cryptographic hash pointer $H_{i-1}$, immediately exposing unauthorized tampering.
3. **Defense-in-Depth Watermarking:** Prevents covert leaks by embedding recipient metadata on every rendered confidential page.

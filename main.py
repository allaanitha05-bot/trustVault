import os
from pathlib import Path
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware

from app.api import auth, documents, shares, audit

app = FastAPI(
    title="TrustVault API",
    description="Secure, multi-tenant document sharing platform with cryptographic audit trail.",
    version="1.0.0"
)

# Enable CORS for open interaction
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include Routers
app.include_router(auth.router)
app.include_router(documents.router)
app.include_router(shares.router)
app.include_router(audit.router)

STATIC_DIR = Path(__file__).parent / "static"

@app.get("/health")
def healthcheck():
    return {"status": "ok", "service": "TrustVault", "security": "AES-256-GCM + SHA-256 Chain"}

@app.get("/", response_class=FileResponse)
def serve_dashboard():
    index_file = STATIC_DIR / "index.html"
    return FileResponse(index_file)

@app.get("/share/{token}", response_class=FileResponse)
def serve_share_page(token: str):
    share_file = STATIC_DIR / "share.html"
    return FileResponse(share_file)

# Mount remaining static assets (CSS, JS)
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

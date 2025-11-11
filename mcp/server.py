from __future__ import annotations
import os
from typing import Optional

from fastapi import FastAPI, Depends, Header, HTTPException, status
from pydantic import BaseModel, Field

from .policy import Policy
from .cli import sanitize_text

def load_api_token(path: str = "./keys/mcp_api_token") -> str:
    try:
        with open(path, "r", encoding="utf-8") as f:
            tok = f.read().strip()
    except FileNotFoundError:
        raise RuntimeError(
            "Missing API token file ./keys/mcp_api_token "
            "(create with: openssl rand -hex 32 > keys/mcp_api_token)"
        )
    if len(tok) < 16:
        raise RuntimeError("API token too short; require >= 16 chars.")
    return tok

API_TOKEN = load_api_token()
DEFAULT_POLICY = os.getenv("MCP_POLICY", "examples/mcp_policy.yaml")

def bearer_auth(authorization: Optional[str] = Header(None)) -> None:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing Bearer token")
    token = authorization[7:].strip()
    if token != API_TOKEN:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Invalid token")

class SanitizeRequest(BaseModel):
    text: str = Field(..., description="Raw text to sanitize")
    policy_path: str = Field(DEFAULT_POLICY, description="Path to YAML policy", examples=[DEFAULT_POLICY])
    dry_run: bool = Field(False, description="If true, do not modify text; only audit")

class SanitizeResponse(BaseModel):
    sanitized: str
    blocked: bool
    policy_sha256: str

class StatusResponse(BaseModel):
    status: str
    policy_path: str
    policy_sha256: str

app = FastAPI(
    title="MCP (Micro-Cleanse Preprocessor) — Local API",
    description="Local-only secret removal proxy. Bind to 127.0.0.1 by default. DO NOT expose publicly.",
    version="0.1.0",
)

def policy_hash(path: str) -> str:
    import hashlib
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()

@app.get("/health", response_model=StatusResponse)
def health(_: None = Depends(bearer_auth)):
    pol_path = DEFAULT_POLICY
    return StatusResponse(status="ok", policy_path=pol_path, policy_sha256=policy_hash(pol_path))

@app.post("/sanitize", response_model=SanitizeResponse)
def sanitize(req: SanitizeRequest, _: None = Depends(bearer_auth)):
    pol = Policy.load(req.policy_path)
    out, blocked = sanitize_text(req.text, pol, dry_run=req.dry_run)
    return SanitizeResponse(sanitized=out, blocked=blocked, policy_sha256=policy_hash(req.policy_path))

@app.post("/scan", response_model=SanitizeResponse)
def scan(req: SanitizeRequest, _: None = Depends(bearer_auth)):
    pol = Policy.load(req.policy_path)
    out, blocked = sanitize_text(req.text, pol, dry_run=True)
    return SanitizeResponse(sanitized=out, blocked=blocked, policy_sha256=policy_hash(req.policy_path))

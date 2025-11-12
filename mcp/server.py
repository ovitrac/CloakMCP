from __future__ import annotations
import os
from typing import Optional

from fastapi import FastAPI, Depends, Header, HTTPException, status, Request
from pydantic import BaseModel, Field

from .policy import Policy
from .cli import sanitize_text

# Rate limiting imports (optional dependency)
try:
    from slowapi import Limiter, _rate_limit_exceeded_handler
    from slowapi.util import get_remote_address
    from slowapi.errors import RateLimitExceeded
    RATE_LIMITING_ENABLED = True
except ImportError:
    RATE_LIMITING_ENABLED = False
    Limiter = None

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
    title="Cloak (Micro-Cleanse Preprocessor) — Local API",
    description="Local-only secret removal proxy. Bind to 127.0.0.1 by default. DO NOT expose publicly.",
    version="0.3.2",
)

# Initialize rate limiter if available
if RATE_LIMITING_ENABLED:
    limiter = Limiter(key_func=get_remote_address, default_limits=["10/minute"])
    app.state.limiter = limiter
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
    print("Rate limiting enabled: 10 requests/minute per IP", flush=True)
else:
    limiter = None
    print("Warning: Rate limiting not available (install slowapi: pip install slowapi)", flush=True)

def policy_hash(path: str) -> str:
    import hashlib
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()

@app.get("/health", response_model=StatusResponse)
def health(request: Request, _: None = Depends(bearer_auth)):
    if RATE_LIMITING_ENABLED and limiter:
        limiter.limit("10/minute")(lambda: None)()
    pol_path = DEFAULT_POLICY
    return StatusResponse(status="ok", policy_path=pol_path, policy_sha256=policy_hash(pol_path))

@app.post("/sanitize", response_model=SanitizeResponse)
def sanitize(request: Request, req: SanitizeRequest, _: None = Depends(bearer_auth)):
    if RATE_LIMITING_ENABLED and limiter:
        limiter.limit("10/minute")(lambda: None)()
    pol = Policy.load(req.policy_path)
    out, blocked = sanitize_text(req.text, pol, dry_run=req.dry_run)
    return SanitizeResponse(sanitized=out, blocked=blocked, policy_sha256=policy_hash(req.policy_path))

@app.post("/scan", response_model=SanitizeResponse)
def scan(request: Request, req: SanitizeRequest, _: None = Depends(bearer_auth)):
    if RATE_LIMITING_ENABLED and limiter:
        limiter.limit("10/minute")(lambda: None)()
    pol = Policy.load(req.policy_path)
    out, blocked = sanitize_text(req.text, pol, dry_run=True)
    return SanitizeResponse(sanitized=out, blocked=blocked, policy_sha256=policy_hash(req.policy_path))

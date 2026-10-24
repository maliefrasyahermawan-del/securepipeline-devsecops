"""
SecurePipeline — Vulnerable-by-Design FastAPI Demo App
This application intentionally contains security vulnerabilities to demonstrate
that the DevSecOps pipeline (Gitleaks, Semgrep, Trivy, ZAP) can detect them.
DO NOT deploy this to production.
"""
import os
import shutil
from fastapi import FastAPI, HTTPException, UploadFile, File
from app.database import init_db, get_all_users, get_user_by_id_vulnerable, get_user_by_credentials
from app.models import LoginRequest, UploadResponse

# INTENTIONAL VULNERABILITY: hardcoded credentials — for Gitleaks demo
AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"      # INTENTIONAL: for Gitleaks demo
DB_PASSWORD = "supersecret123"               # INTENTIONAL: for Gitleaks demo
SECRET_TOKEN = "ghp_FAKETOKEN1234567890abcdefghijklmno"  # INTENTIONAL: for Gitleaks demo

app = FastAPI(
    title="SecurePipeline Demo App",
    description="Intentionally vulnerable FastAPI app for DevSecOps pipeline demo",
    version="1.0.0",
)


@app.on_event("startup")
def on_startup():
    init_db()


@app.get("/health")
def health_check():
    """Health check endpoint — used by staging wait loop and ZAP baseline."""
    return {"status": "ok", "version": "1.0.0"}


@app.get("/users")
def list_users():
    """Return all users from database (no auth required — INTENTIONAL)."""
    # INTENTIONAL VULNERABILITY: missing authentication — any caller can list users
    users = get_all_users()
    return {"users": users}


@app.get("/users/{user_id}")
def get_user(user_id: str):
    """
    Get user by ID.
    INTENTIONAL VULNERABILITY: SQL Injection — user_id is passed directly into
    the SQL query. Example attack: GET /users/1 OR 1=1--
    Semgrep rule python.lang.security.audit.sqli will flag database.py line.
    """
    try:
        result = get_user_by_id_vulnerable(user_id)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    if not result:
        raise HTTPException(status_code=404, detail="User not found")
    return {"users": result}


@app.post("/login")
def login(credentials: LoginRequest):
    """
    Authenticate user.
    INTENTIONAL VULNERABILITY: plain-text password storage and comparison.
    No bcrypt/argon2, no rate-limiting, no account lockout.
    """
    # INTENTIONAL VULNERABILITY: password compared in plain text
    user = get_user_by_credentials(credentials.username, credentials.password)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    return {"message": "Login successful", "user": user}


@app.get("/admin")
def admin_panel():
    """
    Admin panel endpoint.
    INTENTIONAL VULNERABILITY: missing authentication/authorization guard.
    Any unauthenticated request can access admin data.
    Semgrep and ZAP should flag missing auth controls.
    """
    # INTENTIONAL VULNERABILITY: no auth check before returning sensitive data
    return {
        "message": "Admin panel",
        "db_password": DB_PASSWORD,          # INTENTIONAL: secret exposed in response
        "aws_key": AWS_ACCESS_KEY,           # INTENTIONAL: secret exposed in response
        "server_info": {
            "python": "3.11",
            "db_path": os.getenv("DB_PATH", "users.db"),
        },
    }


@app.post("/upload", response_model=UploadResponse)
async def upload_file(file: UploadFile = File(...)):
    """
    File upload endpoint.
    INTENTIONAL VULNERABILITY: no file extension validation, no size limit,
    no content-type check. Allows uploading any file including .php/.py scripts.
    """
    # INTENTIONAL VULNERABILITY: unrestricted file upload — no extension whitelist
    upload_dir = "/tmp/uploads"
    os.makedirs(upload_dir, exist_ok=True)
    dest = os.path.join(upload_dir, file.filename)   # INTENTIONAL: path traversal risk
    with open(dest, "wb") as f:
        shutil.copyfileobj(file.file, f)
    size = os.path.getsize(dest)
    return UploadResponse(filename=file.filename, size=size, message="File uploaded")

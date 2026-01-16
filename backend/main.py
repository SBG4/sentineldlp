"""
Sensitive Information Detection System - Backend API
FastAPI service with Claude API integration for document analysis
FR-005/GAP-001: Redis + Celery queue system for 1000+ concurrent users
"""

import os
import json
import uuid
import hashlib
from datetime import datetime
from pathlib import Path
from typing import Optional, List
import asyncio

from fastapi import FastAPI, UploadFile, File, HTTPException, BackgroundTasks, Request, Response, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, FileResponse
from pydantic import BaseModel, Field
import anthropic

# Celery imports (FR-005/GAP-001)
CELERY_ENABLED = os.getenv("CELERY_ENABLED", "true").lower() == "true"
celery_app = None
analyze_document_task = None

if CELERY_ENABLED:
    try:
        from celery.result import AsyncResult
        from celery_app import celery_app
        from tasks import analyze_document_task
    except ImportError as e:
        print(f"Warning: Celery not available, running in sync mode: {e}")
        CELERY_ENABLED = False

# Import configuration management (FR-002)
from config_manager import ConfigManager, SystemConfig, LLMProvider
from crypto_utils import mask_secret

# Import Elasticsearch and file storage services
from elasticsearch_service import ElasticsearchService
from file_storage_service import FileStorageService

# Import universal file processor (FR-001)
from file_processor import FileProcessor, get_file_processor, ProcessedFile

# Import authentication modules (FR-006/GAP-002)
from auth_service import auth_service, auth_audit, UserRole, AuthProvider, ROLE_PERMISSIONS
from user_manager import user_manager
from ldap_connector import ldap_connector

# Import security middleware (FR-006 Phase 2)
from security_middleware import (
    SecurityHeadersMiddleware,
    CSRFMiddleware,
    CSRFProtection,
    SecureCookies,
    check_rate_limit,
    record_attempt,
    reset_rate_limit,
    RATE_LIMIT_ENABLED
)

# Initialize FastAPI app
app = FastAPI(
    title="Sensitive Information Detection API",
    description="Enterprise document sensitivity analysis powered by Claude AI",
    version="1.2.0"
)

# CORS middleware for frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*", "X-CSRF-Token"],  # Allow CSRF header
    expose_headers=["X-RateLimit-Remaining", "X-RateLimit-Reset"],  # Expose rate limit headers
)

# Security middleware (FR-006 Phase 2)
# Note: Middleware order matters - first added = last executed
# CSRF middleware validates tokens for state-changing requests
app.add_middleware(CSRFMiddleware)
# Security headers added to all responses
app.add_middleware(SecurityHeadersMiddleware)

# Data storage paths - handle both Docker (/app) and local development
# In Docker: WORKDIR is /app, data should be at /app/data
# Locally: data is relative to project root (parent of backend/)
import os

# Check if running in Docker (WORKDIR=/app) or locally
if Path("/app/main.py").exists():
    # Running in Docker container
    DATA_DIR = Path("/app/data")
else:
    # Running locally - use relative path from backend/
    DATA_DIR = Path(__file__).parent.parent / "data"

CONFIG_DIR = DATA_DIR / "config"
SETTINGS_FILE = DATA_DIR / "settings.json"
INCIDENTS_FILE = DATA_DIR / "incidents.json"
UPLOADS_DIR = DATA_DIR / "uploads"

# Ensure directories exist (parents=True creates parent dirs if needed)
DATA_DIR.mkdir(parents=True, exist_ok=True)
CONFIG_DIR.mkdir(parents=True, exist_ok=True)
UPLOADS_DIR.mkdir(parents=True, exist_ok=True)

# Initialize configuration manager (FR-002)
config_manager = ConfigManager(CONFIG_DIR)

# Initialize Elasticsearch and file storage services
es_service = ElasticsearchService(config_manager)
file_storage = FileStorageService(UPLOADS_DIR)

# Initialize universal file processor (FR-001)
# OCR languages: eng (English) + ara (Arabic) for Dubai deployment
file_processor = get_file_processor(
    max_chunk_size=50000,  # ~50K chars per chunk for LLM
    ocr_enabled=True,
    ocr_languages="eng+ara"
)

# ============== Models ==============

class Settings(BaseModel):
    api_key: str = ""
    model: str = "claude-sonnet-4-20250514"
    max_tokens: int = 4096
    auto_delete_uploads: bool = True
    retention_days: int = 30

class SettingsUpdate(BaseModel):
    api_key: Optional[str] = None
    model: Optional[str] = None
    max_tokens: Optional[int] = None
    auto_delete_uploads: Optional[bool] = None
    retention_days: Optional[int] = None

class AnalysisRequest(BaseModel):
    document_text: str
    filename: str = "unknown"
    filetype: str = "unknown"
    filesize: str = "unknown"

class DimensionScores(BaseModel):
    pii: int = 0
    financial: int = 0
    strategic_business: int = 0
    intellectual_property: int = 0
    legal_compliance: int = 0
    operational_security: int = 0
    hr_employee: int = 0

class DepartmentRelevance(BaseModel):
    HR: str = "NONE"
    Finance: str = "NONE"
    Legal: str = "NONE"
    IT_Security: str = "NONE"
    Executive: str = "NONE"
    RnD: str = "NONE"
    Sales: str = "NONE"
    Operations: str = "NONE"
    Marketing: str = "NONE"

class Finding(BaseModel):
    category: str
    severity: str
    description: str
    count: int = 1
    examples: List[str] = []

class AnalysisResult(BaseModel):
    id: str
    timestamp: str
    filename: str
    filetype: str
    filesize: str
    overall_sensitivity_score: int
    sensitivity_level: str
    confidence: float
    dimension_scores: DimensionScores
    department_relevance: DepartmentRelevance
    findings: List[Finding]
    regulatory_concerns: List[str]
    recommended_actions: List[str]
    reasoning: str
    status: str = "completed"
    error: Optional[str] = None

class Incident(BaseModel):
    id: str
    timestamp: str
    filename: str
    filetype: str
    filesize: str
    sensitivity_level: str
    overall_score: int
    top_categories: List[str]
    departments_affected: List[str]
    status: str
    hash: str


# ============== Authentication Models (FR-006/GAP-002) ==============

class LoginRequest(BaseModel):
    """Login request with username and password."""
    username: str
    password: str
    provider: Optional[str] = "auto"  # auto, local, ldap

class TokenResponse(BaseModel):
    """JWT token response."""
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int
    user: dict

class RefreshTokenRequest(BaseModel):
    """Token refresh request."""
    refresh_token: str

class PasswordChangeRequest(BaseModel):
    """Password change request."""
    current_password: Optional[str] = None
    new_password: str

class UserCreateRequest(BaseModel):
    """Request to create a new user."""
    username: str
    password: str
    email: str
    role: str = "viewer"
    display_name: Optional[str] = None

class UserUpdateRequest(BaseModel):
    """Request to update user properties."""
    email: Optional[str] = None
    role: Optional[str] = None
    display_name: Optional[str] = None
    enabled: Optional[bool] = None


# ============== Authentication Dependency ==============

AUTH_MODE = os.getenv("AUTH_MODE", "hybrid")

async def get_current_user(request: Request) -> dict:
    """
    FastAPI dependency to get current authenticated user from JWT token.

    Extracts and validates JWT from Authorization header.
    Returns user payload if valid, raises HTTPException if not.
    """
    auth_header = request.headers.get("Authorization")

    if not auth_header or not auth_header.startswith("Bearer "):
        raise HTTPException(
            status_code=401,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"}
        )

    token = auth_header.split(" ")[1]
    payload = auth_service.verify_token(token, token_type="access")

    if not payload:
        raise HTTPException(
            status_code=401,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"}
        )

    return payload

async def get_optional_user(request: Request) -> Optional[dict]:
    """
    Optional authentication - returns None if not authenticated.
    Use for endpoints that work with or without auth.
    """
    try:
        return await get_current_user(request)
    except HTTPException:
        return None

def require_role(required_roles: List[UserRole]):
    """
    Dependency factory to require specific roles.

    Usage: Depends(require_role([UserRole.ADMIN]))
    """
    async def role_checker(user: dict = Depends(get_current_user)) -> dict:
        user_role = UserRole(user.get("role", "viewer"))
        if user_role not in required_roles:
            raise HTTPException(
                status_code=403,
                detail=f"Insufficient permissions. Required: {[r.value for r in required_roles]}"
            )
        return user
    return role_checker

def require_permission(permission: str):
    """
    Dependency factory to require specific permission.

    Usage: Depends(require_permission("scans:create"))
    """
    async def permission_checker(user: dict = Depends(get_current_user)) -> dict:
        user_role = UserRole(user.get("role", "viewer"))
        if not auth_service.has_permission(user_role, permission):
            raise HTTPException(
                status_code=403,
                detail=f"Permission denied: {permission}"
            )
        return user
    return permission_checker


# ============== Storage Functions ==============

def load_settings() -> Settings:
    """
    Load settings with backward compatibility.
    First checks new encrypted config, falls back to legacy settings.json
    """
    # Try to load from new config manager first (FR-002)
    try:
        config = config_manager.load_config()
        if config.llm.claude_api_key or config.llm.provider != LLMProvider.CLAUDE_API:
            return Settings(
                api_key=config.llm.claude_api_key,
                model=config.llm.claude_model,
                max_tokens=config.llm.max_tokens,
                auto_delete_uploads=config.processing.auto_delete_uploads,
                retention_days=config.processing.retention_days
            )
    except Exception:
        pass
    
    # Fall back to legacy settings.json
    if SETTINGS_FILE.exists():
        with open(SETTINGS_FILE, 'r') as f:
            data = json.load(f)
            return Settings(**data)
    return Settings()

def save_settings(settings: Settings):
    """
    Save settings to both legacy file and new encrypted config.
    """
    # Save to legacy settings.json for backward compatibility
    with open(SETTINGS_FILE, 'w') as f:
        json.dump(settings.model_dump(), f, indent=2)
    
    # Also update new config manager (FR-002)
    try:
        config_manager.update_config({
            "llm": {
                "claude_api_key": settings.api_key,
                "claude_model": settings.model,
                "max_tokens": settings.max_tokens
            },
            "processing": {
                "auto_delete_uploads": settings.auto_delete_uploads,
                "retention_days": settings.retention_days
            }
        }, user="legacy_api")
    except Exception:
        pass  # Don't fail if new config update fails

def load_incidents() -> List[dict]:
    if INCIDENTS_FILE.exists():
        with open(INCIDENTS_FILE, 'r') as f:
            return json.load(f)
    return []

def save_incidents(incidents: List[dict]):
    with open(INCIDENTS_FILE, 'w') as f:
        json.dump(incidents, f, indent=2, default=str)

def add_incident(result: AnalysisResult, doc_hash: str):
    incidents = load_incidents()
    
    # Get top categories (score > 50)
    dim_scores = result.dimension_scores.model_dump()
    top_cats = [k for k, v in dim_scores.items() if v > 50]
    
    # Get affected departments (HIGH or CRITICAL)
    dept_rel = result.department_relevance.model_dump()
    affected_depts = [k for k, v in dept_rel.items() if v in ["HIGH", "CRITICAL"]]
    
    incident = Incident(
        id=result.id,
        timestamp=result.timestamp,
        filename=result.filename,
        filetype=result.filetype,
        filesize=result.filesize,
        sensitivity_level=result.sensitivity_level,
        overall_score=result.overall_sensitivity_score,
        top_categories=top_cats,
        departments_affected=affected_depts,
        status=result.status,
        hash=doc_hash
    )
    
    incidents.insert(0, incident.model_dump())
    
    # Keep last 1000 incidents
    incidents = incidents[:1000]
    save_incidents(incidents)

# ============== Analysis System Prompt ==============

ANALYSIS_PROMPT = """You are a sensitive information detection system deployed in an enterprise environment. Your task is to analyze documents and assign accurate sensitivity ratings to prevent data leakage, ensure compliance, and protect organizational information.

Analyze the provided document and generate a comprehensive sensitivity assessment. Output ONLY valid JSON matching this exact schema:

{
  "overall_sensitivity_score": <0-100>,
  "sensitivity_level": "<LOW|MEDIUM|HIGH|CRITICAL>",
  "confidence": <0.0-1.0>,
  
  "dimension_scores": {
    "pii": <0-100>,
    "financial": <0-100>,
    "strategic_business": <0-100>,
    "intellectual_property": <0-100>,
    "legal_compliance": <0-100>,
    "operational_security": <0-100>,
    "hr_employee": <0-100>
  },
  
  "department_relevance": {
    "HR": "<NONE|LOW|MEDIUM|HIGH|CRITICAL>",
    "Finance": "<NONE|LOW|MEDIUM|HIGH|CRITICAL>",
    "Legal": "<NONE|LOW|MEDIUM|HIGH|CRITICAL>",
    "IT_Security": "<NONE|LOW|MEDIUM|HIGH|CRITICAL>",
    "Executive": "<NONE|LOW|MEDIUM|HIGH|CRITICAL>",
    "RnD": "<NONE|LOW|MEDIUM|HIGH|CRITICAL>",
    "Sales": "<NONE|LOW|MEDIUM|HIGH|CRITICAL>",
    "Operations": "<NONE|LOW|MEDIUM|HIGH|CRITICAL>",
    "Marketing": "<NONE|LOW|MEDIUM|HIGH|CRITICAL>"
  },
  
  "findings": [
    {
      "category": "<dimension name>",
      "severity": "<LOW|MEDIUM|HIGH|CRITICAL>",
      "description": "<what was found, with values redacted>",
      "count": <number of instances>,
      "examples": ["<redacted sample 1>", "<redacted sample 2>"]
    }
  ],
  
  "regulatory_concerns": ["<GDPR|HIPAA|PCI-DSS|SOX|NONE>"],
  
  "recommended_actions": ["<specific action recommendation>"],
  
  "reasoning": "<brief explanation of scoring rationale>"
}

Sensitivity Dimensions to analyze:
1. PII: Names, IDs, SSN, financial accounts, medical records, biometrics
2. Financial: Revenue, budgets, salaries, banking, forecasts
3. Strategic Business: M&A, partnerships, roadmaps, competitive analysis
4. Intellectual Property: Patents, source code, R&D, trade secrets
5. Legal & Compliance: Attorney-client privilege, regulatory filings, audits
6. Operational Security: Credentials, network diagrams, vulnerabilities
7. HR & Employee: Performance reviews, disciplinary actions, terminations

Scoring Guide:
- Low (0-30): Public information, marketing materials
- Medium (31-60): Internal use, non-sensitive business data  
- High (61-85): Confidential, limited distribution
- Critical (86-100): Highly restricted, severe impact if leaked

CRITICAL: Output ONLY the JSON object, no markdown, no explanation outside JSON."""

# ============== API Endpoints ==============

@app.get("/")
async def root():
    return {"status": "online", "service": "Sensitive Information Detection API", "version": "1.0.0"}

@app.get("/api/health")
async def health_check():
    settings = load_settings()
    return {
        "status": "healthy",
        "api_configured": bool(settings.api_key),
        "model": settings.model
    }

# Settings endpoints
@app.get("/api/settings")
async def get_settings():
    settings = load_settings()
    # Mask API key for security
    masked = settings.model_dump()
    if masked["api_key"]:
        masked["api_key"] = masked["api_key"][:8] + "..." + masked["api_key"][-4:] if len(masked["api_key"]) > 12 else "***configured***"
    masked["api_key_set"] = bool(settings.api_key)
    return masked

@app.put("/api/settings")
async def update_settings(update: SettingsUpdate):
    settings = load_settings()
    update_data = update.model_dump(exclude_unset=True)
    
    for key, value in update_data.items():
        if value is not None:
            setattr(settings, key, value)
    
    save_settings(settings)
    return {"status": "updated", "message": "Settings saved successfully"}

@app.post("/api/settings/test")
async def test_api_connection():
    settings = load_settings()
    if not settings.api_key:
        raise HTTPException(status_code=400, detail="API key not configured")
    
    try:
        client = anthropic.Anthropic(api_key=settings.api_key)
        response = client.messages.create(
            model=settings.model,
            max_tokens=50,
            messages=[{"role": "user", "content": "Say 'API connection successful' in exactly those words."}]
        )
        return {"status": "success", "message": "API connection verified", "model": settings.model}
    except anthropic.AuthenticationError:
        raise HTTPException(status_code=401, detail="Invalid API key")
    except anthropic.APIError as e:
        raise HTTPException(status_code=500, detail=f"API error: {str(e)}")

# Analysis endpoints
@app.post("/api/analyze/text")
async def analyze_text(analysis_request: AnalysisRequest, background_tasks: BackgroundTasks, request: Request = None, user: dict = Depends(get_current_user)):
    """Analyze document text directly"""
    settings = load_settings()
    if not settings.api_key:
        raise HTTPException(status_code=400, detail="API key not configured. Please configure in Settings.")

    # Generate analysis ID and hash
    analysis_id = str(uuid.uuid4())
    doc_hash = hashlib.sha256(analysis_request.document_text.encode()).hexdigest()[:16]
    timestamp = datetime.utcnow().isoformat() + "Z"

    try:
        client = anthropic.Anthropic(api_key=settings.api_key)

        # Build the analysis request
        user_message = f"""Analyze this document:

<document>
{analysis_request.document_text}
</document>

<metadata>
File name: {analysis_request.filename}
File type: {analysis_request.filetype}
File size: {analysis_request.filesize}
Upload timestamp: {timestamp}
</metadata>"""

        response = client.messages.create(
            model=settings.model,
            max_tokens=settings.max_tokens,
            system=ANALYSIS_PROMPT,
            messages=[{"role": "user", "content": user_message}]
        )

        # Parse response
        response_text = response.content[0].text

        # Clean potential markdown wrapping
        if response_text.startswith("```"):
            lines = response_text.split("\n")
            response_text = "\n".join(lines[1:-1] if lines[-1] == "```" else lines[1:])

        analysis_data = json.loads(response_text)

        # Build result object
        result = AnalysisResult(
            id=analysis_id,
            timestamp=timestamp,
            filename=analysis_request.filename,
            filetype=analysis_request.filetype,
            filesize=analysis_request.filesize,
            overall_sensitivity_score=analysis_data.get("overall_sensitivity_score", 0),
            sensitivity_level=analysis_data.get("sensitivity_level", "LOW"),
            confidence=analysis_data.get("confidence", 0.5),
            dimension_scores=DimensionScores(**analysis_data.get("dimension_scores", {})),
            department_relevance=DepartmentRelevance(**analysis_data.get("department_relevance", {})),
            findings=[Finding(**f) for f in analysis_data.get("findings", [])],
            regulatory_concerns=analysis_data.get("regulatory_concerns", []),
            recommended_actions=analysis_data.get("recommended_actions", []),
            reasoning=analysis_data.get("reasoning", ""),
            status="completed"
        )

        # Log incident to JSON
        add_incident(result, doc_hash)

        # Index to Elasticsearch if enabled
        if es_service.is_enabled:
            dim_scores = result.dimension_scores.model_dump()
            top_cats = [k for k, v in dim_scores.items() if v > 50]
            dept_rel = result.department_relevance.model_dump()
            affected_depts = [k for k, v in dept_rel.items() if v in ["HIGH", "CRITICAL"]]

            scan_doc = {
                **result.model_dump(),
                "file_id": None,
                "file_stored": False,
                "hash": doc_hash,
                "file_hash": None,  # FR-007: No binary file for text analysis
                "content_preview": analysis_request.document_text[:1000],
                "filesize_bytes": len(analysis_request.document_text.encode()),
                "top_categories": top_cats,
                "departments_affected": affected_depts,
                "client_ip": request.client.host if request and request.client else None,
                "user_agent": request.headers.get("user-agent") if request else None,
                "analyzed_at": timestamp,
                # FR-009: User tracking
                "scanned_by": user.get("sub") if user else None
            }
            await es_service.index_scan(scan_doc)

        return result.model_dump()

    except json.JSONDecodeError as e:
        # Return partial result with error
        result = AnalysisResult(
            id=analysis_id,
            timestamp=timestamp,
            filename=analysis_request.filename,
            filetype=analysis_request.filetype,
            filesize=analysis_request.filesize,
            overall_sensitivity_score=0,
            sensitivity_level="UNKNOWN",
            confidence=0,
            dimension_scores=DimensionScores(),
            department_relevance=DepartmentRelevance(),
            findings=[],
            regulatory_concerns=[],
            recommended_actions=[],
            reasoning="",
            status="error",
            error=f"Failed to parse AI response: {str(e)}"
        )
        add_incident(result, doc_hash)
        return result.model_dump()

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")

@app.post("/api/analyze/file")
async def analyze_file(file: UploadFile = File(...), request: Request = None, user: dict = Depends(get_current_user)):
    """
    Analyze uploaded file with universal format support (FR-001).

    Supports: PDF, DOCX, XLSX, PPTX, images (with OCR), text files, and more.
    Large files are automatically chunked for processing.
    """
    settings = load_settings()
    config = config_manager.load_config()

    if not settings.api_key:
        raise HTTPException(status_code=400, detail="API key not configured. Please configure in Settings.")

    # Read file content
    content = await file.read()
    filesize = f"{len(content)} bytes"
    filesize_bytes = len(content)
    filename = file.filename or "unknown"

    # FR-004: Server-side file size validation (defense in depth)
    MAX_FILE_SIZE_GB = 10
    MAX_FILE_SIZE_BYTES = MAX_FILE_SIZE_GB * 1024 * 1024 * 1024
    if filesize_bytes > MAX_FILE_SIZE_BYTES:
        raise HTTPException(
            status_code=413,
            detail=f"File too large: {filesize_bytes / (1024**3):.2f} GB. Maximum allowed: {MAX_FILE_SIZE_GB} GB. Please contact IT for assistance."
        )

    # Process file using universal file processor (FR-001)
    try:
        processed = await file_processor.process_file(content, filename)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"File processing failed: {str(e)}")

    # Check if we got any text
    document_text = processed.text_content
    if not document_text or not document_text.strip():
        raise HTTPException(
            status_code=400,
            detail=f"Could not extract text from file. Type: {processed.detected_type.extension}. "
                   f"Warnings: {'; '.join(processed.extraction_warnings) if processed.extraction_warnings else 'None'}"
        )

    # Use detected file type
    filetype = processed.detected_type.extension

    # Generate IDs
    analysis_id = str(uuid.uuid4())
    file_id = str(uuid.uuid4())
    doc_hash = hashlib.sha256(document_text.encode()).hexdigest()[:16]
    file_hash = hashlib.sha256(content).hexdigest()  # FR-007: Full binary file hash
    timestamp = datetime.utcnow().isoformat() + "Z"

    # Store file if ES is enabled and auto_delete is disabled
    file_stored = False
    if es_service.is_enabled and not config.processing.auto_delete_uploads:
        try:
            file_id, _ = await file_storage.store_file(content, filename, file_id)
            file_stored = True
        except Exception as e:
            print(f"Warning: Failed to store file: {e}")

    # Perform analysis
    try:
        client = anthropic.Anthropic(api_key=settings.api_key)

        # FR-001: Smart text sampling for large files
        # Claude has ~200K token limit (~800K chars). Use 150K char limit for safety.
        MAX_ANALYSIS_CHARS = 150000
        total_chars = len(document_text)
        text_was_sampled = False
        sampling_note = ""

        if total_chars > MAX_ANALYSIS_CHARS:
            text_was_sampled = True
            # Sample from beginning, middle, and end for comprehensive coverage
            section_size = MAX_ANALYSIS_CHARS // 3

            # Beginning section
            begin_text = document_text[:section_size]

            # Middle section
            middle_start = (total_chars - section_size) // 2
            middle_text = document_text[middle_start:middle_start + section_size]

            # End section
            end_text = document_text[-section_size:]

            # Combine with markers
            analysis_text = f"""[BEGINNING OF DOCUMENT - First {section_size:,} characters]
{begin_text}

[MIDDLE OF DOCUMENT - Characters {middle_start:,} to {middle_start + section_size:,}]
{middle_text}

[END OF DOCUMENT - Last {section_size:,} characters]
{end_text}"""

            sampling_note = f"\n\nNOTE: This is a large file ({total_chars:,} characters). Content has been sampled from beginning, middle, and end sections for analysis. Some sensitive information may exist in unsampled portions."
        else:
            analysis_text = document_text

        user_message = f"""Analyze this document:

<document>
{analysis_text}
</document>

<metadata>
File name: {filename}
File type: {filetype}
File size: {filesize}
Total characters: {total_chars:,}
Content sampled: {text_was_sampled}
Upload timestamp: {timestamp}
</metadata>{sampling_note}"""

        response = client.messages.create(
            model=settings.model,
            max_tokens=settings.max_tokens,
            system=ANALYSIS_PROMPT,
            messages=[{"role": "user", "content": user_message}]
        )

        response_text = response.content[0].text

        # Clean potential markdown wrapping
        if response_text.startswith("```"):
            lines = response_text.split("\n")
            response_text = "\n".join(lines[1:-1] if lines[-1] == "```" else lines[1:])

        analysis_data = json.loads(response_text)

        # Build result object
        result = AnalysisResult(
            id=analysis_id,
            timestamp=timestamp,
            filename=filename,
            filetype=filetype,
            filesize=filesize,
            overall_sensitivity_score=analysis_data.get("overall_sensitivity_score", 0),
            sensitivity_level=analysis_data.get("sensitivity_level", "LOW"),
            confidence=analysis_data.get("confidence", 0.5),
            dimension_scores=DimensionScores(**analysis_data.get("dimension_scores", {})),
            department_relevance=DepartmentRelevance(**analysis_data.get("department_relevance", {})),
            findings=[Finding(**f) for f in analysis_data.get("findings", [])],
            regulatory_concerns=analysis_data.get("regulatory_concerns", []),
            recommended_actions=analysis_data.get("recommended_actions", []),
            reasoning=analysis_data.get("reasoning", ""),
            status="completed"
        )

        # Log incident to JSON
        add_incident(result, doc_hash)

        # Index to Elasticsearch if enabled
        if es_service.is_enabled:
            # Get top categories and affected departments
            dim_scores = result.dimension_scores.model_dump()
            top_cats = [k for k, v in dim_scores.items() if v > 50]
            dept_rel = result.department_relevance.model_dump()
            affected_depts = [k for k, v in dept_rel.items() if v in ["HIGH", "CRITICAL"]]

            scan_doc = {
                **result.model_dump(),
                "file_id": file_id if file_stored else None,
                "file_stored": file_stored,
                "hash": doc_hash,
                "file_hash": file_hash,  # FR-007: Binary file hash
                "content_preview": document_text[:1000] if document_text else "",
                "filesize_bytes": filesize_bytes,
                "top_categories": top_cats,
                "departments_affected": affected_depts,
                "client_ip": request.client.host if request and request.client else None,
                "user_agent": request.headers.get("user-agent") if request else None,
                "analyzed_at": timestamp,
                # FR-001: Processing metadata
                "ocr_applied": processed.ocr_applied,
                "page_count": processed.page_count,
                "word_count": processed.word_count,
                "detected_mime_type": processed.detected_type.mime_type,
                "file_category": processed.detected_type.category.value,
                "extraction_warnings": processed.extraction_warnings if processed.extraction_warnings else None,
                # Large file sampling metadata
                "content_sampled": text_was_sampled,
                "total_characters": total_chars,
                # FR-009: User tracking
                "scanned_by": user.get("sub") if user else None
            }
            await es_service.index_scan(scan_doc)

        # Include sampling info in response for large files
        response_data = result.model_dump()
        if text_was_sampled:
            response_data["_sampling_notice"] = f"Large file ({total_chars:,} characters). Content was sampled from beginning, middle, and end for analysis."
        return response_data

    except json.JSONDecodeError as e:
        result = AnalysisResult(
            id=analysis_id,
            timestamp=timestamp,
            filename=filename,
            filetype=filetype,
            filesize=filesize,
            overall_sensitivity_score=0,
            sensitivity_level="UNKNOWN",
            confidence=0,
            dimension_scores=DimensionScores(),
            department_relevance=DepartmentRelevance(),
            findings=[],
            regulatory_concerns=[],
            recommended_actions=[],
            reasoning="",
            status="error",
            error=f"Failed to parse AI response: {str(e)}"
        )
        add_incident(result, doc_hash)
        return result.model_dump()

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")

# Incidents/Dashboard endpoints
@app.get("/api/incidents")
async def get_incidents(
    limit: int = 50,
    offset: int = 0,
    severity: Optional[str] = None,
    department: Optional[str] = None
):
    """Get incident log with optional filtering"""
    incidents = load_incidents()
    
    # Apply filters
    if severity:
        incidents = [i for i in incidents if i.get("sensitivity_level") == severity.upper()]
    
    if department:
        incidents = [i for i in incidents if department in i.get("departments_affected", [])]
    
    total = len(incidents)
    incidents = incidents[offset:offset + limit]
    
    return {
        "total": total,
        "offset": offset,
        "limit": limit,
        "incidents": incidents
    }

@app.get("/api/incidents/{incident_id}")
async def get_incident(incident_id: str):
    """Get specific incident details"""
    incidents = load_incidents()
    for incident in incidents:
        if incident.get("id") == incident_id:
            return incident
    raise HTTPException(status_code=404, detail="Incident not found")

@app.delete("/api/incidents/{incident_id}")
async def delete_incident(incident_id: str):
    """Delete an incident"""
    incidents = load_incidents()
    incidents = [i for i in incidents if i.get("id") != incident_id]
    save_incidents(incidents)
    return {"status": "deleted", "id": incident_id}

@app.delete("/api/incidents")
async def clear_incidents():
    """Clear all incidents"""
    save_incidents([])
    return {"status": "cleared", "message": "All incidents deleted"}

# Statistics endpoint
@app.get("/api/stats")
async def get_statistics():
    """Get dashboard statistics"""
    incidents = load_incidents()
    
    if not incidents:
        return {
            "total_scans": 0,
            "by_severity": {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0},
            "by_department": {},
            "by_category": {},
            "avg_score": 0,
            "recent_critical": []
        }
    
    # Count by severity
    by_severity = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0, "UNKNOWN": 0}
    for i in incidents:
        level = i.get("sensitivity_level", "UNKNOWN")
        by_severity[level] = by_severity.get(level, 0) + 1
    
    # Count by department
    by_department = {}
    for i in incidents:
        for dept in i.get("departments_affected", []):
            by_department[dept] = by_department.get(dept, 0) + 1
    
    # Count by category
    by_category = {}
    for i in incidents:
        for cat in i.get("top_categories", []):
            by_category[cat] = by_category.get(cat, 0) + 1
    
    # Average score
    scores = [i.get("overall_score", 0) for i in incidents]
    avg_score = sum(scores) / len(scores) if scores else 0
    
    # Recent critical
    recent_critical = [i for i in incidents if i.get("sensitivity_level") == "CRITICAL"][:5]
    
    return {
        "total_scans": len(incidents),
        "by_severity": by_severity,
        "by_department": by_department,
        "by_category": by_category,
        "avg_score": round(avg_score, 1),
        "recent_critical": recent_critical
    }

# Available models endpoint
@app.get("/api/models")
async def get_available_models():
    """Get list of available Claude models"""
    return {
        "models": [
            {"id": "claude-sonnet-4-20250514", "name": "Claude Sonnet 4", "description": "Fast and capable"},
            {"id": "claude-opus-4-20250514", "name": "Claude Opus 4", "description": "Most capable"},
            {"id": "claude-haiku-4-20250514", "name": "Claude Haiku 4", "description": "Fastest, most economical"}
        ]
    }


# ============== Elasticsearch Scan History Endpoints ==============

@app.get("/api/scans")
async def search_scans(
    query: Optional[str] = None,
    severity: Optional[str] = None,
    department: Optional[str] = None,
    filetype: Optional[str] = None,
    date_from: Optional[str] = None,
    date_to: Optional[str] = None,
    min_score: Optional[int] = None,
    max_score: Optional[int] = None,
    scanned_by: Optional[str] = None,  # FR-009: Filter by user
    file_hash: Optional[str] = None,  # FR-007: Search by file hash
    page: int = 1,
    size: int = 20,
    sort_by: str = "timestamp",
    sort_order: str = "desc"
):
    """
    Search and retrieve scan history from Elasticsearch.

    Supports:
    - Full-text search across filename and content
    - Filtering by severity, department, filetype, date range, score range, user
    - Pagination and sorting

    Falls back to JSON file storage if Elasticsearch is not enabled.
    """
    if es_service.is_enabled:
        return await es_service.search_scans(
            query=query,
            severity=severity,
            department=department,
            filetype=filetype,
            date_from=date_from,
            date_to=date_to,
            min_score=min_score,
            max_score=max_score,
            scanned_by=scanned_by,  # FR-009: Pass user filter
            file_hash=file_hash,  # FR-007: Pass file hash filter
            page=page,
            size=size,
            sort_by=sort_by,
            sort_order=sort_order
        )

    # Fall back to JSON file storage
    incidents = load_incidents()

    # Apply basic filters
    if severity:
        incidents = [i for i in incidents if i.get("sensitivity_level") == severity.upper()]
    if department:
        incidents = [i for i in incidents if department in i.get("departments_affected", [])]

    total = len(incidents)
    start = (page - 1) * size
    incidents = incidents[start:start + size]

    return {
        "total": total,
        "page": page,
        "size": size,
        "pages": (total + size - 1) // size if total > 0 else 0,
        "scans": incidents
    }


@app.get("/api/scans/aggregations")
async def get_scan_aggregations():
    """
    Get aggregated statistics from Elasticsearch.

    Returns counts by severity, department, filetype, category,
    average score, and timeline data.
    """
    if es_service.is_enabled:
        return await es_service.get_aggregations()

    # Fall back to regular stats
    return await get_statistics()


@app.get("/api/scans/{scan_id}")
async def get_scan_details(scan_id: str):
    """Get full details of a specific scan."""
    if es_service.is_enabled:
        scan = await es_service.get_scan(scan_id)
        if scan:
            return scan

    # Fall back to incidents file
    incidents = load_incidents()
    for incident in incidents:
        if incident.get("id") == scan_id:
            return incident

    raise HTTPException(status_code=404, detail="Scan not found")


@app.delete("/api/scans/{scan_id}")
async def delete_scan(scan_id: str):
    """Delete a scan from Elasticsearch and optionally its file."""
    deleted_from_es = False
    deleted_file = False

    if es_service.is_enabled:
        # Get scan to find file_id before deleting
        scan = await es_service.get_scan(scan_id)
        if scan and scan.get("file_id"):
            deleted_file = await file_storage.delete_file(scan["file_id"])

        deleted_from_es = await es_service.delete_scan(scan_id)

    # Also delete from JSON file
    incidents = load_incidents()
    incidents = [i for i in incidents if i.get("id") != scan_id]
    save_incidents(incidents)

    return {
        "status": "deleted",
        "id": scan_id,
        "deleted_from_es": deleted_from_es,
        "deleted_file": deleted_file
    }


# ============== File Preview/Download Endpoints ==============

@app.get("/api/files/{file_id}/preview")
async def preview_file(file_id: str, max_chars: int = 5000):
    """
    Get text preview of a stored file.

    Args:
        file_id: UUID of the stored file
        max_chars: Maximum characters to return (default 5000)
    """
    preview = await file_storage.get_preview(file_id, max_chars)

    if preview is None:
        raise HTTPException(status_code=404, detail="File not found")

    return preview


@app.get("/api/files/{file_id}/download")
async def download_file(file_id: str):
    """
    Download original file.

    Args:
        file_id: UUID of the stored file
    """
    result = await file_storage.get_file(file_id)

    if result is None:
        raise HTTPException(status_code=404, detail="File not found")

    file_path, content_type = result

    return FileResponse(
        path=str(file_path),
        media_type=content_type,
        filename=file_path.name
    )


@app.get("/api/files/stats")
async def get_file_storage_stats():
    """Get file storage statistics."""
    return await file_storage.get_storage_stats()


@app.post("/api/files/cleanup")
async def cleanup_old_files():
    """
    Clean up files older than retention period.
    Uses retention_days from processing config.
    """
    config = config_manager.load_config()
    retention_days = config.processing.retention_days

    result = await file_storage.cleanup_old_files(retention_days)
    return {
        "status": "success",
        "retention_days": retention_days,
        **result
    }


# ============== File Processor Endpoints (FR-001) ==============

@app.get("/api/processor/capabilities")
async def get_processor_capabilities():
    """
    Get file processor capabilities and supported formats.
    Returns available extraction methods and OCR status.
    """
    capabilities = file_processor.get_capabilities()
    formats = file_processor.get_supported_formats()

    return {
        "capabilities": capabilities,
        "supported_formats": formats,
        "max_file_size_mb": file_processor.max_file_size_bytes // (1024 * 1024),
        "max_chunk_size": file_processor.max_chunk_size
    }


@app.get("/api/processor/formats")
async def get_supported_formats():
    """Get list of all supported file formats organized by category."""
    return file_processor.get_supported_formats()


# ============== Oversized File Logging (FR-004) ==============

class OversizedFileAcknowledgment(BaseModel):
    """Model for oversized file acknowledgment logging."""
    filename: str
    filesize_bytes: int
    filesize_display: str
    user_acknowledged: bool = True


# Store oversized file attempts in memory (could be moved to ES later)
_oversized_file_log = []


@app.post("/api/log/oversized-file")
async def log_oversized_file(
    ack: OversizedFileAcknowledgment,
    request: Request
):
    """
    Log when a user attempts to upload a file exceeding 10GB limit.
    User must acknowledge they will contact IT for assistance.
    """
    timestamp = datetime.utcnow().isoformat() + "Z"
    client_ip = request.client.host if request.client else "unknown"
    user_agent = request.headers.get("user-agent", "unknown")

    log_entry = {
        "id": str(uuid.uuid4()),
        "timestamp": timestamp,
        "event_type": "OVERSIZED_FILE_ATTEMPT",
        "filename": ack.filename,
        "filesize_bytes": ack.filesize_bytes,
        "filesize_display": ack.filesize_display,
        "max_allowed_gb": 10,
        "user_acknowledged": ack.user_acknowledged,
        "client_ip": client_ip,
        "user_agent": user_agent,
        "action_required": "Contact IT for large file processing"
    }

    # Store in memory log
    _oversized_file_log.append(log_entry)

    # Also log to Elasticsearch if enabled
    if es_service.is_enabled:
        try:
            await es_service.client.index(
                index=f"sentineldlp-oversized-{datetime.utcnow().strftime('%Y-%m')}",
                document=log_entry
            )
        except Exception as e:
            print(f"Warning: Failed to log oversized file to ES: {e}")

    # Also write to a file for audit
    try:
        log_file = DATA_DIR / "oversized_files.log"
        with open(log_file, "a") as f:
            f.write(json.dumps(log_entry) + "\n")
    except Exception as e:
        print(f"Warning: Failed to write oversized file log: {e}")

    return {
        "status": "logged",
        "log_id": log_entry["id"],
        "message": "Oversized file attempt has been logged. Please contact IT for assistance with files larger than 10GB.",
        "timestamp": timestamp
    }


@app.get("/api/log/oversized-files")
async def get_oversized_file_logs(limit: int = 100):
    """
    Get recent oversized file attempt logs for admin review.
    """
    # Return most recent entries first
    return {
        "logs": _oversized_file_log[-limit:][::-1],
        "total": len(_oversized_file_log)
    }


# ============== Admin Configuration Endpoints (FR-002) ==============

class AdminConfigUpdate(BaseModel):
    """Model for admin configuration updates."""
    llm: Optional[dict] = None
    elasticsearch: Optional[dict] = None
    active_directory: Optional[dict] = None
    processing: Optional[dict] = None
    security: Optional[dict] = None


def get_client_info(request: Request) -> tuple:
    """Extract client IP and user agent from request."""
    ip_address = request.client.host if request.client else "unknown"
    user_agent = request.headers.get("user-agent", "unknown")
    return ip_address, user_agent


@app.get("/api/admin/config")
async def get_admin_config(request: Request):
    """
    Get current system configuration with secrets masked.
    
    Returns configuration for all categories:
    - LLM provider settings
    - Elasticsearch connection
    - Active Directory settings
    - Processing parameters
    - Security settings
    """
    try:
        config = config_manager.get_config_masked()
        config["first_run"] = config_manager.is_first_run()
        return config
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to load configuration: {str(e)}")


@app.put("/api/admin/config")
async def update_admin_config(update: AdminConfigUpdate, request: Request):
    """
    Update system configuration.
    
    Accepts partial updates - only provided fields will be updated.
    Secret fields are encrypted before storage.
    All changes are logged to audit trail.
    """
    ip_address, user_agent = get_client_info(request)
    
    try:
        updates = update.model_dump(exclude_unset=True, exclude_none=True)
        
        if not updates:
            raise HTTPException(status_code=400, detail="No configuration updates provided")
        
        config_manager.update_config(
            updates,
            user="admin",  # TODO: Get from auth when AD is implemented
            ip_address=ip_address,
            user_agent=user_agent
        )
        
        return {
            "status": "success",
            "message": "Configuration updated successfully",
            "updated_categories": list(updates.keys())
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to update configuration: {str(e)}")


@app.post("/api/admin/config/test")
async def test_admin_config(request: Request, category: str = "llm"):
    """
    Test configuration connectivity.
    
    Supports testing:
    - llm: Test LLM provider connection (Claude API, Ollama, vLLM)
    - elasticsearch: Test Elasticsearch connection
    - active_directory: Test AD/LDAP connection
    """
    config = config_manager.load_config()
    
    if category == "llm":
        # Test LLM connection
        if config.llm.provider == LLMProvider.CLAUDE_API:
            if not config.llm.claude_api_key:
                raise HTTPException(status_code=400, detail="Claude API key not configured")
            
            try:
                client = anthropic.Anthropic(api_key=config.llm.claude_api_key)
                response = client.messages.create(
                    model=config.llm.claude_model,
                    max_tokens=50,
                    messages=[{"role": "user", "content": "Say 'connected' in one word."}]
                )
                return {
                    "status": "success",
                    "provider": "claude_api",
                    "model": config.llm.claude_model,
                    "message": "Claude API connection verified"
                }
            except anthropic.AuthenticationError:
                raise HTTPException(status_code=401, detail="Invalid Claude API key")
            except anthropic.APIError as e:
                raise HTTPException(status_code=500, detail=f"Claude API error: {str(e)}")
        
        elif config.llm.provider == LLMProvider.OLLAMA:
            # Test Ollama connection
            import httpx
            try:
                async with httpx.AsyncClient(timeout=10.0) as client:
                    response = await client.get(f"{config.llm.ollama_endpoint}/api/tags")
                    if response.status_code == 200:
                        return {
                            "status": "success",
                            "provider": "ollama",
                            "endpoint": config.llm.ollama_endpoint,
                            "message": "Ollama connection verified"
                        }
                    else:
                        raise HTTPException(status_code=500, detail=f"Ollama returned status {response.status_code}")
            except Exception as e:
                raise HTTPException(status_code=500, detail=f"Ollama connection failed: {str(e)}")
        
        elif config.llm.provider == LLMProvider.VLLM:
            # Test vLLM connection
            import httpx
            try:
                async with httpx.AsyncClient(timeout=10.0) as client:
                    response = await client.get(f"{config.llm.vllm_endpoint}/health")
                    if response.status_code == 200:
                        return {
                            "status": "success",
                            "provider": "vllm",
                            "endpoint": config.llm.vllm_endpoint,
                            "message": "vLLM connection verified"
                        }
                    else:
                        raise HTTPException(status_code=500, detail=f"vLLM returned status {response.status_code}")
            except Exception as e:
                raise HTTPException(status_code=500, detail=f"vLLM connection failed: {str(e)}")
    
    elif category == "elasticsearch":
        if not config.elasticsearch.enabled:
            raise HTTPException(status_code=400, detail="Elasticsearch is not enabled")
        
        # Test Elasticsearch connection
        try:
            from elasticsearch import Elasticsearch
            
            es_config = {
                "hosts": config.elasticsearch.hosts,
                "verify_certs": config.elasticsearch.verify_certs
            }
            
            if config.elasticsearch.api_key:
                es_config["api_key"] = config.elasticsearch.api_key
            elif config.elasticsearch.username and config.elasticsearch.password:
                es_config["basic_auth"] = (config.elasticsearch.username, config.elasticsearch.password)
            
            if config.elasticsearch.ca_cert_path:
                es_config["ca_certs"] = config.elasticsearch.ca_cert_path
            
            es = Elasticsearch(**es_config)
            info = es.info()
            
            return {
                "status": "success",
                "cluster_name": info.get("cluster_name"),
                "version": info.get("version", {}).get("number"),
                "message": "Elasticsearch connection verified"
            }
        except ImportError:
            raise HTTPException(status_code=500, detail="Elasticsearch library not installed")
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Elasticsearch connection failed: {str(e)}")
    
    elif category == "active_directory":
        if not config.active_directory.enabled:
            raise HTTPException(status_code=400, detail="Active Directory is not enabled")
        
        # Test AD/LDAP connection
        try:
            import ldap3
            
            server = ldap3.Server(
                config.active_directory.server,
                port=config.active_directory.port,
                use_ssl=config.active_directory.use_ssl,
                get_info=ldap3.ALL
            )
            
            conn = ldap3.Connection(
                server,
                user=config.active_directory.bind_user,
                password=config.active_directory.bind_password,
                auto_bind=True
            )
            
            conn.unbind()
            
            return {
                "status": "success",
                "server": config.active_directory.server,
                "message": "Active Directory connection verified"
            }
        except ImportError:
            raise HTTPException(status_code=500, detail="ldap3 library not installed")
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Active Directory connection failed: {str(e)}")
    
    else:
        raise HTTPException(status_code=400, detail=f"Unknown test category: {category}")


@app.post("/api/admin/config/rotate-key")
async def rotate_encryption_key(request: Request):
    """
    Rotate the master encryption key.
    
    This re-encrypts all stored secrets with a new key.
    The old key is backed up temporarily and removed after successful rotation.
    """
    ip_address, user_agent = get_client_info(request)
    
    try:
        success = config_manager.rotate_encryption_key(
            user="admin",  # TODO: Get from auth when AD is implemented
            ip_address=ip_address,
            user_agent=user_agent
        )
        
        if success:
            return {
                "status": "success",
                "message": "Encryption key rotated successfully"
            }
        else:
            raise HTTPException(status_code=500, detail="Key rotation failed")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Key rotation failed: {str(e)}")


@app.get("/api/admin/config/audit")
async def get_config_audit_log(limit: int = 100, offset: int = 0):
    """
    Get configuration change audit log.
    
    Returns a paginated list of configuration changes with:
    - Timestamp
    - User who made the change
    - Category and field changed
    - Hash of old/new values (actual values never logged)
    """
    try:
        audit_log = config_manager.get_audit_log(limit=limit, offset=offset)
        return audit_log
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to load audit log: {str(e)}")


@app.get("/api/admin/config/status")
async def get_config_status():
    """
    Get configuration status summary.
    
    Returns status of each configuration category:
    - Whether it's configured
    - Whether it's enabled
    - Last modification time
    """
    config = config_manager.load_config()
    
    return {
        "first_run": config_manager.is_first_run(),
        "version": config.version,
        "last_modified": config.last_modified,
        "last_modified_by": config.last_modified_by,
        "categories": {
            "llm": {
                "configured": bool(config.llm.claude_api_key) or config.llm.provider != LLMProvider.CLAUDE_API,
                "provider": config.llm.provider.value,
                "model": config.llm.claude_model if config.llm.provider == LLMProvider.CLAUDE_API else config.llm.ollama_model
            },
            "elasticsearch": {
                "enabled": config.elasticsearch.enabled,
                "configured": bool(config.elasticsearch.hosts)
            },
            "active_directory": {
                "enabled": config.active_directory.enabled,
                "configured": bool(config.active_directory.server)
            },
            "processing": {
                "max_file_size_mb": config.processing.max_file_size_mb,
                "ocr_enabled": config.processing.ocr_enabled
            },
            "security": {
                "session_timeout_minutes": config.security.session_timeout_minutes,
                "audit_retention_days": config.security.audit_retention_days
            }
        }
    }


# ============== Async Job Endpoints (FR-005/GAP-001) ==============

class AsyncJobRequest(BaseModel):
    """Request model for async analysis."""
    document_text: Optional[str] = None
    filename: str = "unknown"
    filetype: str = "unknown"
    filesize: str = "unknown"


@app.post("/api/jobs/analyze")
async def submit_async_analysis(file: UploadFile = File(...), request: Request = None, user: dict = Depends(get_current_user)):
    """
    Submit a file for async analysis via Celery queue.

    Returns a job_id that can be used to check status and retrieve results.
    Falls back to sync processing if Celery is not available.
    """
    if not CELERY_ENABLED:
        # Fall back to sync processing
        return await analyze_file(file, request, user)

    settings = load_settings()
    config = config_manager.load_config()

    if not settings.api_key:
        raise HTTPException(status_code=400, detail="API key not configured")

    # Read and process file
    content = await file.read()
    filesize_bytes = len(content)
    filename = file.filename or "unknown"

    # File size validation
    MAX_FILE_SIZE_GB = 10
    MAX_FILE_SIZE_BYTES = MAX_FILE_SIZE_GB * 1024 * 1024 * 1024
    if filesize_bytes > MAX_FILE_SIZE_BYTES:
        raise HTTPException(
            status_code=413,
            detail=f"File too large: {filesize_bytes / (1024**3):.2f} GB. Maximum: {MAX_FILE_SIZE_GB} GB."
        )

    # Process file
    try:
        processed = await file_processor.process_file(content, filename)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"File processing failed: {str(e)}")

    document_text = processed.text_content
    if not document_text or not document_text.strip():
        raise HTTPException(status_code=400, detail="Could not extract text from file")

    filetype = processed.detected_type.extension
    filesize = f"{filesize_bytes} bytes"

    # Store file if needed
    file_id = str(uuid.uuid4())
    file_stored = False
    if es_service.is_enabled and not config.processing.auto_delete_uploads:
        try:
            file_id, _ = await file_storage.store_file(content, filename, file_id)
            file_stored = True
        except Exception as e:
            print(f"Warning: Failed to store file: {e}")

    # Submit to Celery queue
    task = analyze_document_task.delay(
        document_text=document_text,
        filename=filename,
        filetype=filetype,
        filesize=filesize,
        filesize_bytes=filesize_bytes,
        file_id=file_id if file_stored else None,
        file_stored=file_stored,
        client_ip=request.client.host if request and request.client else None,
        user_agent=request.headers.get("user-agent") if request else None,
        ocr_applied=processed.ocr_applied,
        page_count=processed.page_count,
        word_count=processed.word_count,
        detected_mime_type=processed.detected_type.mime_type,
        file_category=processed.detected_type.category.value,
        extraction_warnings=processed.extraction_warnings,
        scanned_by=user.get("sub") if user else None  # FR-009: User tracking
    )

    return {
        "job_id": task.id,
        "status": "PENDING",
        "message": "Analysis job submitted to queue",
        "filename": filename,
        "filesize": filesize,
        "queue_position": None  # Could be calculated if needed
    }


@app.get("/api/jobs/{job_id}")
async def get_job_status(job_id: str):
    """
    Get the status and result of an async analysis job.

    Status values:
    - PENDING: Job is waiting in queue
    - ANALYZING: Job is being processed
    - SUCCESS: Job completed successfully (result included)
    - FAILURE: Job failed (error included)
    - REVOKED: Job was cancelled
    """
    if not CELERY_ENABLED:
        raise HTTPException(status_code=400, detail="Async jobs not enabled")

    try:
        task = AsyncResult(job_id, app=celery_app)

        response = {
            "job_id": job_id,
            "status": task.status,
            "ready": task.ready(),
            "successful": task.successful() if task.ready() else None
        }

        # Add progress info for ANALYZING state
        if task.status == "ANALYZING" and task.info:
            response["progress"] = task.info.get("progress", 0)
            response["stage"] = task.info.get("stage", "Processing")
            response["filename"] = task.info.get("filename")

        # Add result if complete
        if task.ready():
            if task.successful():
                result = task.result
                response["result"] = result

                # Index to ES if not already done
                if es_service.is_enabled and result.get("status") == "completed":
                    try:
                        await es_service.index_scan(result)
                    except Exception as e:
                        print(f"Warning: Failed to index to ES: {e}")
            else:
                response["error"] = str(task.result) if task.result else "Unknown error"

        return response

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get job status: {str(e)}")


@app.delete("/api/jobs/{job_id}")
async def cancel_job(job_id: str):
    """Cancel a pending or running job."""
    if not CELERY_ENABLED:
        raise HTTPException(status_code=400, detail="Async jobs not enabled")

    try:
        task = AsyncResult(job_id, app=celery_app)
        task.revoke(terminate=True)
        return {"job_id": job_id, "status": "REVOKED", "message": "Job cancelled"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to cancel job: {str(e)}")


@app.get("/api/jobs/queue/stats")
async def get_queue_stats():
    """
    Get queue statistics for monitoring.

    Returns:
    - Active workers count
    - Tasks in queue
    - Tasks being processed
    - Tasks completed (recent)
    """
    if not CELERY_ENABLED:
        return {
            "celery_enabled": False,
            "message": "Running in synchronous mode"
        }

    try:
        # Get worker stats
        inspect = celery_app.control.inspect()

        # Active tasks (currently being processed)
        active = inspect.active() or {}
        active_count = sum(len(tasks) for tasks in active.values())

        # Reserved tasks (in queue, assigned to workers)
        reserved = inspect.reserved() or {}
        reserved_count = sum(len(tasks) for tasks in reserved.values())

        # Scheduled tasks
        scheduled = inspect.scheduled() or {}
        scheduled_count = sum(len(tasks) for tasks in scheduled.values())

        # Worker count
        worker_count = len(active.keys())

        # Get queue length from Redis
        queue_length = 0
        try:
            import redis
            redis_url = os.getenv("REDIS_URL", "redis://redis:6379/0")
            r = redis.from_url(redis_url)
            queue_length = r.llen("sentineldlp_analysis")
        except Exception:
            pass

        return {
            "celery_enabled": True,
            "workers": {
                "count": worker_count,
                "names": list(active.keys())
            },
            "tasks": {
                "active": active_count,
                "reserved": reserved_count,
                "scheduled": scheduled_count,
                "queued": queue_length
            },
            "status": "healthy" if worker_count > 0 else "no_workers"
        }

    except Exception as e:
        return {
            "celery_enabled": True,
            "status": "error",
            "error": str(e)
        }


# ============== Authentication Endpoints (FR-006/GAP-002) ==============

@app.post("/api/auth/login")
async def login(login_request: LoginRequest, request: Request):
    """
    Authenticate user and return JWT tokens.

    Supports three provider modes:
    - auto: Try local first, then LDAP if configured
    - local: Only authenticate against local user database
    - ldap: Only authenticate against Active Directory

    Returns access_token (in body) and sets refresh_token as HttpOnly cookie.

    Security (FR-006 Phase 2):
    - Rate limiting: 5 attempts per 15 minutes per IP+username
    - HttpOnly cookie for refresh token (XSS protection)
    - CSRF token set on successful login
    """
    ip_address = request.client.host if request.client else "unknown"
    user_agent = request.headers.get("user-agent", "unknown")
    provider = login_request.provider or "auto"

    # FR-006 Phase 2: Rate limiting check
    rate_check = check_rate_limit(request, "login", login_request.username)
    if rate_check["limited"]:
        auth_audit.log_event(
            event_type="LOGIN_RATE_LIMITED",
            username=login_request.username,
            success=False,
            provider=provider,
            ip_address=ip_address,
            user_agent=user_agent,
            details={"retry_after": rate_check["retry_after"]}
        )
        raise HTTPException(
            status_code=429,
            detail=f"Too many login attempts. Try again in {rate_check['retry_after']} seconds.",
            headers={
                "Retry-After": str(rate_check["retry_after"]),
                "X-RateLimit-Remaining": "0"
            }
        )

    user_data = None
    auth_provider = None

    # Try authentication based on provider mode
    if provider in ["auto", "local"]:
        # Try local authentication
        local_user, error = user_manager.authenticate(
            login_request.username,
            login_request.password
        )
        if local_user:
            user_data = {
                "id": local_user.id,
                "username": local_user.username,
                "email": local_user.email,
                "role": local_user.role,
                "display_name": local_user.display_name,
                "must_change_password": local_user.must_change_password
            }
            auth_provider = AuthProvider.LOCAL

            # Log successful login
            auth_audit.log_event(
                event_type="LOGIN_SUCCESS",
                username=login_request.username,
                success=True,
                provider="local",
                ip_address=ip_address,
                user_agent=user_agent
            )

    # Try LDAP if local failed and LDAP is configured
    if not user_data and provider in ["auto", "ldap"]:
        if ldap_connector.is_enabled:
            ldap_user = ldap_connector.authenticate(
                login_request.username,
                login_request.password
            )
            if ldap_user:
                user_data = {
                    "id": ldap_user.distinguished_name,
                    "username": ldap_user.username,
                    "email": ldap_user.email or f"{ldap_user.username}@{ldap_connector.domain}",
                    "role": ldap_connector.get_role_for_user(ldap_user).value,
                    "display_name": ldap_user.display_name,
                    "must_change_password": False,
                    "groups": ldap_user.groups
                }
                auth_provider = AuthProvider.LDAP

                # Log successful LDAP login
                auth_audit.log_event(
                    event_type="LOGIN_SUCCESS",
                    username=login_request.username,
                    success=True,
                    provider="ldap",
                    ip_address=ip_address,
                    user_agent=user_agent,
                    details={"groups": ldap_user.groups[:5]}  # Log first 5 groups
                )

    # Authentication failed
    if not user_data:
        # FR-006 Phase 2: Record failed attempt for rate limiting
        record_attempt(request, "login", login_request.username)

        # Log failed login
        auth_audit.log_event(
            event_type="LOGIN_FAILED",
            username=login_request.username,
            success=False,
            provider=provider,
            ip_address=ip_address,
            user_agent=user_agent
        )

        # Include remaining attempts in response
        rate_check = check_rate_limit(request, "login", login_request.username)
        raise HTTPException(
            status_code=401,
            detail="Invalid username or password",
            headers={"X-RateLimit-Remaining": str(rate_check["remaining"])}
        )

    # FR-006 Phase 2: Reset rate limit on successful login
    reset_rate_limit(request, "login", login_request.username)

    # Generate tokens
    role = UserRole(user_data["role"])
    tokens = auth_service.create_token_pair(
        user_id=user_data["id"],
        username=user_data["username"],
        role=role,
        provider=auth_provider,
        additional_claims={"email": user_data["email"]}
    )

    # FR-006 Phase 2: Build response with secure cookies
    response_data = {
        "access_token": tokens["access_token"],
        "token_type": tokens["token_type"],
        "expires_in": tokens["expires_in"],
        "user": {
            "id": user_data["id"],
            "username": user_data["username"],
            "email": user_data["email"],
            "role": user_data["role"],
            "display_name": user_data["display_name"],
            "must_change_password": user_data.get("must_change_password", False),
            "provider": auth_provider.value,
            "permissions": ROLE_PERMISSIONS.get(role, [])
        }
    }

    # Create response with cookies
    response = JSONResponse(content=response_data)

    # Set refresh token in HttpOnly cookie (XSS protection)
    SecureCookies.set_refresh_token(response, tokens["refresh_token"])

    # Set CSRF token cookie (readable by JavaScript for header)
    csrf_token = CSRFProtection.generate_token()
    CSRFProtection.set_csrf_cookie(response, csrf_token)

    return response


class RefreshTokenRequestOptional(BaseModel):
    """Optional refresh token in body (can also come from cookie)."""
    refresh_token: Optional[str] = None


@app.post("/api/auth/refresh")
async def refresh_token_endpoint(
    request: Request,
    response: Response,
    refresh_request: RefreshTokenRequestOptional = None
):
    """
    Get new access token using refresh token.

    FR-006 Phase 2: Refresh token is read from:
    1. HttpOnly cookie (preferred, secure against XSS)
    2. Request body (fallback for API clients)

    FR-006 Phase 3: Token Rotation
    - Each refresh returns a new refresh token
    - Old refresh token is invalidated
    - Cookie is updated with new token
    """
    # Try to get refresh token from cookie first (more secure)
    token = SecureCookies.get_refresh_token(request)

    # Fall back to request body if no cookie
    if not token and refresh_request and refresh_request.refresh_token:
        token = refresh_request.refresh_token

    if not token:
        raise HTTPException(
            status_code=401,
            detail="Refresh token required (in cookie or request body)"
        )

    result = auth_service.refresh_access_token(token)

    if not result:
        raise HTTPException(
            status_code=401,
            detail="Invalid or expired refresh token"
        )

    # FR-006 Phase 3: Set new refresh token cookie (token rotation)
    if "refresh_token" in result:
        SecureCookies.set_refresh_token(response, result["refresh_token"])
        # Remove refresh_token from response body (security - avoid exposure)
        del result["refresh_token"]

    return result


@app.post("/api/auth/logout")
async def logout(request: Request, user: dict = Depends(get_current_user)):
    """
    Logout user by revoking refresh token.

    FR-006 Phase 2: Reads refresh token from cookie or body, clears all auth cookies.
    """
    ip_address = request.client.host if request.client else "unknown"
    user_agent = request.headers.get("user-agent", "unknown")

    # Try to get refresh token from cookie first
    refresh_token = SecureCookies.get_refresh_token(request)

    # Fall back to request body
    if not refresh_token:
        try:
            body = await request.json()
            refresh_token = body.get("refresh_token")
        except Exception:
            pass

    # Revoke the refresh token if found
    if refresh_token:
        auth_service.revoke_refresh_token(refresh_token)

    # Log logout
    auth_audit.log_event(
        event_type="LOGOUT",
        username=user.get("username", "unknown"),
        success=True,
        provider=user.get("provider", "unknown"),
        ip_address=ip_address,
        user_agent=user_agent
    )

    # FR-006 Phase 2: Clear all auth cookies
    response = JSONResponse(
        content={"status": "logged_out", "message": "Successfully logged out"}
    )
    SecureCookies.clear_all_auth_cookies(response)

    return response


@app.get("/api/auth/me")
async def get_current_user_info(user: dict = Depends(get_current_user)):
    """
    Get current user information from JWT token.

    Returns user details including role and permissions.
    """
    role = UserRole(user.get("role", "viewer"))

    return {
        "id": user.get("sub"),
        "username": user.get("username"),
        "email": user.get("email"),
        "role": user.get("role"),
        "provider": user.get("provider"),
        "permissions": auth_service.get_role_permissions(role),
        "token_expires": user.get("exp")
    }


@app.post("/api/auth/change-password")
async def change_password(
    password_request: PasswordChangeRequest,
    request: Request,
    user: dict = Depends(get_current_user)
):
    """
    Change current user's password.

    For local users only. LDAP users must change password via AD.
    """
    if user.get("provider") == "ldap":
        raise HTTPException(
            status_code=400,
            detail="LDAP users must change password via Active Directory"
        )

    ip_address = request.client.host if request.client else "unknown"
    user_agent = request.headers.get("user-agent", "unknown")
    user_id = user.get("sub")

    # Verify current password if provided
    local_user = user_manager.get_user(user_id)
    if not local_user:
        raise HTTPException(status_code=404, detail="User not found")

    if password_request.current_password:
        if not auth_service.verify_password(
            password_request.current_password,
            local_user.password_hash
        ):
            raise HTTPException(status_code=400, detail="Current password is incorrect")

    # Change password
    try:
        success = user_manager.change_password(user_id, password_request.new_password)
        if not success:
            raise HTTPException(status_code=500, detail="Failed to change password")

        # Log password change
        auth_audit.log_event(
            event_type="PASSWORD_CHANGED",
            username=user.get("username"),
            success=True,
            provider="local",
            ip_address=ip_address,
            user_agent=user_agent
        )

        return {"status": "success", "message": "Password changed successfully"}

    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


# ============== User Management Endpoints (FR-006/GAP-002) ==============

@app.get("/api/users")
async def list_users(
    role: Optional[str] = None,
    enabled_only: bool = False,
    user: dict = Depends(require_role([UserRole.ADMIN]))
):
    """
    List all local users. Admin only.

    Supports filtering by role and enabled status.
    """
    role_filter = UserRole(role) if role else None
    users = user_manager.list_users(role=role_filter, enabled_only=enabled_only)

    return {
        "users": [u.to_dict(include_password=False) for u in users],
        "total": len(users)
    }


@app.post("/api/users")
async def create_user(
    user_request: UserCreateRequest,
    request: Request,
    admin: dict = Depends(require_role([UserRole.ADMIN]))
):
    """
    Create a new local user. Admin only.
    """
    ip_address = request.client.host if request.client else "unknown"
    user_agent = request.headers.get("user-agent", "unknown")

    try:
        role = UserRole(user_request.role)
    except ValueError:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid role: {user_request.role}. Valid roles: admin, analyst, viewer"
        )

    try:
        new_user = user_manager.create_user(
            username=user_request.username,
            password=user_request.password,
            email=user_request.email,
            role=role,
            display_name=user_request.display_name
        )

        # Log user creation
        auth_audit.log_event(
            event_type="USER_CREATED",
            username=user_request.username,
            success=True,
            provider="local",
            ip_address=ip_address,
            user_agent=user_agent,
            details={"created_by": admin.get("username"), "role": role.value}
        )

        return {
            "status": "created",
            "user": new_user.to_dict(include_password=False)
        }

    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.get("/api/users/stats")
async def get_user_stats(admin: dict = Depends(require_role([UserRole.ADMIN]))):
    """
    Get user statistics. Admin only.
    """
    return user_manager.get_stats()


@app.get("/api/users/{user_id}")
async def get_user(
    user_id: str,
    admin: dict = Depends(require_role([UserRole.ADMIN]))
):
    """
    Get user details by ID. Admin only.
    """
    user = user_manager.get_user(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    return user.to_dict(include_password=False)


@app.put("/api/users/{user_id}")
async def update_user(
    user_id: str,
    user_request: UserUpdateRequest,
    request: Request,
    admin: dict = Depends(require_role([UserRole.ADMIN]))
):
    """
    Update user properties. Admin only.
    """
    ip_address = request.client.host if request.client else "unknown"
    user_agent = request.headers.get("user-agent", "unknown")

    role = None
    if user_request.role:
        try:
            role = UserRole(user_request.role)
        except ValueError:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid role: {user_request.role}"
            )

    try:
        updated_user = user_manager.update_user(
            user_id=user_id,
            email=user_request.email,
            role=role,
            display_name=user_request.display_name,
            enabled=user_request.enabled
        )

        if not updated_user:
            raise HTTPException(status_code=404, detail="User not found")

        # Log update
        auth_audit.log_event(
            event_type="USER_UPDATED",
            username=updated_user.username,
            success=True,
            provider="local",
            ip_address=ip_address,
            user_agent=user_agent,
            details={"updated_by": admin.get("username")}
        )

        return {
            "status": "updated",
            "user": updated_user.to_dict(include_password=False)
        }

    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.delete("/api/users/{user_id}")
async def delete_user(
    user_id: str,
    request: Request,
    admin: dict = Depends(require_role([UserRole.ADMIN]))
):
    """
    Delete user account. Admin only.
    """
    ip_address = request.client.host if request.client else "unknown"
    user_agent = request.headers.get("user-agent", "unknown")

    user = user_manager.get_user(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    try:
        success = user_manager.delete_user(user_id)
        if not success:
            raise HTTPException(status_code=500, detail="Failed to delete user")

        # Log deletion
        auth_audit.log_event(
            event_type="USER_DELETED",
            username=user.username,
            success=True,
            provider="local",
            ip_address=ip_address,
            user_agent=user_agent,
            details={"deleted_by": admin.get("username")}
        )

        return {"status": "deleted", "username": user.username}

    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/api/users/{user_id}/reset-password")
async def admin_reset_password(
    user_id: str,
    password_request: PasswordChangeRequest,
    request: Request,
    admin: dict = Depends(require_role([UserRole.ADMIN]))
):
    """
    Admin reset user password. Sets must_change_password flag.
    """
    ip_address = request.client.host if request.client else "unknown"
    user_agent = request.headers.get("user-agent", "unknown")

    user = user_manager.get_user(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    try:
        success = user_manager.change_password(
            user_id,
            password_request.new_password,
            require_change=True  # Force password change on next login
        )

        if not success:
            raise HTTPException(status_code=500, detail="Failed to reset password")

        # Log password reset
        auth_audit.log_event(
            event_type="PASSWORD_RESET",
            username=user.username,
            success=True,
            provider="local",
            ip_address=ip_address,
            user_agent=user_agent,
            details={"reset_by": admin.get("username")}
        )

        return {"status": "success", "message": f"Password reset for {user.username}"}

    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/api/users/{user_id}/unlock")
async def unlock_user(
    user_id: str,
    request: Request,
    admin: dict = Depends(require_role([UserRole.ADMIN]))
):
    """
    Unlock a locked user account. Admin only.
    """
    ip_address = request.client.host if request.client else "unknown"
    user_agent = request.headers.get("user-agent", "unknown")

    user = user_manager.get_user(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    success = user_manager.reset_failed_attempts(user_id)
    if not success:
        raise HTTPException(status_code=500, detail="Failed to unlock user")

    # Log unlock
    auth_audit.log_event(
        event_type="USER_UNLOCKED",
        username=user.username,
        success=True,
        provider="local",
        ip_address=ip_address,
        user_agent=user_agent,
        details={"unlocked_by": admin.get("username")}
    )

    return {"status": "unlocked", "username": user.username}


# ============== LDAP/AD Endpoints (FR-006/GAP-002) ==============

@app.get("/api/ldap/status")
async def get_ldap_status(admin: dict = Depends(require_role([UserRole.ADMIN]))):
    """
    Get LDAP/AD connection status. Admin only.
    """
    if not ldap_connector.is_enabled:
        return {
            "enabled": False,
            "message": "LDAP is not configured"
        }

    return {
        "enabled": True,
        "server": ldap_connector.server,
        "domain": ldap_connector.domain,
        "base_dn": ldap_connector.base_dn,
        "use_ssl": ldap_connector.use_ssl,
        "use_starttls": ldap_connector.use_starttls
    }


@app.post("/api/ldap/test")
async def test_ldap_connection(
    request: Request,
    admin: dict = Depends(require_role([UserRole.ADMIN]))
):
    """
    Test LDAP/AD connection. Admin only.
    """
    if not ldap_connector.is_enabled:
        raise HTTPException(status_code=400, detail="LDAP is not configured")

    success, message = ldap_connector.test_connection()

    if success:
        return {
            "status": "success",
            "message": message,
            "server": ldap_connector.server
        }
    else:
        raise HTTPException(status_code=500, detail=message)


@app.get("/api/ldap/groups")
async def get_ldap_role_mappings(admin: dict = Depends(require_role([UserRole.ADMIN]))):
    """
    Get LDAP group to role mappings. Admin only.
    """
    if not ldap_connector.is_enabled:
        raise HTTPException(status_code=400, detail="LDAP is not configured")

    return {
        "mappings": {
            "admin_groups": ldap_connector.admin_groups,
            "analyst_groups": ldap_connector.analyst_groups,
            "viewer_groups": ldap_connector.viewer_groups,
            "default_role": ldap_connector.default_role.value
        }
    }


@app.get("/api/ldap/search")
async def search_ldap_users(
    query: str,
    limit: int = 20,
    admin: dict = Depends(require_role([UserRole.ADMIN]))
):
    """
    Search for users in Active Directory. Admin only.
    """
    if not ldap_connector.is_enabled:
        raise HTTPException(status_code=400, detail="LDAP is not configured")

    users = ldap_connector.search_users(query, max_results=limit)

    return {
        "query": query,
        "results": [
            {
                "username": u.username,
                "email": u.email,
                "display_name": u.display_name,
                "groups": u.groups[:5],  # First 5 groups
                "role": ldap_connector.get_role_for_user(u).value
            }
            for u in users
        ],
        "total": len(users)
    }


# ============== Auth Audit Endpoints (FR-006/GAP-002) ==============

@app.get("/api/auth/audit")
async def get_auth_audit_log(
    limit: int = 100,
    username: Optional[str] = None,
    event_type: Optional[str] = None,
    admin: dict = Depends(require_role([UserRole.ADMIN]))
):
    """
    Get authentication audit log. Admin only.
    """
    events = auth_audit.get_recent_events(
        limit=limit,
        username=username,
        event_type=event_type
    )

    return {
        "events": events,
        "total": len(events)
    }


@app.get("/api/auth/config")
async def get_auth_config():
    """
    Get authentication configuration (public info only).
    """
    return {
        "mode": AUTH_MODE,
        "local_enabled": True,
        "ldap_enabled": ldap_connector.is_enabled,
        "ldap_domain": ldap_connector.domain if ldap_connector.is_enabled else None
    }


@app.get("/api/system/status")
async def get_system_status():
    """
    Get overall system status including all services.
    """
    status = {
        "api": "healthy",
        "version": "1.6.0",
        "celery_enabled": CELERY_ENABLED,
        "timestamp": datetime.utcnow().isoformat() + "Z"
    }

    # Check Elasticsearch
    if es_service.is_enabled:
        try:
            es_healthy = await es_service.health_check()
            status["elasticsearch"] = "healthy" if es_healthy else "unhealthy"
        except Exception:
            status["elasticsearch"] = "error"
    else:
        status["elasticsearch"] = "disabled"

    # Check Redis/Celery
    if CELERY_ENABLED:
        try:
            import redis
            redis_url = os.getenv("REDIS_URL", "redis://redis:6379/0")
            r = redis.from_url(redis_url)
            r.ping()
            status["redis"] = "healthy"

            # Check workers
            inspect = celery_app.control.inspect()
            workers = inspect.ping() or {}
            status["celery_workers"] = len(workers)
        except Exception as e:
            status["redis"] = "error"
            status["celery_workers"] = 0
    else:
        status["redis"] = "disabled"
        status["celery_workers"] = 0

    # Check file storage
    try:
        storage_stats = await file_storage.get_storage_stats()
        status["file_storage"] = "healthy"
        status["files_stored"] = storage_stats.get("file_count", 0)
    except Exception:
        status["file_storage"] = "error"

    return status


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)

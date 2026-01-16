"""
SentinelDLP - Celery Tasks (FR-005/GAP-001)
Async document analysis tasks for enterprise scalability
"""

import os
import json
import uuid
import hashlib
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict, Any

from celery import shared_task
from celery.exceptions import SoftTimeLimitExceeded

import anthropic

# Import from celery_app
from celery_app import celery_app

# Data paths
if Path("/app/main.py").exists():
    DATA_DIR = Path("/app/data")
else:
    DATA_DIR = Path(__file__).parent.parent / "data"

CONFIG_DIR = DATA_DIR / "config"
SETTINGS_FILE = DATA_DIR / "settings.json"
INCIDENTS_FILE = DATA_DIR / "incidents.json"


def load_settings() -> dict:
    """Load settings from file."""
    if SETTINGS_FILE.exists():
        with open(SETTINGS_FILE, 'r') as f:
            return json.load(f)
    return {"api_key": "", "model": "claude-sonnet-4-20250514", "max_tokens": 4096}


def load_incidents() -> list:
    """Load incidents from file."""
    if INCIDENTS_FILE.exists():
        with open(INCIDENTS_FILE, 'r') as f:
            return json.load(f)
    return []


def save_incidents(incidents: list):
    """Save incidents to file."""
    with open(INCIDENTS_FILE, 'w') as f:
        json.dump(incidents, f, indent=2, default=str)


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


def add_incident(result: dict, doc_hash: str):
    """Add incident to JSON file."""
    incidents = load_incidents()

    dim_scores = result.get("dimension_scores", {})
    top_cats = [k for k, v in dim_scores.items() if v > 50]

    dept_rel = result.get("department_relevance", {})
    affected_depts = [k for k, v in dept_rel.items() if v in ["HIGH", "CRITICAL"]]

    incident = {
        "id": result["id"],
        "timestamp": result["timestamp"],
        "filename": result["filename"],
        "filetype": result["filetype"],
        "filesize": result["filesize"],
        "sensitivity_level": result["sensitivity_level"],
        "overall_score": result["overall_sensitivity_score"],
        "top_categories": top_cats,
        "departments_affected": affected_depts,
        "status": result["status"],
        "hash": doc_hash
    }

    incidents.insert(0, incident)
    incidents = incidents[:1000]  # Keep last 1000
    save_incidents(incidents)


@celery_app.task(
    bind=True,
    name="tasks.analyze_document_task",
    max_retries=3,
    default_retry_delay=30,
    soft_time_limit=540,
    time_limit=600
)
def analyze_document_task(
    self,
    document_text: str,
    filename: str,
    filetype: str,
    filesize: str,
    filesize_bytes: int,
    file_id: Optional[str] = None,
    file_stored: bool = False,
    client_ip: Optional[str] = None,
    user_agent: Optional[str] = None,
    ocr_applied: bool = False,
    page_count: Optional[int] = None,
    word_count: Optional[int] = None,
    detected_mime_type: Optional[str] = None,
    file_category: Optional[str] = None,
    extraction_warnings: Optional[list] = None,
    scanned_by: Optional[str] = None  # FR-009: User tracking
) -> Dict[str, Any]:
    """
    Async task for document analysis.

    This task is executed by Celery workers, enabling:
    - 1000+ concurrent users
    - Automatic retry on failure
    - Task timeout handling
    - Progress tracking via task state
    """
    settings = load_settings()

    if not settings.get("api_key"):
        return {
            "status": "error",
            "error": "API key not configured"
        }

    analysis_id = str(uuid.uuid4())
    doc_hash = hashlib.sha256(document_text.encode()).hexdigest()[:16]
    timestamp = datetime.utcnow().isoformat() + "Z"

    # Update task state for progress tracking
    self.update_state(
        state="ANALYZING",
        meta={
            "progress": 10,
            "stage": "Starting analysis",
            "filename": filename,
            "analysis_id": analysis_id
        }
    )

    try:
        client = anthropic.Anthropic(api_key=settings["api_key"])

        # Smart text sampling for large files
        MAX_ANALYSIS_CHARS = 150000
        total_chars = len(document_text)
        text_was_sampled = False
        sampling_note = ""

        if total_chars > MAX_ANALYSIS_CHARS:
            text_was_sampled = True
            section_size = MAX_ANALYSIS_CHARS // 3

            begin_text = document_text[:section_size]
            middle_start = (total_chars - section_size) // 2
            middle_text = document_text[middle_start:middle_start + section_size]
            end_text = document_text[-section_size:]

            analysis_text = f"""[BEGINNING OF DOCUMENT - First {section_size:,} characters]
{begin_text}

[MIDDLE OF DOCUMENT - Characters {middle_start:,} to {middle_start + section_size:,}]
{middle_text}

[END OF DOCUMENT - Last {section_size:,} characters]
{end_text}"""

            sampling_note = f"\n\nNOTE: This is a large file ({total_chars:,} characters). Content has been sampled from beginning, middle, and end sections for analysis."
        else:
            analysis_text = document_text

        # Update progress
        self.update_state(
            state="ANALYZING",
            meta={
                "progress": 30,
                "stage": "Sending to Claude AI",
                "filename": filename,
                "analysis_id": analysis_id
            }
        )

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
            model=settings.get("model", "claude-sonnet-4-20250514"),
            max_tokens=settings.get("max_tokens", 4096),
            system=ANALYSIS_PROMPT,
            messages=[{"role": "user", "content": user_message}]
        )

        # Update progress
        self.update_state(
            state="ANALYZING",
            meta={
                "progress": 70,
                "stage": "Processing response",
                "filename": filename,
                "analysis_id": analysis_id
            }
        )

        response_text = response.content[0].text

        # Clean potential markdown wrapping
        if response_text.startswith("```"):
            lines = response_text.split("\n")
            response_text = "\n".join(lines[1:-1] if lines[-1] == "```" else lines[1:])

        analysis_data = json.loads(response_text)

        # Build result
        result = {
            "id": analysis_id,
            "timestamp": timestamp,
            "filename": filename,
            "filetype": filetype,
            "filesize": filesize,
            "overall_sensitivity_score": analysis_data.get("overall_sensitivity_score", 0),
            "sensitivity_level": analysis_data.get("sensitivity_level", "LOW"),
            "confidence": analysis_data.get("confidence", 0.5),
            "dimension_scores": analysis_data.get("dimension_scores", {}),
            "department_relevance": analysis_data.get("department_relevance", {}),
            "findings": analysis_data.get("findings", []),
            "regulatory_concerns": analysis_data.get("regulatory_concerns", []),
            "recommended_actions": analysis_data.get("recommended_actions", []),
            "reasoning": analysis_data.get("reasoning", ""),
            "status": "completed",
            "error": None,
            # Metadata for ES indexing
            "file_id": file_id,
            "file_stored": file_stored,
            "hash": doc_hash,
            "content_preview": document_text[:1000] if document_text else "",
            "filesize_bytes": filesize_bytes,
            "client_ip": client_ip,
            "user_agent": user_agent,
            "analyzed_at": timestamp,
            # FR-001 metadata
            "ocr_applied": ocr_applied,
            "page_count": page_count,
            "word_count": word_count,
            "detected_mime_type": detected_mime_type,
            "file_category": file_category,
            "extraction_warnings": extraction_warnings,
            # Large file metadata
            "content_sampled": text_was_sampled,
            "total_characters": total_chars,
            # FR-009: User tracking
            "scanned_by": scanned_by
        }

        # Calculate derived fields
        dim_scores = result["dimension_scores"]
        result["top_categories"] = [k for k, v in dim_scores.items() if v > 50]
        dept_rel = result["department_relevance"]
        result["departments_affected"] = [k for k, v in dept_rel.items() if v in ["HIGH", "CRITICAL"]]

        # Add sampling notice if applicable
        if text_was_sampled:
            result["_sampling_notice"] = f"Large file ({total_chars:,} characters). Content was sampled."

        # Log to JSON incidents
        add_incident(result, doc_hash)

        # Update final progress
        self.update_state(
            state="ANALYZING",
            meta={
                "progress": 100,
                "stage": "Complete",
                "filename": filename,
                "analysis_id": analysis_id
            }
        )

        return result

    except SoftTimeLimitExceeded:
        result = {
            "id": analysis_id,
            "timestamp": timestamp,
            "filename": filename,
            "filetype": filetype,
            "filesize": filesize,
            "overall_sensitivity_score": 0,
            "sensitivity_level": "UNKNOWN",
            "confidence": 0,
            "dimension_scores": {},
            "department_relevance": {},
            "findings": [],
            "regulatory_concerns": [],
            "recommended_actions": [],
            "reasoning": "",
            "status": "error",
            "error": "Analysis timed out. File may be too complex."
        }
        add_incident(result, doc_hash)
        return result

    except json.JSONDecodeError as e:
        result = {
            "id": analysis_id,
            "timestamp": timestamp,
            "filename": filename,
            "filetype": filetype,
            "filesize": filesize,
            "overall_sensitivity_score": 0,
            "sensitivity_level": "UNKNOWN",
            "confidence": 0,
            "dimension_scores": {},
            "department_relevance": {},
            "findings": [],
            "regulatory_concerns": [],
            "recommended_actions": [],
            "reasoning": "",
            "status": "error",
            "error": f"Failed to parse AI response: {str(e)}"
        }
        add_incident(result, doc_hash)
        return result

    except anthropic.AuthenticationError:
        return {
            "status": "error",
            "error": "Invalid API key"
        }

    except anthropic.RateLimitError as e:
        # Retry on rate limit
        raise self.retry(exc=e, countdown=60)

    except Exception as e:
        # Retry on transient errors
        if self.request.retries < self.max_retries:
            raise self.retry(exc=e, countdown=30)

        result = {
            "id": analysis_id,
            "timestamp": timestamp,
            "filename": filename,
            "filetype": filetype,
            "filesize": filesize,
            "overall_sensitivity_score": 0,
            "sensitivity_level": "UNKNOWN",
            "confidence": 0,
            "dimension_scores": {},
            "department_relevance": {},
            "findings": [],
            "regulatory_concerns": [],
            "recommended_actions": [],
            "reasoning": "",
            "status": "error",
            "error": f"Analysis failed: {str(e)}"
        }
        add_incident(result, doc_hash)
        return result


@celery_app.task(
    bind=True,
    name="tasks.analyze_text_task",
    max_retries=3,
    default_retry_delay=30
)
def analyze_text_task(
    self,
    document_text: str,
    filename: str,
    filetype: str,
    filesize: str,
    client_ip: Optional[str] = None,
    user_agent: Optional[str] = None
) -> Dict[str, Any]:
    """
    Async task for text analysis (simpler variant without file processing).
    """
    return analyze_document_task(
        document_text=document_text,
        filename=filename,
        filetype=filetype,
        filesize=filesize,
        filesize_bytes=len(document_text.encode()),
        client_ip=client_ip,
        user_agent=user_agent
    )

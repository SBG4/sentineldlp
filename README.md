# SentinelDLP v1.6.0

Enterprise-grade document sensitivity analysis powered by Claude AI. Automatically detect PII, financial data, intellectual property, and other sensitive information across 40+ file formats with support for 1000+ concurrent users.

## Features

### Document Scanner
- **Universal File Support (FR-001)**: 40+ file types including PDF, DOCX, XLSX, images, archives
- **OCR Integration**: Automatic text extraction from scanned documents and images via Tesseract
- **Large File Handling (FR-004)**: Files up to 10GB with smart content sampling
- **Real-time Progress**: 3-stage upload tracking (Upload → Process → Analyze)

### Supported File Types
| Category | Extensions |
|----------|------------|
| Documents | PDF, DOCX, DOC, ODT, RTF, TXT |
| Spreadsheets | XLSX, XLS, CSV, ODS |
| Presentations | PPTX, PPT, ODP |
| Images (OCR) | PNG, JPG, JPEG, GIF, BMP, TIFF, WEBP |
| Archives | ZIP, TAR, GZ |
| Code | JS, TS, PY, JAVA, GO, RS, CPP, C, H, and 20+ more |
| Data | JSON, XML, YAML, TOML |
| Email | EML, MSG |

### Sensitivity Analysis
Analyzes documents across 7 key dimensions:
- **PII**: Names, IDs, SSN, financial accounts, medical records
- **Financial**: Revenue, budgets, salaries, transactions
- **Strategic Business**: M&A plans, partnerships, roadmaps
- **Intellectual Property**: Patents, source code, trade secrets
- **Legal & Compliance**: Attorney-client privilege, regulatory filings
- **Operational Security**: Credentials, network diagrams, vulnerabilities
- **HR & Employee**: Performance reviews, disciplinary actions

### Department Classification
Identifies which departments should be concerned:
- HR, Finance, Legal, IT/Security, Executive, R&D, Sales, Operations, Marketing

### Scan History (FR-003)
- **Elasticsearch Integration**: Persistent storage of all scan results
- **Advanced Search**: Full-text search across all scans
- **Filtering**: By severity, department, file type, date range, score
- **File Preview/Download**: View or download original scanned files

### Dashboard
- Real-time statistics and analytics
- Incident log with filtering
- Category and department breakdown
- Critical alert tracking

### Admin Configuration (FR-002)
Secure web-based configuration management:
- **LLM Provider**: Configure Claude API, Ollama, or vLLM
- **Elasticsearch**: Connect to your ES 9.1.3 cluster
- **Active Directory**: LDAP/AD authentication settings
- **Processing**: File size limits, OCR, retention policies
- **Security**: Session timeouts, rate limits, audit retention
- **Encrypted Storage**: All secrets encrypted at rest with Fernet

## Quick Start

### Docker Deployment (Recommended)

```bash
# Clone the repository
git clone https://github.com/SBG4/sentineldlp.git
cd sentineldlp

# Copy environment template and configure
cp .env.example .env
nano .env  # Add your ANTHROPIC_API_KEY

# Build and start all services
docker-compose build
docker-compose up -d
```

**Access**: http://localhost:8122

### Docker Services

| Service | Port | Description |
|---------|------|-------------|
| Frontend | 8122 | Web UI (NGINX) |
| Backend | 8000 | FastAPI API (internal) |
| Redis | 6379 | Message broker (internal) |
| Celery Worker | - | Async task processor |
| Elasticsearch | 9200 | Search & storage |
| Kibana | 5601 | ES management UI |

### Docker Commands

| Command | Description |
|---------|-------------|
| `make build` | Build Docker images |
| `make up` | Start all services |
| `make down` | Stop all services |
| `make logs` | View logs (follow mode) |
| `make health` | Check service health |
| `make restart` | Restart services |
| `make clean` | Remove containers |

### Architecture

```
┌─────────────────────────────────────────────────────────┐
│                Host (localhost:8122)                    │
└────────────────────────┬────────────────────────────────┘
                         │
┌────────────────────────▼────────────────────────────────┐
│              NGINX (Frontend Container)                 │
│  - Serves React SPA                                     │
│  - Proxies /api/* to backend                            │
└────────────────────────┬────────────────────────────────┘
                         │ internal network
┌────────────────────────▼────────────────────────────────┐
│             FastAPI (Backend Container)                 │
│  - REST API on port 8000                                │
│  - Claude AI integration                                │
│  - File processing & OCR                                │
└───────────┬─────────────┬─────────────┬─────────────────┘
            │             │             │
┌───────────▼───────────┐ │   ┌─────────▼─────────┐
│       Redis           │ │   │   File Storage    │
│  - Message broker     │ │   │  - Upload files   │
│  - Result backend     │ │   │  - Preview/DL     │
└───────────┬───────────┘ │   └───────────────────┘
            │             │
┌───────────▼───────────┐ │
│   Celery Workers      │ │
│  - Async analysis     │ │
│  - 4+ concurrent      │ │
└───────────────────────┘ │
                          │
            ┌─────────────▼─────────────┐
            │      Elasticsearch        │
            │  - Scan persistence       │
            │  - Search & filter        │
            └───────────────────────────┘
```

## Environment Variables

Configure via `.env` file:

| Variable | Default | Description |
|----------|---------|-------------|
| `ANTHROPIC_API_KEY` | (required) | Your Anthropic API key |
| `CLAUDE_MODEL` | `claude-sonnet-4-20250514` | Claude model for analysis |
| `MAX_TOKENS` | `4096` | Max tokens for responses |
| `FRONTEND_PORT` | `8122` | Host port for web UI |
| `ELASTIC_PASSWORD` | `changeme` | Elasticsearch password |
| `KIBANA_PORT` | `5601` | Kibana UI port |
| `CELERY_ENABLED` | `true` | Enable async task queue |
| `CELERY_CONCURRENCY` | `4` | Workers per Celery container |
| `LOG_LEVEL` | `INFO` | Logging verbosity |

## API Endpoints

### Analysis
```
POST /api/analyze          # Analyze uploaded file (multipart/form-data)
```

### Async Jobs (FR-005)
```
POST   /api/jobs/analyze      # Submit async analysis job
GET    /api/jobs/{job_id}     # Get job status and result
DELETE /api/jobs/{job_id}     # Cancel pending/running job
GET    /api/jobs/queue/stats  # Queue statistics
GET    /api/system/status     # Overall system health
```

### Scan History (FR-003)
```
GET  /api/scans            # Paginated scan history with search/filter
GET  /api/scans/{id}       # Get specific scan details
GET  /api/scans/aggregations  # Dashboard statistics
```

### File Access
```
GET  /api/files/{id}/preview   # Text preview of stored file
GET  /api/files/{id}/download  # Download original file
```

### Admin Configuration (FR-002)
```
GET  /api/admin/config         # Get config (secrets masked)
PUT  /api/admin/config         # Update configuration
POST /api/admin/config/test    # Test connectivity
GET  /api/admin/config/audit   # Get audit log
```

### Legacy Endpoints
```
GET  /api/settings
PUT  /api/settings
GET  /api/incidents
GET  /api/stats
```

## Large File Handling (FR-004)

Files larger than 150,000 characters are automatically sampled:
- **Beginning**: First 50,000 characters
- **Middle**: 50,000 characters from document center
- **End**: Last 50,000 characters

This ensures comprehensive coverage while staying within API limits. A sampling notice is displayed in results when applied.

**Limits:**
- Maximum file size: 10GB
- Files over limit show an informative modal with guidance

## Project Structure

```
sentineldlp/
├── backend/
│   ├── main.py                    # FastAPI application
│   ├── celery_app.py              # Celery configuration (FR-005)
│   ├── tasks.py                   # Async analysis tasks (FR-005)
│   ├── file_processor.py          # Universal file processing + OCR
│   ├── elasticsearch_service.py   # ES client & operations
│   ├── elasticsearch_mappings.py  # Index schema
│   ├── file_storage_service.py    # File persistence
│   ├── config_manager.py          # Admin config management
│   ├── crypto_utils.py            # Encryption utilities
│   ├── migrate_to_elasticsearch.py # Migration script
│   └── requirements.txt
├── frontend/
│   └── index.html                 # React SPA
├── docker/
│   ├── Dockerfile.backend
│   ├── Dockerfile.frontend
│   ├── nginx.conf
│   └── entrypoint.sh
├── docs/
│   ├── CHANGELOG.md
│   ├── VERSION-1.0.0.md
│   ├── VERSION-1.1.0.md
│   ├── VERSION-1.2.0.md
│   ├── VERSION-1.3.0.md
│   ├── VERSION-1.4.0.md
│   ├── VERSION-1.5.0.md
│   └── VERSION-1.6.0.md
├── docker-compose.yml
├── Makefile
├── SPECIFICATION.xml              # Project guardrail document
├── .env.example
└── README.md
```

## Scoring Guide

| Score | Level | Description |
|-------|-------|-------------|
| 0-30 | LOW | Public information, marketing materials |
| 31-60 | MEDIUM | Internal use, non-sensitive business data |
| 61-85 | HIGH | Confidential, limited distribution |
| 86-100 | CRITICAL | Highly restricted, severe impact if leaked |

## Version History

| Version | Features |
|---------|----------|
| 1.6.0 | FR-005 Redis + Celery Queue (1000+ users), Async Jobs |
| 1.5.0 | FR-001 Universal File Types + OCR, FR-004 Large File Handling |
| 1.4.0 | FR-003 Elasticsearch Integration, Scan History, File Storage |
| 1.3.0 | FR-002 Admin Configuration Panel |
| 1.2.0 | Backend improvements, enhanced metadata |
| 1.1.0 | UI enhancements, sensitivity gauge |
| 1.0.0 | Initial release |

See `/docs/` for detailed version documentation.

## Security Notes

- API keys stored in environment variables (not in images)
- All admin secrets encrypted at rest with Fernet
- Containers run as non-root users
- Internal network isolation between services
- NGINX security headers configured

## License

Internal use - Enterprise document sensitivity detection system.

---

Built with FastAPI, React, Elasticsearch, and Claude AI

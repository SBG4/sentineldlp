# SentinelDLP - Sensitive Information Detection System

Enterprise-grade document sensitivity analysis powered by Claude AI. Automatically detect PII, financial data, intellectual property, and other sensitive information in your documents.

## Features

### 🔍 Document Scanner
- **File Upload**: Drag-and-drop or browse for text-based files
- **Text Paste**: Directly paste document content for analysis
- **Multi-format Support**: TXT, CSV, JSON, XML, HTML, MD, LOG, PY, JS, YAML, and more

### 📊 Sensitivity Analysis
Analyzes documents across 7 key dimensions:
- **PII**: Names, IDs, SSN, financial accounts, medical records
- **Financial**: Revenue, budgets, salaries, transactions
- **Strategic Business**: M&A plans, partnerships, roadmaps
- **Intellectual Property**: Patents, source code, trade secrets
- **Legal & Compliance**: Attorney-client privilege, regulatory filings
- **Operational Security**: Credentials, network diagrams, vulnerabilities
- **HR & Employee**: Performance reviews, disciplinary actions

### 🏢 Department Classification
Identifies which departments should be concerned:
- HR, Finance, Legal, IT/Security, Executive, R&D, Sales, Operations, Marketing

### 📈 Dashboard
- Real-time statistics and analytics
- Incident log with filtering
- Category and department breakdown
- Critical alert tracking

### ⚙️ Admin Configuration (FR-002)
Secure web-based configuration management:
- **LLM Provider**: Configure Claude API, Ollama, or vLLM
- **Elasticsearch**: Connect to your ES 9.1.3 cluster
- **Active Directory**: LDAP/AD authentication settings
- **Processing**: File size limits, OCR, retention policies
- **Security**: Session timeouts, rate limits, audit retention
- **Audit Log**: Track all configuration changes
- **Encrypted Storage**: All secrets encrypted at rest with Fernet
- **Key Rotation**: Rotate encryption keys without data loss

## Quick Start

### 🐳 Docker Deployment (Recommended)

The fastest way to get started:

```bash
# Clone or download the project
cd sensitive-detector

# Copy environment template and add your API key
cp .env.example .env
nano .env  # Add your ANTHROPIC_API_KEY

# Build and start with Make
make quickstart

# Or use docker-compose directly
docker-compose build
docker-compose up -d
```

**Access**: http://localhost:8080

### Docker Commands

| Command | Description |
|---------|-------------|
| `make build` | Build Docker images |
| `make up` | Start all services |
| `make down` | Stop all services |
| `make logs` | View logs (follow mode) |
| `make health` | Check service health |
| `make restart` | Restart services |
| `make ps` | Show container status |
| `make clean` | Remove containers |
| `make prune` | Remove containers + volumes (⚠️ data loss) |

### Docker Architecture

```
┌─────────────────────────────────────────────────┐
│              Host (localhost:8080)              │
└─────────────────────┬───────────────────────────┘
                      │
┌─────────────────────▼───────────────────────────┐
│           NGINX (Frontend Container)            │
│  - Serves React SPA                             │
│  - Proxies /api/* to backend                    │
└─────────────────────┬───────────────────────────┘
                      │ internal network
┌─────────────────────▼───────────────────────────┐
│          FastAPI (Backend Container)            │
│  - REST API on port 8000                        │
│  - Claude AI integration                        │
└─────────────────────────────────────────────────┘
         │                    │
    ┌────▼────┐          ┌────▼────┐
    │ Volume  │          │ Volume  │
    │  data   │          │ uploads │
    └─────────┘          └─────────┘
```

### Environment Variables

Configure via `.env` file:

| Variable | Default | Description |
|----------|---------|-------------|
| `ANTHROPIC_API_KEY` | (required) | Your Anthropic API key |
| `CLAUDE_MODEL` | `claude-sonnet-4-20250514` | Claude model for analysis |
| `MAX_TOKENS` | `4096` | Max tokens for responses |
| `FRONTEND_PORT` | `8080` | Host port for web UI |
| `LOG_LEVEL` | `INFO` | Logging verbosity |

---

### 🖥️ Standalone Deployment (Development)

For development without Docker:

#### Prerequisites
- Python 3.10+
- Anthropic API key

### Installation

```bash
# Clone or download the project
cd sensitive-detector

# Install dependencies
pip install -r backend/requirements.txt --break-system-packages

# Start the application
chmod +x start.sh
./start.sh
```

### Access
- **Frontend**: http://localhost:3000
- **API**: http://localhost:8000
- **API Documentation**: http://localhost:8000/docs

### Configuration
1. Open the web interface at http://localhost:3000
2. Navigate to **Settings**
3. Enter your Anthropic API key
4. Select your preferred Claude model
5. Click **Save Settings**
6. Click **Test Connection** to verify

## API Endpoints

### Analysis
```
POST /api/analyze/text
POST /api/analyze/file
```

### Settings (Legacy)
```
GET  /api/settings
PUT  /api/settings
POST /api/settings/test
```

### Admin Configuration (FR-002)
```
GET  /api/admin/config         # Get config (secrets masked)
PUT  /api/admin/config         # Update configuration
POST /api/admin/config/test    # Test connectivity (llm/elasticsearch/active_directory)
POST /api/admin/config/rotate-key  # Rotate encryption key
GET  /api/admin/config/audit   # Get audit log
GET  /api/admin/config/status  # Get config status summary
```

### Incidents
```
GET    /api/incidents
GET    /api/incidents/{id}
DELETE /api/incidents/{id}
DELETE /api/incidents
```

### Statistics
```
GET /api/stats
GET /api/models
```

## Example API Usage

### Analyze Text
```bash
curl -X POST http://localhost:8000/api/analyze/text \
  -H "Content-Type: application/json" \
  -d '{
    "document_text": "Employee John Smith (SSN: 123-45-6789) salary: $85,000",
    "filename": "employee_data.txt",
    "filetype": "txt",
    "filesize": "58 bytes"
  }'
```

### Response Format
```json
{
  "id": "uuid",
  "timestamp": "2025-01-13T10:00:00Z",
  "filename": "employee_data.txt",
  "overall_sensitivity_score": 85,
  "sensitivity_level": "HIGH",
  "confidence": 0.95,
  "dimension_scores": {
    "pii": 90,
    "financial": 70,
    "hr_employee": 80,
    ...
  },
  "department_relevance": {
    "HR": "CRITICAL",
    "Finance": "HIGH",
    ...
  },
  "findings": [...],
  "regulatory_concerns": ["GDPR"],
  "recommended_actions": [...],
  "reasoning": "..."
}
```

## Scoring Guide

| Score | Level | Description |
|-------|-------|-------------|
| 0-30 | LOW | Public information, marketing materials |
| 31-60 | MEDIUM | Internal use, non-sensitive business data |
| 61-85 | HIGH | Confidential, limited distribution |
| 86-100 | CRITICAL | Highly restricted, severe impact if leaked |

## Project Structure

```
sensitive-detector/
├── docker/
│   ├── Dockerfile.backend    # Backend container config
│   ├── Dockerfile.frontend   # Frontend container config
│   └── nginx.conf            # NGINX configuration
├── backend/
│   ├── main.py               # FastAPI application
│   └── requirements.txt      # Python dependencies
├── frontend/
│   └── index.html            # React SPA
├── data/
│   ├── settings.json         # Configuration
│   └── incidents.json        # Incident log
├── docker-compose.yml        # Container orchestration
├── Makefile                  # Docker management commands
├── .env.example              # Environment template
├── .dockerignore             # Docker build exclusions
├── start.sh                  # Standalone startup script
└── README.md
```

## Extending

### Add PDF/DOCX Support
The current implementation supports text-based files. To add binary format support:

1. Install additional libraries:
```bash
pip install pypdf python-docx --break-system-packages
```

2. Add extraction logic in `backend/main.py` for each format

### Elasticsearch Integration
To push incidents to Elasticsearch:

```python
from elasticsearch import Elasticsearch

es = Elasticsearch(["http://localhost:9200"])

def push_to_elastic(incident):
    es.index(index="sensitivity-incidents", document=incident)
```

### Custom Sensitivity Dimensions
Modify the `ANALYSIS_PROMPT` in `backend/main.py` to add industry-specific sensitivity categories.

## Security Notes

### Docker Security
- Containers run as non-root users
- API keys passed via environment variables (not baked into images)
- Internal network isolation between containers
- Health checks for service monitoring
- Resource limits prevent runaway processes

### Application Security
- API keys are stored locally in `data/settings.json` (standalone) or env vars (Docker)
- Document content is sent to Claude API for analysis
- Incident logs are stored in Docker volumes or local filesystem
- Consider TLS termination for production (NGINX supports this)
- NGINX includes security headers (X-Frame-Options, X-Content-Type-Options, etc.)

### Production Recommendations
- Use secrets management (Vault, AWS Secrets Manager) for API keys
- Enable HTTPS with valid certificates
- Implement authentication (Active Directory integration pending)
- Restrict network access to authorized users
- Regular backup of incident data volumes

## License

Internal use - Enterprise document sensitivity detection system.

---

Built with FastAPI, React, and Claude AI

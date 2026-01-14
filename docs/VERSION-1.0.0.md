# SentinelDLP v1.0.0

**Release Date:** Initial Release
**Status:** Stable

## Overview

Initial release of SentinelDLP - an AI-powered Data Loss Prevention system that uses Claude AI to analyze documents for sensitive information across 7 sensitivity dimensions.

## Features

### Core Analysis Engine
- Claude AI-powered document analysis
- 7-dimension sensitivity scoring:
  - PII (Personally Identifiable Information)
  - Financial Data
  - Strategic Business Information
  - Intellectual Property
  - Legal/Compliance
  - Operational Security
  - HR/Employee Data

### 9-Department Relevance Mapping
- HR
- Finance
- Legal
- IT/Security
- Executive
- R&D
- Sales
- Operations
- Marketing

### Document Support
- Text files (.txt)
- PDF documents
- Microsoft Word (.docx)
- Basic file metadata extraction

### User Interface
- React-based single-page application
- Dark theme with modern UI
- Drag-and-drop file upload
- Real-time analysis results
- Sensitivity gauge visualization

### Backend
- FastAPI Python backend
- RESTful API architecture
- Docker containerization

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/analyze` | Analyze uploaded document |
| GET | `/api/health` | Health check endpoint |

## Installation

```bash
docker compose up -d
```

Access the application at `http://localhost:8080`

## Known Limitations

- Limited file type support
- No persistent storage of scan results
- No OCR support for image-based PDFs
- No admin configuration interface

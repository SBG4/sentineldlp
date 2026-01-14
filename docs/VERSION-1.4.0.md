# SentinelDLP v1.4.0

**Release Date:** Feature Release
**Status:** Stable
**Feature:** FR-003 - Elasticsearch Integration

## Overview

Major infrastructure release adding Elasticsearch 9.1.3 for persistent scan storage, advanced search capabilities, and file preview/download functionality.

## New Features

### Elasticsearch Integration (FR-003)

Full integration with Elasticsearch for scan result persistence and advanced querying.

#### Persistent Scan Storage
- All scan results automatically indexed to Elasticsearch
- Full metadata preservation including all 7 dimensions and 9 departments
- Nested findings structure for complex queries

#### Scan History Page
- Paginated, searchable scan history
- Advanced filtering:
  - Sensitivity level (LOW/MEDIUM/HIGH/CRITICAL)
  - Department relevance
  - File type
  - Date range
  - Score range
- Sortable columns
- Quick actions per row

#### File Storage Service
- Original files persisted for preview/download
- Date-organized directory structure: `/app/data/uploads/{YYYY}/{MM}/{DD}/`
- UUID-based naming prevents collisions

#### File Preview/Download
- Text preview modal (up to 5000 characters)
- Original file download capability
- Syntax highlighting for code files

### New API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/scans` | Paginated scan history with search/filter |
| GET | `/api/scans/{id}` | Get specific scan details |
| GET | `/api/scans/aggregations` | Dashboard statistics |
| GET | `/api/files/{id}/preview` | Text preview of stored file |
| GET | `/api/files/{id}/download` | Download original file |
| POST | `/api/admin/migrate-to-elasticsearch` | Migrate existing JSON incidents |

### Docker Stack Additions

#### Elasticsearch Service
```yaml
elasticsearch:
  image: docker.elastic.co/elasticsearch/elasticsearch:9.1.3
  environment:
    - discovery.type=single-node
    - xpack.security.enabled=true
    - ELASTIC_PASSWORD=${ELASTIC_PASSWORD:-changeme}
    - "ES_JAVA_OPTS=-Xms1g -Xmx1g"
  volumes:
    - sentineldlp-esdata:/usr/share/elasticsearch/data
```

#### Kibana Service (Optional)
```yaml
kibana:
  image: docker.elastic.co/kibana/kibana:9.1.3
  ports:
    - "5601:5601"
```

## Elasticsearch Index Schema

### Key Fields
- `id`, `file_id`, `hash`, `timestamp`
- `filename`, `filetype`, `filesize`, `filesize_bytes`
- `overall_sensitivity_score`, `sensitivity_level`, `confidence`
- `dimension_scores` (7 nested fields)
- `department_relevance` (9 nested fields)
- `findings` (nested array with category, severity, description, count, examples)
- `file_stored`, `content_preview`
- `client_ip`, `user_agent`, `scanned_by`

### Custom Analyzers
- `filename_analyzer`: Optimized for file name searches with lowercase and ASCII folding

## New Backend Files

| File | Purpose |
|------|---------|
| `elasticsearch_service.py` | ES client, indexing, search, aggregations |
| `elasticsearch_mappings.py` | Index schema definitions |
| `file_storage_service.py` | File persistence service |
| `migrate_to_elasticsearch.py` | Migration script for existing data |

## Changes from v1.3.0

### Added
- Elasticsearch 9.1.3 service in Docker stack
- Kibana 9.1.3 for ES management (optional)
- ScanHistoryPage React component
- FilePreviewModal React component
- Navigation item for Scan History
- 6 new API endpoints

### Modified
- `main.py`: Integrated ES indexing into analyze flow
- `docker-compose.yml`: Added ES, Kibana services and volumes
- `requirements.txt`: Added `elasticsearch>=9.0.0,<10.0.0`

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `ELASTIC_PASSWORD` | `changeme` | Elasticsearch password |
| `ELASTICSEARCH_URL` | `http://elasticsearch:9200` | ES connection URL |

## Upgrade Notes

### First-time Setup
```bash
docker compose up -d
# Wait for Elasticsearch to be healthy
docker compose logs -f elasticsearch
```

### Migration from v1.3.0
```bash
# Start new services
docker compose up -d

# Run migration for existing JSON incidents (if any)
curl -X POST http://localhost:8080/api/admin/migrate-to-elasticsearch
```

### Verification
1. Check Kibana at `http://localhost:5601`
2. Upload a test file
3. Verify scan appears in Scan History page
4. Test search and filter functionality
5. Test file preview and download

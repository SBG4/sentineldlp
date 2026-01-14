# SentinelDLP Changelog

All notable changes to SentinelDLP are documented in this file.

## [1.5.0] - January 2026

### Added
- **FR-001**: Universal file type support (40+ formats)
- **FR-004**: Large file handling up to 10GB
- OCR integration with Tesseract for image-based documents
- Smart content sampling for files over 150K characters
- Real-time upload progress tracking (3-stage indicator)
- Oversized file modal with clear feedback
- Sampling notice in results view
- Server-side file size validation (defense in depth)
- New ES fields: `ocr_applied`, `page_count`, `word_count`, `detected_mime_type`, `file_category`, `content_sampled`, `total_characters`

### Fixed
- Browser hang when uploading files over 10GB
- 5GB file analysis timeout (token limit exceeded)
- Missing upload progress indication

### Technical
- Replaced `fetch()` with `XMLHttpRequest` for progress events
- Added `requestAnimationFrame()` for non-blocking file handling
- Implemented 3-section sampling (beginning, middle, end)

## [1.4.0] - Elasticsearch Integration

### Added
- **FR-003**: Elasticsearch 9.1.3 integration
- Kibana 9.1.3 for ES management
- Persistent scan storage with full metadata
- Scan History page with search/filter
- File preview and download functionality
- 6 new API endpoints for scans and files
- Migration script for existing JSON incidents

### New Files
- `elasticsearch_service.py`
- `elasticsearch_mappings.py`
- `file_storage_service.py`
- `migrate_to_elasticsearch.py`

## [1.3.0] - Admin Configuration

### Added
- **FR-002**: Admin configuration panel
- Sensitivity threshold configuration
- File handling settings
- Department enable/disable
- Analysis parameter tuning
- Settings export/import
- Settings page in navigation

## [1.2.0] - Backend Improvements

### Added
- Enhanced document metadata extraction
- Processing time metrics
- Structured logging
- Debug mode support

### Improved
- PDF text extraction quality
- Memory efficiency
- API response structure

### Fixed
- Unicode handling issues
- Memory leaks in document processing

## [1.1.0] - UI Enhancements

### Added
- Interactive sensitivity gauge
- Department relevance chips
- Regulatory concerns display
- Recommended actions section
- Custom icon library

### Improved
- Mobile responsiveness
- Error handling
- Loading states

## [1.0.0] - Initial Release

### Added
- Claude AI-powered document analysis
- 7-dimension sensitivity scoring
- 9-department relevance mapping
- React single-page application
- FastAPI backend
- Docker containerization
- Basic file type support (TXT, PDF, DOCX)

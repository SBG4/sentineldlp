# SentinelDLP v1.5.0

**Release Date:** January 2026
**Status:** Stable
**Features:** FR-001 (Universal File Type Support), FR-004 (Large File Handling)

## Overview

Major release focusing on universal file type support with OCR capabilities and robust large file handling with smart content sampling.

## New Features

### Universal File Type Support (FR-001)

Comprehensive file processing with automatic text extraction and OCR.

#### Supported File Types
- **Documents**: PDF, DOCX, DOC, ODT, RTF, TXT
- **Spreadsheets**: XLSX, XLS, CSV, ODS
- **Presentations**: PPTX, PPT, ODP
- **Images**: PNG, JPG, JPEG, GIF, BMP, TIFF, WEBP (with OCR)
- **Archives**: ZIP, TAR, GZ (content extraction)
- **Code**: JS, TS, PY, JAVA, GO, RS, CPP, C, H, and 20+ more
- **Data**: JSON, XML, YAML, TOML
- **Email**: EML, MSG

#### OCR Integration
- Tesseract OCR for image-based text extraction
- Automatic detection of scanned PDFs
- Multi-language support
- Image preprocessing for improved accuracy

#### Processing Metadata
New fields tracked for each scan:
- `ocr_applied`: Whether OCR was used
- `page_count`: Number of pages processed
- `word_count`: Total words extracted
- `detected_mime_type`: Actual MIME type detected
- `file_category`: Category classification
- `extraction_warnings`: Any issues during extraction

### Large File Handling (FR-004)

Robust handling of files up to 10GB with smart content sampling.

#### File Size Limits
- **Frontend validation**: Immediate feedback for oversized files
- **Configurable max size**: Default 10GB (admin configurable)
- **Oversized file modal**: Clear messaging with options

#### Smart Content Sampling
For files exceeding 150,000 characters:
- **Beginning sample**: First 50,000 characters
- **Middle sample**: 50,000 characters from document center
- **End sample**: Last 50,000 characters
- Ensures comprehensive coverage while respecting API limits

#### Upload Progress Tracking
Three-stage progress indicator:
1. **Upload Stage**: Real-time progress bar with bytes transferred
2. **Processing Stage**: Document text extraction
3. **Analysis Stage**: Claude AI analysis in progress

#### Technical Implementation
- `XMLHttpRequest` with progress events (replaced fetch)
- `requestAnimationFrame()` for non-blocking UI updates
- 10-minute timeout for large file uploads
- Server-side defense-in-depth size validation

### Sampling Notice

When content sampling is applied:
- Clear indicator in results view
- Shows total document size vs. analyzed portion
- Explains sampling methodology
- Stored in Elasticsearch for audit trail

## New Elasticsearch Fields

```python
# FR-001: Processing metadata
"ocr_applied": {"type": "boolean"},
"page_count": {"type": "integer"},
"word_count": {"type": "integer"},
"detected_mime_type": {"type": "keyword"},
"file_category": {"type": "keyword"},
"extraction_warnings": {"type": "keyword"},

# FR-004: Large file sampling metadata
"content_sampled": {"type": "boolean"},
"total_characters": {"type": "long"}
```

## API Changes

### Enhanced Response Fields
```json
{
  "ocr_applied": false,
  "page_count": 25,
  "word_count": 12500,
  "detected_mime_type": "application/pdf",
  "file_category": "document",
  "content_sampled": true,
  "total_characters": 5000000,
  "_sampling_notice": "This document contained 5,000,000 characters. Due to analysis limits, content was sampled from the beginning (50,000 chars), middle (50,000 chars), and end (50,000 chars) for comprehensive coverage."
}
```

### Error Responses
```json
// 413 Payload Too Large
{
  "detail": "File too large: 15.50 GB. Maximum allowed: 10 GB."
}
```

## Frontend Changes

### OversizedFileModal Component
Displays when file exceeds limit:
- File name and size
- Maximum allowed size
- Helpful guidance message
- Dismiss button

### UploadProgress Component
Real-time progress display:
- Stage indicator (Upload/Process/Analyze)
- Progress bar with percentage
- Bytes uploaded / total bytes
- Animated transitions

### SamplingNotice Component
Shown in results when sampling applied:
- Alert icon with explanation
- Total vs. sampled character counts
- Methodology description

### New Icons
- `AlertTriangle`: Warning indicator
- `Info`: Information notices

## Backend Changes

### file_processor.py
- Universal file type detection
- OCR integration with Tesseract
- Text extraction for 40+ file types
- Archive content extraction
- Metadata extraction

### main.py
- Server-side file size validation (defense in depth)
- Smart content sampling algorithm
- Enhanced response with processing metadata
- Sampling notice generation

## Dependencies

### New Python Packages
```
pytesseract>=0.3.10
Pillow>=10.0.0
python-magic>=0.4.27
openpyxl>=3.1.0
python-pptx>=0.6.21
striprtf>=0.0.26
odfpy>=1.4.1
```

### System Dependencies
```dockerfile
# In Dockerfile
RUN apt-get install -y tesseract-ocr tesseract-ocr-eng
```

## Performance Considerations

### Large File Handling
- Files under 150K chars: Full analysis (no sampling)
- Files 150K-10GB: Smart sampling with 3-section coverage
- Files over 10GB: Rejected with clear error message

### Memory Usage
- Streaming file uploads prevent memory exhaustion
- Chunked text extraction for large documents
- Lazy loading of archive contents

## Upgrade Notes

### From v1.4.0
```bash
# Pull latest images
docker compose pull

# Rebuild if using custom Dockerfile
docker compose build --no-cache

# Restart services
docker compose up -d
```

### Elasticsearch Index Update
The new fields are automatically added when documents are indexed. Existing documents will have null values for new fields.

### Testing Large Files
```bash
# Generate test file
dd if=/dev/zero bs=1M count=5000 | base64 > test_5gb.txt

# Upload via UI and verify:
# 1. Progress bar appears
# 2. Sampling notice in results
# 3. Document indexed in ES with content_sampled=true
```

## Resolved Issues

- **GAP-005**: Large file browser hang - RESOLVED
  - Root cause: Blocking file operations before size check
  - Fix: `requestAnimationFrame()` wrapper for non-blocking execution

- **5GB file timeout**:
  - Root cause: Entire text sent to Claude API exceeding token limits
  - Fix: Smart 3-section sampling keeping under 150K chars

- **No upload progress**:
  - Root cause: `fetch()` doesn't support progress events
  - Fix: Replaced with `XMLHttpRequest` with progress listeners

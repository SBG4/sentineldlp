# SentinelDLP v1.2.0

**Release Date:** Incremental Update
**Status:** Stable

## Overview

Backend improvements and enhanced document processing capabilities.

## New Features

### Enhanced Document Processing
- Improved text extraction for complex documents
- Better handling of multi-page PDFs
- Enhanced DOCX parsing

### API Improvements
- More detailed response metadata
- Improved error responses with actionable messages
- Request validation enhancements

### Logging and Monitoring
- Structured logging implementation
- Request/response timing metrics
- Debug mode support

## Changes from v1.1.0

### Added
- Document metadata in API response (page count, word count)
- Processing time metrics
- Enhanced file type detection

### Improved
- PDF text extraction quality
- Memory efficiency for large documents
- API response structure

### Fixed
- Edge cases in document parsing
- Unicode handling issues
- Memory leaks in document processing

## API Changes

Response now includes additional metadata:
```json
{
  "filename": "document.pdf",
  "filesize": "2.5 MB",
  "page_count": 10,
  "word_count": 5000,
  "processing_time_ms": 1234,
  ...
}
```

## Upgrade Notes

No breaking changes. Direct upgrade supported.

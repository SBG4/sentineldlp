"""
SentinelDLP - Elasticsearch Index Mappings
Defines the schema for scan documents with all metadata fields
"""

SCAN_INDEX_MAPPING = {
    "settings": {
        "number_of_shards": 1,
        "number_of_replicas": 0,
        "analysis": {
            "analyzer": {
                "filename_analyzer": {
                    "type": "custom",
                    "tokenizer": "standard",
                    "filter": ["lowercase", "asciifolding"]
                }
            }
        }
    },
    "mappings": {
        "properties": {
            # Document identifiers
            "id": {"type": "keyword"},
            "file_id": {"type": "keyword"},
            "hash": {"type": "keyword"},
            "file_hash": {"type": "keyword"},  # FR-007: Full SHA256 of binary file

            # Timestamps
            "timestamp": {"type": "date"},
            "analyzed_at": {"type": "date"},

            # File metadata
            "filename": {
                "type": "text",
                "analyzer": "filename_analyzer",
                "fields": {"keyword": {"type": "keyword"}}
            },
            "filetype": {"type": "keyword"},
            "filesize": {"type": "keyword"},
            "filesize_bytes": {"type": "long"},
            "file_stored": {"type": "boolean"},
            "content_preview": {"type": "text"},

            # Overall assessment
            "overall_sensitivity_score": {"type": "integer"},
            "sensitivity_level": {"type": "keyword"},
            "confidence": {"type": "float"},
            "status": {"type": "keyword"},
            "error": {"type": "text"},

            # 7 Dimension scores
            "dimension_scores": {
                "properties": {
                    "pii": {"type": "integer"},
                    "financial": {"type": "integer"},
                    "strategic_business": {"type": "integer"},
                    "intellectual_property": {"type": "integer"},
                    "legal_compliance": {"type": "integer"},
                    "operational_security": {"type": "integer"},
                    "hr_employee": {"type": "integer"}
                }
            },

            # 9 Department relevance
            "department_relevance": {
                "properties": {
                    "HR": {"type": "keyword"},
                    "Finance": {"type": "keyword"},
                    "Legal": {"type": "keyword"},
                    "IT_Security": {"type": "keyword"},
                    "Executive": {"type": "keyword"},
                    "RnD": {"type": "keyword"},
                    "Sales": {"type": "keyword"},
                    "Operations": {"type": "keyword"},
                    "Marketing": {"type": "keyword"}
                }
            },
            "departments_affected": {"type": "keyword"},

            # Findings (nested for complex queries)
            "findings": {
                "type": "nested",
                "properties": {
                    "category": {"type": "keyword"},
                    "severity": {"type": "keyword"},
                    "description": {"type": "text"},
                    "count": {"type": "integer"},
                    "examples": {"type": "keyword"}
                }
            },
            "top_categories": {"type": "keyword"},

            # Compliance
            "regulatory_concerns": {"type": "keyword"},

            # Actions and reasoning
            "recommended_actions": {"type": "text"},
            "reasoning": {"type": "text"},

            # Audit fields
            "scanned_by": {"type": "keyword"},
            "client_ip": {"type": "ip"},
            "user_agent": {"type": "text"},

            # Migration tracking
            "migrated_from_json": {"type": "boolean"},

            # FR-001: Processing metadata
            "ocr_applied": {"type": "boolean"},
            "page_count": {"type": "integer"},
            "word_count": {"type": "integer"},
            "detected_mime_type": {"type": "keyword"},
            "file_category": {"type": "keyword"},
            "extraction_warnings": {"type": "keyword"},

            # Large file sampling metadata
            "content_sampled": {"type": "boolean"},
            "total_characters": {"type": "long"}
        }
    }
}

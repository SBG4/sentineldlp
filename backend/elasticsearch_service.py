"""
SentinelDLP - Elasticsearch Service
Handles all Elasticsearch operations for scan storage and retrieval
"""

import os
import logging
from datetime import datetime
from typing import Optional, List, Dict, Any

from elasticsearch import Elasticsearch, NotFoundError
from elasticsearch.helpers import bulk

from config_manager import ConfigManager
from elasticsearch_mappings import SCAN_INDEX_MAPPING

logger = logging.getLogger(__name__)


class ElasticsearchService:
    """Manages Elasticsearch operations for scan storage."""

    def __init__(self, config_manager: ConfigManager):
        self.config_manager = config_manager
        self._client: Optional[Elasticsearch] = None
        self._index_prefix = "sentineldlp-scans"

    def reset_client(self):
        """Reset the client to pick up new configuration."""
        self._client = None

    @property
    def is_enabled(self) -> bool:
        """Check if Elasticsearch is enabled in config."""
        config = self.config_manager.load_config()
        return config.elasticsearch.enabled

    @property
    def client(self) -> Optional[Elasticsearch]:
        """Get or create Elasticsearch client."""
        if not self.is_enabled:
            return None

        if self._client is None:
            config = self.config_manager.load_config()
            es_config = config.elasticsearch

            # Build hosts list
            hosts = es_config.hosts
            if not hosts:
                # Fall back to environment variable
                env_hosts = os.getenv("ELASTICSEARCH_HOSTS", "http://elasticsearch:9200")
                hosts = [h.strip() for h in env_hosts.split(",")]

            client_args = {
                "hosts": hosts,
                "verify_certs": es_config.verify_certs,
            }

            # Authentication - prefer config, fall back to environment
            api_key = es_config.api_key
            username = es_config.username or os.getenv("ELASTICSEARCH_USERNAME", "")
            password = es_config.password or os.getenv("ELASTICSEARCH_PASSWORD", "")

            if api_key:
                client_args["api_key"] = api_key
            elif username and password:
                client_args["basic_auth"] = (username, password)

            if es_config.ca_cert_path:
                client_args["ca_certs"] = es_config.ca_cert_path

            try:
                self._client = Elasticsearch(**client_args)
            except Exception as e:
                logger.error(f"Failed to create Elasticsearch client: {e}")
                return None

        return self._client

    def get_current_index(self) -> str:
        """Get current index name with date suffix."""
        date_suffix = datetime.utcnow().strftime("%Y-%m")
        return f"{self._index_prefix}-{date_suffix}"

    def ensure_index_exists(self) -> bool:
        """Create index if it doesn't exist."""
        if not self.client:
            return False

        index_name = self.get_current_index()
        try:
            if not self.client.indices.exists(index=index_name):
                self.client.indices.create(
                    index=index_name,
                    body=SCAN_INDEX_MAPPING
                )
                logger.info(f"Created index: {index_name}")
            return True
        except Exception as e:
            logger.error(f"Failed to create index {index_name}: {e}")
            return False

    async def index_scan(self, scan_data: Dict[str, Any]) -> Optional[str]:
        """
        Index a scan document in Elasticsearch.

        Args:
            scan_data: Complete scan result data

        Returns:
            Document ID if successful, None otherwise
        """
        if not self.client:
            return None

        try:
            self.ensure_index_exists()

            result = self.client.index(
                index=self.get_current_index(),
                id=scan_data.get("id"),
                document=scan_data
            )

            logger.info(f"Indexed scan document: {scan_data.get('id')}")
            return result.get("_id")
        except Exception as e:
            logger.error(f"Failed to index scan: {e}")
            return None

    async def get_scan(self, scan_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve a specific scan by ID."""
        if not self.client:
            return None

        try:
            # Search across all indices matching pattern
            result = self.client.search(
                index=f"{self._index_prefix}-*",
                body={
                    "query": {"term": {"id": scan_id}},
                    "size": 1
                }
            )

            hits = result.get("hits", {}).get("hits", [])
            if hits:
                return hits[0].get("_source")
        except NotFoundError:
            pass
        except Exception as e:
            logger.error(f"Failed to get scan {scan_id}: {e}")

        return None

    async def search_scans(
        self,
        query: Optional[str] = None,
        severity: Optional[str] = None,
        department: Optional[str] = None,
        date_from: Optional[str] = None,
        date_to: Optional[str] = None,
        filetype: Optional[str] = None,
        min_score: Optional[int] = None,
        max_score: Optional[int] = None,
        scanned_by: Optional[str] = None,  # FR-009: User filter
        file_hash: Optional[str] = None,  # FR-007: File hash filter
        page: int = 1,
        size: int = 20,
        sort_by: str = "timestamp",
        sort_order: str = "desc"
    ) -> Dict[str, Any]:
        """
        Search scans with filtering and pagination.

        Returns:
            Dict with total, page, size, and scans array
        """
        if not self.client:
            return {"total": 0, "page": page, "size": size, "pages": 0, "scans": []}

        # Build query
        must_clauses = []
        filter_clauses = []

        # Full-text search on filename, reasoning, findings
        if query:
            must_clauses.append({
                "multi_match": {
                    "query": query,
                    "fields": ["filename^3", "reasoning", "content_preview"],
                    "type": "best_fields",
                    "fuzziness": "AUTO"
                }
            })

        # Severity filter
        if severity:
            filter_clauses.append({"term": {"sensitivity_level": severity.upper()}})

        # Department filter
        if department:
            filter_clauses.append({"term": {"departments_affected": department}})

        # File type filter
        if filetype:
            filter_clauses.append({"term": {"filetype": filetype.lower()}})

        # Date range
        if date_from or date_to:
            range_clause = {"range": {"timestamp": {}}}
            if date_from:
                range_clause["range"]["timestamp"]["gte"] = date_from
            if date_to:
                range_clause["range"]["timestamp"]["lte"] = date_to
            filter_clauses.append(range_clause)

        # Score range
        if min_score is not None or max_score is not None:
            score_range = {"range": {"overall_sensitivity_score": {}}}
            if min_score is not None:
                score_range["range"]["overall_sensitivity_score"]["gte"] = min_score
            if max_score is not None:
                score_range["range"]["overall_sensitivity_score"]["lte"] = max_score
            filter_clauses.append(score_range)

        # FR-009: User filter
        if scanned_by:
            filter_clauses.append({"term": {"scanned_by": scanned_by}})

        # FR-007: File hash filter
        if file_hash:
            filter_clauses.append({"term": {"file_hash": file_hash}})

        # Build final query
        es_query: Dict[str, Any] = {"bool": {}}
        if must_clauses:
            es_query["bool"]["must"] = must_clauses
        if filter_clauses:
            es_query["bool"]["filter"] = filter_clauses
        if not must_clauses and not filter_clauses:
            es_query = {"match_all": {}}

        # Execute search
        from_offset = (page - 1) * size

        try:
            result = self.client.search(
                index=f"{self._index_prefix}-*",
                body={
                    "query": es_query,
                    "sort": [{sort_by: {"order": sort_order}}],
                    "from": from_offset,
                    "size": size,
                    "track_total_hits": True
                }
            )

            total = result["hits"]["total"]["value"]
            scans = [hit["_source"] for hit in result["hits"]["hits"]]

            return {
                "total": total,
                "page": page,
                "size": size,
                "pages": (total + size - 1) // size if total > 0 else 0,
                "scans": scans
            }
        except Exception as e:
            logger.error(f"Search failed: {e}")
            return {"total": 0, "page": page, "size": size, "pages": 0, "scans": []}

    async def get_aggregations(self) -> Dict[str, Any]:
        """Get aggregated statistics for dashboard."""
        if not self.client:
            return {}

        try:
            result = self.client.search(
                index=f"{self._index_prefix}-*",
                body={
                    "size": 0,
                    "aggs": {
                        "by_severity": {"terms": {"field": "sensitivity_level"}},
                        "by_department": {"terms": {"field": "departments_affected"}},
                        "by_filetype": {"terms": {"field": "filetype"}},
                        "by_category": {"terms": {"field": "top_categories"}},
                        "avg_score": {"avg": {"field": "overall_sensitivity_score"}},
                        "total_scans": {"value_count": {"field": "id"}},
                        "scans_over_time": {
                            "date_histogram": {
                                "field": "timestamp",
                                "calendar_interval": "day"
                            }
                        }
                    }
                }
            )

            aggs = result.get("aggregations", {})

            # Transform to cleaner format
            return {
                "total_scans": aggs.get("total_scans", {}).get("value", 0),
                "avg_score": round(aggs.get("avg_score", {}).get("value", 0) or 0, 1),
                "by_severity": {
                    b["key"]: b["doc_count"]
                    for b in aggs.get("by_severity", {}).get("buckets", [])
                },
                "by_department": {
                    b["key"]: b["doc_count"]
                    for b in aggs.get("by_department", {}).get("buckets", [])
                },
                "by_filetype": {
                    b["key"]: b["doc_count"]
                    for b in aggs.get("by_filetype", {}).get("buckets", [])
                },
                "by_category": {
                    b["key"]: b["doc_count"]
                    for b in aggs.get("by_category", {}).get("buckets", [])
                },
                "timeline": [
                    {"date": b["key_as_string"], "count": b["doc_count"]}
                    for b in aggs.get("scans_over_time", {}).get("buckets", [])
                ]
            }
        except Exception as e:
            logger.error(f"Failed to get aggregations: {e}")
            return {}

    async def delete_scan(self, scan_id: str) -> bool:
        """Delete a scan by ID."""
        if not self.client:
            return False

        try:
            self.client.delete_by_query(
                index=f"{self._index_prefix}-*",
                body={"query": {"term": {"id": scan_id}}}
            )
            logger.info(f"Deleted scan: {scan_id}")
            return True
        except Exception as e:
            logger.error(f"Failed to delete scan {scan_id}: {e}")
            return False

    def test_connection(self) -> Dict[str, Any]:
        """Test Elasticsearch connection."""
        if not self.is_enabled:
            return {"status": "disabled", "message": "Elasticsearch is not enabled"}

        if not self.client:
            return {"status": "error", "message": "Failed to create client"}

        try:
            info = self.client.info()
            health = self.client.cluster.health()

            return {
                "status": "connected",
                "cluster_name": info.get("cluster_name"),
                "version": info.get("version", {}).get("number"),
                "cluster_status": health.get("status"),
                "number_of_nodes": health.get("number_of_nodes")
            }
        except Exception as e:
            return {"status": "error", "message": str(e)}

    async def bulk_index(self, scans: List[Dict[str, Any]]) -> int:
        """
        Bulk index multiple scan documents.

        Args:
            scans: List of scan documents

        Returns:
            Number of successfully indexed documents
        """
        if not self.client or not scans:
            return 0

        self.ensure_index_exists()
        index_name = self.get_current_index()

        actions = [
            {
                "_index": index_name,
                "_id": scan.get("id"),
                "_source": scan
            }
            for scan in scans
        ]

        try:
            success, failed = bulk(self.client, actions, raise_on_error=False)
            if failed:
                logger.warning(f"Failed to index {len(failed)} documents")
            return success
        except Exception as e:
            logger.error(f"Bulk indexing failed: {e}")
            return 0

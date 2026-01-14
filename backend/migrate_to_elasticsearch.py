"""
SentinelDLP - Migration Script
Migrate existing JSON incidents to Elasticsearch

Usage:
    python migrate_to_elasticsearch.py

This script should be run once after Elasticsearch is set up and enabled.
"""

import asyncio
import json
import sys
from pathlib import Path
from datetime import datetime

# Add backend to path for imports
sys.path.insert(0, str(Path(__file__).parent))

from config_manager import ConfigManager
from elasticsearch_service import ElasticsearchService


async def migrate_incidents():
    """Migrate existing incidents from JSON to Elasticsearch."""

    # Determine paths
    if Path("/app/main.py").exists():
        DATA_DIR = Path("/app/data")
    else:
        DATA_DIR = Path(__file__).parent.parent / "data"

    CONFIG_DIR = DATA_DIR / "config"
    INCIDENTS_FILE = DATA_DIR / "incidents.json"

    print(f"Data directory: {DATA_DIR}")
    print(f"Incidents file: {INCIDENTS_FILE}")

    # Check if incidents file exists
    if not INCIDENTS_FILE.exists():
        print("No incidents.json file found. Nothing to migrate.")
        return

    # Load existing incidents
    with open(INCIDENTS_FILE, 'r') as f:
        incidents = json.load(f)

    if not incidents:
        print("Incidents file is empty. Nothing to migrate.")
        return

    print(f"Found {len(incidents)} incidents to migrate.")

    # Initialize config manager and ES service
    config_manager = ConfigManager(CONFIG_DIR)
    es_service = ElasticsearchService(config_manager)

    # Check if ES is enabled
    if not es_service.is_enabled:
        print("\nElasticsearch is not enabled in configuration.")
        print("Please enable it in Admin > Elasticsearch settings first.")
        print("\nTo enable:")
        print("  1. Go to http://localhost:8122 (or your frontend URL)")
        print("  2. Navigate to Admin > Elasticsearch tab")
        print("  3. Enable Elasticsearch and configure connection")
        print("  4. Save and test the connection")
        print("  5. Run this script again")
        return

    # Test connection
    conn_status = es_service.test_connection()
    if conn_status.get("status") != "connected":
        print(f"\nFailed to connect to Elasticsearch: {conn_status.get('message', 'Unknown error')}")
        return

    print(f"Connected to Elasticsearch cluster: {conn_status.get('cluster_name')}")
    print(f"Elasticsearch version: {conn_status.get('version')}")

    # Ensure index exists
    if not es_service.ensure_index_exists():
        print("Failed to create index. Check Elasticsearch logs.")
        return

    print(f"Index ready: {es_service.get_current_index()}")

    # Migrate incidents
    print("\nMigrating incidents...")
    migrated = 0
    failed = 0

    for i, incident in enumerate(incidents):
        try:
            # Transform incident to scan document format
            scan_doc = {
                "id": incident.get("id"),
                "timestamp": incident.get("timestamp"),
                "filename": incident.get("filename"),
                "filetype": incident.get("filetype"),
                "filesize": incident.get("filesize"),
                "overall_sensitivity_score": incident.get("overall_score", 0),
                "sensitivity_level": incident.get("sensitivity_level", "UNKNOWN"),
                "top_categories": incident.get("top_categories", []),
                "departments_affected": incident.get("departments_affected", []),
                "status": incident.get("status", "completed"),
                "hash": incident.get("hash", ""),
                "file_id": None,
                "file_stored": False,
                "migrated_from_json": True,
                "migrated_at": datetime.utcnow().isoformat() + "Z"
            }

            doc_id = await es_service.index_scan(scan_doc)
            if doc_id:
                migrated += 1
            else:
                failed += 1

            # Progress indicator
            if (i + 1) % 100 == 0:
                print(f"  Processed {i + 1}/{len(incidents)}...")

        except Exception as e:
            print(f"  Failed to migrate incident {incident.get('id')}: {e}")
            failed += 1

    print(f"\nMigration complete!")
    print(f"  Successfully migrated: {migrated}")
    print(f"  Failed: {failed}")
    print(f"  Total: {len(incidents)}")

    # Backup original file
    if migrated > 0:
        backup_file = INCIDENTS_FILE.with_suffix('.json.migrated')
        print(f"\nBacking up original file to: {backup_file}")
        INCIDENTS_FILE.rename(backup_file)

        # Create empty incidents file to avoid re-migration
        with open(INCIDENTS_FILE, 'w') as f:
            json.dump([], f)
        print("Created empty incidents.json (old data preserved in .json.migrated)")

    print("\nDone!")


if __name__ == "__main__":
    asyncio.run(migrate_incidents())

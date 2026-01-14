"""
SentinelDLP - File Storage Service
Handles file persistence for preview and download capabilities
"""

import os
import uuid
import mimetypes
import logging
from pathlib import Path
from typing import Optional, Tuple
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)

# Determine storage directory based on environment
if Path("/app/main.py").exists():
    UPLOADS_DIR = Path("/app/data/uploads")
else:
    UPLOADS_DIR = Path(__file__).parent.parent / "data" / "uploads"


class FileStorageService:
    """Manages file storage for scan documents."""

    def __init__(self, uploads_dir: Path = UPLOADS_DIR):
        self.uploads_dir = uploads_dir
        self.uploads_dir.mkdir(parents=True, exist_ok=True)

    def _get_file_dir(self) -> Path:
        """Get storage directory organized by date."""
        date_prefix = datetime.utcnow().strftime("%Y/%m/%d")
        dir_path = self.uploads_dir / date_prefix
        dir_path.mkdir(parents=True, exist_ok=True)
        return dir_path

    def _get_file_path(self, file_id: str, filename: str) -> Path:
        """Get storage path for a file."""
        dir_path = self._get_file_dir()
        # Preserve extension from original filename
        ext = Path(filename).suffix.lower() if filename else ""
        return dir_path / f"{file_id}{ext}"

    async def store_file(
        self,
        content: bytes,
        filename: str,
        file_id: Optional[str] = None
    ) -> Tuple[str, str]:
        """
        Store a file and return its ID and relative path.

        Args:
            content: File content as bytes
            filename: Original filename
            file_id: Optional pre-generated UUID

        Returns:
            Tuple of (file_id, relative_path)
        """
        if file_id is None:
            file_id = str(uuid.uuid4())

        file_path = self._get_file_path(file_id, filename)

        try:
            with open(file_path, 'wb') as f:
                f.write(content)

            relative_path = str(file_path.relative_to(self.uploads_dir))
            logger.info(f"Stored file: {file_id} at {relative_path}")
            return file_id, relative_path
        except Exception as e:
            logger.error(f"Failed to store file {file_id}: {e}")
            raise

    async def get_file(self, file_id: str) -> Optional[Tuple[Path, str]]:
        """
        Retrieve a stored file by ID.

        Args:
            file_id: UUID of the stored file

        Returns:
            Tuple of (file_path, content_type) or None if not found
        """
        # Search for file in uploads directory (could be in any date folder)
        for file_path in self.uploads_dir.rglob(f"{file_id}*"):
            if file_path.is_file():
                content_type = mimetypes.guess_type(str(file_path))[0] or "application/octet-stream"
                return file_path, content_type

        return None

    async def get_file_content(self, file_id: str) -> Optional[bytes]:
        """
        Get file content for preview.

        Args:
            file_id: UUID of the stored file

        Returns:
            File content as bytes or None
        """
        result = await self.get_file(file_id)
        if result:
            file_path, _ = result
            try:
                with open(file_path, 'rb') as f:
                    return f.read()
            except Exception as e:
                logger.error(f"Failed to read file {file_id}: {e}")
        return None

    async def get_preview(self, file_id: str, max_chars: int = 5000) -> Optional[dict]:
        """
        Get text preview of a file.

        Args:
            file_id: UUID of the stored file
            max_chars: Maximum characters to return

        Returns:
            Dict with preview content and metadata
        """
        result = await self.get_file(file_id)
        if not result:
            return None

        file_path, content_type = result
        content = await self.get_file_content(file_id)

        if content:
            try:
                # Try UTF-8 first
                text = content.decode('utf-8')
            except UnicodeDecodeError:
                try:
                    # Fall back to Latin-1
                    text = content.decode('latin-1')
                except Exception:
                    return {
                        "file_id": file_id,
                        "preview": "[Binary file - preview not available]",
                        "truncated": False,
                        "total_size": len(content),
                        "content_type": content_type,
                        "is_binary": True
                    }

            truncated = len(text) > max_chars
            preview_text = text[:max_chars]
            if truncated:
                preview_text += "\n\n... (truncated)"

            return {
                "file_id": file_id,
                "preview": preview_text,
                "truncated": truncated,
                "total_size": len(content),
                "total_chars": len(text),
                "content_type": content_type,
                "is_binary": False
            }

        return None

    async def delete_file(self, file_id: str) -> bool:
        """
        Delete a stored file.

        Args:
            file_id: UUID of the stored file

        Returns:
            True if deleted, False otherwise
        """
        result = await self.get_file(file_id)
        if result:
            file_path, _ = result
            try:
                file_path.unlink()
                logger.info(f"Deleted file: {file_id}")
                return True
            except Exception as e:
                logger.error(f"Failed to delete file {file_id}: {e}")
        return False

    async def cleanup_old_files(self, retention_days: int = 30) -> dict:
        """
        Delete files older than retention period.

        Args:
            retention_days: Number of days to retain files

        Returns:
            Dict with cleanup statistics
        """
        cutoff = datetime.utcnow() - timedelta(days=retention_days)
        deleted_count = 0
        deleted_size = 0
        errors = 0

        for file_path in self.uploads_dir.rglob("*"):
            if file_path.is_file():
                try:
                    mtime = datetime.fromtimestamp(file_path.stat().st_mtime)
                    if mtime < cutoff:
                        size = file_path.stat().st_size
                        file_path.unlink()
                        deleted_count += 1
                        deleted_size += size
                except Exception as e:
                    logger.error(f"Failed to cleanup file {file_path}: {e}")
                    errors += 1

        # Clean up empty directories
        for dir_path in sorted(self.uploads_dir.rglob("*"), reverse=True):
            if dir_path.is_dir():
                try:
                    dir_path.rmdir()  # Only removes if empty
                except OSError:
                    pass  # Directory not empty, skip

        logger.info(f"Cleanup complete: deleted {deleted_count} files ({deleted_size} bytes)")
        return {
            "deleted_count": deleted_count,
            "deleted_size_bytes": deleted_size,
            "errors": errors
        }

    async def get_storage_stats(self) -> dict:
        """
        Get storage statistics.

        Returns:
            Dict with storage statistics
        """
        total_files = 0
        total_size = 0
        by_extension: dict = {}

        for file_path in self.uploads_dir.rglob("*"):
            if file_path.is_file():
                total_files += 1
                size = file_path.stat().st_size
                total_size += size

                ext = file_path.suffix.lower() or "no_extension"
                if ext not in by_extension:
                    by_extension[ext] = {"count": 0, "size": 0}
                by_extension[ext]["count"] += 1
                by_extension[ext]["size"] += size

        return {
            "total_files": total_files,
            "total_size_bytes": total_size,
            "total_size_mb": round(total_size / (1024 * 1024), 2),
            "by_extension": by_extension
        }

    def file_exists(self, file_id: str) -> bool:
        """
        Check if a file exists.

        Args:
            file_id: UUID of the file

        Returns:
            True if file exists
        """
        for file_path in self.uploads_dir.rglob(f"{file_id}*"):
            if file_path.is_file():
                return True
        return False

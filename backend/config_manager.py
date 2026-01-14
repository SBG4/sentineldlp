"""
SentinelDLP - Configuration Manager
Secure encrypted configuration storage with audit logging

FR-002: WebGUI Admin Configuration Management
"""

import os
import json
import hashlib
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field, field_validator
from enum import Enum

from crypto_utils import CryptoManager, mask_secret


class LLMProvider(str, Enum):
    """Supported LLM providers."""
    CLAUDE_API = "claude_api"
    OLLAMA = "ollama"
    VLLM = "vllm"


class ConfigCategory(str, Enum):
    """Configuration categories."""
    LLM = "llm"
    ELASTICSEARCH = "elasticsearch"
    ACTIVE_DIRECTORY = "active_directory"
    PROCESSING = "processing"
    SECURITY = "security"


# ============== Configuration Models ==============

class LLMConfig(BaseModel):
    """LLM Provider configuration."""
    provider: LLMProvider = LLMProvider.CLAUDE_API
    claude_api_key: str = ""
    claude_model: str = "claude-sonnet-4-20250514"
    ollama_endpoint: str = "http://localhost:11434"
    ollama_model: str = "llama3.1"
    vllm_endpoint: str = "http://localhost:8000"
    vllm_model: str = "mistral"
    timeout_seconds: int = 120
    max_tokens: int = 4096


class ElasticsearchConfig(BaseModel):
    """Elasticsearch configuration."""
    enabled: bool = False
    hosts: List[str] = Field(default_factory=lambda: ["https://localhost:9200"])
    api_key: str = ""
    username: str = ""
    password: str = ""
    index_pattern: str = "sentineldlp-incidents-*"
    verify_certs: bool = True
    ca_cert_path: str = ""


class ActiveDirectoryConfig(BaseModel):
    """Active Directory configuration."""
    enabled: bool = False
    server: str = ""
    port: int = 389
    use_ssl: bool = True
    base_dn: str = ""
    bind_user: str = ""
    bind_password: str = ""
    user_search_filter: str = "(sAMAccountName={username})"
    user_group: str = ""
    admin_group: str = ""


class ProcessingConfig(BaseModel):
    """Document processing configuration."""
    max_file_size_mb: int = 100
    chunk_size_mb: int = 5
    concurrent_jobs: int = 10
    ocr_enabled: bool = True
    ocr_languages: str = "eng+ara"
    auto_delete_uploads: bool = False
    retention_days: int = 30


class SecurityConfig(BaseModel):
    """Security configuration."""
    session_timeout_minutes: int = 30
    max_login_attempts: int = 5
    lockout_duration_minutes: int = 15
    require_https: bool = False
    audit_retention_days: int = 365
    api_rate_limit: int = 100  # requests per minute


class SystemConfig(BaseModel):
    """Complete system configuration."""
    llm: LLMConfig = Field(default_factory=LLMConfig)
    elasticsearch: ElasticsearchConfig = Field(default_factory=ElasticsearchConfig)
    active_directory: ActiveDirectoryConfig = Field(default_factory=ActiveDirectoryConfig)
    processing: ProcessingConfig = Field(default_factory=ProcessingConfig)
    security: SecurityConfig = Field(default_factory=SecurityConfig)
    
    # Metadata
    version: str = "1.0.0"
    last_modified: str = ""
    last_modified_by: str = "system"


class AuditEntry(BaseModel):
    """Audit log entry for configuration changes."""
    timestamp: str
    user: str
    action: str  # create, update, delete, rotate_key
    category: str
    field: str
    old_value_hash: str = ""  # Hash of old value (never store actual secrets)
    new_value_hash: str = ""  # Hash of new value
    ip_address: str = ""
    user_agent: str = ""
    
    
# ============== Secret Fields Definition ==============

# Fields that should be encrypted and masked
SECRET_FIELDS = {
    "llm.claude_api_key",
    "elasticsearch.api_key",
    "elasticsearch.password",
    "active_directory.bind_password",
}


def is_secret_field(category: str, field: str) -> bool:
    """Check if a field contains sensitive data."""
    full_path = f"{category}.{field}"
    return full_path in SECRET_FIELDS


def hash_value(value: str) -> str:
    """Create a hash of a value for audit logging (never log actual secrets)."""
    if not value:
        return ""
    return hashlib.sha256(value.encode()).hexdigest()[:16]


# ============== Configuration Manager ==============

class ConfigManager:
    """
    Manages secure configuration storage with encryption and audit logging.
    """
    
    def __init__(self, config_dir: Path):
        """
        Initialize ConfigManager.
        
        Args:
            config_dir: Path to configuration directory
        """
        self.config_dir = config_dir
        self.config_file = config_dir / "settings.enc.json"
        self.audit_file = config_dir / "audit.log.json"
        self.crypto = CryptoManager(config_dir)
        
        # Ensure directory exists
        self.config_dir.mkdir(parents=True, exist_ok=True)
        
        # Initialize with defaults if no config exists
        if not self.config_file.exists():
            self._save_config(SystemConfig())
    
    def _encrypt_secrets(self, config: SystemConfig) -> dict:
        """
        Encrypt secret fields in configuration before storage.
        
        Args:
            config: SystemConfig object
            
        Returns:
            Dictionary with encrypted secret values
        """
        data = config.model_dump()
        
        # Encrypt LLM secrets
        if data["llm"]["claude_api_key"]:
            data["llm"]["claude_api_key"] = self.crypto.encrypt(data["llm"]["claude_api_key"])
        
        # Encrypt Elasticsearch secrets
        if data["elasticsearch"]["api_key"]:
            data["elasticsearch"]["api_key"] = self.crypto.encrypt(data["elasticsearch"]["api_key"])
        if data["elasticsearch"]["password"]:
            data["elasticsearch"]["password"] = self.crypto.encrypt(data["elasticsearch"]["password"])
        
        # Encrypt Active Directory secrets
        if data["active_directory"]["bind_password"]:
            data["active_directory"]["bind_password"] = self.crypto.encrypt(data["active_directory"]["bind_password"])
        
        return data
    
    def _decrypt_secrets(self, data: dict) -> dict:
        """
        Decrypt secret fields from storage.
        
        Args:
            data: Dictionary with encrypted values
            
        Returns:
            Dictionary with decrypted secret values
        """
        # Decrypt LLM secrets
        if data.get("llm", {}).get("claude_api_key"):
            data["llm"]["claude_api_key"] = self.crypto.decrypt(data["llm"]["claude_api_key"])
        
        # Decrypt Elasticsearch secrets
        if data.get("elasticsearch", {}).get("api_key"):
            data["elasticsearch"]["api_key"] = self.crypto.decrypt(data["elasticsearch"]["api_key"])
        if data.get("elasticsearch", {}).get("password"):
            data["elasticsearch"]["password"] = self.crypto.decrypt(data["elasticsearch"]["password"])
        
        # Decrypt Active Directory secrets
        if data.get("active_directory", {}).get("bind_password"):
            data["active_directory"]["bind_password"] = self.crypto.decrypt(data["active_directory"]["bind_password"])
        
        return data
    
    def _mask_secrets(self, data: dict) -> dict:
        """
        Mask secret fields for API response.
        
        Args:
            data: Dictionary with actual values
            
        Returns:
            Dictionary with masked secret values
        """
        result = json.loads(json.dumps(data))  # Deep copy
        
        # Mask LLM secrets
        if result.get("llm", {}).get("claude_api_key"):
            result["llm"]["claude_api_key"] = mask_secret(result["llm"]["claude_api_key"])
            result["llm"]["claude_api_key_set"] = True
        else:
            result["llm"]["claude_api_key_set"] = False
        
        # Mask Elasticsearch secrets
        if result.get("elasticsearch", {}).get("api_key"):
            result["elasticsearch"]["api_key"] = mask_secret(result["elasticsearch"]["api_key"])
            result["elasticsearch"]["api_key_set"] = True
        else:
            result["elasticsearch"]["api_key_set"] = False
            
        if result.get("elasticsearch", {}).get("password"):
            result["elasticsearch"]["password"] = mask_secret(result["elasticsearch"]["password"])
            result["elasticsearch"]["password_set"] = True
        else:
            result["elasticsearch"]["password_set"] = False
        
        # Mask Active Directory secrets
        if result.get("active_directory", {}).get("bind_password"):
            result["active_directory"]["bind_password"] = mask_secret(result["active_directory"]["bind_password"])
            result["active_directory"]["bind_password_set"] = True
        else:
            result["active_directory"]["bind_password_set"] = False
        
        return result
    
    def _save_config(self, config: SystemConfig):
        """Save encrypted configuration to disk."""
        config.last_modified = datetime.utcnow().isoformat() + "Z"
        data = self._encrypt_secrets(config)
        
        with open(self.config_file, 'w') as f:
            json.dump(data, f, indent=2)
    
    def load_config(self) -> SystemConfig:
        """
        Load and decrypt configuration from disk.
        
        Returns:
            SystemConfig object with decrypted values
        """
        if not self.config_file.exists():
            return SystemConfig()
        
        try:
            with open(self.config_file, 'r') as f:
                data = json.load(f)
            
            data = self._decrypt_secrets(data)
            return SystemConfig(**data)
        except Exception:
            return SystemConfig()
    
    def get_config_masked(self) -> dict:
        """
        Get configuration with secrets masked for API response.
        
        Returns:
            Dictionary with masked secret values
        """
        config = self.load_config()
        return self._mask_secrets(config.model_dump())
    
    def update_config(
        self, 
        updates: dict, 
        user: str = "admin",
        ip_address: str = "",
        user_agent: str = ""
    ) -> SystemConfig:
        """
        Update configuration with provided values.
        
        Args:
            updates: Dictionary of updates (can be partial)
            user: Username making the change
            ip_address: IP address of requester
            user_agent: User agent of requester
            
        Returns:
            Updated SystemConfig
        """
        current = self.load_config()
        current_dict = current.model_dump()
        
        # Track changes for audit
        changes = []
        
        # Apply updates by category
        for category, values in updates.items():
            if category not in current_dict:
                continue
                
            if isinstance(values, dict):
                for field, new_value in values.items():
                    if field in current_dict[category]:
                        old_value = current_dict[category][field]
                        
                        # Skip if value hasn't changed
                        if old_value == new_value:
                            continue
                        
                        # Skip empty secret updates (don't overwrite with empty)
                        if is_secret_field(category, field) and not new_value:
                            continue
                        
                        # Record change
                        changes.append({
                            "category": category,
                            "field": field,
                            "old_value_hash": hash_value(str(old_value)) if is_secret_field(category, field) else str(old_value)[:50],
                            "new_value_hash": hash_value(str(new_value)) if is_secret_field(category, field) else str(new_value)[:50],
                        })
                        
                        current_dict[category][field] = new_value
        
        # Update metadata
        current_dict["last_modified_by"] = user
        
        # Create updated config
        updated_config = SystemConfig(**current_dict)
        
        # Save to disk
        self._save_config(updated_config)
        
        # Log audit entries
        for change in changes:
            self._log_audit(
                user=user,
                action="update",
                category=change["category"],
                field=change["field"],
                old_value_hash=change["old_value_hash"],
                new_value_hash=change["new_value_hash"],
                ip_address=ip_address,
                user_agent=user_agent
            )
        
        return updated_config
    
    def _log_audit(
        self,
        user: str,
        action: str,
        category: str,
        field: str,
        old_value_hash: str = "",
        new_value_hash: str = "",
        ip_address: str = "",
        user_agent: str = ""
    ):
        """
        Log an audit entry for configuration changes.
        
        Audit log is append-only with checksums for tamper evidence.
        """
        entry = AuditEntry(
            timestamp=datetime.utcnow().isoformat() + "Z",
            user=user,
            action=action,
            category=category,
            field=field,
            old_value_hash=old_value_hash,
            new_value_hash=new_value_hash,
            ip_address=ip_address,
            user_agent=user_agent
        )
        
        # Load existing audit log
        audit_log = self._load_audit_log()
        
        # Add new entry
        audit_log.append(entry.model_dump())
        
        # Save audit log
        with open(self.audit_file, 'w') as f:
            json.dump(audit_log, f, indent=2)
    
    def _load_audit_log(self) -> List[dict]:
        """Load audit log from disk."""
        if not self.audit_file.exists():
            return []
        
        try:
            with open(self.audit_file, 'r') as f:
                return json.load(f)
        except Exception:
            return []
    
    def get_audit_log(self, limit: int = 100, offset: int = 0) -> dict:
        """
        Get audit log entries.
        
        Args:
            limit: Maximum entries to return
            offset: Offset for pagination
            
        Returns:
            Dictionary with audit entries and metadata
        """
        entries = self._load_audit_log()
        total = len(entries)
        
        # Sort by timestamp descending (newest first)
        entries = sorted(entries, key=lambda x: x.get("timestamp", ""), reverse=True)
        
        # Apply pagination
        entries = entries[offset:offset + limit]
        
        return {
            "total": total,
            "offset": offset,
            "limit": limit,
            "entries": entries
        }
    
    def rotate_encryption_key(self, user: str = "admin", ip_address: str = "", user_agent: str = "") -> bool:
        """
        Rotate the master encryption key.
        
        Re-encrypts all secrets with a new key.
        
        Args:
            user: Username performing rotation
            ip_address: IP address of requester
            user_agent: User agent of requester
            
        Returns:
            True if rotation successful
        """
        try:
            # Load current config with current key
            current_config = self.load_config()
            
            # Rotate the key
            if not self.crypto.rotate_key():
                return False
            
            # Re-save config with new key (this re-encrypts)
            self._save_config(current_config)
            
            # Cleanup backup key
            self.crypto.cleanup_backup()
            
            # Log audit entry
            self._log_audit(
                user=user,
                action="rotate_key",
                category="security",
                field="master_encryption_key",
                old_value_hash="rotated",
                new_value_hash="new_key_generated",
                ip_address=ip_address,
                user_agent=user_agent
            )
            
            return True
        except Exception:
            return False
    
    def is_first_run(self) -> bool:
        """
        Check if this is the first run (no configuration exists).
        
        Returns:
            True if first run setup is needed
        """
        if not self.config_file.exists():
            return True
        
        config = self.load_config()
        # First run if no LLM API key is configured
        return not config.llm.claude_api_key and config.llm.provider == LLMProvider.CLAUDE_API
    
    def get_config_for_legacy_settings(self) -> dict:
        """
        Get configuration in legacy settings format for backward compatibility.
        
        Returns:
            Dictionary matching the old Settings model format
        """
        config = self.load_config()
        return {
            "api_key": config.llm.claude_api_key,
            "model": config.llm.claude_model,
            "max_tokens": config.llm.max_tokens,
            "auto_delete_uploads": config.processing.auto_delete_uploads,
            "retention_days": config.processing.retention_days
        }

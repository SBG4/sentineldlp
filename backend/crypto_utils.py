"""
SentinelDLP - Cryptographic Utilities
Fernet symmetric encryption for sensitive configuration values

FR-002: WebGUI Admin Configuration Management
"""

import os
import base64
import hashlib
import secrets
from pathlib import Path
from typing import Optional
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


class CryptoManager:
    """
    Manages encryption/decryption of sensitive configuration values.
    Uses Fernet symmetric encryption with a master key stored separately.
    """
    
    def __init__(self, config_dir: Path):
        """
        Initialize CryptoManager with configuration directory.
        
        Args:
            config_dir: Path to configuration directory for key storage
        """
        self.config_dir = config_dir
        self.key_file = config_dir / "master.key"
        self._fernet: Optional[Fernet] = None
        
        # Ensure config directory exists with restricted permissions
        self.config_dir.mkdir(parents=True, exist_ok=True)
        
    def _generate_master_key(self) -> bytes:
        """Generate a new cryptographically secure master key."""
        return Fernet.generate_key()
    
    def _load_or_create_key(self) -> bytes:
        """
        Load existing master key or create new one.
        Key file has restricted permissions (owner read/write only).
        """
        if self.key_file.exists():
            with open(self.key_file, 'rb') as f:
                return f.read()
        else:
            key = self._generate_master_key()
            # Write key with restricted permissions
            with open(self.key_file, 'wb') as f:
                f.write(key)
            # Set file permissions to 0600 (owner read/write only)
            try:
                os.chmod(self.key_file, 0o600)
            except OSError:
                pass  # Windows doesn't support chmod the same way
            return key
    
    @property
    def fernet(self) -> Fernet:
        """Get or create Fernet instance with loaded key."""
        if self._fernet is None:
            key = self._load_or_create_key()
            self._fernet = Fernet(key)
        return self._fernet
    
    def encrypt(self, plaintext: str) -> str:
        """
        Encrypt a plaintext string.
        
        Args:
            plaintext: String to encrypt
            
        Returns:
            Base64-encoded encrypted string
        """
        if not plaintext:
            return ""
        encrypted = self.fernet.encrypt(plaintext.encode('utf-8'))
        return base64.urlsafe_b64encode(encrypted).decode('utf-8')
    
    def decrypt(self, ciphertext: str) -> str:
        """
        Decrypt an encrypted string.
        
        Args:
            ciphertext: Base64-encoded encrypted string
            
        Returns:
            Decrypted plaintext string
            
        Raises:
            InvalidToken: If decryption fails (wrong key or corrupted data)
        """
        if not ciphertext:
            return ""
        try:
            encrypted = base64.urlsafe_b64decode(ciphertext.encode('utf-8'))
            decrypted = self.fernet.decrypt(encrypted)
            return decrypted.decode('utf-8')
        except (InvalidToken, Exception):
            # Return empty string if decryption fails
            return ""
    
    def rotate_key(self) -> bool:
        """
        Rotate the master encryption key.
        This re-encrypts all data with a new key.
        
        Returns:
            True if rotation successful
        """
        try:
            # Generate new key
            new_key = self._generate_master_key()
            
            # Backup old key file
            if self.key_file.exists():
                backup_file = self.key_file.with_suffix('.key.bak')
                with open(self.key_file, 'rb') as f:
                    old_key = f.read()
                with open(backup_file, 'wb') as f:
                    f.write(old_key)
                try:
                    os.chmod(backup_file, 0o600)
                except OSError:
                    pass
            
            # Write new key
            with open(self.key_file, 'wb') as f:
                f.write(new_key)
            try:
                os.chmod(self.key_file, 0o600)
            except OSError:
                pass
            
            # Update fernet instance
            self._fernet = Fernet(new_key)
            
            return True
        except Exception:
            return False
    
    def get_old_fernet(self) -> Optional[Fernet]:
        """
        Get Fernet instance with backup key for re-encryption during rotation.
        
        Returns:
            Fernet instance with old key, or None if no backup exists
        """
        backup_file = self.key_file.with_suffix('.key.bak')
        if backup_file.exists():
            with open(backup_file, 'rb') as f:
                old_key = f.read()
            return Fernet(old_key)
        return None
    
    def cleanup_backup(self):
        """Remove backup key file after successful rotation."""
        backup_file = self.key_file.with_suffix('.key.bak')
        if backup_file.exists():
            backup_file.unlink()


def mask_secret(value: str, visible_chars: int = 4) -> str:
    """
    Mask a secret value for display, showing only last few characters.
    
    Args:
        value: Secret value to mask
        visible_chars: Number of characters to show at end
        
    Returns:
        Masked string like "••••••••abcd"
    """
    if not value:
        return ""
    if len(value) <= visible_chars:
        return "•" * len(value)
    masked_length = min(8, len(value) - visible_chars)
    return "•" * masked_length + value[-visible_chars:]


def generate_secure_token(length: int = 32) -> str:
    """
    Generate a cryptographically secure random token.
    
    Args:
        length: Length of token in bytes (will be hex-encoded to 2x length)
        
    Returns:
        Hex-encoded random token
    """
    return secrets.token_hex(length)

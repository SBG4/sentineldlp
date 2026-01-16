"""
SentinelDLP Authentication Service (FR-006/GAP-002)
JWT-based authentication with support for local users and Active Directory

Best Practices Implemented:
- JWT tokens with configurable expiration
- Secure password hashing with bcrypt (cost factor 12)
- Token refresh mechanism
- Role-based access control (RBAC)
- Audit logging for authentication events
- Constant-time password comparison to prevent timing attacks
"""

import os
import json
import uuid
import secrets
import logging
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any, List, Tuple
from enum import Enum
from pathlib import Path

# JWT handling
from jose import jwt, JWTError, ExpiredSignatureError
# Password hashing
import bcrypt
# FR-006 Phase 3: Argon2id hashing
try:
    from argon2 import PasswordHasher
    from argon2.exceptions import VerifyMismatchError, InvalidHashError
    ARGON2_AVAILABLE = True
except ImportError:
    ARGON2_AVAILABLE = False

logger = logging.getLogger(__name__)

# =============================================================================
# CONFIGURATION
# =============================================================================

# JWT Settings
JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", None)  # Will be auto-generated if not set
JWT_ALGORITHM = "HS256"
JWT_ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("JWT_ACCESS_TOKEN_EXPIRE_MINUTES", "30"))
JWT_REFRESH_TOKEN_EXPIRE_DAYS = int(os.getenv("JWT_REFRESH_TOKEN_EXPIRE_DAYS", "7"))

# Bcrypt cost factor (12 is recommended for 2024+)
BCRYPT_COST_FACTOR = 12

# FR-006 Phase 3: Password hashing preference
# "argon2id" (recommended), "bcrypt" (fallback)
PASSWORD_HASH_ALGORITHM = os.getenv("PASSWORD_HASH_ALGORITHM", "argon2id" if ARGON2_AVAILABLE else "bcrypt")

# Auth mode: local, ldap, hybrid
AUTH_MODE = os.getenv("AUTH_MODE", "hybrid")


class UserRole(str, Enum):
    """Role-Based Access Control roles"""
    ADMIN = "admin"      # Full access: configuration, user management, all scans
    ANALYST = "analyst"  # Scan documents, view history, export reports
    VIEWER = "viewer"    # View scan results only (read-only)


class AuthProvider(str, Enum):
    """Authentication provider types"""
    LOCAL = "local"
    LDAP = "ldap"


# Role permissions mapping
ROLE_PERMISSIONS = {
    UserRole.ADMIN: [
        "admin:*",           # All admin operations
        "users:*",           # User management
        "config:*",          # Configuration management
        "scans:*",           # All scan operations
        "files:*",           # File operations
        "reports:*",         # Report generation
    ],
    UserRole.ANALYST: [
        "scans:create",      # Create new scans
        "scans:read",        # View scans
        "scans:delete",      # Delete own scans
        "files:read",        # View files
        "files:download",    # Download files
        "reports:create",    # Generate reports
        "reports:read",      # View reports
    ],
    UserRole.VIEWER: [
        "scans:read",        # View scans only
        "files:read",        # View file previews
        "reports:read",      # View reports
    ],
}


class AuthService:
    """
    Authentication service handling JWT tokens, password verification,
    and session management.

    FR-006 Phase 3 Features:
    - Argon2id password hashing (backward compatible with bcrypt)
    - Refresh token rotation
    - Token reuse detection (security breach indicator)
    """

    def __init__(self, config_path: str = "/app/data/config"):
        self.config_path = Path(config_path)
        self.jwt_secret = self._get_or_create_jwt_secret()
        self.active_refresh_tokens: Dict[str, Dict[str, Any]] = {}
        # FR-006 Phase 3: Track used tokens for reuse detection
        self.used_token_jti: Dict[str, str] = {}  # jti -> user_id mapping
        self._load_refresh_tokens()
        self._load_used_tokens()
        # FR-006 Phase 3: Argon2id password hasher
        if ARGON2_AVAILABLE:
            self.argon2_hasher = PasswordHasher(
                time_cost=2,
                memory_cost=65536,  # 64MB
                parallelism=1
            )

    def _get_or_create_jwt_secret(self) -> str:
        """Get existing JWT secret or generate a new one"""
        if JWT_SECRET_KEY:
            return JWT_SECRET_KEY

        secret_file = self.config_path / "jwt_secret.key"

        if secret_file.exists():
            return secret_file.read_text().strip()

        # Generate new secret
        new_secret = secrets.token_urlsafe(64)

        # Ensure directory exists
        self.config_path.mkdir(parents=True, exist_ok=True)

        # Write with secure permissions
        secret_file.write_text(new_secret)
        try:
            os.chmod(secret_file, 0o600)
        except OSError:
            pass

        logger.info("Generated new JWT secret key")
        return new_secret

    def _load_refresh_tokens(self):
        """Load active refresh tokens from storage"""
        tokens_file = self.config_path / "refresh_tokens.json"
        if tokens_file.exists():
            try:
                data = json.loads(tokens_file.read_text())
                # Filter out expired tokens
                now = datetime.now(timezone.utc)
                self.active_refresh_tokens = {
                    k: v for k, v in data.items()
                    if datetime.fromisoformat(v.get("expires_at", "2000-01-01")) > now
                }
            except Exception as e:
                logger.warning(f"Failed to load refresh tokens: {e}")
                self.active_refresh_tokens = {}

    def _save_refresh_tokens(self):
        """Persist refresh tokens to storage"""
        tokens_file = self.config_path / "refresh_tokens.json"
        try:
            self.config_path.mkdir(parents=True, exist_ok=True)
            tokens_file.write_text(json.dumps(self.active_refresh_tokens, indent=2))
            os.chmod(tokens_file, 0o600)
        except Exception as e:
            logger.error(f"Failed to save refresh tokens: {e}")

    def _load_used_tokens(self):
        """FR-006 Phase 3: Load used token JTIs for reuse detection"""
        tokens_file = self.config_path / "used_tokens.json"
        if tokens_file.exists():
            try:
                data = json.loads(tokens_file.read_text())
                # Keep only tokens from the last 7 days to prevent unbounded growth
                now = datetime.now(timezone.utc)
                cutoff = (now - timedelta(days=JWT_REFRESH_TOKEN_EXPIRE_DAYS)).isoformat()
                self.used_token_jti = {
                    k: v for k, v in data.items()
                    if v.get("used_at", "2000-01-01") > cutoff
                }
            except Exception as e:
                logger.warning(f"Failed to load used tokens: {e}")
                self.used_token_jti = {}

    def _save_used_tokens(self):
        """FR-006 Phase 3: Persist used token JTIs"""
        tokens_file = self.config_path / "used_tokens.json"
        try:
            self.config_path.mkdir(parents=True, exist_ok=True)
            tokens_file.write_text(json.dumps(self.used_token_jti, indent=2))
            os.chmod(tokens_file, 0o600)
        except Exception as e:
            logger.error(f"Failed to save used tokens: {e}")

    # =========================================================================
    # PASSWORD HASHING (ARGON2ID / BCRYPT)
    # =========================================================================

    def hash_password(self, password: str) -> str:
        """
        FR-006 Phase 3: Hash password using Argon2id (preferred) or bcrypt.
        Argon2id is the recommended algorithm for password hashing as of 2024+.
        Returns hash string with algorithm prefix for auto-detection.
        """
        if ARGON2_AVAILABLE and PASSWORD_HASH_ALGORITHM == "argon2id":
            # Argon2id: memory-hard, resistant to GPU/ASIC attacks
            return self.argon2_hasher.hash(password)
        else:
            # Fallback to bcrypt
            salt = bcrypt.gensalt(rounds=BCRYPT_COST_FACTOR)
            hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
            return hashed.decode('utf-8')

    def verify_password(self, password: str, hashed_password: str) -> bool:
        """
        FR-006 Phase 3: Verify password against hash.
        Auto-detects Argon2id vs bcrypt based on hash format.
        Uses constant-time comparison to prevent timing attacks.
        """
        try:
            # Argon2id hashes start with "$argon2"
            if hashed_password.startswith("$argon2"):
                if not ARGON2_AVAILABLE:
                    logger.error("Argon2 hash found but argon2-cffi not installed")
                    return False
                try:
                    self.argon2_hasher.verify(hashed_password, password)
                    return True
                except VerifyMismatchError:
                    return False
                except InvalidHashError as e:
                    logger.warning(f"Invalid Argon2 hash format: {e}")
                    return False
            else:
                # Bcrypt hashes start with "$2a$", "$2b$", or "$2y$"
                return bcrypt.checkpw(
                    password.encode('utf-8'),
                    hashed_password.encode('utf-8')
                )
        except Exception as e:
            logger.warning(f"Password verification failed: {e}")
            return False

    def needs_rehash(self, hashed_password: str) -> bool:
        """
        FR-006 Phase 3: Check if password hash should be upgraded.
        Returns True if using bcrypt but Argon2id is preferred.
        """
        if PASSWORD_HASH_ALGORITHM == "argon2id" and ARGON2_AVAILABLE:
            return not hashed_password.startswith("$argon2")
        return False

    # =========================================================================
    # JWT TOKEN MANAGEMENT
    # =========================================================================

    def create_access_token(
        self,
        user_id: str,
        username: str,
        role: UserRole,
        provider: AuthProvider,
        additional_claims: Optional[Dict[str, Any]] = None
    ) -> str:
        """
        Create JWT access token with user claims.

        Token payload includes:
        - sub: user_id
        - username: display name
        - role: user role (admin, analyst, viewer)
        - provider: auth provider (local, ldap)
        - permissions: list of allowed operations
        - exp: expiration timestamp
        - iat: issued at timestamp
        - jti: unique token ID
        """
        now = datetime.now(timezone.utc)
        expires = now + timedelta(minutes=JWT_ACCESS_TOKEN_EXPIRE_MINUTES)

        payload = {
            "sub": user_id,
            "username": username,
            "role": role.value,
            "provider": provider.value,
            "permissions": ROLE_PERMISSIONS.get(role, []),
            "exp": expires,
            "iat": now,
            "jti": str(uuid.uuid4()),
            "type": "access"
        }

        if additional_claims:
            payload.update(additional_claims)

        return jwt.encode(payload, self.jwt_secret, algorithm=JWT_ALGORITHM)

    def create_refresh_token(
        self,
        user_id: str,
        username: str,
        role: UserRole,
        provider: AuthProvider
    ) -> str:
        """
        Create JWT refresh token for obtaining new access tokens.
        Refresh tokens are longer-lived and stored server-side.
        """
        now = datetime.now(timezone.utc)
        expires = now + timedelta(days=JWT_REFRESH_TOKEN_EXPIRE_DAYS)
        token_id = str(uuid.uuid4())

        payload = {
            "sub": user_id,
            "username": username,
            "role": role.value,
            "provider": provider.value,
            "exp": expires,
            "iat": now,
            "jti": token_id,
            "type": "refresh"
        }

        token = jwt.encode(payload, self.jwt_secret, algorithm=JWT_ALGORITHM)

        # Store refresh token for validation
        self.active_refresh_tokens[token_id] = {
            "user_id": user_id,
            "username": username,
            "role": role.value,
            "provider": provider.value,
            "expires_at": expires.isoformat(),
            "created_at": now.isoformat()
        }
        self._save_refresh_tokens()

        return token

    def create_token_pair(
        self,
        user_id: str,
        username: str,
        role: UserRole,
        provider: AuthProvider,
        additional_claims: Optional[Dict[str, Any]] = None
    ) -> Dict[str, str]:
        """Create both access and refresh tokens"""
        return {
            "access_token": self.create_access_token(
                user_id, username, role, provider, additional_claims
            ),
            "refresh_token": self.create_refresh_token(
                user_id, username, role, provider
            ),
            "token_type": "bearer",
            "expires_in": JWT_ACCESS_TOKEN_EXPIRE_MINUTES * 60
        }

    def verify_token(self, token: str, token_type: str = "access") -> Optional[Dict[str, Any]]:
        """
        Verify and decode JWT token.
        Returns payload if valid, None if invalid or expired.
        """
        try:
            payload = jwt.decode(
                token,
                self.jwt_secret,
                algorithms=[JWT_ALGORITHM]
            )

            # Verify token type
            if payload.get("type") != token_type:
                logger.warning(f"Token type mismatch: expected {token_type}")
                return None

            # For refresh tokens, verify it's still active
            if token_type == "refresh":
                jti = payload.get("jti")
                if jti not in self.active_refresh_tokens:
                    logger.warning(f"Refresh token not found in active tokens")
                    return None

            return payload

        except ExpiredSignatureError:
            logger.debug("Token has expired")
            return None
        except JWTError as e:
            logger.warning(f"Token verification failed: {e}")
            return None

    def refresh_access_token(self, refresh_token: str) -> Optional[Dict[str, Any]]:
        """
        FR-006 Phase 3: Use refresh token to get new token pair with rotation.

        Security features:
        - Token Rotation: Returns new refresh token on each use
        - Reuse Detection: If old token is reused, revoke ALL user tokens (breach indicator)

        Returns new token pair if valid, None if invalid.
        """
        payload = self.verify_token(refresh_token, token_type="refresh")
        if not payload:
            return None

        jti = payload.get("jti")
        user_id = payload.get("sub")

        # FR-006 Phase 3: Token Reuse Detection
        # If this token was already used, it's a potential breach
        if jti in self.used_token_jti:
            logger.warning(
                f"TOKEN REUSE DETECTED for user {user_id}! "
                f"Token JTI {jti} was already used. Revoking all tokens."
            )
            # Revoke ALL tokens for this user - potential session hijacking
            self.revoke_all_user_tokens(user_id)
            return None

        try:
            role = UserRole(payload.get("role"))
            provider = AuthProvider(payload.get("provider"))
        except ValueError:
            logger.warning("Invalid role or provider in refresh token")
            return None

        # FR-006 Phase 3: Mark token as used (for reuse detection)
        self.used_token_jti[jti] = {
            "user_id": user_id,
            "used_at": datetime.now(timezone.utc).isoformat()
        }
        self._save_used_tokens()

        # Remove old refresh token from active list
        if jti in self.active_refresh_tokens:
            del self.active_refresh_tokens[jti]

        # FR-006 Phase 3: Token Rotation - Create new token pair
        new_access = self.create_access_token(
            user_id,
            payload["username"],
            role,
            provider
        )
        new_refresh = self.create_refresh_token(
            user_id,
            payload["username"],
            role,
            provider
        )

        return {
            "access_token": new_access,
            "refresh_token": new_refresh,  # New refresh token (rotation)
            "token_type": "bearer",
            "expires_in": JWT_ACCESS_TOKEN_EXPIRE_MINUTES * 60
        }

    def revoke_refresh_token(self, refresh_token: str) -> bool:
        """
        Revoke a refresh token (logout).
        Returns True if token was found and revoked.
        """
        try:
            payload = jwt.decode(
                refresh_token,
                self.jwt_secret,
                algorithms=[JWT_ALGORITHM],
                options={"verify_exp": False}  # Allow revoking expired tokens
            )

            jti = payload.get("jti")
            if jti in self.active_refresh_tokens:
                del self.active_refresh_tokens[jti]
                self._save_refresh_tokens()
                return True

        except JWTError:
            pass

        return False

    def revoke_all_user_tokens(self, user_id: str) -> int:
        """
        Revoke all refresh tokens for a user (e.g., password change).
        Returns number of tokens revoked.
        """
        tokens_to_revoke = [
            jti for jti, data in self.active_refresh_tokens.items()
            if data.get("user_id") == user_id
        ]

        for jti in tokens_to_revoke:
            del self.active_refresh_tokens[jti]

        if tokens_to_revoke:
            self._save_refresh_tokens()

        return len(tokens_to_revoke)

    # =========================================================================
    # PERMISSION CHECKING
    # =========================================================================

    def has_permission(self, role: UserRole, permission: str) -> bool:
        """
        Check if a role has a specific permission.
        Supports wildcard matching (e.g., "admin:*" matches "admin:users").
        """
        role_permissions = ROLE_PERMISSIONS.get(role, [])

        for perm in role_permissions:
            if perm == permission:
                return True
            # Wildcard matching
            if perm.endswith(":*"):
                prefix = perm[:-1]  # Remove "*"
                if permission.startswith(prefix):
                    return True

        return False

    def get_role_permissions(self, role: UserRole) -> List[str]:
        """Get list of permissions for a role"""
        return ROLE_PERMISSIONS.get(role, [])


# =============================================================================
# AUDIT LOGGING
# =============================================================================

class AuthAuditLogger:
    """Log authentication events for security auditing"""

    def __init__(self, log_path: str = "/app/data/config"):
        self.log_path = Path(log_path)
        self.log_file = self.log_path / "auth_audit.log.json"

    def log_event(
        self,
        event_type: str,
        username: str,
        success: bool,
        provider: str = "unknown",
        ip_address: str = "unknown",
        user_agent: str = "unknown",
        details: Optional[Dict[str, Any]] = None
    ):
        """Log an authentication event"""
        event = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_type": event_type,
            "username": username,
            "success": success,
            "provider": provider,
            "ip_address": ip_address,
            "user_agent": user_agent[:200] if user_agent else "unknown",
            "details": details or {}
        }

        try:
            self.log_path.mkdir(parents=True, exist_ok=True)

            # Append to log file
            with open(self.log_file, "a") as f:
                f.write(json.dumps(event) + "\n")

        except Exception as e:
            logger.error(f"Failed to write auth audit log: {e}")

    def get_recent_events(
        self,
        limit: int = 100,
        username: Optional[str] = None,
        event_type: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """Get recent authentication events"""
        events = []

        if not self.log_file.exists():
            return events

        try:
            with open(self.log_file, "r") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        event = json.loads(line)

                        # Apply filters
                        if username and event.get("username") != username:
                            continue
                        if event_type and event.get("event_type") != event_type:
                            continue

                        events.append(event)
                    except json.JSONDecodeError:
                        continue

            # Return most recent events
            return sorted(
                events,
                key=lambda x: x.get("timestamp", ""),
                reverse=True
            )[:limit]

        except Exception as e:
            logger.error(f"Failed to read auth audit log: {e}")
            return []


# Global instances
auth_service = AuthService()
auth_audit = AuthAuditLogger()

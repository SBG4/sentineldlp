"""
SentinelDLP User Manager (FR-006/GAP-002)
Local user management with encrypted storage

Features:
- CRUD operations for local user accounts
- Bcrypt password hashing
- Role-based access control
- User profile management
- Password policies and validation
- Account lockout after failed attempts
"""

import os
import json
import uuid
import logging
from datetime import datetime, timezone
from typing import Optional, Dict, Any, List
from pathlib import Path
from dataclasses import dataclass, asdict, field

from auth_service import auth_service, UserRole, AuthProvider

logger = logging.getLogger(__name__)

# =============================================================================
# CONFIGURATION
# =============================================================================

# Password policy
MIN_PASSWORD_LENGTH = int(os.getenv("MIN_PASSWORD_LENGTH", "8"))
REQUIRE_UPPERCASE = os.getenv("REQUIRE_PASSWORD_UPPERCASE", "true").lower() == "true"
REQUIRE_LOWERCASE = os.getenv("REQUIRE_PASSWORD_LOWERCASE", "true").lower() == "true"
REQUIRE_DIGIT = os.getenv("REQUIRE_PASSWORD_DIGIT", "true").lower() == "true"
REQUIRE_SPECIAL = os.getenv("REQUIRE_PASSWORD_SPECIAL", "false").lower() == "true"

# Account lockout
MAX_FAILED_ATTEMPTS = int(os.getenv("MAX_FAILED_LOGIN_ATTEMPTS", "5"))
LOCKOUT_DURATION_MINUTES = int(os.getenv("LOCKOUT_DURATION_MINUTES", "15"))

# Default admin credentials (change on first login!)
DEFAULT_ADMIN_USERNAME = os.getenv("DEFAULT_ADMIN_USERNAME", "admin")
DEFAULT_ADMIN_PASSWORD = os.getenv("DEFAULT_ADMIN_PASSWORD", "SentinelDLP@2026!")


@dataclass
class User:
    """Local user account"""
    id: str
    username: str
    email: str
    password_hash: str
    role: str
    display_name: str
    enabled: bool = True
    created_at: str = ""
    updated_at: str = ""
    last_login: Optional[str] = None
    failed_attempts: int = 0
    locked_until: Optional[str] = None
    must_change_password: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self, include_password: bool = False) -> Dict[str, Any]:
        """Convert to dictionary, optionally excluding password hash"""
        data = asdict(self)
        if not include_password:
            del data["password_hash"]
        return data

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "User":
        """Create User from dictionary"""
        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})


class UserManager:
    """
    Manages local user accounts with encrypted storage.
    Users are stored in a JSON file with password hashes.
    """

    def __init__(self, storage_path: str = "/app/data/config"):
        self.storage_path = Path(storage_path)
        self.users_file = self.storage_path / "users.json"
        self.users: Dict[str, User] = {}
        self._load_users()
        self._ensure_default_admin()

    def _load_users(self):
        """Load users from storage"""
        if self.users_file.exists():
            try:
                data = json.loads(self.users_file.read_text())
                self.users = {
                    user_id: User.from_dict(user_data)
                    for user_id, user_data in data.items()
                }
                logger.info(f"Loaded {len(self.users)} users from storage")
            except Exception as e:
                logger.error(f"Failed to load users: {e}")
                self.users = {}
        else:
            self.users = {}

    def _save_users(self):
        """Persist users to storage"""
        try:
            self.storage_path.mkdir(parents=True, exist_ok=True)
            data = {
                user_id: user.to_dict(include_password=True)
                for user_id, user in self.users.items()
            }
            self.users_file.write_text(json.dumps(data, indent=2))
            os.chmod(self.users_file, 0o600)
        except Exception as e:
            logger.error(f"Failed to save users: {e}")
            raise

    def _ensure_default_admin(self):
        """Create default admin user if no users exist"""
        if not self.users:
            logger.info("Creating default admin user...")
            try:
                self.create_user(
                    username=DEFAULT_ADMIN_USERNAME,
                    password=DEFAULT_ADMIN_PASSWORD,
                    email="admin@sentineldlp.local",
                    role=UserRole.ADMIN,
                    display_name="System Administrator",
                    must_change_password=True  # Force password change on first login
                )
                logger.warning(
                    f"Default admin created with username '{DEFAULT_ADMIN_USERNAME}'. "
                    "Please change the password on first login!"
                )
            except Exception as e:
                logger.error(f"Failed to create default admin: {e}")

    # =========================================================================
    # PASSWORD VALIDATION
    # =========================================================================

    def validate_password(self, password: str) -> tuple[bool, str]:
        """
        Validate password against policy.
        Returns (is_valid, error_message).
        """
        errors = []

        if len(password) < MIN_PASSWORD_LENGTH:
            errors.append(f"Password must be at least {MIN_PASSWORD_LENGTH} characters")

        if REQUIRE_UPPERCASE and not any(c.isupper() for c in password):
            errors.append("Password must contain at least one uppercase letter")

        if REQUIRE_LOWERCASE and not any(c.islower() for c in password):
            errors.append("Password must contain at least one lowercase letter")

        if REQUIRE_DIGIT and not any(c.isdigit() for c in password):
            errors.append("Password must contain at least one digit")

        if REQUIRE_SPECIAL and not any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password):
            errors.append("Password must contain at least one special character")

        if errors:
            return False, "; ".join(errors)

        return True, ""

    # =========================================================================
    # USER CRUD OPERATIONS
    # =========================================================================

    def create_user(
        self,
        username: str,
        password: str,
        email: str,
        role: UserRole,
        display_name: Optional[str] = None,
        must_change_password: bool = False,
        metadata: Optional[Dict[str, Any]] = None
    ) -> User:
        """Create a new local user account"""

        # Validate username uniqueness
        if self.get_user_by_username(username):
            raise ValueError(f"Username '{username}' already exists")

        # Validate email uniqueness
        if self.get_user_by_email(email):
            raise ValueError(f"Email '{email}' already registered")

        # Validate password
        is_valid, error = self.validate_password(password)
        if not is_valid:
            raise ValueError(error)

        # Create user
        now = datetime.now(timezone.utc).isoformat()
        user = User(
            id=str(uuid.uuid4()),
            username=username.lower().strip(),
            email=email.lower().strip(),
            password_hash=auth_service.hash_password(password),
            role=role.value,
            display_name=display_name or username,
            enabled=True,
            created_at=now,
            updated_at=now,
            must_change_password=must_change_password,
            metadata=metadata or {}
        )

        self.users[user.id] = user
        self._save_users()

        logger.info(f"Created user '{username}' with role '{role.value}'")
        return user

    def get_user(self, user_id: str) -> Optional[User]:
        """Get user by ID"""
        return self.users.get(user_id)

    def get_user_by_username(self, username: str) -> Optional[User]:
        """Get user by username (case-insensitive)"""
        username_lower = username.lower().strip()
        for user in self.users.values():
            if user.username == username_lower:
                return user
        return None

    def get_user_by_email(self, email: str) -> Optional[User]:
        """Get user by email (case-insensitive)"""
        email_lower = email.lower().strip()
        for user in self.users.values():
            if user.email == email_lower:
                return user
        return None

    def list_users(
        self,
        role: Optional[UserRole] = None,
        enabled_only: bool = False
    ) -> List[User]:
        """List all users with optional filters"""
        users = list(self.users.values())

        if role:
            users = [u for u in users if u.role == role.value]

        if enabled_only:
            users = [u for u in users if u.enabled]

        return sorted(users, key=lambda u: u.username)

    def update_user(
        self,
        user_id: str,
        email: Optional[str] = None,
        role: Optional[UserRole] = None,
        display_name: Optional[str] = None,
        enabled: Optional[bool] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> Optional[User]:
        """Update user properties (not password)"""
        user = self.get_user(user_id)
        if not user:
            return None

        if email:
            # Check uniqueness
            existing = self.get_user_by_email(email)
            if existing and existing.id != user_id:
                raise ValueError(f"Email '{email}' already registered")
            user.email = email.lower().strip()

        if role:
            user.role = role.value

        if display_name:
            user.display_name = display_name

        if enabled is not None:
            user.enabled = enabled

        if metadata:
            user.metadata.update(metadata)

        user.updated_at = datetime.now(timezone.utc).isoformat()
        self._save_users()

        logger.info(f"Updated user '{user.username}'")
        return user

    def change_password(
        self,
        user_id: str,
        new_password: str,
        require_change: bool = False
    ) -> bool:
        """Change user password"""
        user = self.get_user(user_id)
        if not user:
            return False

        # Validate new password
        is_valid, error = self.validate_password(new_password)
        if not is_valid:
            raise ValueError(error)

        user.password_hash = auth_service.hash_password(new_password)
        user.must_change_password = require_change
        user.updated_at = datetime.now(timezone.utc).isoformat()
        self._save_users()

        # Revoke all existing sessions
        auth_service.revoke_all_user_tokens(user_id)

        logger.info(f"Password changed for user '{user.username}'")
        return True

    def delete_user(self, user_id: str) -> bool:
        """Delete user account"""
        user = self.users.get(user_id)
        if not user:
            return False

        # Prevent deleting the last admin
        admin_count = sum(1 for u in self.users.values() if u.role == UserRole.ADMIN.value)
        if user.role == UserRole.ADMIN.value and admin_count <= 1:
            raise ValueError("Cannot delete the last admin user")

        del self.users[user_id]
        self._save_users()

        # Revoke all sessions
        auth_service.revoke_all_user_tokens(user_id)

        logger.info(f"Deleted user '{user.username}'")
        return True

    # =========================================================================
    # AUTHENTICATION
    # =========================================================================

    def authenticate(
        self,
        username: str,
        password: str
    ) -> tuple[Optional[User], str]:
        """
        Authenticate user with username and password.
        Returns (user, error_message).
        Handles account lockout after failed attempts.
        """
        user = self.get_user_by_username(username)

        if not user:
            return None, "Invalid username or password"

        if not user.enabled:
            return None, "Account is disabled"

        # Check lockout
        if user.locked_until:
            locked_until = datetime.fromisoformat(user.locked_until)
            if datetime.now(timezone.utc) < locked_until:
                remaining = (locked_until - datetime.now(timezone.utc)).seconds // 60
                return None, f"Account is locked. Try again in {remaining} minutes"
            else:
                # Lockout expired, reset
                user.locked_until = None
                user.failed_attempts = 0

        # Verify password
        if not auth_service.verify_password(password, user.password_hash):
            user.failed_attempts += 1

            if user.failed_attempts >= MAX_FAILED_ATTEMPTS:
                user.locked_until = (
                    datetime.now(timezone.utc) +
                    __import__("datetime").timedelta(minutes=LOCKOUT_DURATION_MINUTES)
                ).isoformat()
                self._save_users()
                return None, f"Account locked after {MAX_FAILED_ATTEMPTS} failed attempts"

            self._save_users()
            remaining = MAX_FAILED_ATTEMPTS - user.failed_attempts
            return None, f"Invalid username or password. {remaining} attempts remaining"

        # Successful login
        user.failed_attempts = 0
        user.locked_until = None
        user.last_login = datetime.now(timezone.utc).isoformat()
        self._save_users()

        return user, ""

    def reset_failed_attempts(self, user_id: str) -> bool:
        """Reset failed login attempts and unlock account"""
        user = self.get_user(user_id)
        if not user:
            return False

        user.failed_attempts = 0
        user.locked_until = None
        self._save_users()

        logger.info(f"Reset failed attempts for user '{user.username}'")
        return True

    # =========================================================================
    # STATISTICS
    # =========================================================================

    def get_stats(self) -> Dict[str, Any]:
        """Get user statistics"""
        users = list(self.users.values())

        return {
            "total_users": len(users),
            "by_role": {
                "admin": sum(1 for u in users if u.role == UserRole.ADMIN.value),
                "analyst": sum(1 for u in users if u.role == UserRole.ANALYST.value),
                "viewer": sum(1 for u in users if u.role == UserRole.VIEWER.value),
            },
            "enabled": sum(1 for u in users if u.enabled),
            "disabled": sum(1 for u in users if not u.enabled),
            "locked": sum(1 for u in users if u.locked_until),
            "must_change_password": sum(1 for u in users if u.must_change_password),
        }


# Global instance
user_manager = UserManager()

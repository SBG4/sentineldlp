"""
SentinelDLP Security Middleware (FR-006 Phase 2)
Implements OWASP 2024 best practices for authentication security.

Features:
- HttpOnly secure cookies for refresh tokens
- CSRF double-submit cookie protection
- Rate limiting for authentication endpoints
- Security headers middleware
"""

import os
import secrets
import logging
from datetime import datetime, timezone
from typing import Optional, Callable, Dict, Any

from fastapi import Request, Response, HTTPException
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

logger = logging.getLogger(__name__)

# =============================================================================
# CONFIGURATION
# =============================================================================

# Cookie settings
COOKIE_DOMAIN = os.getenv("COOKIE_DOMAIN", None)  # None = same domain
# IMPORTANT: COOKIE_SECURE must be false for HTTP development (localhost without HTTPS)
# Secure cookies are ONLY sent over HTTPS connections
# Set to "true" in production with HTTPS, "false" for HTTP development
COOKIE_SECURE = os.getenv("COOKIE_SECURE", "false").lower() == "true"
COOKIE_SAMESITE = os.getenv("COOKIE_SAMESITE", "lax")  # strict, lax, or none

# CSRF settings
CSRF_TOKEN_LENGTH = 32
CSRF_COOKIE_NAME = "csrf_token"
CSRF_HEADER_NAME = "X-CSRF-Token"

# Rate limiting settings
RATE_LIMIT_ENABLED = os.getenv("RATE_LIMIT_ENABLED", "true").lower() == "true"


# =============================================================================
# CSRF PROTECTION
# =============================================================================

class CSRFProtection:
    """
    Double-submit cookie CSRF protection.

    How it works:
    1. Server generates random token and sets it in a cookie
    2. Client reads cookie and includes token in request header
    3. Server verifies cookie value matches header value

    This works because:
    - Attackers can't read cookies from another domain (SOP)
    - Attackers can't set custom headers in cross-origin requests
    """

    @staticmethod
    def generate_token() -> str:
        """Generate cryptographically secure CSRF token"""
        return secrets.token_urlsafe(CSRF_TOKEN_LENGTH)

    @staticmethod
    def set_csrf_cookie(response: Response, token: str) -> None:
        """Set CSRF token cookie"""
        response.set_cookie(
            key=CSRF_COOKIE_NAME,
            value=token,
            httponly=False,  # Must be readable by JavaScript
            secure=COOKIE_SECURE,
            samesite=COOKIE_SAMESITE,
            domain=COOKIE_DOMAIN,
            max_age=86400,  # 24 hours
            path="/"
        )

    @staticmethod
    def validate_csrf(request: Request) -> bool:
        """
        Validate CSRF token from cookie matches header.

        Returns True if valid, False otherwise.
        """
        cookie_token = request.cookies.get(CSRF_COOKIE_NAME)
        header_token = request.headers.get(CSRF_HEADER_NAME)

        if not cookie_token or not header_token:
            return False

        # Constant-time comparison to prevent timing attacks
        return secrets.compare_digest(cookie_token, header_token)


# =============================================================================
# SECURE COOKIE HELPERS
# =============================================================================

class SecureCookies:
    """
    Secure cookie management for authentication tokens.

    Refresh tokens are stored in HttpOnly cookies to prevent XSS attacks.
    Access tokens are still returned in response body for SPA usage.
    """

    REFRESH_TOKEN_COOKIE = "refresh_token"

    @classmethod
    def set_refresh_token(
        cls,
        response: Response,
        token: str,
        max_age_days: int = 7
    ) -> None:
        """
        Set refresh token in HttpOnly secure cookie.

        HttpOnly: Prevents JavaScript access (XSS protection)
        Secure: Only sent over HTTPS
        SameSite: Prevents CSRF in modern browsers
        """
        response.set_cookie(
            key=cls.REFRESH_TOKEN_COOKIE,
            value=token,
            httponly=True,  # Cannot be accessed by JavaScript
            secure=COOKIE_SECURE,
            samesite=COOKIE_SAMESITE,
            domain=COOKIE_DOMAIN,
            max_age=max_age_days * 24 * 60 * 60,
            path="/api/auth"  # Only sent to auth endpoints
        )

    @classmethod
    def get_refresh_token(cls, request: Request) -> Optional[str]:
        """Get refresh token from cookie"""
        return request.cookies.get(cls.REFRESH_TOKEN_COOKIE)

    @classmethod
    def clear_refresh_token(cls, response: Response) -> None:
        """Clear refresh token cookie on logout"""
        response.delete_cookie(
            key=cls.REFRESH_TOKEN_COOKIE,
            path="/api/auth",
            domain=COOKIE_DOMAIN,
            secure=COOKIE_SECURE,
            httponly=True,
            samesite=COOKIE_SAMESITE
        )

    @classmethod
    def clear_all_auth_cookies(cls, response: Response) -> None:
        """Clear all authentication cookies"""
        cls.clear_refresh_token(response)

        # Also clear CSRF token
        response.delete_cookie(
            key=CSRF_COOKIE_NAME,
            path="/",
            domain=COOKIE_DOMAIN
        )


# =============================================================================
# RATE LIMITING
# =============================================================================

# In-memory rate limiter for when Redis is not available
# Production should use Redis-backed rate limiting
class InMemoryRateLimiter:
    """
    Simple in-memory rate limiter.

    Note: For production, use Redis-backed rate limiting for:
    - Persistence across restarts
    - Distributed rate limiting across multiple instances
    """

    def __init__(self):
        self._attempts: Dict[str, list] = {}

    def _cleanup_old_attempts(self, key: str, window_seconds: int) -> None:
        """Remove attempts outside the time window"""
        if key not in self._attempts:
            return

        cutoff = datetime.now(timezone.utc).timestamp() - window_seconds
        self._attempts[key] = [
            t for t in self._attempts[key] if t > cutoff
        ]

    def is_rate_limited(
        self,
        key: str,
        max_attempts: int,
        window_seconds: int
    ) -> bool:
        """
        Check if key is rate limited.

        Args:
            key: Unique identifier (e.g., IP + username)
            max_attempts: Maximum attempts allowed
            window_seconds: Time window in seconds

        Returns:
            True if rate limited, False otherwise
        """
        self._cleanup_old_attempts(key, window_seconds)

        attempts = self._attempts.get(key, [])
        return len(attempts) >= max_attempts

    def record_attempt(self, key: str) -> None:
        """Record an attempt for rate limiting"""
        if key not in self._attempts:
            self._attempts[key] = []

        self._attempts[key].append(datetime.now(timezone.utc).timestamp())

    def get_remaining_attempts(
        self,
        key: str,
        max_attempts: int,
        window_seconds: int
    ) -> int:
        """Get remaining attempts before rate limit"""
        self._cleanup_old_attempts(key, window_seconds)
        attempts = len(self._attempts.get(key, []))
        return max(0, max_attempts - attempts)

    def reset(self, key: str) -> None:
        """Reset attempts for a key (e.g., after successful login)"""
        if key in self._attempts:
            del self._attempts[key]


# Global rate limiter instance
rate_limiter = InMemoryRateLimiter()

# Rate limit configurations
RATE_LIMITS = {
    "login": {
        "max_attempts": 5,      # 5 attempts
        "window_seconds": 900,  # per 15 minutes
        "lockout_seconds": 900  # 15 minute lockout
    },
    "password_reset": {
        "max_attempts": 3,
        "window_seconds": 3600,  # 1 hour
        "lockout_seconds": 3600
    },
    "api_general": {
        "max_attempts": 100,
        "window_seconds": 60,
        "lockout_seconds": 60
    }
}


def get_rate_limit_key(request: Request, action: str, username: str = None) -> str:
    """Generate rate limit key from request"""
    ip = request.client.host if request.client else "unknown"

    if username:
        return f"{action}:{ip}:{username}"
    return f"{action}:{ip}"


def check_rate_limit(
    request: Request,
    action: str,
    username: str = None
) -> Dict[str, Any]:
    """
    Check if request is rate limited.

    Returns dict with:
    - limited: bool
    - remaining: int
    - retry_after: int (seconds, if limited)
    """
    if not RATE_LIMIT_ENABLED:
        return {"limited": False, "remaining": 999}

    config = RATE_LIMITS.get(action, RATE_LIMITS["api_general"])
    key = get_rate_limit_key(request, action, username)

    is_limited = rate_limiter.is_rate_limited(
        key,
        config["max_attempts"],
        config["window_seconds"]
    )

    remaining = rate_limiter.get_remaining_attempts(
        key,
        config["max_attempts"],
        config["window_seconds"]
    )

    return {
        "limited": is_limited,
        "remaining": remaining,
        "retry_after": config["lockout_seconds"] if is_limited else 0
    }


def record_attempt(request: Request, action: str, username: str = None) -> None:
    """Record an attempt for rate limiting"""
    if not RATE_LIMIT_ENABLED:
        return

    key = get_rate_limit_key(request, action, username)
    rate_limiter.record_attempt(key)


def reset_rate_limit(request: Request, action: str, username: str = None) -> None:
    """Reset rate limit after successful action"""
    if not RATE_LIMIT_ENABLED:
        return

    key = get_rate_limit_key(request, action, username)
    rate_limiter.reset(key)


# =============================================================================
# SECURITY HEADERS MIDDLEWARE
# =============================================================================

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """
    Add security headers to all responses.

    Implements OWASP recommended security headers.
    """

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        response = await call_next(request)

        # Prevent MIME type sniffing
        response.headers["X-Content-Type-Options"] = "nosniff"

        # Prevent clickjacking
        response.headers["X-Frame-Options"] = "DENY"

        # Enable XSS filter (legacy, but still useful)
        response.headers["X-XSS-Protection"] = "1; mode=block"

        # Referrer policy
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"

        # Permissions policy (restrict browser features)
        response.headers["Permissions-Policy"] = (
            "geolocation=(), microphone=(), camera=(), "
            "payment=(), usb=(), magnetometer=(), gyroscope=()"
        )

        # Content Security Policy for API responses
        # Note: Frontend should have its own CSP
        if request.url.path.startswith("/api/"):
            response.headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'"

        return response


# =============================================================================
# CSRF MIDDLEWARE
# =============================================================================

class CSRFMiddleware(BaseHTTPMiddleware):
    """
    CSRF protection middleware.

    Validates CSRF token for state-changing requests to /api/ endpoints.
    Excludes login (needs token first) and other safe methods.
    """

    # Endpoints that don't require CSRF validation
    EXEMPT_PATHS = {
        "/api/auth/login",      # Login generates CSRF token
        "/api/auth/refresh",    # Uses HttpOnly cookie with SameSite protection
        "/api/auth/logout",     # Already protected by JWT auth, SameSite cookie
        "/api/auth/config",     # Public config
        "/api/health",          # Health check
        "/api/models",          # Public model list
    }

    # Safe HTTP methods (don't change state)
    SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        # Skip CSRF for safe methods
        if request.method in self.SAFE_METHODS:
            return await call_next(request)

        # Skip for non-API routes
        if not request.url.path.startswith("/api/"):
            return await call_next(request)

        # Skip for exempt paths
        if request.url.path in self.EXEMPT_PATHS:
            return await call_next(request)

        # Validate CSRF token
        if not CSRFProtection.validate_csrf(request):
            logger.warning(
                f"CSRF validation failed for {request.method} {request.url.path} "
                f"from {request.client.host if request.client else 'unknown'}"
            )
            return JSONResponse(
                status_code=403,
                content={
                    "detail": "CSRF token missing or invalid",
                    "code": "CSRF_VALIDATION_FAILED"
                }
            )

        return await call_next(request)

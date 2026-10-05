from fastapi import Depends, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.core.exceptions import AuthenticationError, PermissionDeniedError, RateLimitError
from app.core.logging import user_id_var
from app.core.security import decode_access_token
from app.db.database import get_session
from app.db.models import User, UserRole
from app.services.rate_limit import RateLimiter, get_rate_limiter

# auto_error=False so that missing credentials produce our unified error format.
bearer_scheme = HTTPBearer(auto_error=False, description="JWT access token")

__all__ = [
    "get_session", "get_current_user", "require_role", "require_admin",
    "get_client_ip", "enforce_login_rate_limit", "enforce_upload_rate_limit",
]


def get_client_ip(request: Request) -> str:
    # X-Forwarded-For is intentionally NOT trusted: it is client-controlled.
    return request.client.host if request.client else "unknown"


async def get_current_user(
    request: Request,
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
    session: AsyncSession = Depends(get_session),
) -> User:
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise AuthenticationError()
    user_id = decode_access_token(credentials.credentials)
    user = await session.get(User, user_id)
    if user is None or not user.is_active:
        raise AuthenticationError()
    request.state.user_id = str(user.id)
    user_id_var.set(str(user.id))
    return user


def require_role(*roles: UserRole):
    """Dependency factory: allow only users whose (DB) role is in `roles`."""
    allowed = {role.value for role in roles}

    async def checker(user: User = Depends(get_current_user)) -> User:
        if user.role not in allowed:
            raise PermissionDeniedError()
        return user

    return checker


require_admin = require_role(UserRole.ADMIN)


async def enforce_upload_rate_limit(
    user: User = Depends(get_current_user), limiter: RateLimiter = Depends(get_rate_limiter)
) -> None:
    result = await limiter.hit("upload", str(user.id), get_settings().RATE_LIMIT_UPLOAD)
    if not result.allowed:
        raise RateLimitError(
            "Too many upload requests, try again later",
            headers={"Retry-After": str(result.retry_after)},
        )


async def enforce_login_rate_limit(
    request: Request, limiter: RateLimiter = Depends(get_rate_limiter)
) -> None:
    result = await limiter.hit("login", get_client_ip(request), get_settings().RATE_LIMIT_LOGIN)
    if not result.allowed:
        raise RateLimitError(
            "Too many login attempts, try again later",
            headers={"Retry-After": str(result.retry_after)},
        )

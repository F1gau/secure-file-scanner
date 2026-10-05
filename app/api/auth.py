from fastapi import APIRouter, Depends, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import enforce_login_rate_limit, get_client_ip, get_current_user, get_session
from app.core.exceptions import AuthenticationError
from app.core.security import create_access_token
from app.db.models import User
from app.schemas.auth import LoginRequest, RegisterRequest, TokenResponse
from app.schemas.common import ErrorResponse
from app.schemas.user import UserOut
from app.services import audit_service, auth_service
from app.services.audit_service import AuditAction

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post(
    "/register",
    response_model=UserOut,
    status_code=status.HTTP_201_CREATED,
    summary="Register a new user",
    description="Creates an account with the USER role. Roles cannot be chosen by the client.",
    responses={409: {"model": ErrorResponse, "description": "Email already registered"}},
)
async def register(
    payload: RegisterRequest, request: Request, session: AsyncSession = Depends(get_session)
) -> User:
    user = await auth_service.create_user(session, payload.email, payload.password)
    await audit_service.record(
        session, AuditAction.USER_REGISTERED, user_id=user.id, ip=get_client_ip(request)
    )
    return user


@router.post(
    "/login",
    response_model=TokenResponse,
    summary="Log in and obtain a JWT access token",
    description="Rate limited per client IP. Failed attempts are written to the audit log.",
    dependencies=[Depends(enforce_login_rate_limit)],
    responses={
        401: {"model": ErrorResponse, "description": "Invalid email or password"},
        429: {"model": ErrorResponse, "description": "Too many login attempts"},
    },
)
async def login(
    payload: LoginRequest, request: Request, session: AsyncSession = Depends(get_session)
) -> TokenResponse:
    ip = get_client_ip(request)
    user, matched_user_id = await auth_service.authenticate(
        session, payload.email, payload.password
    )
    if user is None:
        await audit_service.record(
            session, AuditAction.LOGIN_FAILED, user_id=matched_user_id, ip=ip,
            details={"reason": "invalid_credentials"},
        )
        # Same message for unknown email, wrong password and disabled account.
        raise AuthenticationError("Invalid email or password")
    await audit_service.record(session, AuditAction.USER_LOGIN, user_id=user.id, ip=ip)
    token, expires_in = create_access_token(user.id)
    return TokenResponse(access_token=token, expires_in=expires_in)


@router.get(
    "/me",
    response_model=UserOut,
    summary="Get the current user",
    responses={401: {"model": ErrorResponse, "description": "Missing or invalid token"}},
)
async def me(user: User = Depends(get_current_user)) -> User:
    return user

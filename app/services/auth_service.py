import uuid

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import ConflictError
from app.core.security import dummy_hash, hash_password, verify_password
from app.db.models import User, UserRole


def normalize_email(email: str) -> str:
    return email.strip().lower()


async def get_user_by_email(session: AsyncSession, email: str) -> User | None:
    result = await session.execute(select(User).where(User.email == normalize_email(email)))
    return result.scalar_one_or_none()


async def create_user(
    session: AsyncSession, email: str, password: str, role: UserRole = UserRole.USER
) -> User:
    if await get_user_by_email(session, email) is not None:
        raise ConflictError("User with this email already exists")
    user = User(
        email=normalize_email(email),
        hashed_password=hash_password(password),
        role=role.value,
    )
    session.add(user)
    try:
        await session.commit()
    except IntegrityError:  # concurrent registration of the same email
        await session.rollback()
        raise ConflictError("User with this email already exists") from None
    return user


async def authenticate(
    session: AsyncSession, email: str, password: str
) -> tuple[User | None, uuid.UUID | None]:
    """Return (user, matched_user_id).

    `user` is set only for valid credentials on an active account.
    `matched_user_id` is set whenever the email exists (used for the audit log).
    A password hash is always verified, so unknown emails take similar time.
    """
    user = await get_user_by_email(session, email)
    if user is None:
        verify_password(password, dummy_hash())
        return None, None
    password_ok = verify_password(password, user.hashed_password)
    if not password_ok or not user.is_active:
        return None, user.id
    return user, user.id

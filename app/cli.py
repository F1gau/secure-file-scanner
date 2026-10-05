"""Management commands.

    python -m app.cli create-admin --email admin@example.com

The password is read from the ADMIN_PASSWORD environment variable if set
(useful in containers), otherwise prompted interactively. It is never taken
from command-line arguments, so it does not end up in shell history.
"""
import argparse
import asyncio
import getpass
import os
import sys

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.core.exceptions import AppError
from app.core.security import validate_password_strength
from app.db.models import User, UserRole
from app.services import audit_service, auth_service
from app.services.audit_service import AuditAction


async def create_admin(
    session_factory: async_sessionmaker[AsyncSession], email: str, password: str
) -> User:
    validate_password_strength(password)
    async with session_factory() as session:
        user = await auth_service.create_user(session, email, password, role=UserRole.ADMIN)
        await audit_service.record(
            session, AuditAction.USER_REGISTERED, user_id=user.id,
            details={"via": "cli", "role": UserRole.ADMIN.value},
        )
        return user


def _read_password() -> str:
    env_password = os.environ.get("ADMIN_PASSWORD")
    if env_password:
        return env_password
    first = getpass.getpass("Password: ")
    if first != getpass.getpass("Repeat password: "):
        raise ValueError("Passwords do not match")
    return first


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="app.cli")
    sub = parser.add_subparsers(dest="command", required=True)
    admin = sub.add_parser("create-admin", help="Create a user with the ADMIN role")
    admin.add_argument("--email", required=True)
    args = parser.parse_args(argv)

    from app.db.database import get_session_factory

    try:
        user = asyncio.run(create_admin(get_session_factory(), args.email, _read_password()))
    except (AppError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(f"Admin created: {user.id}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

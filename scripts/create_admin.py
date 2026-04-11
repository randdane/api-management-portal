"""Create the first admin user.

Usage: python scripts/create_admin.py <username> <email> <password>
"""

import asyncio
import sys

from sqlalchemy import select

from portal.auth.passwords import hash_password
from portal.db.models import User
from portal.db.session import AsyncSessionLocal


async def main() -> None:
    if len(sys.argv) != 4:
        print("Usage: python scripts/create_admin.py <username> <email> <password>")
        sys.exit(1)

    username, email, password = sys.argv[1], sys.argv[2], sys.argv[3]

    async with AsyncSessionLocal() as db:
        existing = await db.execute(select(User).where(User.username == username))
        if existing.scalar_one_or_none() is not None:
            print(f"User {username!r} already exists.")
            sys.exit(1)

        user = User(
            username=username,
            email=email,
            password_hash=hash_password(password),
            role="admin",
            is_active=True,
        )
        db.add(user)
        await db.commit()
        await db.refresh(user)
        print(f"Created admin user {username!r} with id {user.id}")


if __name__ == "__main__":
    asyncio.run(main())

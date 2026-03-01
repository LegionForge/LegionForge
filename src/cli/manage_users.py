"""
src/cli/manage_users.py
────────────────────────
Gateway user management CLI for LegionForge.

Usage:
    python -m src.cli.manage_users create-user  --username alice [--daily-limit 100000]
    python -m src.cli.manage_users deactivate-user --username alice
    python -m src.cli.manage_users set-quota --username alice --daily-limit 500000
    python -m src.cli.manage_users list-users

Security:
    - The raw API key is printed exactly once on `create-user` and never stored
      in plain text.  Treat the output like a password — copy it immediately.
    - Requires the DB pool to be initialised (init_db() is called internally).
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import secrets
import sys

logger = logging.getLogger(__name__)


# ── User operations ───────────────────────────────────────────────────────────


async def create_user(username: str, daily_limit: int, is_admin: bool = False) -> None:
    """
    Create a new gateway user and print the raw API key once.

    The raw key is never stored.  The bcrypt hash is stored in gateway_users.
    If the username already exists, the command exits with an error.

    Args:
        username:    Unique username for the new user.
        daily_limit: Daily token budget for this user.
        is_admin:    If True, grant admin privilege (Phase 24).
    """
    from src.database import init_db, create_gateway_user
    from src.gateway.auth import hash_api_key

    await init_db()

    raw_key = secrets.token_urlsafe(32)
    key_hash = hash_api_key(raw_key)

    try:
        user = await create_gateway_user(
            username=username, api_key_hash=key_hash, is_admin=is_admin
        )
    except Exception as exc:
        if "unique" in str(exc).lower() or "duplicate" in str(exc).lower():
            print(f"ERROR: Username '{username}' already exists.", file=sys.stderr)
            sys.exit(1)
        raise

    # Set the daily limit if it differs from the default
    from src.database import set_gateway_user_quota

    await set_gateway_user_quota(username=username, daily_token_limit=daily_limit)

    admin_label = " (admin)" if is_admin else ""
    print(f"✅ User created{admin_label}:")
    print(f"   username:    {user['username']}")
    print(f"   user_id:     {user['user_id']}")
    print(f"   is_admin:    {is_admin}")
    print(f"   daily_limit: {daily_limit:,} tokens/day")
    print()
    print(f"   API KEY (copy now — not stored in plain text):")
    print(f"   {raw_key}")
    print()
    print("   Use with: curl -H 'Authorization: Bearer <key>' ...")


async def deactivate_user(username: str) -> None:
    """
    Deactivate a gateway user so they can no longer authenticate.

    The user row is retained in the DB for audit purposes.  Reactivation
    is not supported via this CLI — create a new user instead.

    Args:
        username: Username to deactivate.
    """
    from src.database import init_db, deactivate_gateway_user

    await init_db()

    updated = await deactivate_gateway_user(username=username)
    if updated:
        print(
            f"✅ User '{username}' deactivated.  Existing sessions will fail on next request."
        )
    else:
        print(
            f"ERROR: User '{username}' not found or already inactive.", file=sys.stderr
        )
        sys.exit(1)


async def set_quota(username: str, daily_limit: int) -> None:
    """
    Update the daily token limit for a user.

    Takes effect immediately on the next task submission.  Tasks already
    queued or running are not affected.

    Args:
        username:    Username to update.
        daily_limit: New daily token limit.
    """
    from src.database import init_db, set_gateway_user_quota

    await init_db()

    updated = await set_gateway_user_quota(
        username=username, daily_token_limit=daily_limit
    )
    if updated:
        print(f"✅ User '{username}' daily limit set to {daily_limit:,} tokens/day.")
    else:
        print(f"ERROR: User '{username}' not found or inactive.", file=sys.stderr)
        sys.exit(1)


async def list_users() -> list:
    """Print all gateway users (active and inactive) in a table. Returns the user list."""
    from src.database import init_db, list_gateway_users

    await init_db()

    users = await list_gateway_users()
    if not users:
        print("No gateway users found.")
        return []

    # Simple fixed-width table
    header = (
        f"{'USERNAME':<20} {'ACTIVE':<8} {'ADMIN':<6} {'DAILY LIMIT':>12} {'USER ID'}"
    )
    print(header)
    print("─" * len(header))
    for u in users:
        active = "yes" if u["is_active"] else "no"
        admin = "yes" if u.get("is_admin") else "no"
        print(
            f"{u['username']:<20} {active:<8} {admin:<6} {u['daily_token_limit']:>12,} "
            f"{u['user_id']}"
        )
    return users


# ── CLI entry point ───────────────────────────────────────────────────────────


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m src.cli.manage_users",
        description="LegionForge gateway user management CLI",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # create-user
    p_create = sub.add_parser("create-user", help="Create a new gateway user")
    p_create.add_argument("--username", required=True, help="Unique username")
    p_create.add_argument(
        "--daily-limit",
        type=int,
        default=100000,
        help="Daily token budget (default: 100000)",
    )
    p_create.add_argument(
        "--admin",
        action="store_true",
        default=False,
        help="Grant admin privilege (Phase 24)",
    )

    # deactivate-user
    p_deactivate = sub.add_parser("deactivate-user", help="Deactivate a user")
    p_deactivate.add_argument(
        "--username", required=True, help="Username to deactivate"
    )

    # set-quota
    p_quota = sub.add_parser("set-quota", help="Update a user's daily token limit")
    p_quota.add_argument("--username", required=True, help="Username to update")
    p_quota.add_argument(
        "--daily-limit",
        type=int,
        required=True,
        help="New daily token limit",
    )

    # list-users
    sub.add_parser("list-users", help="List all gateway users")

    return parser


def main() -> None:
    parser = _build_parser()
    args = parser.parse_args()

    if args.command == "create-user":
        asyncio.run(create_user(args.username, args.daily_limit, args.admin))
    elif args.command == "deactivate-user":
        asyncio.run(deactivate_user(args.username))
    elif args.command == "set-quota":
        asyncio.run(set_quota(args.username, args.daily_limit))
    elif args.command == "list-users":
        asyncio.run(list_users())
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()

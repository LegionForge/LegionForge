# LegionForge — Horizontal Scaling Guide

Phase 11 documents the path from a single-process gateway to a load-balanced
multi-instance deployment. No Redis or additional infrastructure is needed at
household scale; the design scales to the multi-datacenter case when required.

---

## Current Architecture (Phase 11)

```
┌──────────────┐        ┌──────────────────────────────────────────────────┐
│   Client     │──HTTP──▶   Gateway (FastAPI :8080)                        │
│   (browser,  │        │   ├── /tasks (submit, list, cancel)              │
│    Discord)  │        │   ├── /stream/{id}?stream_token=...  (SSE)       │
└──────────────┘        │   ├── /usage/me                                  │
                        │   └── worker (asyncio background task)           │
                        │         ├── polls tasks table (SKIP LOCKED)      │
                        │         └── writes api_usage with user_id        │
                        └───────────────────┬──────────────────────────────┘
                                            │ psycopg async pool
                        ┌───────────────────▼──────────────────────────────┐
                        │   PostgreSQL 17 (legionforge DB)                 │
                        │   ├── gateway_users  (auth, quotas)              │
                        │   ├── tasks          (queue, SKIP LOCKED safe)   │
                        │   ├── stream_tokens  (DB-backed, 30-min TTL)     │
                        │   └── api_usage      (per-user attribution)      │
                        └──────────────────────────────────────────────────┘
```

### Why It's Already Horizontally Safe

The worker uses `FOR UPDATE SKIP LOCKED` when dequeuing tasks, so multiple
gateway instances never claim the same task. Stream tokens are stored in the
`stream_tokens` DB table (Phase 10), not in-process memory, so they survive
restarts and are visible to any instance.

The `DailyCounter` in `src/rate_limiter.py` is intentionally per-process: it
enforces the **global provider cap** (OpenAI, Anthropic). The **per-user
budget** is enforced against `api_usage.user_id` in the DB, which is ground
truth across all instances.

---

## Running Multiple Workers (Same Host)

Use uvicorn's `--workers` flag to run N worker processes sharing one port:

```bash
uvicorn src.gateway.app:app --host 0.0.0.0 --port 8080 --workers 4
```

Or via Docker (see `Dockerfile.gateway`):

```bash
docker run --rm -d --name legionforge-gateway -p 8080:8080 \
  --env POSTGRES_PASSWORD="$POSTGRES_PASSWORD" \
  --env TASK_TOKEN_SECRET="$TASK_TOKEN_SECRET" \
  --add-host host.docker.internal:host-gateway \
  legionforge-gateway:latest \
  uvicorn src.gateway.app:app --host 0.0.0.0 --port 8080 --workers 4
```

Each uvicorn worker process runs its own asyncio event loop and DB pool.
`FOR UPDATE SKIP LOCKED` prevents duplicate task processing across all workers.

---

## Running Multiple Docker Containers (Different Hosts or Ports)

Run multiple gateway containers and place a load balancer in front:

```bash
# Instance 1
docker run -d --name gw1 -p 8081:8080 \
  --env POSTGRES_PASSWORD="$POSTGRES_PASSWORD" \
  --env TASK_TOKEN_SECRET="$TASK_TOKEN_SECRET" \
  --add-host host.docker.internal:host-gateway \
  legionforge-gateway:latest

# Instance 2
docker run -d --name gw2 -p 8082:8080 \
  --env POSTGRES_PASSWORD="$POSTGRES_PASSWORD" \
  --env TASK_TOKEN_SECRET="$TASK_TOKEN_SECRET" \
  --add-host host.docker.internal:host-gateway \
  legionforge-gateway:latest
```

### nginx Load Balancer Config

```nginx
upstream legionforge_gateway {
    least_conn;
    server 127.0.0.1:8081;
    server 127.0.0.1:8082;
    keepalive 32;
}

server {
    listen 8080;

    location / {
        proxy_pass http://legionforge_gateway;
        proxy_http_version 1.1;
        proxy_set_header Connection "";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;

        # SSE requires chunked transfer and long timeouts
        proxy_buffering off;
        proxy_read_timeout 3600s;
        proxy_send_timeout 3600s;
        chunked_transfer_encoding on;
    }
}
```

### Caddy Load Balancer Config

```caddy
:8080 {
    reverse_proxy 127.0.0.1:8081 127.0.0.1:8082 {
        lb_policy least_conn
        flush_interval -1      # disables buffering (required for SSE)
    }
}
```

**Session affinity note:** SSE streams use DB-backed stream tokens, not
in-process pub/sub. Each instance independently reads events from the DB,
so no sticky sessions are required at the load balancer level.

---

## Auth Backend Extensibility (Phase 11)

The `AuthBackend` protocol in `src/gateway/auth.py` allows OAuth, LDAP, or
any other auth scheme to be plugged in without changing `require_user` or any
route code.

### Swapping in a Custom Backend

```python
# In your startup script or gateway app.py lifespan:
from src.gateway.auth import set_auth_backend

class GitHubOAuthBackend:
    def __init__(self, client_id: str, client_secret: str):
        self.client_id = client_id
        self.client_secret = client_secret

    async def authenticate(self, api_key: str) -> dict | None:
        # Exchange api_key (OAuth access token) for GitHub user info
        # Return {"user_id": ..., "username": ..., "daily_token_limit": ...}
        # or None on failure
        ...

set_auth_backend(GitHubOAuthBackend(client_id="...", client_secret="..."))
```

After calling `set_auth_backend()`, every subsequent call to `authenticate()`
and `require_user()` uses the new backend. The `ApiKeyBackend` (default) is
replaced globally — no routes need changes.

---

## When to Add Redis

The current DB-backed approach is correct for:
- Household to small-team deployments (<10 concurrent users)
- Single-datacenter deployments (all instances share one PostgreSQL)

Add Redis when:
- You need **multi-datacenter** deployments with separate PostgreSQL instances
- **>10 concurrent users** are hitting budget checks simultaneously and DB
  lock contention becomes measurable (profile first with `pg_stat_activity`)
- You want sub-millisecond stream token lookups at high volume

### What Changes with Redis

| Component | Without Redis (current) | With Redis |
|-----------|------------------------|------------|
| `stream_tokens` | PostgreSQL table, 30-min TTL via `expires_at` | `SETEX stream:{token} 1800 "{task_id}:{user_id}"` |
| `DailyCounter._reserved_tokens` | Per-process asyncio lock | Redis `INCR/DECR` with TTL key per `(provider, date)` |
| Per-user budget check | `SUM(tokens) FROM api_usage WHERE user_id=... AND date=today` | Redis `INCRBY usage:{user_id}:{date}` with daily TTL |

The rest of the stack (auth, task queue, checkpoints, Guardian) is unaffected.

---

## Checklist Before Going Multi-Instance

- [ ] `TASK_TOKEN_SECRET` is the same value on all instances (JWT validation)
- [ ] `POSTGRES_PASSWORD` points to the same DB on all instances
- [ ] All instances can reach PostgreSQL (connection pool per process)
- [ ] Load balancer has SSE buffering disabled (`proxy_buffering off` / `flush_interval -1`)
- [ ] `make db-init` was run once (idempotent — safe to run again on new instances)
- [ ] Guardian sidecar (:9766) is reachable from all instances (or deploy one per host)

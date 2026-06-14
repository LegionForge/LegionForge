"""
src/gateway/routes/tasks.py
────────────────────────────
Core task API:

    POST   /tasks                       — submit a task
    POST   /tasks/batch                 — submit up to 20 tasks at once (Phase 28)
    GET    /tasks                       — list tasks (authenticated user's own)
    GET    /tasks/{task_id}             — get a single task result
    PUT    /tasks/{task_id}/tags        — replace task tags (Phase 31)
    PUT    /tasks/{task_id}/labels      — replace task labels (Phase 40)
    DELETE /tasks/{task_id}             — cancel a queued task
    POST   /tasks/{task_id}/notes      — add a note to a task (Phase 32)
    GET    /tasks/{task_id}/notes      — list notes on a task (Phase 32)
    DELETE /tasks/{task_id}/notes/{note_id}  — delete a note (Phase 32)
"""

from __future__ import annotations

import base64
import logging

import csv
import io
import json as _json

from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel, Field, field_validator

from src.database import (
    add_task_note,
    bulk_cancel_tasks,
    bulk_delete_tasks,
    bulk_tag_tasks,
    create_task,
    delete_task_note,
    get_worker_pool,
    get_task,
    get_task_stats,
    get_task_timeline,
    list_task_notes,
    list_tasks,
    lookup_cached_task,
    mark_task_cancelled,
    update_task_labels,
    update_task_tags,
    VALID_AGENT_TYPES,
    VALID_TASK_LABELS,
    VALID_TASK_STATUSES,
    decode_task_cursor,
    add_task_attachment,
    list_task_attachments,
    get_task_attachment,
    delete_task_attachment,
    _MAX_ATTACHMENT_BYTES,
    create_task_share,
    list_task_shares,
    revoke_task_share,
)
import re as _re

from src.gateway.auth import create_stream_token, require_user
from src.gateway.metrics import inc_counter
from src.rate_limiter import per_user_budget_check
from src.security.core import sanitize_text, _log_safe

# Maps agent_type → LLM provider (used for per-user budget tracking).
# All current agents run on Ollama; update this if cloud agents are added.
_AGENT_TYPE_TO_PROVIDER: dict[str, str] = {
    "orchestrator": "ollama",
    "researcher": "ollama",
    "base_agent": "ollama",
}

_UUID_RE = _re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", _re.I
)

logger = logging.getLogger(__name__)

router = APIRouter()


async def _check_queue_depth(user_id: str, additional: int = 1) -> None:
    """
    Raise HTTP 429 if the user already has too many tasks pending.

    Counts tasks in 'queued' or 'running' state.  ``additional`` is the number
    of new tasks about to be added (1 for single submit, N for batch).

    Reads the limit from ``settings.gateway.max_queued_tasks_per_user``.
    Set to 0 to disable.  Uses the worker pool (BYPASSRLS) so the count is
    across all of the user's tasks regardless of RLS context.
    """
    from config.settings import settings

    limit = settings.gateway.max_queued_tasks_per_user
    if limit <= 0:
        return
    from psycopg.rows import tuple_row

    pool = get_worker_pool()
    async with pool.connection() as conn:
        async with conn.cursor(row_factory=tuple_row) as cur:
            await cur.execute(
                "SELECT count(*)::int FROM tasks"
                " WHERE user_id = %s AND status IN ('queued', 'running')",
                (user_id,),
            )
            row = await cur.fetchone()
            current = row[0] if row else 0
    if current + additional > limit:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=(
                f"Queue depth limit reached — you already have {current} pending "
                f"task(s). Max {limit} queued+running at once. "
                "Wait for existing tasks to complete before submitting more."
            ),
            headers={"Retry-After": "60"},
        )


# ── Request / response models ──────────────────────────────────────────────────


class TaskConfig(BaseModel):
    tracing_enabled: bool = True
    max_steps: int | None = None


class TaskRequest(BaseModel):
    task: str = Field(..., min_length=1, max_length=4000)
    agent_type: str = Field(default="orchestrator")
    config: TaskConfig = Field(default_factory=TaskConfig)
    priority: int = Field(
        default=5,
        ge=1,
        le=10,
        description="Task priority: 1=low, 5=normal (default), 10=high. "
        "Higher-priority tasks are picked up by the worker first.",
    )
    use_cache: bool = Field(
        default=True,
        description=(
            "Return a cached result if an identical task (same agent_type + text) "
            "completed within cache_ttl seconds.  Set to false to force a fresh run."
        ),
    )
    cache_ttl: int = Field(
        default=3600,
        ge=0,
        le=86400,
        description="Cache validity in seconds (0 disables, max 86400 = 24h).  "
        "Ignored when use_cache=false.",
    )
    tags: list[str] = Field(
        default_factory=list,
        max_length=10,
        description="Up to 10 freeform string tags for filtering and organisation.  "
        "Each tag max 50 characters.  Phase 31.",
    )
    depends_on: str | None = Field(
        default=None,
        description=(
            "UUID of a task that must complete before this task is picked up "
            "by the worker.  If the dependency fails, this task is auto-failed.  "
            "Phase 34 — Task Dependencies."
        ),
    )
    callback_url: str | None = Field(
        default=None,
        max_length=2048,
        description=(
            "Optional HTTP(S) URL to POST the task result to when the task "
            "completes (success or failure).  Phase 26 completion webhooks."
        ),
    )
    dry_run: bool = Field(
        default=False,
        description=(
            "If true, estimate token cost and return immediately without queuing "
            "the task.  Response includes estimated_tokens, estimated_cost_usd, "
            "input_tokens, output_tokens, provider.  Phase 36 — Cost Estimation."
        ),
    )
    session_id: str | None = Field(
        default=None,
        description=(
            "UUID of an existing session. When provided, the task is run using the "
            "session's LangGraph thread_id so the agent can recall prior context.  "
            "Phase 54 — Conversation Sessions."
        ),
    )
    model_preference: str | None = Field(
        default=None,
        description=(
            "Model to use for this task.  Accepts any named preset from the hardware "
            "profile (e.g. 'mercury-2') or any Ollama model ID installed on the server "
            "(e.g. 'qwen2.5:7b', 'llama3.1:8b').  "
            "Null uses the hardware profile's primary model.  "
            "GET /models returns the full list of available options.  "
            "Phase 58 — Model Selection per Task."
        ),
    )
    attachment_text: str | None = Field(
        default=None,
        max_length=16384,
        description=(
            "Optional plain-text file content to attach to this task.  When provided, "
            "the content is prepended to the agent's input so the agent can read and "
            "analyse the file inline.  Max 16 KB.  "
            "Phase 70 — File Attachment on Tasks."
        ),
    )
    attachment_filename: str | None = Field(
        default=None,
        max_length=255,
        description="Original filename for the attached content (display only).",
    )
    image_b64: str | None = Field(
        default=None,
        description="Base64-encoded image (JPEG/PNG/GIF/WEBP only, max 4MB after decode)",
    )
    image_mime: str | None = Field(
        default=None,
        description="MIME type of the image (image/jpeg, image/png, image/gif, image/webp)",
    )

    @field_validator("model_preference")
    @classmethod
    def model_preference_must_be_valid(cls, v: str | None) -> str | None:
        if v is None:
            return v
        # Accept named presets or any Ollama model ID (name:tag or bare name).
        # Reject strings with whitespace or shell-unsafe characters — the value
        # is passed to the Ollama API, not a shell, but we still gate obvious garbage.
        import re

        if not re.fullmatch(r"[a-zA-Z0-9_.:\-/]+", v):
            raise ValueError(
                "model_preference must be a named preset (see GET /models) "
                "or a valid Ollama model ID (e.g. 'qwen2.5:7b')"
            )
        return v

    @field_validator("task")
    @classmethod
    def task_must_not_be_blank(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("task must not be blank")
        return v

    @field_validator("agent_type")
    @classmethod
    def agent_type_must_be_valid(cls, v: str) -> str:
        if v not in VALID_AGENT_TYPES:
            raise ValueError(f"agent_type must be one of {sorted(VALID_AGENT_TYPES)}")
        return v

    @field_validator("tags")
    @classmethod
    def tags_must_be_short(cls, v: list[str]) -> list[str]:
        for tag in v:
            if len(tag) > 50:
                raise ValueError(f"tag {tag!r} exceeds 50 characters")
        return [t.strip() for t in v if t.strip()]

    @field_validator("depends_on")
    @classmethod
    def depends_on_must_be_uuid(cls, v: str | None) -> str | None:
        if v is None:
            return v
        if not _UUID_RE.match(v):
            raise ValueError("depends_on must be a valid UUID")
        return v

    @field_validator("callback_url")
    @classmethod
    def callback_url_must_be_http(cls, v: str | None) -> str | None:
        if v is None:
            return v
        from urllib.parse import urlparse

        parsed = urlparse(v)
        if parsed.scheme not in ("http", "https") or not parsed.netloc:
            raise ValueError("callback_url must be an http:// or https:// URL")
        return v


# ── Endpoints ─────────────────────────────────────────────────────────────────


@router.post("", status_code=status.HTTP_202_ACCEPTED)
async def submit_task(
    body: TaskRequest,
    user: dict = Depends(require_user),
) -> dict:
    """
    Submit a task to the agent queue.

    The task text is sanitized through sanitize_text() before storage.
    Injection detected → 400 (not 401 — don't leak that detection happened).
    """
    # Sanitize input at the gateway boundary
    sanitized, injection_meta = sanitize_text(body.task, check_injection=True)

    if injection_meta.get("injection_detected"):
        logger.warning(
            "[gateway] Injection detected in task submission user=%s pattern_count=%s",
            _log_safe(user["username"]),
            _log_safe(injection_meta.get("pattern_count", 0)),
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Task rejected: invalid input",
        )

    # Phase I: validate image attachment if present
    _ALLOWED_MIMES = {"image/jpeg", "image/png", "image/gif", "image/webp"}
    _MAGIC = {
        "image/jpeg": lambda b: b[:3] == b"\xff\xd8\xff",
        "image/png": lambda b: b[:4] == b"\x89PNG",
        "image/gif": lambda b: b[:4] == b"GIF8",
        "image/webp": lambda b: b[8:12] == b"WEBP",
    }
    if body.image_b64 is not None:
        if not body.image_mime or body.image_mime not in _ALLOWED_MIMES:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=(
                    "image_mime is required and must be one of: "
                    + ", ".join(sorted(_ALLOWED_MIMES))
                ),
            )
        try:
            _img_bytes = base64.b64decode(body.image_b64 + "==")
        except Exception:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="image_b64 is not valid base64",
            )
        if len(_img_bytes) > 4 * 1024 * 1024:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="Image exceeds 4 MB size limit",
            )
        _magic_check = _MAGIC.get(body.image_mime)
        if _magic_check and not _magic_check(_img_bytes):
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=f"Image magic bytes do not match declared MIME type {body.image_mime!r}",
            )

    # Phase 36: dry_run — return cost estimate without queuing
    if body.dry_run:
        from src.cost_estimator import estimate_task_cost

        estimate = estimate_task_cost(body.agent_type, sanitized)
        estimate["agent_type"] = body.agent_type
        estimate["dry_run"] = True
        return JSONResponse(status_code=200, content=estimate)

    # Phase 70: prepend inline file attachment to task input so the agent reads it naturally
    if body.attachment_text:
        fname = (body.attachment_filename or "attachment.txt").replace("\n", " ")[:100]
        sanitized = (
            f"[ATTACHED FILE: {fname}]\n"
            f"---\n"
            f"{body.attachment_text.strip()}\n"
            f"---\n\n"
            f"{sanitized}"
        )

    # Phase 29: always compute content_hash (stored on the task for future lookups)
    from src.task_cache import compute_task_hash

    content_hash = compute_task_hash(body.agent_type, sanitized)

    # Cache lookup: skip queue if an identical completed task exists within TTL
    if body.use_cache and body.cache_ttl > 0:
        hit = await lookup_cached_task(content_hash, max_age_seconds=body.cache_ttl)
        if hit:
            logger.info(
                "[gateway] Cache hit task_id=%s user=%s",
                _log_safe(hit["task_id"]),
                _log_safe(user["username"]),
            )
            return {
                "task_id": hit["task_id"],
                "status": "complete",
                "result": hit["result"],
                "cached": True,
                "cached_at": hit["completed_at"],
            }

    # Estimate token cost for budget check (conservative: word count × 1.3 + 500
    # for system prompt / response overhead).  Actual usage replaces this on
    # task completion via api_usage with user_id set.
    estimated_tokens = int(len(sanitized.split()) * 1.3 + 500)
    provider = _AGENT_TYPE_TO_PROVIDER.get(body.agent_type, "ollama")
    daily_limit = user.get("daily_token_limit", 100000)

    try:
        await per_user_budget_check(
            user_id=user["user_id"],
            provider=provider,
            estimated_tokens=estimated_tokens,
            daily_limit=daily_limit,
        )
    except RuntimeError as budget_err:
        logger.warning(
            "[gateway] Per-user budget exceeded: user=%s estimated=%s limit=%s",
            _log_safe(user["username"]),
            _log_safe(estimated_tokens),
            _log_safe(daily_limit),
        )
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Daily token budget exceeded. Try again tomorrow.",
        ) from budget_err

    # DOS guard: reject if user already has too many pending tasks
    await _check_queue_depth(user["user_id"], additional=1)

    # Phase 54: validate session_id ownership before creating task
    if body.session_id:
        from src.database import get_session as db_get_session

        sess = await db_get_session(body.session_id, user["user_id"])
        if sess is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Session {body.session_id!r} not found",
            )

    _task_config = body.config.model_dump()
    if body.image_b64 is not None:
        _task_config["image_b64"] = body.image_b64
        _task_config["image_mime"] = body.image_mime

    row = await create_task(
        user_id=user["user_id"],
        input_text=sanitized,
        agent_type=body.agent_type,
        config=_task_config,
        estimated_tokens=estimated_tokens,
        callback_url=body.callback_url,
        priority=body.priority,
        content_hash=content_hash,
        tags=body.tags,
        depends_on=body.depends_on,
        session_id=body.session_id,
        model_preference=body.model_preference,
    )

    task_id = row["task_id"]
    stream_token = await create_stream_token(task_id, user["user_id"])

    inc_counter("legionforge_tasks_submitted_total")

    logger.info(
        "[gateway] Task queued task_id=%s agent=%s user=%s",
        _log_safe(task_id),
        _log_safe(body.agent_type),
        _log_safe(user["username"]),
    )

    # Phase 42: rate limit headers
    from src.gateway.rate_limit_headers import compute_rate_limit_headers

    rl_headers = await compute_rate_limit_headers(
        user["user_id"], provider, daily_limit
    )
    return JSONResponse(
        status_code=status.HTTP_202_ACCEPTED,
        content={
            "task_id": task_id,
            "status": "queued",
            "priority": row.get("priority", 5),
            "created_at": str(row["created_at"]),
            "stream_url": f"/tasks/{task_id}/stream",
            "stream_token": stream_token,
        },
        headers=rl_headers,
    )


# ── Batch submission (Phase 28) ────────────────────────────────────────────────


class BatchTaskRequest(BaseModel):
    tasks: list[TaskRequest] = Field(
        ...,
        min_length=1,
        max_length=20,
        description="List of 1–20 task requests to submit atomically.",
    )


@router.post("/batch", status_code=status.HTTP_202_ACCEPTED)
async def submit_tasks_batch(
    body: BatchTaskRequest,
    user: dict = Depends(require_user),
) -> dict:
    """
    Submit up to 20 tasks at once.

    Each task is validated and sanitized individually.  The entire batch fails
    fast if any task fails validation or budget checks.  Returns a list of
    ``task_id`` + ``stream_token`` pairs in the same order as the input.

    Phase 28 — batch submission.
    """
    results = []
    daily_limit = user.get("daily_token_limit", 100000)

    # DOS guard: check the whole batch at once before processing any task.
    # additional=len(body.tasks) ensures a batch of 20 doesn't bypass the cap.
    await _check_queue_depth(user["user_id"], additional=len(body.tasks))

    for idx, req in enumerate(body.tasks):
        # Sanitize + injection check
        sanitized, injection_meta = sanitize_text(req.task, check_injection=True)
        if injection_meta.get("injection_detected"):
            logger.warning(
                "[gateway/batch] Injection detected task %d user=%s",
                idx,
                _log_safe(user["username"]),
            )
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Task {idx}: rejected — invalid input",
            )

        estimated_tokens = int(len(sanitized.split()) * 1.3 + 500)
        provider = _AGENT_TYPE_TO_PROVIDER.get(req.agent_type, "ollama")

        try:
            await per_user_budget_check(
                user_id=user["user_id"],
                provider=provider,
                estimated_tokens=estimated_tokens,
                daily_limit=daily_limit,
            )
        except RuntimeError as budget_err:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"Task {idx}: daily token budget exceeded",
            ) from budget_err

        row = await create_task(
            user_id=user["user_id"],
            input_text=sanitized,
            agent_type=req.agent_type,
            config=req.config.model_dump(),
            estimated_tokens=estimated_tokens,
            callback_url=req.callback_url,
            priority=req.priority,
        )
        task_id = row["task_id"]
        stream_token = await create_stream_token(task_id, user["user_id"])
        inc_counter("legionforge_tasks_submitted_total")

        results.append(
            {
                "task_id": task_id,
                "status": "queued",
                "priority": row.get("priority", 5),
                "created_at": row["created_at"],
                "stream_url": f"/tasks/{task_id}/stream",
                "stream_token": stream_token,
            }
        )

    logger.info(
        "[gateway/batch] Queued %d tasks user=%s",
        len(results),
        _log_safe(user["username"]),
    )
    return {"count": len(results), "tasks": results}


@router.get("")
async def list_user_tasks(
    user: dict = Depends(require_user),
    limit: int = Query(default=20, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    status_filter: str | None = Query(default=None, alias="status"),
    q: str | None = Query(
        default=None, max_length=200, description="Substring search on task input"
    ),
    tags: list[str] | None = Query(
        default=None, description="Filter tasks containing all listed tags"
    ),
    label: str | None = Query(
        default=None, description="Filter tasks with a specific label (Phase 40)"
    ),
    cursor: str | None = Query(
        default=None,
        description=(
            "Opaque keyset cursor for efficient deep pagination (Phase 47). "
            "Use the next_cursor value from the previous response. "
            "When provided, offset is ignored."
        ),
    ),
) -> dict:
    """Return paginated task history for the authenticated user.

    Optional filters (Phase 31 / Phase 40 / Phase 47):
    - ``status``  — filter by task status
    - ``q``       — full-text search on task input (Phase 45)
    - ``tags``    — return only tasks containing ALL specified tags
    - ``label``   — return only tasks with a specific label (bookmarked, starred, …)
    - ``cursor``  — keyset pagination cursor from previous response (Phase 47)
    """
    if status_filter and status_filter not in VALID_TASK_STATUSES:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"status must be one of {sorted(VALID_TASK_STATUSES)}",
        )
    if label and label not in VALID_TASK_LABELS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"label must be one of {sorted(VALID_TASK_LABELS)}",
        )
    if cursor:
        ts, tid = decode_task_cursor(cursor)
        if ts is None or tid is None:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid cursor value",
            )

    return await list_tasks(
        user_id=user["user_id"],
        limit=limit,
        offset=offset,
        status=status_filter,
        q=q,
        tags=tags,
        label=label,
        cursor=cursor,
    )


# ── Task Stats & Analytics (Phase 44) ─────────────────────────────────────────


@router.get("/stats")
async def task_stats(user: dict = Depends(require_user)) -> dict:
    """
    Return aggregate task statistics for the authenticated user.

    Includes: total count, breakdown by status and agent type, average steps
    for completed tasks, cumulative token usage, top 10 tags, and first/last
    task timestamps.

    Phase 44 — Task Stats & Analytics.
    """
    return await get_task_stats(user["user_id"])


# ── Task Bulk Operations (Phase 43) ────────────────────────────────────────────

_MAX_BULK_IDS = 100


class BulkTaskIdsRequest(BaseModel):
    task_ids: list[str] = Field(
        ...,
        min_length=1,
        max_length=_MAX_BULK_IDS,
        description="List of task UUIDs (max 100).",
    )

    @field_validator("task_ids")
    @classmethod
    def ids_must_be_uuid(cls, v: list[str]) -> list[str]:
        import re

        uuid_re = re.compile(
            r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I
        )
        bad = [tid for tid in v if not uuid_re.match(tid)]
        if bad:
            raise ValueError(f"Invalid UUID(s): {bad[:3]}")
        return v


class BulkTagRequest(BulkTaskIdsRequest):
    tags: list[str] = Field(
        ...,
        max_length=10,
        description="Tags to apply to all listed tasks (replaces existing tags).",
    )

    @field_validator("tags")
    @classmethod
    def tags_must_be_short(cls, v: list[str]) -> list[str]:
        for tag in v:
            if len(tag) > 50:
                raise ValueError(f"tag {tag!r} exceeds 50 characters")
        return [t.strip() for t in v if t.strip()]


@router.post("/bulk/cancel", status_code=status.HTTP_200_OK)
async def bulk_cancel(
    body: BulkTaskIdsRequest,
    user: dict = Depends(require_user),
) -> dict:
    """
    Cancel multiple queued tasks in a single request.

    Only queued tasks owned by the authenticated user are cancelled.
    Running/completed/failed tasks are silently skipped.

    Phase 43 — Task Bulk Operations.
    """
    count = await bulk_cancel_tasks(body.task_ids, user["user_id"])
    return {"cancelled": count, "requested": len(body.task_ids)}


@router.post("/bulk/delete", status_code=status.HTTP_200_OK)
async def bulk_delete(
    body: BulkTaskIdsRequest,
    user: dict = Depends(require_user),
) -> dict:
    """
    Hard-delete multiple tasks in a single request.

    Only tasks owned by the authenticated user are deleted.
    Cascades to task_notes, task_events, stream_tokens.

    Phase 43 — Task Bulk Operations.
    """
    count = await bulk_delete_tasks(body.task_ids, user["user_id"])
    return {"deleted": count, "requested": len(body.task_ids)}


@router.post("/bulk/tag", status_code=status.HTTP_200_OK)
async def bulk_tag(
    body: BulkTagRequest,
    user: dict = Depends(require_user),
) -> dict:
    """
    Apply a tag list to multiple tasks in a single request.

    Replaces existing tags on all matching tasks owned by the authenticated user.

    Phase 43 — Task Bulk Operations.
    """
    count = await bulk_tag_tasks(body.task_ids, user["user_id"], body.tags)
    return {"tagged": count, "requested": len(body.task_ids)}


# ── Task Export (Phase 38) ─────────────────────────────────────────────────────

_EXPORT_CSV_FIELDS = [
    "task_id",
    "status",
    "agent_type",
    "priority",
    "input",
    "result",
    "error",
    "steps",
    "created_at",
    "completed_at",
    "tags",
]

_VALID_EXPORT_FORMATS = {"json", "csv", "markdown"}  # Phase 73 adds markdown


@router.get("/export")
async def export_tasks(
    user: dict = Depends(require_user),
    format: str = Query(
        default="json", description="Export format: 'json', 'csv', or 'markdown'"
    ),
    limit: int = Query(default=500, ge=1, le=5000, description="Max tasks to export"),
    status_filter: str | None = Query(default=None, alias="status"),
    q: str | None = Query(default=None, max_length=200),
    tags: list[str] | None = Query(default=None),
):
    """
    Export the authenticated user's tasks as JSON, CSV, or Markdown.

    Query params:
    - ``format`` — ``json`` (default), ``csv``, or ``markdown``
    - ``limit``  — max tasks to include (1–5000, default 500)
    - ``status`` — filter by task status
    - ``q``      — substring search on task input
    - ``tags``   — filter by tags

    Phase 38 — Task Export API.
    """
    if format not in _VALID_EXPORT_FORMATS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"format must be one of {sorted(_VALID_EXPORT_FORMATS)}",
        )
    if status_filter and status_filter not in VALID_TASK_STATUSES:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"status must be one of {sorted(VALID_TASK_STATUSES)}",
        )

    data = await list_tasks(
        user_id=user["user_id"],
        limit=limit,
        offset=0,
        status=status_filter,
        q=q,
        tags=tags,
    )
    tasks_rows = data.get("tasks", [])

    if format == "csv":
        buf = io.StringIO()
        writer = csv.DictWriter(
            buf,
            fieldnames=_EXPORT_CSV_FIELDS,
            extrasaction="ignore",
            lineterminator="\n",
        )
        writer.writeheader()
        for row in tasks_rows:
            # Flatten tags list to semicolon-separated string for CSV
            row_copy = dict(row)
            if isinstance(row_copy.get("tags"), list):
                row_copy["tags"] = ";".join(row_copy["tags"])
            writer.writerow(row_copy)
        csv_bytes = buf.getvalue().encode("utf-8")
        return StreamingResponse(
            iter([csv_bytes]),
            media_type="text/csv",
            headers={
                "Content-Disposition": 'attachment; filename="tasks_export.csv"',
                "X-Export-Count": str(len(tasks_rows)),
            },
        )

    # Phase 73: Markdown export
    if format == "markdown":
        from datetime import datetime, timezone as _tz

        lines: list[str] = [
            "# LegionForge Task Export",
            "",
            f"Generated: {datetime.now(_tz.utc).strftime('%Y-%m-%dT%H:%M:%SZ')}  ",
            f"Total: {len(tasks_rows)} task(s)  ",
            "",
            "---",
        ]
        for row in tasks_rows:
            tid = str(row.get("task_id", ""))[:8]
            status_val = row.get("status", "")
            agent = row.get("agent_type", "")
            created = str(row.get("created_at", ""))[:19]
            completed = str(row.get("completed_at", ""))[:19] or "—"
            tags_val = row.get("tags") or []
            tags_str = ", ".join(tags_val) if tags_val else "—"
            labels_val = row.get("labels") or []
            labels_str = ", ".join(labels_val) if labels_val else "—"
            task_input = str(row.get("input", "")).strip()
            result = str(row.get("result") or "").strip()

            lines += [
                "",
                f"## Task `{tid}…`",
                "",
                f"**Status:** {status_val}  **Agent:** {agent}  ",
                f"**Created:** {created}  **Completed:** {completed}  ",
                f"**Tags:** {tags_str}  **Labels:** {labels_str}  ",
                "",
                "**Input:**",
                "",
            ]
            for input_line in task_input.splitlines()[:20]:
                lines.append(f"> {input_line}")
            if result:
                lines += [
                    "",
                    "**Result:**",
                    "",
                    result[:2000],
                ]
            lines += ["", "---"]

        md_bytes = "\n".join(lines).encode("utf-8")
        return StreamingResponse(
            iter([md_bytes]),
            media_type="text/markdown",
            headers={
                "Content-Disposition": 'attachment; filename="tasks_export.md"',
                "X-Export-Count": str(len(tasks_rows)),
            },
        )

    # JSON export
    payload = _json.dumps(
        {"count": len(tasks_rows), "tasks": tasks_rows}, default=str
    ).encode("utf-8")
    return StreamingResponse(
        iter([payload]),
        media_type="application/json",
        headers={
            "Content-Disposition": 'attachment; filename="tasks_export.json"',
            "X-Export-Count": str(len(tasks_rows)),
        },
    )


@router.get("/{task_id}")
async def get_task_result(
    task_id: str,
    user: dict = Depends(require_user),
) -> dict:
    """
    Return a task's full result.
    Returns 404 for unknown task_id OR task belonging to a different user
    (do not confirm existence to unauthorized callers).
    """
    row = await get_task(task_id, user_id=user["user_id"])
    if row is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Task not found"
        )
    return row


class UpdateTagsRequest(BaseModel):
    tags: list[str] = Field(
        ...,
        max_length=10,
        description="New tag list (replaces existing tags).  Max 10 tags, each max 50 chars.",
    )

    @field_validator("tags")
    @classmethod
    def tags_must_be_short(cls, v: list[str]) -> list[str]:
        for tag in v:
            if len(tag) > 50:
                raise ValueError(f"tag {tag!r} exceeds 50 characters")
        return [t.strip() for t in v if t.strip()]


@router.put("/{task_id}/tags")
async def set_task_tags(
    task_id: str,
    body: UpdateTagsRequest,
    user: dict = Depends(require_user),
) -> dict:
    """
    Replace the tags on a task.

    Returns the updated task with new tags.  404 if task not found or not owned.

    Phase 31 — Task Tags.
    """
    row = await update_task_tags(task_id, user["user_id"], body.tags)
    if row is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Task not found or not owned by this user",
        )
    return row


# ── Task Labels (Phase 40) ─────────────────────────────────────────────────────


class UpdateLabelsRequest(BaseModel):
    labels: list[str] = Field(
        ...,
        max_length=4,
        description=(
            "New label list (replaces existing labels).  "
            "Allowed values: bookmarked, starred, important, archived."
        ),
    )

    @field_validator("labels")
    @classmethod
    def labels_must_be_valid(cls, v: list[str]) -> list[str]:
        unknown = set(v) - VALID_TASK_LABELS
        if unknown:
            raise ValueError(
                f"Unknown labels: {sorted(unknown)}. "
                f"Allowed: {sorted(VALID_TASK_LABELS)}"
            )
        return list(set(v))  # deduplicate


@router.put("/{task_id}/labels")
async def set_task_labels(
    task_id: str,
    body: UpdateLabelsRequest,
    user: dict = Depends(require_user),
) -> dict:
    """
    Replace the labels on a task.

    Allowed labels: ``bookmarked``, ``starred``, ``important``, ``archived``.
    Returns the updated task.  404 if task not found or not owned.

    Phase 40 — Task Labels.
    """
    try:
        row = await update_task_labels(task_id, user["user_id"], body.labels)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)
        ) from exc
    if row is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Task not found or not owned by this user",
        )
    return row


@router.delete("/{task_id}", status_code=status.HTTP_204_NO_CONTENT)
async def cancel_task(
    task_id: str,
    user: dict = Depends(require_user),
) -> None:
    """
    Cancel a queued task.  Only queued tasks can be cancelled — running tasks
    cannot be interrupted in Phase 8.
    """
    cancelled = await mark_task_cancelled(task_id, user["user_id"])
    if not cancelled:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Task not found, not queued, or not owned by this user",
        )


# ── Task Notes (Phase 32) ──────────────────────────────────────────────────────


class AddNoteRequest(BaseModel):
    note: str = Field(
        ..., min_length=1, max_length=2000, description="Note text (max 2000 chars)."
    )


@router.post("/{task_id}/notes", status_code=status.HTTP_201_CREATED)
async def add_note(
    task_id: str,
    body: AddNoteRequest,
    user: dict = Depends(require_user),
) -> dict:
    """
    Append a freeform note to a task.

    Notes are visible only to the task owner.  Returns the new note with its ID.

    Phase 32 — Task Notes & Annotations.
    """
    row = await add_task_note(task_id, user["user_id"], body.note)
    if row is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Task not found or not owned by this user",
        )
    return row


@router.get("/{task_id}/notes")
async def get_notes(
    task_id: str,
    user: dict = Depends(require_user),
) -> dict:
    """
    List all notes on a task, oldest-first.

    Returns 404 if the task doesn't belong to the authenticated user.

    Phase 32 — Task Notes & Annotations.
    """
    # Verify ownership (list_task_notes returns [] for non-owned tasks)
    task_row = await get_task(task_id, user_id=user["user_id"])
    if task_row is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Task not found"
        )
    notes = await list_task_notes(task_id, user["user_id"])
    return {"task_id": task_id, "count": len(notes), "notes": notes}


@router.delete("/{task_id}/notes/{note_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_note(
    task_id: str,
    note_id: int,
    user: dict = Depends(require_user),
) -> None:
    """
    Delete a specific note by ID.

    Returns 404 if the note doesn't exist or doesn't belong to this user.

    Phase 32 — Task Notes & Annotations.
    """
    deleted = await delete_task_note(note_id, task_id, user["user_id"])
    if not deleted:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Note not found or not owned by this user",
        )


# ── Task Timeline (Phase 39) ───────────────────────────────────────────────────


@router.get("/{task_id}/timeline")
async def get_timeline(
    task_id: str,
    user: dict = Depends(require_user),
) -> dict:
    """
    Return the chronological event timeline for a task.

    Events represent state transitions: queued → running → complete/failed.
    Returns 404 if the task does not exist or belongs to another user.

    Phase 39 — Task Timeline.
    """
    task = await get_task(task_id, user["user_id"])
    if task is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Task {task_id} not found",
        )
    events = await get_task_timeline(task_id, user["user_id"])
    return {"task_id": task_id, "count": len(events), "events": events}


# ── Task Attachments (Phase 49) ────────────────────────────────────────────────


class AttachmentCreate(BaseModel):
    filename: str = Field(..., max_length=255)
    content_type: str = Field(default="text/plain", max_length=100)
    data: str = Field(
        ...,
        description=f"Text content of the attachment (max {_MAX_ATTACHMENT_BYTES} bytes when encoded as UTF-8)",
    )


@router.post("/{task_id}/attachments", status_code=status.HTTP_201_CREATED)
async def add_attachment(
    task_id: str,
    body: AttachmentCreate,
    user: dict = Depends(require_user),
) -> dict:
    """
    Attach a text blob to a task (code snippets, file excerpts, structured context).

    Maximum attachment size: 64 KB (UTF-8 encoded).  Phase 49 — Task Attachments.
    """
    try:
        return await add_task_attachment(
            task_id=task_id,
            user_id=user["user_id"],
            filename=body.filename,
            data=body.data,
            content_type=body.content_type,
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))


@router.get("/{task_id}/attachments")
async def list_attachments(
    task_id: str,
    user: dict = Depends(require_user),
) -> dict:
    """
    List all attachments for a task (data fields excluded).

    Returns 404 if the task does not exist or is owned by another user.
    Phase 49 — Task Attachments.
    """
    task = await get_task(task_id, user["user_id"])
    if task is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Task {task_id} not found",
        )
    attachments = await list_task_attachments(task_id, user["user_id"])
    return {"task_id": task_id, "count": len(attachments), "attachments": attachments}


@router.get("/{task_id}/attachments/{attachment_id}")
async def get_attachment(
    task_id: str,
    attachment_id: str,
    user: dict = Depends(require_user),
) -> dict:
    """
    Retrieve a single attachment including its data.

    Phase 49 — Task Attachments.
    """
    row = await get_task_attachment(attachment_id, task_id, user["user_id"])
    if row is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Attachment {attachment_id!r} not found",
        )
    return row


@router.delete(
    "/{task_id}/attachments/{attachment_id}", status_code=status.HTTP_204_NO_CONTENT
)
async def remove_attachment(
    task_id: str,
    attachment_id: str,
    user: dict = Depends(require_user),
) -> None:
    """
    Delete an attachment.

    Phase 49 — Task Attachments.
    """
    deleted = await delete_task_attachment(attachment_id, task_id, user["user_id"])
    if not deleted:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Attachment {attachment_id!r} not found",
        )


# ── Task Retry (Phase 33) ──────────────────────────────────────────────────────

_RETRYABLE_STATUSES = {"failed", "cancelled"}


@router.post("/{task_id}/retry", status_code=status.HTTP_202_ACCEPTED)
async def retry_task(
    task_id: str,
    user: dict = Depends(require_user),
) -> dict:
    """
    Retry a failed or cancelled task.

    Creates a new task with the same input, agent_type, priority, tags, and
    callback_url as the original.  The original task is not modified.

    Only tasks in ``failed`` or ``cancelled`` status can be retried.
    Returns 409 for tasks still queued/running, 404 for unknown tasks.

    Phase 33 — Task Retry API.
    """
    original = await get_task(task_id, user_id=user["user_id"])
    if original is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Task not found"
        )

    if original.get("status") not in _RETRYABLE_STATUSES:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                f"Only failed or cancelled tasks can be retried; "
                f"task is '{original.get('status')}'"
            ),
        )

    input_text = original.get("input", "")
    agent_type = original.get("agent_type", "orchestrator")
    priority = original.get("priority", 5)
    tags = original.get("tags") or []
    callback_url = original.get("callback_url")

    # Budget check for the retry
    estimated_tokens = int(len(input_text.split()) * 1.3 + 500)
    provider = _AGENT_TYPE_TO_PROVIDER.get(agent_type, "ollama")
    daily_limit = user.get("daily_token_limit", 100000)

    try:
        await per_user_budget_check(
            user_id=user["user_id"],
            provider=provider,
            estimated_tokens=estimated_tokens,
            daily_limit=daily_limit,
        )
    except RuntimeError as budget_err:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Daily token budget exceeded. Try again tomorrow.",
        ) from budget_err

    from src.task_cache import compute_task_hash

    content_hash = compute_task_hash(agent_type, input_text)

    row = await create_task(
        user_id=user["user_id"],
        input_text=input_text,
        agent_type=agent_type,
        config=original.get("config") or {},
        estimated_tokens=estimated_tokens,
        callback_url=callback_url,
        priority=priority,
        content_hash=content_hash,
        tags=list(tags),
    )
    new_task_id = row["task_id"]
    stream_token = await create_stream_token(new_task_id, user["user_id"])
    inc_counter("legionforge_tasks_submitted_total")

    logger.info(
        "[gateway] Retried task original=%s new=%s user=%s",
        _log_safe(task_id),
        _log_safe(new_task_id),
        _log_safe(user["username"]),
    )

    return {
        "task_id": new_task_id,
        "original_task_id": task_id,
        "status": "queued",
        "priority": row.get("priority", 5),
        "created_at": row["created_at"],
        "stream_url": f"/tasks/{new_task_id}/stream",
        "stream_token": stream_token,
    }


# ── Task Sharing (Phase 51) ────────────────────────────────────────────────────


class ShareRequest(BaseModel):
    expires_hours: int | None = Field(
        default=None,
        ge=1,
        le=8760,
        description="Optional expiry in hours (1–8760).  Omit for no expiry.",
    )


@router.post("/{task_id}/share", status_code=status.HTTP_201_CREATED)
async def share_task(
    task_id: str,
    body: ShareRequest,
    user: dict = Depends(require_user),
) -> dict:
    """
    Create a read-only share token for a completed task.

    The returned ``share_token`` can be passed to ``GET /shared/{token}`` by
    anyone — no authentication required.  Optionally set ``expires_hours`` to
    auto-expire the link.

    Phase 51 — Task Sharing.
    """
    from datetime import datetime, timedelta, timezone

    expires_at = None
    if body.expires_hours:
        expires_at = datetime.now(timezone.utc) + timedelta(hours=body.expires_hours)

    try:
        share = await create_task_share(
            task_id=task_id,
            user_id=user["user_id"],
            expires_at=expires_at,
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))

    return {
        "share_token": share["share_token"],
        "task_id": task_id,
        "expires_at": share["expires_at"].isoformat() if share["expires_at"] else None,
        "created_at": share["created_at"].isoformat() if share["created_at"] else None,
    }


@router.get("/{task_id}/shares")
async def list_shares(
    task_id: str,
    user: dict = Depends(require_user),
) -> dict:
    """
    List all active share tokens for a task.

    Phase 51 — Task Sharing.
    """
    task = await get_task(task_id, user["user_id"])
    if task is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Task {task_id} not found",
        )
    shares = await list_task_shares(task_id, user["user_id"])
    return {"task_id": task_id, "count": len(shares), "shares": shares}


@router.delete(
    "/{task_id}/shares/{share_token}", status_code=status.HTTP_204_NO_CONTENT
)
async def revoke_share(
    task_id: str,
    share_token: str,
    user: dict = Depends(require_user),
) -> None:
    """
    Revoke a share token immediately.

    Phase 51 — Task Sharing.
    """
    deleted = await revoke_task_share(share_token, user["user_id"])
    if not deleted:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Share token not found",
        )

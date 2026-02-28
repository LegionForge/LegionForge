"""
src/rate_limiter.py
───────────────────
Async rate limiter for paid API calls. Tracks token consumption,
enforces per-minute and per-day limits, and alerts when approaching
thresholds. Backed by PostgreSQL for persistence across restarts.

Usage:
    from src.rate_limiter import RateLimiter, get_limiter

    limiter = get_limiter("openai")
    async with limiter.guard(estimated_tokens=500):
        response = await llm.ainvoke(...)
"""

from __future__ import annotations

import asyncio
import logging
import time
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from typing import AsyncGenerator

from aiolimiter import AsyncLimiter

logger = logging.getLogger(__name__)


# ── Rate limit configuration per provider ─────────────────────────────────────


@dataclass
class ProviderLimits:
    """Rate limits for a single LLM provider."""

    name: str

    # Per-minute limits
    calls_per_minute: int = 60
    tokens_per_minute: int = 100_000

    # Per-day soft limits (alert threshold — not hard block)
    tokens_per_day_alert: int = 500_000
    cost_per_day_alert_usd: float = 10.0

    # Hard daily token limit (blocks further calls)
    tokens_per_day_hard_limit: int = 1_000_000

    # Per-call limits
    max_tokens_per_call: int = 8_000

    # Estimated cost per 1K tokens (for alerting)
    cost_per_1k_input_tokens: float = 0.0
    cost_per_1k_output_tokens: float = 0.0


# Default limits by provider (conservative — adjust to your plan)
PROVIDER_LIMITS: dict[str, ProviderLimits] = {
    "openai": ProviderLimits(
        name="openai",
        calls_per_minute=60,
        tokens_per_minute=90_000,
        tokens_per_day_alert=400_000,
        tokens_per_day_hard_limit=800_000,
        max_tokens_per_call=8_000,
        cost_per_1k_input_tokens=0.00015,  # gpt-4o-mini pricing
        cost_per_1k_output_tokens=0.0006,
    ),
    "anthropic": ProviderLimits(
        name="anthropic",
        calls_per_minute=50,
        tokens_per_minute=80_000,
        tokens_per_day_alert=300_000,
        tokens_per_day_hard_limit=600_000,
        max_tokens_per_call=8_000,
        cost_per_1k_input_tokens=0.0003,  # claude-haiku pricing
        cost_per_1k_output_tokens=0.0015,
    ),
    "ollama": ProviderLimits(
        name="ollama",
        calls_per_minute=999,  # Local — no real limit
        tokens_per_minute=999_999,
        tokens_per_day_alert=99_999_999,
        tokens_per_day_hard_limit=99_999_999,
        max_tokens_per_call=32_000,
        cost_per_1k_input_tokens=0.0,  # Free
        cost_per_1k_output_tokens=0.0,
    ),
}


# ── In-memory daily counter (resets at midnight, persisted to DB) ─────────────


@dataclass
class DailyCounter:
    """Tracks daily token usage in memory."""

    provider: str
    date_str: str = ""
    total_tokens: int = 0
    total_calls: int = 0
    estimated_cost_usd: float = 0.0
    alert_sent: bool = False
    # Tokens reserved by in-flight guard() calls but not yet committed.
    # Included in hard-limit checks so concurrent callers can't both slip
    # through the check window before either has incremented total_tokens.
    _reserved_tokens: int = 0
    _lock: asyncio.Lock = field(default_factory=asyncio.Lock)

    def reset_if_new_day(self) -> None:
        from datetime import date

        today = date.today().isoformat()
        if self.date_str != today:
            self.date_str = today
            self.total_tokens = 0
            self.total_calls = 0
            self.estimated_cost_usd = 0.0
            self.alert_sent = False
            self._reserved_tokens = 0

    async def check_and_reserve(
        self, estimated_tokens: int, limits: ProviderLimits
    ) -> None:
        """
        Atomically check hard limits and reserve the estimated token budget.

        Both the check and the reservation happen under the same lock, so
        concurrent guard() callers cannot both pass the check before either
        has incremented the counter (the classic TOCTOU race).

        Raises RuntimeError if the call would exceed a hard limit.
        Call release_reservation() if the guarded operation is cancelled or fails.
        """
        async with self._lock:
            self.reset_if_new_day()
            effective = self.total_tokens + self._reserved_tokens
            if effective + estimated_tokens > limits.tokens_per_day_hard_limit:
                raise RuntimeError(
                    f"Hard daily token limit reached for '{self.provider}'.\n"
                    f"  Committed: {self.total_tokens:,} | Reserved: {self._reserved_tokens:,} | "
                    f"Limit: {limits.tokens_per_day_hard_limit:,}"
                )
            self._reserved_tokens += estimated_tokens

    async def release_reservation(self, estimated_tokens: int) -> None:
        """Release a previously reserved budget (call in finally after guard())."""
        async with self._lock:
            self._reserved_tokens = max(0, self._reserved_tokens - estimated_tokens)

    async def add(
        self,
        tokens: int,
        input_tokens: int,
        output_tokens: int,
        limits: ProviderLimits,
    ) -> None:
        async with self._lock:
            self.reset_if_new_day()
            self.total_tokens += tokens
            self.total_calls += 1
            self.estimated_cost_usd += (
                input_tokens / 1000
            ) * limits.cost_per_1k_input_tokens + (
                output_tokens / 1000
            ) * limits.cost_per_1k_output_tokens


# ── Rate Limiter class ────────────────────────────────────────────────────────


class RateLimiter:
    """
    Async rate limiter for a single LLM provider.
    Enforces per-minute call rate and token budgets.
    """

    def __init__(self, provider: str):
        if provider not in PROVIDER_LIMITS:
            logger.warning(
                f"No limits configured for provider '{provider}'. Using defaults."
            )
            self._limits = ProviderLimits(name=provider)
        else:
            self._limits = PROVIDER_LIMITS[provider]

        self._provider = provider

        # Token bucket for calls-per-minute
        self._call_limiter = AsyncLimiter(
            max_rate=self._limits.calls_per_minute,
            time_period=60,
        )

        # Daily counter
        self._daily = DailyCounter(provider=provider)

    @property
    def limits(self) -> ProviderLimits:
        return self._limits

    def _check_per_call_limit(self, estimated_tokens: int) -> None:
        """Raise if the per-call estimate exceeds the single-call cap."""
        if estimated_tokens > self._limits.max_tokens_per_call:
            raise RuntimeError(
                f"🚫 Single call token estimate ({estimated_tokens:,}) exceeds "
                f"per-call limit ({self._limits.max_tokens_per_call:,}) "
                f"for '{self._provider}'."
            )

    def _check_soft_alerts(self) -> None:
        """Log warnings when approaching soft limits."""
        self._daily.reset_if_new_day()

        usage_pct = self._daily.total_tokens / max(self._limits.tokens_per_day_alert, 1)

        if usage_pct >= 1.0 and not self._daily.alert_sent:
            logger.warning(
                f"⚠️  ALERT: '{self._provider}' has exceeded daily soft limit!\n"
                f"   Tokens: {self._daily.total_tokens:,} / "
                f"{self._limits.tokens_per_day_alert:,}\n"
                f"   Est. cost: ${self._daily.estimated_cost_usd:.4f}"
            )
            self._daily.alert_sent = True

        elif 0.8 <= usage_pct < 1.0:
            logger.warning(
                f"⚠️  '{self._provider}' at {usage_pct:.0%} of daily token limit. "
                f"({self._daily.total_tokens:,} tokens, "
                f"${self._daily.estimated_cost_usd:.4f} est. cost)"
            )

        if self._daily.estimated_cost_usd >= self._limits.cost_per_day_alert_usd:
            logger.warning(
                f"💰 Cost alert: '{self._provider}' has accumulated "
                f"${self._daily.estimated_cost_usd:.4f} today "
                f"(threshold: ${self._limits.cost_per_day_alert_usd:.2f})"
            )

    @asynccontextmanager
    async def guard(
        self,
        estimated_tokens: int = 1000,
    ) -> AsyncGenerator[None, None]:
        """
        Async context manager that enforces rate limits.
        Wrap any paid API call with this.

        Usage:
            async with limiter.guard(estimated_tokens=500):
                response = await llm.ainvoke(prompt)

        Race-condition fix (Phase 9.5):
            check_and_reserve() atomically checks the daily hard limit AND
            reserves the estimated budget under the DailyCounter lock, so
            concurrent callers cannot both pass the check before either has
            incremented the counter.  The reservation is always released in
            finally — record_actual_usage() commits the real token count
            independently and does not double-count the reservation.
        """
        # Per-call limit is a simple synchronous check — no race risk.
        self._check_per_call_limit(estimated_tokens)

        # Atomic daily-cap check + reservation (fixes TOCTOU race).
        await self._daily.check_and_reserve(estimated_tokens, self._limits)
        self._check_soft_alerts()

        # Acquire the per-minute call token.
        try:
            async with self._call_limiter:
                start = time.monotonic()
                try:
                    yield
                finally:
                    elapsed_ms = int((time.monotonic() - start) * 1000)
                    logger.debug(
                        f"[{self._provider}] call completed in {elapsed_ms}ms "
                        f"(estimated {estimated_tokens} tokens)"
                    )
        finally:
            # Always release the reservation — record_actual_usage() will
            # commit the real token count to total_tokens separately.
            await self._daily.release_reservation(estimated_tokens)

    async def record_actual_usage(
        self,
        input_tokens: int,
        output_tokens: int,
        run_id: str | None = None,
        agent_name: str | None = None,
        success: bool = True,
        latency_ms: int | None = None,
        user_id: str | None = None,
    ) -> None:
        """
        Record actual token usage after a call completes.
        Updates in-memory counter and persists to database.

        Args:
            user_id: Gateway user who submitted the task.  Passed by the worker
                     so api_usage rows can be attributed to specific users for
                     per-user budget accounting.  None for internal agent calls.
        """
        total = input_tokens + output_tokens
        await self._daily.add(
            tokens=total,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            limits=self._limits,
        )

        # Persist to DB (non-blocking — fire and forget)
        try:
            from src.database import record_api_usage

            await record_api_usage(
                provider=self._provider,
                model="unknown",
                input_tokens=input_tokens,
                output_tokens=output_tokens,
                run_id=run_id,
                agent_name=agent_name,
                success=success,
                latency_ms=latency_ms,
                user_id=user_id,
            )
        except Exception as e:
            logger.warning(f"Failed to persist API usage to DB: {e}")

    def get_daily_status(self) -> dict:
        """Return current daily usage status."""
        self._daily.reset_if_new_day()
        return {
            "provider": self._provider,
            "date": self._daily.date_str,
            "total_tokens": self._daily.total_tokens,
            "total_calls": self._daily.total_calls,
            "estimated_cost_usd": round(self._daily.estimated_cost_usd, 6),
            "token_limit_soft": self._limits.tokens_per_day_alert,
            "token_limit_hard": self._limits.tokens_per_day_hard_limit,
            "usage_pct": round(
                self._daily.total_tokens
                / max(self._limits.tokens_per_day_alert, 1)
                * 100,
                1,
            ),
        }


# ── Module-level limiter registry ─────────────────────────────────────────────

_limiters: dict[str, RateLimiter] = {}


def get_limiter(provider: str) -> RateLimiter:
    """Get or create a rate limiter for a provider (singleton per provider)."""
    if provider not in _limiters:
        _limiters[provider] = RateLimiter(provider)
    return _limiters[provider]


def get_all_daily_status() -> list[dict]:
    """Get daily usage status for all active providers."""
    return [limiter.get_daily_status() for limiter in _limiters.values()]


# ── Token estimation ──────────────────────────────────────────────────────────


def estimate_tokens(text: str, model: str = "gpt-3.5-turbo") -> int:
    """
    Estimate the token count for a text string using tiktoken.
    Falls back to len(text) // 4 if the model encoding is not found.

    The gpt-3.5-turbo encoding (cl100k_base) is a reasonable proxy for
    most modern LLMs including Llama 3 and Qwen models.
    """
    try:
        import tiktoken

        enc = tiktoken.encoding_for_model(model)
        return len(enc.encode(text))
    except (KeyError, Exception):
        return len(text) // 4


async def per_user_budget_check(
    user_id: str,
    provider: str,
    estimated_tokens: int,
    daily_limit: int,
) -> None:
    """
    Enforce per-user daily token budget at task submission time.

    Makes two DB reads to prevent TOCTOU races when multiple tasks are
    submitted concurrently by the same user:

      actual_used  — tokens already recorded in api_usage today (rows where
                     user_id IS NOT NULL, written by the worker on completion)
      in_flight    — estimated_tokens sum of queued/running tasks today

    If actual_used + in_flight + estimated_tokens > daily_limit, the
    submission is rejected before the task is queued.

    Args:
        user_id:          UUID string of the gateway user.
        provider:         LLM provider for this task (e.g. "ollama", "openai").
        estimated_tokens: Conservative token estimate for the incoming task.
        daily_limit:      User's daily_token_limit from gateway_users.

    Raises:
        RuntimeError: If submitting this task would exceed the user's budget.
    """
    from src.database import get_user_actual_usage_today, get_user_inflight_tokens

    actual_used = await get_user_actual_usage_today(user_id, provider)
    in_flight = await get_user_inflight_tokens(user_id)

    if actual_used + in_flight + estimated_tokens > daily_limit:
        raise RuntimeError(
            f"Per-user daily token budget exceeded for user '{user_id}'.\n"
            f"  Used today: {actual_used:,} | In-flight: {in_flight:,} | "
            f"Estimated: {estimated_tokens:,} | Daily limit: {daily_limit:,}"
        )

    logger.debug(
        f"[per-user-budget] user={user_id} provider={provider} "
        f"actual={actual_used} in_flight={in_flight} estimated={estimated_tokens} "
        f"limit={daily_limit} — OK"
    )


def preflight_budget_check(estimated_tokens: int, provider: str) -> None:
    """
    Check estimated token cost against hard limits BEFORE calling the LLM.
    Raises RuntimeError (with PREFLIGHT_BUDGET_EXCEEDED context) if the
    estimate would exceed the provider's hard daily or per-call limit.

    Call this immediately before every llm.ainvoke() in agent nodes.
    Note: this is a best-effort synchronous snapshot — use guard() for the
    atomic reservation that prevents the concurrent-caller race condition.

    Args:
        estimated_tokens: Token estimate for the upcoming call (input only is fine).
        provider:         Provider name — must match a key in PROVIDER_LIMITS.
    """
    limiter = get_limiter(provider)
    try:
        limiter._check_per_call_limit(estimated_tokens)
        # Snapshot check (not atomic) — guards against obvious budget bombs.
        limiter._daily.reset_if_new_day()
        if (
            limiter._daily.total_tokens
            + limiter._daily._reserved_tokens
            + estimated_tokens
            > limiter._limits.tokens_per_day_hard_limit
        ):
            raise RuntimeError(
                f"Hard daily token limit reached for '{provider}'.\n"
                f"  Used: {limiter._daily.total_tokens:,} | "
                f"Reserved: {limiter._daily._reserved_tokens:,} | "
                f"Limit: {limiter._limits.tokens_per_day_hard_limit:,}"
            )
    except RuntimeError as e:
        logger.error(
            f"[preflight] PREFLIGHT_BUDGET_EXCEEDED for provider='{provider}' "
            f"estimated_tokens={estimated_tokens}"
        )
        raise RuntimeError(f"PREFLIGHT_BUDGET_EXCEEDED: {e}") from e

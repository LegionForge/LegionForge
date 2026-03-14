# TODO / FIXME / type:ignore Audit — LegionForge

Generated: 2026-03-13
Tool: `grep -rn "TODO|FIXME|HACK|XXX|NOQA|type: ignore" src/ config/ packages/guardian/src/ tests/ --include="*.py"`

## Summary

| Category | Count |
|---|---|
| Real TODO (actionable) | 1 |
| `type: ignore` suppressions | 25 |
| **Total** | **26** |

No FIXME, HACK, or XXX entries found.

---

## Real TODO

### `src/safeguards.py` line 382

```
Phase 2 behaviour (TODO): use LangGraph interrupt_before to pause the graph
and wait for operator approval via the approval API. The 'hitl_pending' flag
in state will be checked by the routing function.
```

**Context:** This is in the HITL (Human-in-the-Loop) gate logic in `safeguards.py`. When a tool call
triggers a HITL-required category (e.g. `CMD_INJECTION`, `PRIVILEGE_ESCALATION`), the current code
halts the run entirely. The TODO describes the full intended behavior: pause the graph at
`interrupt_before`, set `hitl_pending=True` in state, and resume only after an operator approves
via a dedicated approval API endpoint. This is the proper LangGraph-native flow for human-gating.

**Priority:** `[P2-pre-v1.0]` — HITL is a security feature; the current halt-immediately fallback
is safe but doesn't allow approved resumption. This needs to be wired up before v1.0 if operator
approval flows are in scope.

---

## type: ignore Suppressions

These are all `# type: ignore[...]` annotations used to suppress mypy/pyright type errors.
None are `NOQA` (pyflakes-style). Most suppress optional-import patterns or dynamic attribute
assignments that mypy cannot statically verify.

### `src/credentials.py` line 166

```python
_keyring = None  # type: ignore[assignment]
```

**Context:** `keyring` is an optional dependency; the module sets `_keyring = None` as a sentinel
when the import fails, then assigns the real module. Mypy cannot narrow the type after the
conditional import pattern.

**Priority:** `[P4-nice-to-have]` — suppress is correct; no action needed.

---

### `src/gateway/backends/kerberos.py` lines 55–56

```python
import gssapi  # type: ignore[import]
import gssapi.raw as gss_raw  # type: ignore[import]
```

**Context:** `gssapi` is an optional dependency only installed when the Kerberos backend is
active. Mypy has no stub for it so the import must be suppressed.

**Priority:** `[P4-nice-to-have]` — correct suppress; no action needed.

---

### `src/gateway/backends/oidc.py` lines 84 and 97

```python
return self._discovery  # type: ignore[return-value]
return self._jwks  # type: ignore[return-value]
```

**Context:** `_discovery` and `_jwks` are initialized as `None` but populated before any caller
reaches these return paths. The class invariant is enforced by `_ensure_loaded()` but mypy
cannot see that the type has narrowed to non-None by return time.

**Priority:** `[P4-nice-to-have]` — correct suppress. Could be cleaned up with `assert` guards or
`cast()` for clarity, but not urgent.

---

### `src/gateway/state.py` lines 49 and 94

```python
_redis: "redis.asyncio.Redis | None" = None  # type: ignore[name-defined]
def get_redis() -> "redis.asyncio.Redis | None":  # type: ignore[name-defined]
```

**Context:** `redis` is an optional dependency. The type annotation is a forward string reference
to `redis.asyncio.Redis`, but if the package isn't installed mypy can't resolve the name. The
suppression is on the annotation itself, not a logic error.

**Priority:** `[P4-nice-to-have]` — correct. Could use `TYPE_CHECKING` guard.

---

### `src/ingestor.py` line 209

```python
import pdfplumber  # type: ignore[import]
```

**Context:** `pdfplumber` is an optional dependency for PDF ingestion. Mypy has no stubs for it.

**Priority:** `[P4-nice-to-have]` — correct suppress.

---

### `src/ollama_cluster.py` lines 287, 325–329

```python
out.append(r)  # type: ignore[arg-type]
node.url = url  # type: ignore[attr-defined]
node.label = label  # type: ignore[attr-defined]
node.weight = weight  # type: ignore[attr-defined]
node.enabled = enabled  # type: ignore[attr-defined]
node.timeout = timeout  # type: ignore[attr-defined]
```

**Context:** `node` in the cluster code is typed as an abstract base but the runtime objects
are concrete dataclass instances. The attr assignments are valid at runtime but not statically
typed. The `arg-type` suppress on line 287 is for an `httpx` response variant.

**Priority:** `[P3-post-v1.0]` — consider adding a typed `OllamaNode` Protocol or dataclass
to eliminate all five attr-defined suppresses at once. Minor cleanup.

---

### `src/pipeline_runner.py` line 63

```python
def replace(m: re.Match) -> str:  # type: ignore[type-arg]
```

**Context:** `re.Match` without a type argument defaults to `re.Match[Any]` which mypy
treats as needing a type param on older stubs. `re.Match[str]` would be the clean form.

**Priority:** `[P4-nice-to-have]` — change `re.Match` → `re.Match[str]`.

---

### `src/scheduler.py` lines 102, 120, 147

```python
from croniter import croniter  # type: ignore[import]  (×2)
self._task: Optional[asyncio.Task] = None  # type: ignore[type-arg]
```

**Context:** `croniter` is optional; no stubs available. The `asyncio.Task` suppress is
the same pattern as `re.Match` — needs `asyncio.Task[None]` for full type safety.

**Priority:** `[P4-nice-to-have]` — `asyncio.Task[None]` cleanup is a one-liner. croniter
suppresses are correct.

---

### `src/security/core.py` line 30

```python
_keyring = None  # type: ignore[assignment]
```

**Context:** Same as `src/credentials.py` — optional keyring import sentinel.

**Priority:** `[P4-nice-to-have]` — correct.

---

### `src/tools/code_tools.py` line 99

```python
def _replace(m: re.Match) -> str:  # type: ignore[type-arg]
```

**Context:** Same `re.Match` pattern as pipeline_runner.py.

**Priority:** `[P4-nice-to-have]` — change to `re.Match[str]`.

---

### `src/tools/pentest_tools.py` line 1420

```python
result = await fn(env)  # type: ignore[call-arg]
```

**Context:** `fn` is a callable loaded from a registry dict typed as
`Callable[..., Any]`. The env argument is valid at runtime but mypy can't
verify the signature.

**Priority:** `[P4-nice-to-have]` — correct suppress; registry typing is intentionally loose.

---

### `tests/testlab_suite/conftest.py` lines 119, 123, 129, 130

```python
original_startup = self._server.startup  # type: ignore[union-attr]
for s in self._server.servers:  # type: ignore[union-attr]
self._server.startup = patched_startup  # type: ignore[union-attr]
loop.run_until_complete(self._server.serve())  # type: ignore[union-attr]
```

**Context:** `self._server` is typed as `uvicorn.Server | None` in the conftest fixture.
The `if self._server:` guard precedes these lines but mypy doesn't narrow union-optional
attributes inside object methods (only locals). These are test fixtures and the suppresses
are correct.

**Priority:** `[P4-nice-to-have]` — test-only; no action needed.

---

## Action Summary

| Priority | Count | Action |
|---|---|---|
| `[P2-pre-v1.0]` | 1 | `safeguards.py` HITL interrupt_before + approval API |
| `[P3-post-v1.0]` | 1 | `ollama_cluster.py` typed OllamaNode Protocol |
| `[P4-nice-to-have]` | 24 | `type: ignore` cleanups (`re.Match[str]`, `asyncio.Task[None]`, `cast()`) |

The only item requiring engineering attention before v1.0 is the HITL interrupt_before
wiring in `safeguards.py` — everything else is type-annotation hygiene.

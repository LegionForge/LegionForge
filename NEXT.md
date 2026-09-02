# NEXT — Session Handoff
*Updated by Claude at end of each session. Read this first. Takes 30 seconds.*

---

## Last updated
2026-09-02 — Org-wide PR/CI/docs sweep (not a feature session). Reviewed and merged the backlog of Dependabot bumps, real CI bugs (sast permissions startup_failure, CodeQL log-injection, Docker base image), and stale public-website/product docs across the LegionForge GitHub org. No feature work landed. Full list of what was merged this session is in `checkpoint.md` LAST_OP and the org's `lessons-github*.md` memory files.

## State
- **Branch:** `main` — clean, no uncommitted changes
- **Smoke tests:** 2255/2255 (verified locally at HEAD `967f592`)
- **Open PRs:** none
- **Ship target:** v0.8.0 — date TBD
- **Mode:** UAT + pre-v0.8.0 bug fixes

## Note on this file
This file was severely stale before this update (last real entry: 2026-03-26, five months prior). Several items below reference issue numbers (#295/#296/#297) that no longer exist — the corresponding open issues are now **#24, #25, #26** (renumbered at some point after this file was last written). The "Guardian DB connection broken" and "Priority 0/1" sections below are preserved as historical record but have **not been re-verified this session** — treat them as unconfirmed until someone checks current Guardian/Keychain state directly.

## Infrastructure reminder — START OF EVERY SESSION
```bash
make start          # Ollama → PostgreSQL → model warmup → servers
make guardian-start # Guardian Docker sidecar (:9766) — requires Docker Desktop running
make health          # expect: {"status": "ok"}
curl -s http://localhost:9766/health | jq .   # expect: {"status": "ok", ...}
```
**Docker must be running before `make guardian-start`.** Guardian is 1 of 2 containers in the compose file — verify both are up: `docker ps | grep legion`.

**web_fetch_js also requires Docker** (headless Chromium). If Docker is down, JS-rendered sites (CBC, CNN, React SPAs) will fail to fetch. Static HTML sites (HackerNews, Wikipedia) use plain `web_fetch` and work without Docker.

**jp's API key** — retrieve via:
```bash
make rotate-key USERNAME=jp
```

**TestLab admin key** (port 8090): `legionforge_health` Keychain item — retrieve via:
```bash
security find-generic-password -s legionforge_health -a api_key -w
```

## Open priority items (current issue numbers)
- **#24** — auto-generate infrastructure secrets at `make db-init` (removes SSH/Keychain hard dependency). Was previously tracked as #295.
- **#25** — pluggable credential provider (Keychain/LDAP/Kerberos/AD/OIDC). Was previously tracked as #296.
- **#26** — modularize Guardian + Anneal as standalone security primitives, post-v0.8.0. Was previously tracked as #297; see memory `project_strategic_pivot.md` for the sequenced plan already agreed with Jp.
- Untriaged from #29 (per `checkpoint.md`): bandit 99 LOW findings, pytest CVE-2025-71176 bump, semgrep review pass.

## Historical context (pre-2026-03-26, unverified this session)

<details>
<summary>Guardian DB connection / Keychain notes from a prior session — click to expand</summary>

**Root cause (as of 2026-03-21):** `legionforge_guardian` Keychain entry had a null password, causing Guardian to start with an empty `POSTGRES_PASSWORD`, which emptied `_approved_tools` and blocked every tool call with a SECURITY HALT.

**Current state (checked 2026-09-02):** the `legionforge_guardian` Keychain item is not present at all on this machine (`security find-generic-password` returns "item could not be found"), which is a different symptom than "null password." This has not been re-diagnosed — do not assume the old fix still applies. Verify with `make guardian-start` + `curl -s http://localhost:9766/health` before trusting any of this section.

</details>

---

[The full pre-2026-03-26 session log — UAT Day 7 planning, `make preflight` proposal, prior diagnostic work — was removed from this file for length. It is preserved in git history (`git log -p -- NEXT.md`) if needed.]

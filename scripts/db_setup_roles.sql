-- scripts/db_setup_roles.sql
-- ────────────────────────────
-- Standalone SQL reference for the LegionForge 5-role DB privilege model.
-- The framework applies these grants automatically at startup via init_db() →
-- _setup_db_roles(). Use this file for manual cloud/Docker setup, or to
-- audit what privileges each role has.
--
-- Five roles — each with a distinct trust boundary:
--
--   legionforge_worker      BYPASSRLS — broad read/write, no DDL, no DELETE on prunable tables
--   legionforge_gateway     NOBYPASSRLS — RLS-enforced, user-scoped; stream_tokens DELETE only
--   legionforge_maintenance BYPASSRLS — DELETE on prunable tables, ZERO SELECT (exfil-proof)
--   legionforge_guardian    BYPASSRLS — SELECT on security config only; INSERT threat_events
--   legionforge_readonly    BYPASSRLS — SELECT on metrics/health tables only; zero writes
--
-- All roles: NOINHERIT NOCREATEDB NOCREATEROLE NOSUPERUSER
-- Per-role CONNECTION LIMIT and statement_timeout prevent pool starvation + query DOS.
--
-- RLS (Row-Level Security):
--   Enabled on user-scoped tables (tasks, sessions, scheduled_tasks, etc.).
--   legionforge_gateway policy: rows where user_id = app.user_id (session var).
--   All other roles have BYPASSRLS — they are exempt from policy by role attribute.
--
-- Usage (local):
--   make setup-db-roles   — runs init_db() which calls _setup_db_roles() automatically
--
-- Usage (cloud / Docker — manual):
--   PGPASSWORD=<admin_pw> psql -h <host> -U <admin_user> -d legionforge \
--       -f scripts/db_setup_roles.sql
--
-- Note: Passwords are generated and stored in ~/.pgpass + macOS Keychain by init_db().
-- Replace '<ROLE_PASSWORD>' placeholders below before running manually.

-- ── Create roles ──────────────────────────────────────────────────────────────

DO $$ BEGIN IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'legionforge_worker') THEN
    CREATE USER legionforge_worker WITH LOGIN NOINHERIT NOCREATEDB NOCREATEROLE NOSUPERUSER CONNECTION LIMIT 8;
END IF; END $$;
-- ALTER USER legionforge_worker WITH PASSWORD '<ROLE_PASSWORD>';
ALTER ROLE legionforge_worker BYPASSRLS;
ALTER ROLE legionforge_worker SET statement_timeout = '60000ms';

DO $$ BEGIN IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'legionforge_gateway') THEN
    CREATE USER legionforge_gateway WITH LOGIN NOINHERIT NOCREATEDB NOCREATEROLE NOSUPERUSER CONNECTION LIMIT 20;
END IF; END $$;
-- ALTER USER legionforge_gateway WITH PASSWORD '<ROLE_PASSWORD>';
ALTER ROLE legionforge_gateway NOBYPASSRLS;  -- RLS enforced
ALTER ROLE legionforge_gateway SET statement_timeout = '30000ms';

DO $$ BEGIN IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'legionforge_maintenance') THEN
    CREATE USER legionforge_maintenance WITH LOGIN NOINHERIT NOCREATEDB NOCREATEROLE NOSUPERUSER CONNECTION LIMIT 2;
END IF; END $$;
-- ALTER USER legionforge_maintenance WITH PASSWORD '<ROLE_PASSWORD>';
ALTER ROLE legionforge_maintenance BYPASSRLS;
ALTER ROLE legionforge_maintenance SET statement_timeout = '300000ms';  -- prune takes longer

DO $$ BEGIN IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'legionforge_guardian') THEN
    CREATE USER legionforge_guardian WITH LOGIN NOINHERIT NOCREATEDB NOCREATEROLE NOSUPERUSER CONNECTION LIMIT 4;
END IF; END $$;
-- ALTER USER legionforge_guardian WITH PASSWORD '<ROLE_PASSWORD>';
ALTER ROLE legionforge_guardian BYPASSRLS;
ALTER ROLE legionforge_guardian SET statement_timeout = '10000ms';

DO $$ BEGIN IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'legionforge_readonly') THEN
    CREATE USER legionforge_readonly WITH LOGIN NOINHERIT NOCREATEDB NOCREATEROLE NOSUPERUSER CONNECTION LIMIT 10;
END IF; END $$;
-- ALTER USER legionforge_readonly WITH PASSWORD '<ROLE_PASSWORD>';
ALTER ROLE legionforge_readonly BYPASSRLS;
ALTER ROLE legionforge_readonly SET statement_timeout = '10000ms';

-- ── CONNECT + USAGE ───────────────────────────────────────────────────────────

GRANT CONNECT ON DATABASE legionforge TO legionforge_worker, legionforge_gateway,
    legionforge_maintenance, legionforge_guardian, legionforge_readonly;
GRANT USAGE ON SCHEMA public TO legionforge_worker, legionforge_gateway,
    legionforge_maintenance, legionforge_guardian, legionforge_readonly;

-- ── legionforge_worker grants ─────────────────────────────────────────────────

GRANT SELECT ON tasks, sessions, scheduled_tasks, pipelines, pipeline_runs,
    task_notes, task_annotations, task_attachments, task_templates, task_shares,
    webhooks, stream_tokens, user_preferences, gateway_users,
    tool_registry, agent_profiles, threat_rules,
    crystallization_candidates, crystallization_packages, crystallization_analyses,
    task_events, health_metrics, api_usage, documents TO legionforge_worker;
GRANT SELECT, INSERT, UPDATE ON tasks TO legionforge_worker;
GRANT SELECT, INSERT, UPDATE ON api_usage TO legionforge_worker;
GRANT SELECT, INSERT, UPDATE, DELETE ON stream_tokens TO legionforge_worker;
GRANT INSERT ON audit_log, threat_events TO legionforge_worker;
GRANT SELECT, INSERT, UPDATE, DELETE ON checkpoint_migrations, checkpoints,
    checkpoint_blobs, checkpoint_writes TO legionforge_worker;
GRANT USAGE ON ALL SEQUENCES IN SCHEMA public TO legionforge_worker;

-- ── legionforge_gateway grants ────────────────────────────────────────────────
-- Subject to RLS. DELETE only on stream_tokens (SSE expiry cleanup).

GRANT SELECT, INSERT, UPDATE ON tasks, sessions, scheduled_tasks, pipelines,
    pipeline_runs, task_notes, task_annotations, task_attachments, task_templates,
    task_shares, webhooks, user_preferences, gateway_users TO legionforge_gateway;
GRANT SELECT, INSERT, UPDATE, DELETE ON stream_tokens TO legionforge_gateway;
GRANT SELECT ON tool_registry TO legionforge_gateway;
GRANT USAGE ON ALL SEQUENCES IN SCHEMA public TO legionforge_gateway;

-- RLS policies (user_isolation) are created by _setup_rls() in database.py.
-- For manual setup:
-- ALTER TABLE tasks ENABLE ROW LEVEL SECURITY;
-- CREATE POLICY user_isolation ON tasks FOR ALL TO legionforge_gateway
--   USING (current_setting('app.bypass_rls',true)='on'
--          OR current_setting('app.user_id',true)=''
--          OR user_id = current_setting('app.user_id',true))
--   WITH CHECK (same);
-- (Repeat for sessions, scheduled_tasks, pipelines, etc.)

-- ── legionforge_maintenance grants ───────────────────────────────────────────
-- ZERO SELECT — exfiltration-proof. A compromised prune job cannot read data.

GRANT DELETE ON tasks, api_usage, health_metrics, threat_events TO legionforge_maintenance;
GRANT INSERT ON audit_anchors TO legionforge_maintenance;
GRANT USAGE ON ALL SEQUENCES IN SCHEMA public TO legionforge_maintenance;

-- ── legionforge_guardian grants ───────────────────────────────────────────────
-- Security sidecar. No access to user data (tasks, sessions, etc.).

GRANT SELECT ON tool_registry, threat_rules, agent_profiles,
    checkpoint_migrations, checkpoints, checkpoint_blobs, checkpoint_writes
    TO legionforge_guardian;
GRANT INSERT ON threat_events TO legionforge_guardian;
GRANT USAGE ON ALL SEQUENCES IN SCHEMA public TO legionforge_guardian;

-- ── legionforge_readonly grants ───────────────────────────────────────────────
-- Health server + monitoring. Zero writes.

GRANT SELECT ON health_metrics, api_usage, tool_registry, gateway_users,
    threat_events TO legionforge_readonly;

-- ── Verification queries ──────────────────────────────────────────────────────
-- The following should FAIL for legionforge_maintenance (zero SELECT):
--   psql legionforge -U legionforge_maintenance -c "SELECT count(*) FROM tasks;"
--   → 0 rows returned (no permission to read)
--
-- The following should FAIL for legionforge_guardian:
--   psql legionforge -U legionforge_guardian -c "SELECT * FROM tasks LIMIT 1;"
--   → ERROR: permission denied for table tasks
--
-- The following should FAIL for all five roles (no DDL):
--   psql legionforge -U legionforge_worker -c "DROP TABLE tool_registry;"
--   → ERROR: permission denied for table tool_registry

\echo '5-role privilege model applied.'
\echo 'Worker:      broad read/write, BYPASSRLS'
\echo 'Gateway:     user-scoped via RLS (NOBYPASSRLS)'
\echo 'Maintenance: DELETE-only, ZERO SELECT'
\echo 'Guardian:    security config SELECT + threat_events INSERT'
\echo 'Readonly:    metrics/health SELECT only'

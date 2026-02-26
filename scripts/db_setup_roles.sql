-- scripts/db_setup_roles.sql
-- ────────────────────────────
-- Standalone SQL for manual or cloud PostgreSQL role setup.
-- Creates the legionforge_app restricted user with minimal privileges.
--
-- Privilege model:
--   - No DDL (no CREATE TABLE, no DROP, no ALTER)
--   - No DELETE on audit/threat tables (append-only)
--   - INSERT + UPDATE on mutable app tables
--   - Full CRUD on LangGraph checkpoint tables
--   - USAGE on all sequences
--
-- Usage (local):
--   make setup-db-roles
--   # or: psql -U jpc -d legionforge -f scripts/db_setup_roles.sql
--
-- Usage (cloud / Docker):
--   PGPASSWORD=<admin_pw> psql -h <host> -U <admin_user> -d legionforge \
--       -f scripts/db_setup_roles.sql
--
-- Note: Replace '<APP_PASSWORD>' with the actual password before running manually.
-- The 'make setup-db-roles' target generates and stores the password automatically.

-- Create the restricted app user if not exists
DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'legionforge_app') THEN
        CREATE USER legionforge_app WITH LOGIN NOINHERIT;
    END IF;
END
$$;

-- Set password (update this to the actual password — use 'make setup-db-roles' to generate)
-- ALTER USER legionforge_app WITH PASSWORD '<APP_PASSWORD>';

-- Connect on the database
GRANT CONNECT ON DATABASE legionforge TO legionforge_app;

-- Usage on schema
GRANT USAGE ON SCHEMA public TO legionforge_app;

-- SELECT on all tables (read access for agents)
GRANT SELECT ON ALL TABLES IN SCHEMA public TO legionforge_app;

-- Append-only audit tables — INSERT only, no UPDATE/DELETE
GRANT INSERT ON audit_log TO legionforge_app;
GRANT INSERT ON threat_events TO legionforge_app;

-- Mutable app tables — INSERT + UPDATE, no DELETE, no DDL
GRANT INSERT, UPDATE ON api_usage TO legionforge_app;
GRANT INSERT, UPDATE ON health_metrics TO legionforge_app;
GRANT INSERT, UPDATE ON documents TO legionforge_app;
GRANT INSERT, UPDATE ON crystallization_candidates TO legionforge_app;
GRANT INSERT, UPDATE ON crystallization_packages TO legionforge_app;
GRANT INSERT, UPDATE ON crystallization_analyses TO legionforge_app;
GRANT INSERT, UPDATE ON threat_rules TO legionforge_app;
GRANT INSERT, UPDATE ON agent_profiles TO legionforge_app;
GRANT INSERT, UPDATE ON tool_registry TO legionforge_app;

-- LangGraph checkpoint tables — full CRUD required by LangGraph internals
GRANT SELECT, INSERT, UPDATE, DELETE ON checkpoint_migrations TO legionforge_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON checkpoints TO legionforge_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON checkpoint_blobs TO legionforge_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON checkpoint_writes TO legionforge_app;

-- USAGE on all sequences (for BIGSERIAL primary keys)
GRANT USAGE ON ALL SEQUENCES IN SCHEMA public TO legionforge_app;

-- Verify: the following should FAIL for legionforge_app:
--   psql legionforge -U legionforge_app -c "DROP TABLE tool_registry;"
--   → ERROR: permission denied for table tool_registry
--
--   psql legionforge -U legionforge_app -c "DELETE FROM audit_log WHERE seq=1;"
--   → ERROR: permission denied for table audit_log

\echo 'legionforge_app role setup complete.'
\echo 'Test with: psql legionforge -U legionforge_app -c "SELECT count(*) FROM tool_registry;"'

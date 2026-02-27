-- Phase 8 Migration 001: Task queue table
-- Applied by: src/database.py _create_app_tables() (CREATE IF NOT EXISTS — idempotent)

CREATE TABLE IF NOT EXISTS tasks (
    task_id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id         TEXT NOT NULL,
    status          TEXT NOT NULL DEFAULT 'queued'
                        CHECK (status IN ('queued', 'running', 'complete', 'failed', 'cancelled')),
    agent_type      TEXT NOT NULL DEFAULT 'orchestrator'
                        CHECK (agent_type IN ('orchestrator', 'researcher', 'base_agent')),
    input           TEXT NOT NULL,
    result          TEXT,
    error           TEXT,
    config          JSONB NOT NULL DEFAULT '{}',
    run_id          UUID,
    steps           INTEGER,
    tokens          JSONB,
    stream_events   JSONB NOT NULL DEFAULT '[]',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    completed_at    TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_tasks_user_id    ON tasks (user_id);
CREATE INDEX IF NOT EXISTS idx_tasks_status     ON tasks (status);
CREATE INDEX IF NOT EXISTS idx_tasks_created_at ON tasks (created_at DESC);

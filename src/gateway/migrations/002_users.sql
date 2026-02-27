-- Phase 8 Migration 002: Gateway users table
-- Applied by: src/database.py _create_app_tables() (CREATE IF NOT EXISTS — idempotent)
-- User creation: make create-user USERNAME=<name>
-- No self-registration in Phase 8.

CREATE TABLE IF NOT EXISTS gateway_users (
    user_id     UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username    TEXT NOT NULL UNIQUE,
    api_key_hash TEXT NOT NULL UNIQUE,   -- bcrypt hash of the raw API key
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    is_active   BOOLEAN NOT NULL DEFAULT true
);

CREATE INDEX IF NOT EXISTS idx_gateway_users_username ON gateway_users (username);

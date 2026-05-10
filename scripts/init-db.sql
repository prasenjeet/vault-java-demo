-- init-db.sql
-- Creates tables and a Vault root user for dynamic secret generation

-- ── Vault management user ─────────────────────────────────────────────────────
-- Vault uses this account to create/revoke dynamic users
CREATE USER vault_root WITH PASSWORD 'vault_root_password' CREATEROLE;
GRANT ALL PRIVILEGES ON DATABASE mydb TO vault_root;
GRANT ALL PRIVILEGES ON SCHEMA public TO vault_root;

-- Allow vault_root to grant permissions to dynamic users
ALTER DEFAULT PRIVILEGES IN SCHEMA public
    GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO vault_root;
ALTER DEFAULT PRIVILEGES IN SCHEMA public
    GRANT USAGE, SELECT ON SEQUENCES TO vault_root;

-- ── Sample tables ─────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS users (
    id          SERIAL PRIMARY KEY,
    username    VARCHAR(100) NOT NULL UNIQUE,
    email       VARCHAR(255) NOT NULL,
    created_at  TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS orders (
    id          SERIAL PRIMARY KEY,
    user_id     INT REFERENCES users(id),
    amount      NUMERIC(10,2) NOT NULL,
    status      VARCHAR(50) DEFAULT 'pending',
    created_at  TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS audit_log (
    id          SERIAL PRIMARY KEY,
    event       TEXT NOT NULL,
    actor       TEXT,
    created_at  TIMESTAMPTZ DEFAULT NOW()
);

-- ── Grant existing objects to vault_root ──────────────────────────────────────
GRANT ALL PRIVILEGES ON ALL TABLES    IN SCHEMA public TO vault_root;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO vault_root;

-- ── Sample data ───────────────────────────────────────────────────────────────
INSERT INTO users (username, email) VALUES
    ('alice', 'alice@example.com'),
    ('bob',   'bob@example.com'),
    ('carol', 'carol@example.com')
ON CONFLICT DO NOTHING;

INSERT INTO orders (user_id, amount, status) VALUES
    (1, 1500.00, 'completed'),
    (1,  350.50, 'pending'),
    (2, 2200.75, 'completed')
ON CONFLICT DO NOTHING;

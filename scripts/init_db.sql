-- scripts/init_db.sql
-- Run: psql -U pnads -d pnads -f scripts/init_db.sql

CREATE TABLE IF NOT EXISTS assets (
    id             SERIAL PRIMARY KEY,
    mac            VARCHAR(17) UNIQUE NOT NULL,   -- format: AA:BB:CC:DD:EE:FF
    ip             VARCHAR(45),                    -- hỗ trợ IPv4 và IPv6
    hostname       TEXT,
    vendor         TEXT,
    os_guess       TEXT,
    os_confidence  REAL NOT NULL DEFAULT 0,        -- 0.0 - 1.0
    discovered_via TEXT[] NOT NULL DEFAULT '{}',   -- ['arp','dhcp','mdns','ssdp','dns','http']
    first_seen     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    is_active      BOOLEAN NOT NULL DEFAULT TRUE,
    is_trusted     BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE TABLE IF NOT EXISTS events (
    id         SERIAL PRIMARY KEY,
    asset_id   INT NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    event_type VARCHAR(32) NOT NULL,
    -- 'new_asset' | 'ip_change' | 'arp_announce' | 'arp_probe'
    -- 'dhcp_discover' | 'dhcp_request' | 'dhcp_ack'
    -- 'mdns_announce' | 'ssdp_notify' | 'dns_query'
    -- 'asset_gone'
    protocol   VARCHAR(16) NOT NULL DEFAULT 'unknown',
    old_value  TEXT,
    new_value  TEXT,
    detail     JSONB NOT NULL DEFAULT '{}',
    ts         TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS watchlist (
    id         SERIAL PRIMARY KEY,
    mac        VARCHAR(17),
    ip         VARCHAR(45),
    label      TEXT NOT NULL,
    note       TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CHECK (mac IS NOT NULL OR ip IS NOT NULL)
);

CREATE TABLE IF NOT EXISTS alerts (
    id           SERIAL PRIMARY KEY,
    asset_id     INT REFERENCES assets(id) ON DELETE CASCADE,
    rule_type    VARCHAR(32) NOT NULL,   -- 'watchlist_match' | 'new_device' | 'arp_spoofing'
    severity     VARCHAR(16) NOT NULL DEFAULT 'medium',  -- low | medium | high
    message      TEXT NOT NULL,
    detail       JSONB NOT NULL DEFAULT '{}',
    acknowledged BOOLEAN NOT NULL DEFAULT FALSE,
    ts           TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_assets_mac      ON assets(mac);
CREATE INDEX IF NOT EXISTS idx_assets_ip       ON assets(ip);
CREATE INDEX IF NOT EXISTS idx_events_asset_id ON events(asset_id);
CREATE INDEX IF NOT EXISTS idx_events_ts       ON events(ts);
CREATE INDEX IF NOT EXISTS idx_events_type     ON events(event_type);
CREATE INDEX IF NOT EXISTS idx_watchlist_mac   ON watchlist(mac);
CREATE INDEX IF NOT EXISTS idx_watchlist_ip    ON watchlist(ip);
CREATE INDEX IF NOT EXISTS idx_alerts_ts       ON alerts(ts);
CREATE INDEX IF NOT EXISTS idx_alerts_type     ON alerts(rule_type);

CREATE OR REPLACE VIEW asset_summary AS
SELECT a.*, COUNT(e.id) AS event_count
FROM assets a
LEFT JOIN events e ON e.asset_id = a.id
GROUP BY a.id;

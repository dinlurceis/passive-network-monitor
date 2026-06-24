-- scripts/init_db.sql
-- Run: psql -U netmon -d netmon -f scripts/init_db.sql

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

CREATE TABLE IF NOT EXISTS assets (
    id          SERIAL PRIMARY KEY,
    mac         VARCHAR(17) UNIQUE NOT NULL,   -- format: AA:BB:CC:DD:EE:FF
    ip          VARCHAR(15),                    -- last known IP
    hostname    TEXT,
    vendor      TEXT,
    os_guess    TEXT,
    first_seen  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    is_active   BOOLEAN NOT NULL DEFAULT TRUE,
    metadata    JSONB NOT NULL DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS events (
    id          SERIAL PRIMARY KEY,
    asset_id    INT NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    event_type  VARCHAR(32) NOT NULL,
    -- event_type values:
    -- 'new_asset'     : asset chưa từng thấy
    -- 'ip_change'     : MAC giữ nguyên nhưng IP thay đổi
    -- 'arp_announce'  : ARP gratuitous
    -- 'arp_probe'     : ARP probe (ip=0.0.0.0)
    -- 'dhcp_discover' : DHCP discover
    -- 'dhcp_request'  : DHCP request
    -- 'dhcp_ack'      : DHCP ack (server phân phối IP)
    -- 'asset_gone'    : không còn thấy sau timeout
    old_value   TEXT,
    new_value   TEXT,
    detail      JSONB NOT NULL DEFAULT '{}',
    ts          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_assets_mac       ON assets(mac);
CREATE INDEX IF NOT EXISTS idx_assets_ip        ON assets(ip);
CREATE INDEX IF NOT EXISTS idx_events_asset_id  ON events(asset_id);
CREATE INDEX IF NOT EXISTS idx_events_ts        ON events(ts);
CREATE INDEX IF NOT EXISTS idx_events_type      ON events(event_type);

-- View tiện để query
CREATE OR REPLACE VIEW asset_summary AS
SELECT
    a.id,
    a.mac,
    a.ip,
    a.hostname,
    a.vendor,
    a.os_guess,
    a.first_seen,
    a.last_seen,
    a.is_active,
    COUNT(e.id) AS event_count
FROM assets a
LEFT JOIN events e ON e.asset_id = a.id
GROUP BY a.id;

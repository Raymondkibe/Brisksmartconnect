-- ════════════════════════════════════════════════════════════════
--  BRISK Smart Connect — Migration 002: Network / Connect Features
--  Adds: access_points, pppoe_users, connection_incidents
--  Safe to run multiple times (IF NOT EXISTS everywhere).
--  Run this against the SAME database referenced by DATABASE_URL.
-- ════════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS access_points (
  id              SERIAL PRIMARY KEY,
  owner_id        INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  router_id       INTEGER REFERENCES routers(id) ON DELETE SET NULL,
  name            VARCHAR(120) NOT NULL,
  brand           VARCHAR(40)  DEFAULT 'mikrotik',   -- mikrotik | omada | unifi | openwrt | other
  model           VARCHAR(80),
  ip              VARCHAR(45)  NOT NULL,
  location        VARCHAR(120),
  ssid            VARCHAR(64),
  status          VARCHAR(20)  DEFAULT 'offline',     -- online | offline | warning
  connected_users INTEGER      DEFAULT 0,
  bandwidth_mbps  NUMERIC      DEFAULT 0,
  signal_dbm      INTEGER,
  uptime          VARCHAR(40),
  last_seen       TIMESTAMPTZ,
  created_at      TIMESTAMPTZ  DEFAULT NOW(),
  updated_at      TIMESTAMPTZ  DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_aps_owner ON access_points(owner_id);
CREATE INDEX IF NOT EXISTS idx_aps_router ON access_points(router_id);

CREATE TABLE IF NOT EXISTS pppoe_users (
  id              SERIAL PRIMARY KEY,
  owner_id        INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  router_id       INTEGER REFERENCES routers(id) ON DELETE SET NULL,
  username        VARCHAR(80) NOT NULL,
  password_hash   VARCHAR(255) NOT NULL,
  service_type    VARCHAR(20) DEFAULT 'client',        -- client | server | brisk_managed | external
  speed_profile   VARCHAR(40),
  ip_address      VARCHAR(45),
  status          VARCHAR(20) DEFAULT 'inactive',       -- active | inactive | expired | disconnected
  expires_at      TIMESTAMPTZ,
  session_started TIMESTAMPTZ,
  created_at      TIMESTAMPTZ DEFAULT NOW(),
  UNIQUE(router_id, username)
);
CREATE INDEX IF NOT EXISTS idx_pppoe_owner ON pppoe_users(owner_id);

CREATE TABLE IF NOT EXISTS connection_incidents (
  id           SERIAL PRIMARY KEY,
  owner_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  device_type  VARCHAR(20) NOT NULL,      -- router | access_point
  device_id    INTEGER NOT NULL,
  event        VARCHAR(20) NOT NULL,      -- offline | online | warning
  detected_at  TIMESTAMPTZ DEFAULT NOW(),
  resolved_at  TIMESTAMPTZ,
  notified     BOOLEAN DEFAULT FALSE
);
CREATE INDEX IF NOT EXISTS idx_incidents_owner ON connection_incidents(owner_id);

-- Versioned config templates BRISK generates for the Connect wizard.
-- Kept in DB (not hardcoded) so templates can be updated without a deploy.
CREATE TABLE IF NOT EXISTS connection_templates (
  id            SERIAL PRIMARY KEY,
  device_type   VARCHAR(30) NOT NULL,     -- mikrotik_hotspot | mikrotik_pppoe | mikrotik_ap | omada | unifi | openwrt
  routeros_ver  VARCHAR(10) DEFAULT '7',
  method        VARCHAR(20) NOT NULL,     -- local | vpn | wireguard | api | rest_api
  title         VARCHAR(120) NOT NULL,
  script_body   TEXT NOT NULL,            -- template with {{PLACEHOLDERS}}
  created_at    TIMESTAMPTZ DEFAULT NOW()
);

INSERT INTO connection_templates(device_type, method, title, script_body)
SELECT * FROM (VALUES
  ('mikrotik_hotspot','local','MikroTik RouterOS 7 — Hotspot (Local Network)',
   '/ip hotspot profile add name=brisk-profile hotspot-address={{ROUTER_IP}} dns-name=connect.brisk
/ip hotspot add name=brisk-hotspot interface={{INTERFACE}} profile=brisk-profile address-pool=brisk-pool
/ip pool add name=brisk-pool ranges=192.168.88.10-192.168.88.254
/ip hotspot user add name={{API_USER}} password={{API_PASSWORD}}
/ip service set api port={{API_PORT}} disabled=no
/ip service set api-ssl disabled=yes'),
  ('mikrotik_pppoe','local','MikroTik RouterOS 7 — PPPoE Server (BRISK billing)',
   '/interface pppoe-server server add service-name=brisk-pppoe interface={{INTERFACE}} default-profile=brisk-pppoe-profile
/ppp profile add name=brisk-pppoe-profile local-address=10.10.0.1 remote-address=brisk-pppoe-pool
/ip pool add name=brisk-pppoe-pool ranges=10.10.0.2-10.10.0.254
/ip service set api port={{API_PORT}} disabled=no'),
  ('mikrotik_api','api','MikroTik RouterOS 7 — API Only (existing hotspot)',
   '/user add name={{API_USER}} password={{API_PASSWORD}} group=full
/ip service set api port={{API_PORT}} disabled=no
/ip firewall filter add chain=input protocol=tcp dst-port={{API_PORT}} src-address={{BRISK_SERVER_IP}} action=accept
/ip firewall filter add chain=input protocol=tcp dst-port={{API_PORT}} action=drop'),
  ('mikrotik_wireguard','wireguard','MikroTik RouterOS 7 — WireGuard to BRISK (no public IP needed)',
   '/interface wireguard add name=brisk-wg listen-port=13231 private-key="{{WG_PRIVATE_KEY}}"
/interface wireguard peers add interface=brisk-wg public-key="{{BRISK_WG_PUBLIC_KEY}}" endpoint-address={{BRISK_SERVER_IP}} endpoint-port=13231 allowed-address=10.20.0.0/24
/ip address add address=10.20.0.2/24 interface=brisk-wg
/ip service set api port={{API_PORT}} disabled=no')
) AS v(device_type, method, title, script_body)
WHERE NOT EXISTS (SELECT 1 FROM connection_templates);

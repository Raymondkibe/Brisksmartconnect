'use strict';
const { createClient } = require('@supabase/supabase-js');

let supabaseClient = null;
let currentConfig = {
  url: process.env.SUPABASE_URL || '',
  key: process.env.SUPABASE_SERVICE_ROLE_KEY || process.env.SUPABASE_KEY || process.env.SUPABASE_ANON_KEY || ''
};

function initSupabase(url, key) {
  const targetUrl = (url || currentConfig.url || '').trim();
  const targetKey = (key || currentConfig.key || '').trim();

  if (!targetUrl || !targetKey) {
    supabaseClient = null;
    return null;
  }

  try {
    supabaseClient = createClient(targetUrl, targetKey, {
      auth: {
        persistSession: false,
        autoRefreshToken: false
      }
    });
    currentConfig = { url: targetUrl, key: targetKey };
    console.log('✅ Supabase client initialized:', targetUrl);
    return supabaseClient;
  } catch (err) {
    console.warn('⚠️ Supabase client initialization failed:', err.message);
    supabaseClient = null;
    return null;
  }
}

// Auto-initialize on module load if environment variables exist
if (currentConfig.url && currentConfig.key) {
  initSupabase(currentConfig.url, currentConfig.key);
}

function getSupabase() {
  if (!supabaseClient && currentConfig.url && currentConfig.key) {
    return initSupabase(currentConfig.url, currentConfig.key);
  }
  return supabaseClient;
}

function isConfigured() {
  return !!(currentConfig.url && currentConfig.key);
}

async function testConnection() {
  const client = getSupabase();
  if (!client) {
    return {
      connected: false,
      message: 'Supabase URL or Key is not configured yet. Set SUPABASE_URL and SUPABASE_ANON_KEY (or SUPABASE_SERVICE_ROLE_KEY).'
    };
  }

  try {
    // Attempt to query packages or auth or a public table
    const { data, error } = await client.from('packages').select('id, name').limit(1);
    if (error) {
      if (error.code === '42P01') {
        // Table does not exist yet
        return {
          connected: true,
          tablesReady: false,
          message: 'Connected to Supabase! The packages table does not exist yet. Please run the schema SQL script in your Supabase SQL Editor.'
        };
      }
      return { connected: false, message: 'Supabase error: ' + error.message };
    }
    return {
      connected: true,
      tablesReady: true,
      message: 'Successfully connected to live Supabase database!',
      sampleCount: data ? data.length : 0
    };
  } catch (err) {
    return { connected: false, message: 'Connection error: ' + err.message };
  }
}

const SCHEMA_SQL = `-- ═════════════════════════════════════════════════════════════════
-- BRISK Smart Connect — Live Supabase PostgreSQL Schema
-- Run this in your Supabase Dashboard: SQL Editor -> New Query -> Run
-- ═════════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS users (
  id BIGSERIAL PRIMARY KEY,
  name TEXT NOT NULL,
  phone TEXT,
  email TEXT,
  password_hash TEXT NOT NULL,
  role TEXT DEFAULT 'customer',
  status TEXT DEFAULT 'active',
  national_id TEXT,
  avatar TEXT,
  referral_code TEXT UNIQUE,
  referred_by BIGINT,
  wallet_balance NUMERIC DEFAULT 0,
  two_fa_secret TEXT,
  two_fa_enabled BOOLEAN DEFAULT FALSE,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS packages (
  id BIGSERIAL PRIMARY KEY,
  name TEXT NOT NULL,
  price NUMERIC DEFAULT 0,
  duration TEXT,
  duration_mins INT DEFAULT 0,
  speed TEXT,
  data_limit_mb INT DEFAULT 0,
  description TEXT,
  is_free BOOLEAN DEFAULT FALSE,
  active BOOLEAN DEFAULT TRUE,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS routers (
  id BIGSERIAL PRIMARY KEY,
  owner_id BIGINT REFERENCES users(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  brand TEXT DEFAULT 'mikrotik',
  model TEXT,
  ip TEXT NOT NULL,
  port TEXT DEFAULT '8728',
  username TEXT,
  password_hash TEXT,
  password_encrypted TEXT,
  connection_type TEXT DEFAULT 'direct',
  isp TEXT,
  business_name TEXT,
  location TEXT,
  is_main BOOLEAN DEFAULT FALSE,
  is_ap BOOLEAN DEFAULT FALSE,
  parent_router_id BIGINT,
  vpn_config TEXT,
  status TEXT DEFAULT 'online',
  connected_users INT DEFAULT 0,
  cpu_load INT DEFAULT 0,
  memory_used INT DEFAULT 0,
  bandwidth_download INT DEFAULT 0,
  bandwidth_upload INT DEFAULT 0,
  temperature INT DEFAULT 0,
  uptime TEXT,
  firmware TEXT,
  last_seen TIMESTAMPTZ,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS vouchers (
  id BIGSERIAL PRIMARY KEY,
  owner_id BIGINT REFERENCES users(id) ON DELETE CASCADE,
  package_id BIGINT REFERENCES packages(id),
  code TEXT UNIQUE NOT NULL,
  batch_id TEXT,
  status TEXT DEFAULT 'unused',
  used_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS sessions (
  id BIGSERIAL PRIMARY KEY,
  user_id BIGINT REFERENCES users(id),
  router_id BIGINT,
  package_id BIGINT,
  package_name TEXT,
  duration_mins INT DEFAULT 0,
  mac TEXT,
  ip TEXT,
  device_name TEXT,
  started_at TIMESTAMPTZ DEFAULT NOW(),
  expires_at TIMESTAMPTZ,
  status TEXT DEFAULT 'active'
);

CREATE TABLE IF NOT EXISTS payments (
  id BIGSERIAL PRIMARY KEY,
  user_id BIGINT REFERENCES users(id),
  package_id BIGINT,
  amount NUMERIC,
  phone TEXT,
  mpesa_code TEXT UNIQUE,
  checkout_id TEXT,
  status TEXT DEFAULT 'pending',
  router_id BIGINT,
  package_name TEXT,
  voucher_qty INT DEFAULT 1,
  purpose TEXT DEFAULT 'package',
  via_owner_id BIGINT,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS subscription_plans (
  id BIGSERIAL PRIMARY KEY,
  name TEXT NOT NULL,
  price NUMERIC NOT NULL DEFAULT 0,
  duration_days INT DEFAULT 30,
  max_routers INT DEFAULT 5,
  max_access_points INT DEFAULT 10,
  max_vouchers_per_month INT DEFAULT 1000,
  features JSONB DEFAULT '[]'::jsonb,
  active BOOLEAN DEFAULT TRUE,
  sort_order INT DEFAULT 0,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS owner_subscriptions (
  id BIGSERIAL PRIMARY KEY,
  owner_id BIGINT UNIQUE NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  plan_id BIGINT REFERENCES subscription_plans(id),
  status TEXT DEFAULT 'trial',
  trial_started_at TIMESTAMPTZ DEFAULT NOW(),
  trial_ends_at TIMESTAMPTZ,
  started_at TIMESTAMPTZ,
  expires_at TIMESTAMPTZ,
  auto_renew BOOLEAN DEFAULT FALSE,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS notifications (
  id BIGSERIAL PRIMARY KEY,
  user_id BIGINT REFERENCES users(id),
  type TEXT,
  title TEXT,
  message TEXT NOT NULL,
  read BOOLEAN DEFAULT FALSE,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS router_logs (
  id BIGSERIAL PRIMARY KEY,
  router_id BIGINT,
  event TEXT,
  details TEXT,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Seed Starter Packages
INSERT INTO packages (name, price, duration, duration_mins, speed, description, is_free, active)
VALUES
  ('FREE 3-Day Starter', 0, '3 Days', 4320, '5 Mbps', 'Welcome package — one time for new users', true, true),
  ('1 Hour Express', 20, '1 Hour', 60, '5 Mbps', 'Quick browsing session', false, true),
  ('3 Hours', 50, '3 Hours', 180, '5 Mbps', 'Work sessions and streaming', false, true),
  ('6 Hours Half-Day', 80, '6 Hours', 360, '10 Mbps', 'Half-day heavy usage', false, true),
  ('24 Hours Day Pass', 150, '24 Hours', 1440, '10 Mbps', 'Full day internet access', false, true),
  ('7 Days Weekly', 500, '7 Days', 10080, '15 Mbps', 'Most popular weekly plan', false, true),
  ('14 Days Bi-Weekly', 900, '14 Days', 20160, '15 Mbps', 'Two-week internet', false, true),
  ('30 Days Basic', 1500, '30 Days', 43200, '20 Mbps', 'Monthly basic plan', false, true),
  ('30 Days Premium', 2500, '30 Days', 43200, '50 Mbps', 'Premium monthly — fastest speeds', false, true)
ON CONFLICT DO NOTHING;

-- Seed Subscription Plans
INSERT INTO subscription_plans (name, price, duration_days, max_routers, max_access_points, max_vouchers_per_month, features, sort_order)
VALUES
  ('Starter', 400, 30, 2, 3, 200, '["2 routers","3 access points","Basic support"]'::jsonb, 1),
  ('Basic', 750, 30, 5, 8, 500, '["5 routers","8 access points","Email support"]'::jsonb, 2),
  ('Standard', 1500, 30, 15, 25, 2000, '["15 routers","25 access points","Priority support","API access"]'::jsonb, 3),
  ('Professional', 2500, 30, 40, 60, 10000, '["40 routers","60 access points","Priority support","API access","Advanced reports"]'::jsonb, 4),
  ('Business', 3500, 30, 999999, 999999, 999999, '["Unlimited routers","Unlimited APs","Dedicated support","Full API access","Advanced reports"]'::jsonb, 5)
ON CONFLICT DO NOTHING;
`;

module.exports = {
  initSupabase,
  getSupabase,
  isConfigured,
  testConnection,
  getConfig: () => ({ url: currentConfig.url, hasKey: !!currentConfig.key }),
  SCHEMA_SQL
};

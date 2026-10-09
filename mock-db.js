'use strict';
const bcrypt = require('bcryptjs');
const supabase = require('./supabase');

function createInMemoryDb() {
  const tables = {
    users: [],
    packages: [],
    subscription_plans: [],
    owner_subscriptions: [],
    owner_integrations: [],
    subscription_payments: [],
    routers: [],
    router_logs: [],
    router_stats: [],
    vpn_connections: [],
    sessions: [],
    payments: [],
    transactions: [],
    referrals: [],
    notifications: [],
    devices: [],
    support_tickets: [],
    withdrawals: [],
    installation_requests: [],
    technicians: [],
    announcements: [],
    contacts: [],
    network_alerts: [],
    api_keys: [],
    templates: [],
    hosting_plans: [],
    vouchers: [],
    wifi_hosts: [],
    wifi_host_sales: []
  };

  const autoInc = {};
  for (const k of Object.keys(tables)) autoInc[k] = 1;

  function nextId(table) {
    autoInc[table] = (autoInc[table] || 0) + 1;
    return autoInc[table];
  }

  // Pre-seed super admin
  const adminHash = bcrypt.hashSync('Admin@2025!', 10);
  tables.users.push({
    id: 1,
    name: 'Super Admin',
    phone: '0712883849',
    email: 'admin@brisksmartconnect.com',
    password_hash: adminHash,
    role: 'admin',
    status: 'active',
    national_id: '12345678',
    referral_code: 'BSC-000001',
    wallet_balance: 5000,
    created_at: new Date()
  });
  autoInc.users = 2;

  // Pre-seed default packages
  const defaultPkgs = [
    { id: 1, name: 'FREE 3-Day Starter', price: 0, duration: '3 Days', duration_mins: 4320, speed: '5 Mbps', description: 'Welcome package — one time for new users', is_free: true, active: true, created_at: new Date() },
    { id: 2, name: '1 Hour Express', price: 20, duration: '1 Hour', duration_mins: 60, speed: '5 Mbps', description: 'Quick browsing session', is_free: false, active: true, created_at: new Date() },
    { id: 3, name: '3 Hours', price: 50, duration: '3 Hours', duration_mins: 180, speed: '5 Mbps', description: 'Work sessions and streaming', is_free: false, active: true, created_at: new Date() },
    { id: 4, name: '6 Hours Half-Day', price: 80, duration: '6 Hours', duration_mins: 360, speed: '10 Mbps', description: 'Half-day heavy usage', is_free: false, active: true, created_at: new Date() },
    { id: 5, name: '24 Hours Day Pass', price: 150, duration: '24 Hours', duration_mins: 1440, speed: '10 Mbps', description: 'Full day internet access', is_free: false, active: true, created_at: new Date() },
    { id: 6, name: '7 Days Weekly', price: 500, duration: '7 Days', duration_mins: 10080, speed: '15 Mbps', description: 'Most popular weekly plan', is_free: false, active: true, created_at: new Date() },
    { id: 7, name: '14 Days Bi-Weekly', price: 900, duration: '14 Days', duration_mins: 20160, speed: '15 Mbps', description: 'Two-week internet', is_free: false, active: true, created_at: new Date() },
    { id: 8, name: '30 Days Basic', price: 1500, duration: '30 Days', duration_mins: 43200, speed: '20 Mbps', description: 'Monthly basic plan', is_free: false, active: true, created_at: new Date() },
    { id: 9, name: '30 Days Premium', price: 2500, duration: '30 Days', duration_mins: 43200, speed: '50 Mbps', description: 'Premium monthly — fastest speeds', is_free: false, active: true, created_at: new Date() }
  ];
  tables.packages.push(...defaultPkgs);
  autoInc.packages = 10;

  // Pre-seed default subscription plans
  const defaultPlans = [
    { id: 1, name: 'Starter', price: 400, duration_days: 30, max_routers: 2, max_access_points: 3, max_vouchers_per_month: 200, features: ['2 routers','3 access points','Basic support'], sort_order: 1, active: true, created_at: new Date() },
    { id: 2, name: 'Basic', price: 750, duration_days: 30, max_routers: 5, max_access_points: 8, max_vouchers_per_month: 500, features: ['5 routers','8 access points','Email support'], sort_order: 2, active: true, created_at: new Date() },
    { id: 3, name: 'Standard', price: 1500, duration_days: 30, max_routers: 15, max_access_points: 25, max_vouchers_per_month: 2000, features: ['15 routers','25 access points','Priority support','API access'], sort_order: 3, active: true, created_at: new Date() },
    { id: 4, name: 'Professional', price: 2500, duration_days: 30, max_routers: 40, max_access_points: 60, max_vouchers_per_month: 10000, features: ['40 routers','60 access points','Priority support','API access','Advanced reports'], sort_order: 4, active: true, created_at: new Date() },
    { id: 5, name: 'Business', price: 3500, duration_days: 30, max_routers: 999999, max_access_points: 999999, max_vouchers_per_month: 999999, features: ['Unlimited routers','Unlimited APs','Dedicated support','Full API access','Advanced reports'], sort_order: 5, active: true, created_at: new Date() }
  ];
  tables.subscription_plans.push(...defaultPlans);
  autoInc.subscription_plans = 6;

  // Pre-seed sample routers
  tables.routers.push(
    { id: 1, owner_id: 1, name: 'Kiambu Main MikroTik', brand: 'mikrotik', model: 'RB4011iGS+', ip: '192.168.88.1', port: '8728', username: 'admin', connection_type: 'direct', isp: 'Safaricom Fibre', business_name: 'BRISK Smart Connect', location: 'Kiambu Town', is_main: true, is_ap: false, status: 'online', connected_users: 34, cpu_load: 18, memory_used: 42, bandwidth_download: 45, bandwidth_upload: 12, temperature: 41, uptime: '14d 8h 22m', firmware: 'RouterOS 7.14', last_seen: new Date(), created_at: new Date() },
    { id: 2, owner_id: 1, name: 'Ndumberi Market AP', brand: 'mikrotik', model: 'cAP ac', ip: '192.168.88.10', port: '8728', username: 'admin', connection_type: 'direct', isp: 'BRISK P2P', business_name: 'BRISK Ndumberi', location: 'Ndumberi', is_main: false, is_ap: true, parent_router_id: 1, status: 'online', connected_users: 18, cpu_load: 12, memory_used: 35, bandwidth_download: 22, bandwidth_upload: 6, temperature: 38, uptime: '8d 3h 11m', firmware: 'RouterOS 7.14', last_seen: new Date(), created_at: new Date() }
  );
  autoInc.routers = 3;

  // Pre-seed sample vouchers
  tables.vouchers.push(
    { id: 1, owner_id: 1, package_id: 2, code: 'BSC-1H-882194', batch_id: 'batch_01', status: 'unused', created_at: new Date() },
    { id: 2, owner_id: 1, package_id: 5, code: 'BSC-24H-391048', batch_id: 'batch_01', status: 'unused', created_at: new Date() },
    { id: 3, owner_id: 1, package_id: 6, code: 'BSC-7D-910283', batch_id: 'batch_01', status: 'used', used_at: new Date(), created_at: new Date() }
  );
  autoInc.vouchers = 4;

  async function query(sql, params = []) {
    const s = sql.trim().replace(/\s+/g, ' ');
    const upper = s.toUpperCase();

    // 1. DDL: CREATE / ALTER / DROP
    if (upper.startsWith('CREATE TABLE') || upper.startsWith('ALTER TABLE') || upper.startsWith('DROP TABLE')) {
      const match = s.match(/CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?([a-zA-Z0-9_]+)/i);
      if (match) {
        const t = match[1].toLowerCase();
        if (!tables[t]) {
          tables[t] = [];
          autoInc[t] = 1;
        }
      }
      return { rows: [], rowCount: 0 };
    }

    // 2. COUNT queries
    if (upper.includes('COUNT(')) {
      const fromMatch = s.match(/FROM\s+([a-zA-Z0-9_]+)/i);
      const tableName = fromMatch ? fromMatch[1].toLowerCase() : '';
      const list = tables[tableName] || [];
      const usedCount = list.filter(x => x.status === 'used').length;
      const unusedCount = list.filter(x => x.status === 'unused').length;
      return {
        rows: [{
          count: String(list.length),
          total: String(list.length),
          cnt: String(list.length),
          used: String(usedCount),
          unused: String(unusedCount),
          owners: '1',
          value: '15000',
          earned: '0'
        }],
        rowCount: 1
      };
    }

    // 3. INSERT INTO
    if (upper.startsWith('INSERT INTO')) {
      const match = s.match(/INSERT\s+INTO\s+([a-zA-Z0-9_]+)\s*\(([^)]+)\)\s*VALUES/i);
      if (match) {
        const table = match[1].toLowerCase();
        tables[table] = tables[table] || [];
        const cols = match[2].split(',').map(c => c.trim().toLowerCase());
        const newRow = { id: nextId(table), created_at: new Date(), status: 'active' };
        cols.forEach((col, idx) => {
          if (params && params[idx] !== undefined) {
            newRow[col] = params[idx];
          }
        });
        tables[table].push(newRow);
        const supa = supabase.getSupabase();
        if (supa) {
          supa.from(table).insert([newRow]).then(({ error }) => {
            if (error) console.warn(`Supabase sync insert into [${table}] notice:`, error.message);
            else console.log(`✓ Row synced to Supabase [${table}]:`, newRow.id);
          }).catch(() => {});
        }
        return { rows: [newRow], rowCount: 1 };
      }
      return { rows: [{ id: 1 }], rowCount: 1 };
    }

    // 4. UPDATE
    if (upper.startsWith('UPDATE')) {
      const tableMatch = s.match(/UPDATE\s+([a-zA-Z0-9_]+)/i);
      const table = tableMatch ? tableMatch[1].toLowerCase() : '';
      const list = tables[table] || [];
      const updated = [];

      // Determine matching rows
      for (const row of list) {
        let matches = true;
        if (s.includes('WHERE id=$') || s.includes('WHERE id = $')) {
          const idVal = params[params.length - 1];
          if (row.id !== idVal) matches = false;
        } else if (s.includes('WHERE code=$') || s.includes('WHERE code = $')) {
          const codeVal = params[0];
          if (row.code !== codeVal) matches = false;
        }
        if (matches) {
          if (s.includes('status=')) {
            const sm = s.match(/status\s*=\s*'([^']+)'/i);
            if (sm) row.status = sm[1];
          }
          if (s.includes('referral_code=$1') && params[0]) row.referral_code = params[0];
          if (s.includes('password_hash=$1') && params[0]) row.password_hash = params[0];
          if (s.includes('active=false')) row.active = false;
          updated.push(row);
          const supa = supabase.getSupabase();
          if (supa && row.id) {
            supa.from(table).update(row).eq('id', row.id).catch(() => {});
          }
        }
      }
      return { rows: updated, rowCount: updated.length };
    }

    // 5. DELETE
    if (upper.startsWith('DELETE FROM')) {
      const tableMatch = s.match(/DELETE\s+FROM\s+([a-zA-Z0-9_]+)/i);
      const table = tableMatch ? tableMatch[1].toLowerCase() : '';
      if (tables[table] && !upper.includes('WHERE')) {
        tables[table] = [];
      }
      return { rows: [], rowCount: 0 };
    }

    // 6. SELECT
    const fromMatch = s.match(/FROM\s+([a-zA-Z0-9_]+)/i);
    const tableName = fromMatch ? fromMatch[1].toLowerCase() : '';
    let list = tables[tableName] || [];

    // Filter by query conditions
    if (tableName === 'users') {
      if (s.includes('phone=$1 OR email=$') || s.includes('phone=$1 OR email=$1')) {
        const p = params[0];
        list = list.filter(u => u.phone === p || u.email === p);
      } else if (s.includes('id=$1') || s.includes('id = $1')) {
        list = list.filter(u => u.id === params[0]);
      } else if (s.includes("role='admin'")) {
        list = list.filter(u => u.role === 'admin');
      }
    } else if (tableName === 'packages') {
      if (s.includes('id=$1') || s.includes('id = $1')) {
        list = list.filter(p => p.id === Number(params[0]));
      } else if (s.includes('active=true')) {
        list = list.filter(p => p.active !== false);
      }
      if (s.includes('ORDER BY price ASC')) {
        list = [...list].sort((a, b) => (Number(a.price) || 0) - (Number(b.price) || 0));
      }
    } else if (tableName === 'subscription_plans') {
      if (s.includes('active=true')) {
        list = list.filter(p => p.active !== false);
      }
      if (s.includes('ORDER BY price ASC')) {
        list = [...list].sort((a, b) => (Number(a.price) || 0) - (Number(b.price) || 0));
      }
    } else if (tableName === 'routers') {
      if (s.includes('owner_id=$1')) {
        list = list.filter(r => r.owner_id === params[0] || r.owner_id === 1);
      } else if (s.includes('id=$1')) {
        list = list.filter(r => r.id === Number(params[0]));
      }
    } else if (tableName === 'vouchers') {
      if (s.includes('code=$1')) {
        list = list.filter(v => v.code === String(params[0]).trim().toUpperCase());
      } else if (s.includes('owner_id=$1')) {
        list = list.filter(v => v.owner_id === params[0]);
      }
      // Populate package_name
      list = list.map(v => {
        const pkg = tables.packages.find(p => p.id === v.package_id);
        return {
          ...v,
          package_name: pkg?.name || 'WiFi Package',
          duration_mins: pkg?.duration_mins || 60,
          price: pkg?.price || 0
        };
      });
    } else if (tableName === 'owner_subscriptions') {
      if (s.includes('owner_id=$1')) {
        list = list.filter(sub => sub.owner_id === params[0]);
      }
    } else if (tableName === 'owner_integrations') {
      if (s.includes('owner_id=$1')) {
        list = list.filter(i => i.owner_id === params[0]);
      }
    } else if (tableName === 'sessions') {
      if (s.includes('user_id=$1')) {
        list = list.filter(sess => sess.user_id === params[0]);
      }
    }

    if (s.includes('LIMIT 1')) {
      list = list.slice(0, 1);
    }

    return { rows: [...list], rowCount: list.length };
  }

  return {
    query,
    connect: async () => ({ query, release: () => {} }),
    on: () => {},
    isMock: true
  };
}

function createDb(Pool, connectionString) {
  const mockDb = createInMemoryDb();

  if (!connectionString) {
    console.log('ℹ️  No DATABASE_URL configured — running with in-memory database');
    return mockDb;
  }

  let realPool;
  try {
    realPool = new Pool({
      connectionString,
      ssl: { rejectUnauthorized: false },
      max: 3,
      idleTimeoutMillis: 10000,
      connectionTimeoutMillis: 3000
    });
  } catch (err) {
    console.warn('⚠️  Could not create PostgreSQL Pool, using in-memory database:', err.message);
    return mockDb;
  }

  let fallbackActive = false;

  const dbProxy = {
    async query(sql, params) {
      if (fallbackActive) {
        return mockDb.query(sql, params);
      }
      try {
        return await realPool.query(sql, params);
      } catch (err) {
        if (err.code === 'ECONNREFUSED' || err.code === 'ETIMEDOUT' || err.message.includes('connect')) {
          if (!fallbackActive) {
            console.warn('⚠️  PostgreSQL connection failed (' + err.message + ') — switching to in-memory database fallback');
            fallbackActive = true;
          }
          return mockDb.query(sql, params);
        }
        throw err;
      }
    },
    async connect() {
      if (fallbackActive) return mockDb.connect();
      try {
        return await realPool.connect();
      } catch {
        fallbackActive = true;
        return mockDb.connect();
      }
    },
    on: (...args) => {
      try { realPool.on(...args); } catch {}
    }
  };

  return dbProxy;
}

module.exports = { createDb, createInMemoryDb };

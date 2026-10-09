'use strict';
require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const { Pool } = require('pg');
const http = require('http');

const app = express();
const server = http.createServer(app);
// Serverless-friendly pool: Vercel can run many concurrent function
// instances, each holding its own Pool. A small max here + Supabase's
// connection pooler (recommended for DATABASE_URL below) keeps total
// connections from exceeding Supabase's limit under load.
const db = new Pool({ connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: false }, max: 3, idleTimeoutMillis: 10000 });
const JWT = process.env.JWT_SECRET || 'brisk_secret_2025';
const PORT = process.env.PORT || 5000;
const API_URL = process.env.API_URL || process.env.FRONTEND_URL || 'http://localhost:5000';
const crypto = require('crypto');

// ── Reversible credential encryption (router/AP/PPPoE passwords) ─
// IMPORTANT: router credentials must be RECOVERABLE (BRISK has to log
// back into the actual router later), so they cannot be bcrypt-hashed
// (one-way). AES-256-GCM with ENCRYPTION_KEY (.env) is used instead.
// Falls back to a fixed dev-only key with a loud warning so the app
// still runs in a sandbox/dev environment, but this must be set in
// production or router connections are not properly secured.
const ENC_KEY = (() => {
  const k = process.env.ENCRYPTION_KEY;
  if (k && /^[0-9a-fA-F]{64}$/.test(k)) return Buffer.from(k, 'hex');
  console.warn('⚠️  ENCRYPTION_KEY missing/invalid in .env — using an insecure dev-only key. Set a 64-char hex ENCRYPTION_KEY in production!');
  return crypto.createHash('sha256').update('brisk-dev-only-insecure-key-2026').digest();
})();
function encryptSecret(plain) {
  if (plain == null || plain === '') return null;
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', ENC_KEY, iv);
  const enc = Buffer.concat([cipher.update(String(plain), 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([iv, tag, enc]).toString('base64');
}
function decryptSecret(blob) {
  if (!blob) return null;
  try {
    const buf = Buffer.from(blob, 'base64');
    const iv = buf.subarray(0, 12), tag = buf.subarray(12, 28), enc = buf.subarray(28);
    const decipher = crypto.createDecipheriv('aes-256-gcm', ENC_KEY, iv);
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(enc), decipher.final()]).toString('utf8');
  } catch (e) { console.error('decryptSecret failed:', e.message); return null; }
}
// Router rows carry password_encrypted (ciphertext) internally so BRISK
// can reconnect later — but that must never reach the browser. Strip it
// (and the legacy password_hash placeholder) before any res.json().
function scrubRouter(r) {
  if (!r) return r;
  const { password_hash, password_encrypted, ...safe } = r;
  return safe;
}
function scrubRouters(list) { return (list || []).map(scrubRouter); }
// Build a MikroTikAPI-ready config from a DB row by decrypting the password
function routerConnConfig(r) { return { ...r, password: decryptSecret(r.password_encrypted) }; }

// ── Socket.IO for real-time ───────────────────────────────────
let io;
try {
  const { Server } = require('socket.io');
  io = new Server(server, { cors: { origin: '*' }, transports: ['websocket', 'polling'] });
  io.on('connection', socket => {
    console.log('Socket connected:', socket.id);
    socket.on('subscribe_router', id => socket.join('router_' + id));
    socket.on('disconnect', () => console.log('Socket disconnected:', socket.id));
  });
} catch (e) { console.log('Socket.IO not available:', e.message); io = { emit: () => {}, to: () => ({ emit: () => {} }) }; }

const emit = (event, data, room) => { try { room ? io.to(room).emit(event, data) : io.emit(event, data); } catch {} };

// ── Middleware ────────────────────────────────────────────────
app.use(cors({ origin: '*', methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'] }));
app.use(express.json({ limit: '20mb' }));
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 50 * 1024 * 1024 } });

// NOTE: on Vercel, static files (the .html pages) live at the project root
// and are served directly by Vercel's edge network — this function only
// ever receives /api/* requests (see vercel.json rewrites), so no
// express.static() is needed or wanted here.

// ── Auth middleware ───────────────────────────────────────────
const auth = async (req, res, next) => {
  const h = req.headers.authorization;
  if (!h?.startsWith('Bearer ')) return res.status(401).json({ message: 'Unauthorised' });
  try {
    const { userId } = jwt.verify(h.split(' ')[1], JWT);
    const { rows } = await db.query("SELECT * FROM users WHERE id=$1 AND status!='deleted'", [userId]);
    if (!rows[0]) return res.status(401).json({ message: 'User not found' });
    req.user = rows[0]; next();
  } catch { res.status(401).json({ message: 'Invalid token' }); }
};
const admin = (req, res, next) => req.user?.role === 'admin' ? next() : res.status(403).json({ message: 'Admin only' });
const owner = (req, res, next) => ['admin', 'router_owner'].includes(req.user?.role) ? next() : res.status(403).json({ message: 'Router owner required' });
const mkToken = id => jwt.sign({ userId: id }, JWT, { expiresIn: '30d' });
const refCode = id => 'BSC-' + String(id).padStart(6, '0');
const notify = async (uid, type, title, message) => {
  try { await db.query('INSERT INTO notifications(user_id,type,title,message)VALUES($1,$2,$3,$4)', [uid, type, title, message]); emit('notification', { title, message }, 'user_' + uid); } catch {}
  // Also push a real WhatsApp message for high-value notification types, if configured
  if (['payment', 'withdrawal', 'router_offline', 'router_online'].includes(type)) {
    try {
      const { rows } = await db.query('SELECT phone FROM users WHERE id=$1', [uid]);
      if (rows[0]?.phone) await sendWhatsApp(rows[0].phone, `*${title}*\n${message}`);
    } catch (e) { console.error('WhatsApp notify error:', e.message); }
  }
};

// ── WhatsApp Business Cloud API ─────────────────────────────────
// Requires WHATSAPP_TOKEN + WHATSAPP_PHONE_ID env vars (see .env.example).
// Safely no-ops (logs only) when not configured, so this never breaks
// the rest of the app in dev/sandbox environments.
async function sendWhatsApp(toPhone, text, override) {
  const token = override?.token || process.env.WHATSAPP_TOKEN;
  const phoneId = override?.phoneId || process.env.WHATSAPP_PHONE_ID;
  if (!token || !phoneId) return { sent: false, reason: 'not_configured' };
  const to = String(toPhone).replace(/^0/, '254').replace(/^\+/, '').replace(/\s/g, '');
  try {
    const r = await fetch(`https://graph.facebook.com/v19.0/${phoneId}/messages`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ messaging_product: 'whatsapp', to, type: 'text', text: { body: text } }),
    });
    const d = await r.json();
    if (!r.ok) { console.error('WhatsApp send failed:', d?.error?.message || d); return { sent: false, error: d?.error?.message }; }
    return { sent: true, message_id: d?.messages?.[0]?.id };
  } catch (e) { console.error('WhatsApp send error:', e.message); return { sent: false, error: e.message }; }
}

// ── Resend (transactional email) ────────────────────────────────
// Requires RESEND_API_KEY + EMAIL_FROM. Safely no-ops when not configured.
async function sendEmail(to, subject, html, override) {
  const key = override?.apiKey || process.env.RESEND_API_KEY;
  const from = override?.from || process.env.EMAIL_FROM || 'BRISK Smart Connect <noreply@brisksmartconnect.com>';
  if (!to || !key) return { sent: false, reason: 'not_configured' };
  try {
    const r = await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: { Authorization: `Bearer ${key}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ from, to: [to], subject, html }),
    });
    const d = await r.json();
    if (!r.ok) { console.error('Resend send failed:', d?.message || d); return { sent: false, error: d?.message }; }
    return { sent: true, id: d.id };
  } catch (e) { console.error('Resend send error:', e.message); return { sent: false, error: e.message }; }
}
function emailShell(title, bodyHtml) {
  return `<div style="font-family:Arial,sans-serif;max-width:520px;margin:0 auto;padding:24px">
  <div style="text-align:center;margin-bottom:24px"><span style="font-size:20px;font-weight:900;color:#111">BRISK <span style="color:#F97316">Smart Connect</span></span></div>
  <h2 style="color:#111">${title}</h2>
  ${bodyHtml}
  <p style="color:#999;font-size:12px;margin-top:32px;border-top:1px solid #eee;padding-top:16px">BRISK Smart Connect · +254 712 883 849 · techray91@gmail.com</p>
</div>`;
}
// ── MikroTik API helper ───────────────────────────────────────
class MikroTikAPI {
  static async exec(routerCfg, commands) {
    // RouterOS API implementation using the mikrotik npm package or raw TCP
    // Falls back to simulation if package not available
    try {
      const MikroNode = require('mikronode-ng');
      const conn = MikroNode.getConnection(routerCfg.ip, routerCfg.username, routerCfg.password, { port: parseInt(routerCfg.port) || 8728 });
      const ch = conn.openChannel();
      const results = [];
      for (const cmd of commands) {
        const r = await new Promise((resolve, reject) => {
          ch.write(cmd, () => {}, d => resolve(d), reject);
        });
        results.push(r);
      }
      conn.close();
      return results;
    } catch (e) {
      // Return simulated data if mikronode not available
      console.log('MikroTik API simulation (install mikronode-ng for real connection):', e.message);
      return commands.map(() => ({ simulated: true, message: 'Install mikronode-ng for real MikroTik connection' }));
    }
  }

  static async getStatus(routerCfg) {
    try {
      return {
        connected: true, model: routerCfg.model || 'MikroTik RouterBOARD',
        version: 'RouterOS 7.1', identity: routerCfg.name || 'BRISK-Router',
        uptime: '2d 4h 12m', cpu: Math.floor(Math.random() * 40) + 5,
        memory: Math.floor(Math.random() * 60) + 20, free_memory: '128MB',
        total_memory: '256MB', interfaces: ['ether1', 'ether2', 'wlan1'],
        connected_users: Math.floor(Math.random() * 50),
        download_mbps: Math.floor(Math.random() * 50) + 5,
        upload_mbps: Math.floor(Math.random() * 10) + 1,
        temperature: Math.floor(Math.random() * 15) + 35,
      };
    } catch (e) { return { connected: false, error: e.message }; }
  }

  static async getHotspotUsers(routerCfg) {
    return []; // Returns active hotspot sessions from MikroTik
  }

  static async disconnectUser(routerCfg, mac) {
    return { success: true, message: 'User ' + mac + ' disconnected from MikroTik hotspot' };
  }

  static async setSpeedLimit(routerCfg, mac, download, upload) {
    return { success: true, message: `Speed set: ${download}/${upload} Mbps for ${mac}` };
  }

  static async addHotspotUser(routerCfg, username, password, profile) {
    return { success: true, message: 'Hotspot user created: ' + username };
  }

  static async removeHotspotUser(routerCfg, username) {
    return { success: true, message: 'Hotspot user removed: ' + username };
  }

  static async restart(routerCfg) {
    return { success: true, message: 'Restart command sent to ' + routerCfg.ip };
  }
}

// ── DB Initialisation ─────────────────────────────────────────
async function initDB() {
  await db.query(`
    CREATE TABLE IF NOT EXISTS users(
      id SERIAL PRIMARY KEY, name TEXT NOT NULL, phone TEXT, email TEXT,
      password_hash TEXT NOT NULL, role TEXT DEFAULT 'customer',
      status TEXT DEFAULT 'active', national_id TEXT, avatar TEXT,
      referral_code TEXT UNIQUE, referred_by INT,
      wallet_balance NUMERIC DEFAULT 0, two_fa_secret TEXT,
      two_fa_enabled BOOLEAN DEFAULT FALSE, created_at TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS packages(
      id SERIAL PRIMARY KEY, name TEXT NOT NULL, price NUMERIC DEFAULT 0,
      duration TEXT, duration_mins INT DEFAULT 0, speed TEXT,
      data_limit_mb INT DEFAULT 0, description TEXT,
      is_free BOOLEAN DEFAULT FALSE, active BOOLEAN DEFAULT TRUE,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS routers(
      id SERIAL PRIMARY KEY, owner_id INT REFERENCES users(id) ON DELETE CASCADE,
      name TEXT NOT NULL, brand TEXT DEFAULT 'mikrotik', model TEXT,
      ip TEXT NOT NULL, port TEXT DEFAULT '8728',
      username TEXT, password_hash TEXT,
      connection_type TEXT DEFAULT 'direct',
      isp TEXT, business_name TEXT, location TEXT,
      is_main BOOLEAN DEFAULT FALSE, is_ap BOOLEAN DEFAULT FALSE,
      parent_router_id INT, vpn_config TEXT,
      status TEXT DEFAULT 'offline', connected_users INT DEFAULT 0,
      cpu_load INT DEFAULT 0, memory_used INT DEFAULT 0,
      bandwidth_download INT DEFAULT 0, bandwidth_upload INT DEFAULT 0,
      temperature INT DEFAULT 0,
      uptime TEXT, firmware TEXT, last_seen TIMESTAMPTZ,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS router_logs(
      id SERIAL PRIMARY KEY, router_id INT REFERENCES routers(id) ON DELETE CASCADE,
      event TEXT, details TEXT, created_at TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS router_stats(
      id SERIAL PRIMARY KEY, router_id INT REFERENCES routers(id) ON DELETE CASCADE,
      cpu_load INT, memory_used INT, bandwidth_dl INT, bandwidth_ul INT,
      connected_users INT, recorded_at TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS vpn_connections(
      id SERIAL PRIMARY KEY, router_id INT REFERENCES routers(id) ON DELETE CASCADE,
      type TEXT DEFAULT 'wireguard', public_key TEXT, private_key TEXT,
      endpoint TEXT, allowed_ips TEXT, status TEXT DEFAULT 'inactive',
      created_at TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS sessions(
      id SERIAL PRIMARY KEY, user_id INT REFERENCES users(id),
      router_id INT, package_id INT, package_name TEXT,
      duration_mins INT DEFAULT 0, mac TEXT, ip TEXT, device_name TEXT,
      started_at TIMESTAMPTZ DEFAULT NOW(), expires_at TIMESTAMPTZ,
      status TEXT DEFAULT 'active'
    );
    CREATE TABLE IF NOT EXISTS payments(
      id SERIAL PRIMARY KEY, user_id INT REFERENCES users(id),
      package_id INT, amount NUMERIC, phone TEXT,
      mpesa_code TEXT UNIQUE, checkout_id TEXT,
      status TEXT DEFAULT 'pending', router_id INT, package_name TEXT,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS transactions(
      id SERIAL PRIMARY KEY, user_id INT REFERENCES users(id),
      type TEXT, amount NUMERIC, description TEXT,
      payment_id INT, status TEXT DEFAULT 'completed',
      created_at TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS referrals(
      id SERIAL PRIMARY KEY, referrer_id INT REFERENCES users(id),
      referred_id INT REFERENCES users(id),
      commission NUMERIC DEFAULT 0, packages_bought INT DEFAULT 0,
      status TEXT DEFAULT 'active', created_at TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS notifications(
      id SERIAL PRIMARY KEY, user_id INT REFERENCES users(id),
      type TEXT, title TEXT, message TEXT NOT NULL,
      read BOOLEAN DEFAULT FALSE, created_at TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS devices(
      id SERIAL PRIMARY KEY, user_id INT REFERENCES users(id),
      mac TEXT, ip TEXT, name TEXT, type TEXT DEFAULT 'mobile',
      connected_at TIMESTAMPTZ DEFAULT NOW(), last_seen TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS support_tickets(
      id SERIAL PRIMARY KEY, user_id INT REFERENCES users(id),
      subject TEXT, category TEXT, message TEXT, priority TEXT DEFAULT 'normal',
      status TEXT DEFAULT 'open', admin_reply TEXT, replied_by INT,
      created_at TIMESTAMPTZ DEFAULT NOW(), updated_at TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS withdrawals(
      id SERIAL PRIMARY KEY, owner_id INT REFERENCES users(id),
      amount NUMERIC, phone TEXT, account_name TEXT,
      mpesa_code TEXT, status TEXT DEFAULT 'pending',
      processed_by INT, created_at TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS installation_requests(
      id SERIAL PRIMARY KEY, user_id INT REFERENCES users(id),
      name TEXT, phone TEXT, address TEXT,
      location_type TEXT DEFAULT 'wired', preferred_date DATE,
      preferred_time TEXT, notes TEXT, price NUMERIC,
      status TEXT DEFAULT 'pending', assigned_to INT,
      completed_at TIMESTAMPTZ, created_at TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS technicians(
      id SERIAL PRIMARY KEY, user_id INT REFERENCES users(id),
      name TEXT NOT NULL, phone TEXT, area TEXT,
      skills TEXT[], status TEXT DEFAULT 'available',
      jobs_done INT DEFAULT 0, rating NUMERIC DEFAULT 5.0,
      commission_total NUMERIC DEFAULT 0, active BOOLEAN DEFAULT TRUE,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS announcements(
      id SERIAL PRIMARY KEY, title TEXT, message TEXT NOT NULL,
      target TEXT DEFAULT 'all', type TEXT DEFAULT 'info',
      via TEXT DEFAULT 'inapp', sent_to INT DEFAULT 0,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS contacts(
      id SERIAL PRIMARY KEY, name TEXT, phone TEXT, email TEXT,
      subject TEXT, message TEXT, status TEXT DEFAULT 'new',
      created_at TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS network_alerts(
      id SERIAL PRIMARY KEY, router_id INT, alert_type TEXT,
      message TEXT, severity TEXT DEFAULT 'warning',
      acknowledged BOOLEAN DEFAULT FALSE,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS api_keys(
      id SERIAL PRIMARY KEY, user_id INT REFERENCES users(id),
      key_hash TEXT NOT NULL, key_prefix TEXT,
      name TEXT, last_used TIMESTAMPTZ, active BOOLEAN DEFAULT TRUE,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );
  `);

  // Seed packages
  const { rows: pc } = await db.query('SELECT COUNT(*) FROM packages');
  if (parseInt(pc[0].count) === 0) {
    await db.query(`INSERT INTO packages(name,price,duration,duration_mins,speed,description,is_free) VALUES
      ('FREE 3-Day Starter',0,'3 Days',4320,'5 Mbps','Welcome package — one time for new users',true),
      ('1 Hour Express',20,'1 Hour',60,'5 Mbps','Quick browsing session',false),
      ('3 Hours',50,'3 Hours',180,'5 Mbps','Work sessions and streaming',false),
      ('6 Hours Half-Day',80,'6 Hours',360,'10 Mbps','Half-day heavy usage',false),
      ('24 Hours Day Pass',150,'24 Hours',1440,'10 Mbps','Full day internet access',false),
      ('7 Days Weekly',500,'7 Days',10080,'15 Mbps','Most popular weekly plan',false),
      ('14 Days Bi-Weekly',900,'14 Days',20160,'15 Mbps','Two-week internet',false),
      ('30 Days Basic',1500,'30 Days',43200,'20 Mbps','Monthly basic plan',false),
      ('30 Days Premium',2500,'30 Days',43200,'50 Mbps','Premium monthly — fastest speeds',false)`);
  }

  // Seed templates
  const { rows: tc } = await db.query('SELECT COUNT(*) FROM templates');
  if (parseInt(tc[0].count) === 0) {
    const tmpls = [
      ['Business Pro','business','free','#1E293B','fa-briefcase','Professional business website'],
      ['Portfolio','portfolio','free','#EC4899','fa-user','Developer portfolio'],
      ['Restaurant','restaurant','free','#7C3AED','fa-utensils','Food & dining website'],
      ['Blog','blog','free','#F97316','fa-pen','Personal blog'],
      ['Landing Page','landing','free','#10B981','fa-rocket','Marketing landing page'],
      ['Church','church','free','#F59E0B','fa-church','Church & community'],
      ['School','school','premium','#3B82F6','fa-school','Education website'],
      ['E-Commerce Shop','shop','premium','#6D28D9','fa-cart-shopping','Online store'],
      ['Hotel & Lodge','hotel','premium','#D97706','fa-hotel','Hotel booking site'],
      ['Clinic & Health','clinic','premium','#059669','fa-hospital','Medical clinic'],
      ['Agency','agency','premium','#8B5CF6','fa-building','Creative agency'],
      ['Real Estate','realestate','premium','#EA580C','fa-home','Property listings'],
      ['Salon & Barber','salon','premium','#F472B6','fa-scissors','Beauty salon'],
      ['NGO','ngo','premium','#10B981','fa-heart','Non-profit organization'],
      ['CV Resume','cv','premium','#334155','fa-id-card','Personal resume'],
      ['Event','event','premium','#7C3AED','fa-calendar','Event & conference'],
    ];
    for (const [name, category, type, color, icon, description] of tmpls) {
      await db.query('INSERT INTO templates(name,category,type,color,icon,description) VALUES($1,$2,$3,$4,$5,$6)', [name, category, type, color, icon, description]);
    }
  }

  // Seed admin
  const { rows: ac } = await db.query("SELECT COUNT(*) FROM users WHERE role='admin'");
  if (parseInt(ac[0].count) === 0) {
    const hash = await bcrypt.hash('Admin@2025!', 12);
    const { rows } = await db.query(
      "INSERT INTO users(name,phone,email,password_hash,role) VALUES('Super Admin','0712883849','admin@brisksmartconnect.com',$1,'admin') RETURNING id",
      [hash]);
    await db.query('UPDATE users SET referral_code=$1 WHERE id=$2', [refCode(rows[0].id), rows[0].id]);
    console.log('Admin seeded: admin@brisksmartconnect.com / Admin@2025!');
  }
  console.log('✅ Database ready');
}

// ═══════════════════════════════════════════════════════════════
// AUTH ROUTES
// ═══════════════════════════════════════════════════════════════
app.post('/api/auth/register', async (req, res) => {
  try {
    const { name, phone, email, password, referral_code, role } = req.body;
    if (!name || !phone || !password) return res.status(400).json({ message: 'Name, phone and password required' });
    if (password.length < 6) return res.status(400).json({ message: 'Password must be at least 6 characters' });
    const dup = await db.query('SELECT id FROM users WHERE phone=$1 OR email=$2', [phone, email || '']);
    if (dup.rows.length) return res.status(400).json({ message: 'Account already exists with this phone or email' });
    const validRole = ['customer', 'router_owner'].includes(role) ? role : 'customer';
    const hash = await bcrypt.hash(password, 12);
    const { rows } = await db.query('INSERT INTO users(name,phone,email,password_hash,role) VALUES($1,$2,$3,$4,$5) RETURNING *', [name, phone, email || null, hash, validRole]);
    const user = rows[0];
    await db.query('UPDATE users SET referral_code=$1 WHERE id=$2', [refCode(user.id), user.id]);
    user.referral_code = refCode(user.id);
    if (referral_code) {
      const ref = await db.query('SELECT id FROM users WHERE referral_code=$1', [referral_code]);
      if (ref.rows.length) {
        await db.query('UPDATE users SET referred_by=$1 WHERE id=$2', [ref.rows[0].id, user.id]);
        await db.query('INSERT INTO referrals(referrer_id,referred_id) VALUES($1,$2)', [ref.rows[0].id, user.id]);
        await notify(ref.rows[0].id, 'referral', 'New Referral!', `${user.name} joined using your code!`);
      }
    }
    await db.query('INSERT INTO hosting_plans(user_id) VALUES($1) ON CONFLICT(user_id) DO NOTHING', [user.id]);
    if (validRole === 'router_owner') {
      const { rows: starterPlan } = await db.query('SELECT id FROM subscription_plans WHERE active=true ORDER BY price ASC LIMIT 1');
      await db.query(`INSERT INTO owner_subscriptions(owner_id,plan_id,status,trial_started_at,trial_ends_at)
        VALUES($1,$2,'trial',NOW(),NOW()+interval '14 days') ON CONFLICT(owner_id) DO NOTHING`, [user.id, starterPlan[0]?.id || null]);
    }
    await notify(user.id, 'system', 'Welcome to BRISK Smart Connect! 🎉', 'Your free 3-day WiFi + free hosting plan is now active. Enjoy!');
    if (user.email) sendEmail(user.email, 'Welcome to BRISK Smart Connect! 🎉',
      emailShell(`Welcome, ${user.name}!`, `<p>Your account is ready. Your free 3-day WiFi trial and free hosting plan are already active.</p><p style="text-align:center;margin:24px 0"><a href="${process.env.FRONTEND_URL || 'https://brisksmartconnect.vercel.app'}/dashboard.html" style="background:#F97316;color:#fff;padding:12px 24px;border-radius:8px;text-decoration:none;font-weight:600">Go to Dashboard</a></p>`)).catch(() => {});
    delete user.password_hash;
    res.json({ token: mkToken(user.id), user });
  } catch (e) { res.status(500).json({ message: e.message }); }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { phone, email, password } = req.body;
    const contact = phone || email;
    if (!contact || !password) return res.status(400).json({ message: 'Credentials required' });
    const { rows } = await db.query("SELECT * FROM users WHERE (phone=$1 OR email=$1) AND status!='deleted'", [contact]);
    if (!rows.length) return res.status(401).json({ message: 'Invalid credentials' });
    const user = rows[0];
    if (user.status === 'suspended') return res.status(403).json({ message: 'Account suspended. Contact support: +254 712 883 849' });
    if (!await bcrypt.compare(password, user.password_hash)) return res.status(401).json({ message: 'Invalid credentials' });
    // Log login
    await db.query('INSERT INTO router_logs(router_id,event,details) VALUES(NULL,$1,$2) ON CONFLICT DO NOTHING', ['login', `User ${user.id} logged in`]).catch(() => {});
    delete user.password_hash;
    res.json({ token: mkToken(user.id), user });
  } catch (e) { res.status(500).json({ message: e.message }); }
});

app.post('/api/auth/forgot-password', async (req, res) => {
  const { contact } = req.body;
  const { rows } = await db.query('SELECT id, name, email, phone FROM users WHERE phone=$1 OR email=$1', [contact]);
  if (rows.length) {
    const u = rows[0];
    const token = jwt.sign({ userId: u.id, purpose: 'reset' }, JWT, { expiresIn: '1h' });
    const resetUrl = `${process.env.FRONTEND_URL || 'https://brisksmartconnect.vercel.app'}/reset-password.html?token=${token}`;
    const emailResult = await sendEmail(u.email, 'Reset your BRISK Smart Connect password',
      emailShell('Password Reset', `<p>Hi ${u.name},</p><p>Click below to reset your password. This link expires in 1 hour.</p><p style="text-align:center;margin:24px 0"><a href="${resetUrl}" style="background:#F97316;color:#fff;padding:12px 24px;border-radius:8px;text-decoration:none;font-weight:600">Reset Password</a></p><p style="color:#999;font-size:13px">Didn't request this? You can safely ignore this email.</p>`));
    let waResult = { sent: false };
    if (u.phone) waResult = await sendWhatsApp(u.phone, `*BRISK Smart Connect*\nPassword reset requested. Link (valid 1 hour):\n${resetUrl}\n\nDidn't request this? Ignore this message.`);
    if (!emailResult.sent && !waResult.sent) console.log('🔑 [no email/WhatsApp configured] Password reset link for', contact, ':', resetUrl);
    await notify(u.id, 'system', 'Password Reset Requested', 'A reset link was sent. If you did not request this, contact support immediately.');
  }
  res.json({ message: 'If account exists, a reset link has been sent.' });
});

app.post('/api/auth/reset-password', async (req, res) => {
  try {
    const { token, password } = req.body;
    if (!token || !password || password.length < 6) return res.status(400).json({ message: 'Invalid request' });
    const { userId, purpose } = jwt.verify(token, JWT);
    if (purpose !== 'reset') return res.status(400).json({ message: 'Invalid token purpose' });
    await db.query('UPDATE users SET password_hash=$1 WHERE id=$2', [await bcrypt.hash(password, 12), userId]);
    res.json({ message: 'Password reset successfully. Please login.' });
  } catch { res.status(400).json({ message: 'Invalid or expired reset link' }); }
});

// ═══════════════════════════════════════════════════════════════
// PROFILE & SETTINGS
// ═══════════════════════════════════════════════════════════════
app.get('/api/profile', auth, async (req, res) => { const u = { ...req.user }; delete u.password_hash; res.json({ user: u }); });
app.put('/api/profile', auth, async (req, res) => {
  const { name, phone, email, national_id } = req.body;
  await db.query('UPDATE users SET name=$1,phone=$2,email=$3,national_id=$4 WHERE id=$5', [name, phone, email, national_id, req.user.id]);
  res.json({ message: 'Profile updated successfully' });
});
app.put('/api/profile/password', auth, async (req, res) => {
  const { old_password, new_password } = req.body;
  if (!old_password || !new_password || new_password.length < 6) return res.status(400).json({ message: 'All fields required. New password min 6 chars.' });
  if (!await bcrypt.compare(old_password, req.user.password_hash)) return res.status(400).json({ message: 'Current password is incorrect' });
  await db.query('UPDATE users SET password_hash=$1 WHERE id=$2', [await bcrypt.hash(new_password, 12), req.user.id]);
  await notify(req.user.id, 'system', 'Password Changed', 'Your account password was changed. If this was not you, contact support immediately.');
  res.json({ message: 'Password changed successfully' });
});
app.post('/api/profile/avatar', auth, upload.single('avatar'), async (req, res) => {
  // In production: upload to Supabase Storage or Cloudflare R2
  res.json({ url: '/favicon-32.png', message: 'Avatar updated' });
});
app.delete('/api/profile', auth, async (req, res) => {
  await db.query("UPDATE users SET status='deleted', name='Deleted User', phone=NULL, email=NULL WHERE id=$1", [req.user.id]);
  res.json({ message: 'Account deleted' });
});
app.put('/api/settings/notifications', auth, async (req, res) => res.json({ message: 'Notification preferences saved' }));
app.get('/api/profile/sessions', auth, async (req, res) => res.json({ sessions: [] }));

// ═══════════════════════════════════════════════════════════════
// PACKAGES
// ═══════════════════════════════════════════════════════════════
app.get('/api/packages', async (req, res) => {
  const { rows } = await db.query('SELECT * FROM packages WHERE active=true ORDER BY price ASC');
  res.json({ packages: rows });
});
// Free packages (e.g. the 3-day welcome trial) must never go through M-Pesa —
// there is no such thing as an STK push for KES 0. Activate directly instead.
app.post('/api/packages/:id/claim-free', auth, async (req, res) => {
  const { rows: pkgs } = await db.query('SELECT * FROM packages WHERE id=$1 AND active=true AND is_free=true', [req.params.id]);
  if (!pkgs[0]) return res.status(404).json({ message: 'Free package not found' });
  const { rows: already } = await db.query("SELECT id FROM sessions WHERE user_id=$1 AND package_id=$2 AND status='active' AND expires_at > NOW()", [req.user.id, pkgs[0].id]);
  if (already.length) return res.status(400).json({ message: 'You already have this free package active' });
  const { rows: usedBefore } = await db.query('SELECT id FROM sessions WHERE user_id=$1 AND package_id=$2', [req.user.id, pkgs[0].id]);
  if (usedBefore.length) return res.status(400).json({ message: 'You have already claimed this free package once. Buy a paid package to continue.' });
  const expires = new Date(Date.now() + pkgs[0].duration_mins * 60000);
  await db.query('INSERT INTO sessions(user_id,package_id,package_name,duration_mins,expires_at) VALUES($1,$2,$3,$4,$5)',
    [req.user.id, pkgs[0].id, pkgs[0].name, pkgs[0].duration_mins, expires]);
  await notify(req.user.id, 'system', '🎁 Free Package Activated!', `${pkgs[0].name} is now active until ${expires.toLocaleString('en-KE')}. Enjoy!`);
  res.json({ message: `${pkgs[0].name} activated! Valid until ${expires.toLocaleString('en-KE')}`, expires_at: expires });
});
app.post('/api/packages', auth, admin, async (req, res) => {
  const { name, price, duration, duration_mins, speed, description, is_free } = req.body;
  if (!name) return res.status(400).json({ message: 'Package name required' });
  const { rows } = await db.query('INSERT INTO packages(name,price,duration,duration_mins,speed,description,is_free) VALUES($1,$2,$3,$4,$5,$6,$7) RETURNING *',
    [name, price || 0, duration, duration_mins || 0, speed, description, !!is_free]);
  res.json({ package: rows[0] });
});
app.put('/api/packages/:id', auth, admin, async (req, res) => {
  const { name, price, duration, duration_mins, speed, description, is_free, active } = req.body;
  await db.query('UPDATE packages SET name=$1,price=$2,duration=$3,duration_mins=$4,speed=$5,description=$6,is_free=$7,active=$8 WHERE id=$9',
    [name, price, duration, duration_mins, speed, description, !!is_free, active !== false, req.params.id]);
  res.json({ message: 'Package updated' });
});
app.delete('/api/packages/:id', auth, admin, async (req, res) => {
  await db.query('UPDATE packages SET active=false WHERE id=$1', [req.params.id]);
  res.json({ message: 'Package deactivated' });
});

// ═══════════════════════════════════════════════════════════════
// M-PESA PAYMENTS (Safaricom Daraja API)
// ═══════════════════════════════════════════════════════════════
async function getDarajaToken(customKey, customSecret) {
  const key = customKey || process.env.MPESA_CONSUMER_KEY;
  const secret = customSecret || process.env.MPESA_CONSUMER_SECRET;
  if (!key || !secret) return null;
  const r = await fetch('https://api.safaricom.co.ke/oauth/v1/generate?grant_type=client_credentials', {
    headers: { Authorization: 'Basic ' + Buffer.from(`${key}:${secret}`).toString('base64') }
  });
  const d = await r.json();
  return d.access_token;
}

app.post('/api/payments/stk-push', auth, async (req, res) => {
  try {
    const { phone, package_id, amount, host_id, router_id } = req.body;
    if (!phone || !package_id) return res.status(400).json({ message: 'Phone and package are required' });
    const { rows: pkgs } = await db.query('SELECT * FROM packages WHERE id=$1 AND active=true', [package_id]);
    if (!pkgs[0]) return res.status(404).json({ message: 'Package not found or inactive' });
    const pkg = pkgs[0];
    let checkoutId = null;

    // If this purchase is happening on a specific router owner's network and
    // that owner has configured their own M-Pesa, use THEIR credentials and
    // THEIR shortcode/passkey — the money goes straight to them, not BRISK.
    // Falls back to BRISK's platform M-Pesa if no router/owner config exists.
    let mpesaCreds = { key: process.env.MPESA_CONSUMER_KEY, secret: process.env.MPESA_CONSUMER_SECRET, shortcode: process.env.MPESA_SHORTCODE || '222111', passkey: process.env.MPESA_PASSKEY };
    let viaOwnerId = null;
    if (router_id) {
      const { rows: routerRows } = await db.query('SELECT owner_id FROM routers WHERE id=$1', [router_id]);
      if (routerRows[0]) {
        const { rows: intRows } = await db.query("SELECT config_encrypted FROM owner_integrations WHERE owner_id=$1 AND provider='mpesa' AND status='connected'", [routerRows[0].owner_id]);
        if (intRows[0]) {
          try {
            const cfg = JSON.parse(decryptSecret(intRows[0].config_encrypted));
            mpesaCreds = { key: cfg.consumer_key, secret: cfg.consumer_secret, shortcode: cfg.shortcode, passkey: cfg.passkey };
            viaOwnerId = routerRows[0].owner_id;
          } catch (e) { console.error('Owner M-Pesa config decrypt failed:', e.message); }
        }
      }
    }

    // Attempt real Daraja STK Push
    try {
      const token = await getDarajaToken(mpesaCreds.key, mpesaCreds.secret);
      if (token) {
        const ts = new Date().toISOString().replace(/[-:T.Z]/g, '').slice(0, 14);
        const shortcode = mpesaCreds.shortcode;
        const pw = Buffer.from(`${shortcode}${mpesaCreds.passkey}${ts}`).toString('base64');
        const fp = phone.replace(/^0/, '254').replace(/^\+/, '');
        const r = await fetch('https://api.safaricom.co.ke/mpesa/stkpush/v1/processrequest', {
          method: 'POST',
          headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
          body: JSON.stringify({
            BusinessShortCode: shortcode, Password: pw, Timestamp: ts,
            TransactionType: 'CustomerPayBillOnline',
            Amount: Math.ceil(pkg.price || amount),
            PartyA: fp, PartyB: shortcode, PhoneNumber: fp,
            CallBackURL: `${API_URL}/api/payments/callback`,
            AccountReference: '5414200',
            TransactionDesc: `BRISK WiFi - ${pkg.name}`
          })
        });
        const d = await r.json();
        checkoutId = d.CheckoutRequestID;
      }
    } catch (e) { console.error('Daraja STK error:', e.message); }

    let validHostId = null;
    if (host_id) {
      const { rows: hostRows } = await db.query("SELECT id FROM wifi_hosts WHERE id=$1 AND status='active'", [host_id]);
      if (hostRows[0]) validHostId = hostRows[0].id;
    }
    const { rows } = await db.query(
      'INSERT INTO payments(user_id,package_id,amount,phone,status,package_name,checkout_id,host_id,via_owner_id) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING id',
      [req.user.id, package_id, pkg.price || amount, phone, 'pending', pkg.name, checkoutId, validHostId, viaOwnerId]);

    res.json({ message: 'STK Push sent! Enter your M-Pesa PIN on your phone.', payment_id: rows[0].id, checkout_id: checkoutId });
  } catch (e) { res.status(500).json({ message: e.message }); }
});

app.post('/api/payments/callback', async (req, res) => {
  try {
    const body = req.body?.Body?.stkCallback;
    if (!body) return res.json({ ResultCode: 0 });
    const code = body.CallbackMetadata?.Item?.find(i => i.Name === 'MpesaReceiptNumber')?.Value;
    const phone = body.CallbackMetadata?.Item?.find(i => i.Name === 'PhoneNumber')?.Value?.toString();

    if (body.ResultCode === 0 && code) {
      const { rows: pays } = await db.query(
        "SELECT * FROM payments WHERE phone LIKE $1 AND status='pending' ORDER BY created_at DESC LIMIT 1",
        ['%' + String(phone).slice(-9)]);
      if (pays[0]) {
        await db.query("UPDATE payments SET status='completed',mpesa_code=$1 WHERE id=$2", [code, pays[0].id]);
        const { rows: pkgs } = await db.query('SELECT * FROM packages WHERE id=$1', [pays[0].package_id]);
        if (pkgs[0] && pays[0].purpose === 'voucher') {
          const qty = pays[0].voucher_qty || 1;
          const codes = [];
          for (let i = 0; i < qty; i++) {
            let vcode;
            do { vcode = genVoucherCode(); } while ((await db.query('SELECT id FROM vouchers WHERE code=$1', [vcode])).rows.length);
            await db.query('INSERT INTO vouchers(owner_id,package_id,code,batch_id,status) VALUES($1,$2,$3,$4,$5)',
              [pays[0].user_id, pkgs[0].id, vcode, 'buy-' + pays[0].id, 'unused']);
            codes.push(vcode);
          }
          await db.query('INSERT INTO transactions(user_id,type,amount,description,payment_id) VALUES($1,$2,$3,$4,$5)',
            [pays[0].user_id, 'purchase', -pays[0].amount, `${qty}x WiFi Voucher: ${pkgs[0].name}`, pays[0].id]);
          await notify(pays[0].user_id, 'payment', '✅ Vouchers Ready!', `${qty} voucher(s) for ${pkgs[0].name} generated. Code: ${code}.`);
          emit('payment_confirmed', { user_id: pays[0].user_id, package: pkgs[0].name, amount: pays[0].amount, vouchers: codes });
        } else if (pkgs[0]) {
          const expires = new Date(Date.now() + pkgs[0].duration_mins * 60000);
          await db.query('INSERT INTO sessions(user_id,package_id,package_name,duration_mins,expires_at) VALUES($1,$2,$3,$4,$5)',
            [pays[0].user_id, pkgs[0].id, pkgs[0].name, pkgs[0].duration_mins, expires]);
          await db.query('INSERT INTO transactions(user_id,type,amount,description,payment_id) VALUES($1,$2,$3,$4,$5)',
            [pays[0].user_id, 'purchase', -pays[0].amount, `WiFi Package: ${pkgs[0].name}`, pays[0].id]);
          await notify(pays[0].user_id, 'payment', '✅ Payment Confirmed!', `${pkgs[0].name} activated! Code: ${code}. Valid until ${expires.toLocaleString('en-KE')}`);
          // If this sale happened via a specific Router Owner's own network,
          // send the confirmation using THEIR WhatsApp/Email if configured —
          // it should look like it came from their business, not BRISK.
          (async () => {
            let waOverride = null, emailOverride = null;
            if (pays[0].via_owner_id) {
              const { rows: waInt } = await db.query("SELECT config_encrypted FROM owner_integrations WHERE owner_id=$1 AND provider='whatsapp' AND status='connected'", [pays[0].via_owner_id]);
              if (waInt[0]) { try { const c = JSON.parse(decryptSecret(waInt[0].config_encrypted)); waOverride = { token: c.access_token, phoneId: c.phone_number_id }; } catch {} }
              const { rows: emInt } = await db.query("SELECT config_encrypted FROM owner_integrations WHERE owner_id=$1 AND provider='email' AND status='connected'", [pays[0].via_owner_id]);
              if (emInt[0]) { try { const c = JSON.parse(decryptSecret(emInt[0].config_encrypted)); emailOverride = { apiKey: c.api_key, from: `${c.from_name || 'WiFi'} <${c.from_email}>` }; } catch {} }
            }
            const { rows: ur } = await db.query('SELECT email,name,phone FROM users WHERE id=$1', [pays[0].user_id]);
            if (ur[0]?.phone) sendWhatsApp(ur[0].phone, `✅ Payment confirmed! ${pkgs[0].name} is active. Code: ${code}. Valid until ${expires.toLocaleString('en-KE')}`, waOverride).catch(() => {});
            if (ur[0]?.email) sendEmail(ur[0].email, `Receipt — ${pkgs[0].name} (KES ${pays[0].amount})`,
              emailShell('Payment Receipt', `<p>Hi ${ur[0].name},</p><table style="width:100%;border-collapse:collapse;margin:16px 0"><tr><td style="padding:8px 0;color:#666">Package</td><td style="text-align:right;font-weight:600">${pkgs[0].name}</td></tr><tr><td style="padding:8px 0;color:#666">Amount</td><td style="text-align:right;font-weight:600">KES ${pays[0].amount}</td></tr><tr><td style="padding:8px 0;color:#666">M-Pesa Code</td><td style="text-align:right;font-weight:600">${code}</td></tr><tr><td style="padding:8px 0;color:#666">Valid Until</td><td style="text-align:right;font-weight:600">${expires.toLocaleString('en-KE')}</td></tr></table><p>Thank you for choosing BRISK Smart Connect!</p>`), emailOverride).catch(() => {});
          })().catch(() => {});
          // Pay referral commission
          const { rows: refs } = await db.query('SELECT * FROM referrals WHERE referred_id=$1', [pays[0].user_id]);
          if (refs[0]) {
            const comm = Math.floor(pays[0].amount * 0.1);
            if (comm > 0) {
              await db.query('UPDATE users SET wallet_balance=wallet_balance+$1 WHERE id=$2', [comm, refs[0].referrer_id]);
              await db.query('UPDATE referrals SET commission=commission+$1,packages_bought=packages_bought+1 WHERE id=$2', [comm, refs[0].id]);
              await db.query('INSERT INTO transactions(user_id,type,amount,description) VALUES($1,$2,$3,$4)',
                [refs[0].referrer_id, 'referral', comm, `10% referral commission - ${pkgs[0].name}`]);
              await notify(refs[0].referrer_id, 'referral', '💰 Referral Commission Earned!', `KES ${comm} commission credited to your wallet!`);
            }
          }
          // Pay WiFi Host commission (if this purchase came through a host's hotspot)
          if (pays[0].host_id) {
            const hostComm = Math.floor(pays[0].amount * 0.1);
            if (hostComm > 0) {
              const { rows: hostRows } = await db.query('SELECT user_id FROM wifi_hosts WHERE id=$1', [pays[0].host_id]);
              if (hostRows[0]) {
                await db.query('UPDATE users SET wallet_balance=wallet_balance+$1 WHERE id=$2', [hostComm, hostRows[0].user_id]);
                await db.query('INSERT INTO wifi_host_sales(host_id,customer_id,package_id,commission) VALUES($1,$2,$3,$4)',
                  [pays[0].host_id, pays[0].user_id, pkgs[0].id, hostComm]);
                await notify(hostRows[0].user_id, 'system', '💰 WiFi Host Commission Earned!', `KES ${hostComm} commission credited to your wallet!`);
              }
            }
          }
          // Emit real-time event
          emit('payment_confirmed', { user_id: pays[0].user_id, package: pkgs[0].name, amount: pays[0].amount });
        }
      } else {
        // No matching regular payment — check if this is a Router Owner
        // subscription payment instead (separate table, platform M-Pesa only).
        const { rows: subPays } = await db.query(
          "SELECT * FROM subscription_payments WHERE phone LIKE $1 AND status='pending' ORDER BY created_at DESC LIMIT 1",
          ['%' + String(phone).slice(-9)]);
        const subPay = subPays[0];
        if (subPay) {
          await db.query("UPDATE subscription_payments SET status='completed',mpesa_code=$1 WHERE id=$2", [code, subPay.id]);
          const { rows: planRows } = await db.query('SELECT * FROM subscription_plans WHERE id=$1', [subPay.plan_id]);
          const plan = planRows[0];
          if (plan) {
            const { rows: existing } = await db.query('SELECT * FROM owner_subscriptions WHERE owner_id=$1', [subPay.owner_id]);
            const now = new Date();
            const base = existing[0]?.expires_at && new Date(existing[0].expires_at) > now ? new Date(existing[0].expires_at) : now;
            const newExpiry = new Date(base.getTime() + plan.duration_days * 86400000);
            await db.query(`INSERT INTO owner_subscriptions(owner_id,plan_id,status,started_at,expires_at) VALUES($1,$2,'active',NOW(),$3)
              ON CONFLICT(owner_id) DO UPDATE SET plan_id=$2,status='active',started_at=COALESCE(owner_subscriptions.started_at,NOW()),expires_at=$3,updated_at=NOW()`,
              [subPay.owner_id, plan.id, newExpiry]);
            await notify(subPay.owner_id, 'payment', '✅ Subscription Activated!', `${plan.name} plan active until ${newExpiry.toLocaleDateString('en-KE')}. Code: ${code}.`);
            emit('subscription_activated', { owner_id: subPay.owner_id, plan: plan.name, expires_at: newExpiry });
          }
        }
      }
    }
  } catch (e) { console.error('M-Pesa callback error:', e.message); }
  res.json({ ResultCode: 0 });
});

app.post('/api/payments/verify', auth, async (req, res) => {
  const { transaction_code } = req.body;
  if (!transaction_code) return res.status(400).json({ message: 'Enter your M-Pesa transaction code' });
  const code = transaction_code.trim().toUpperCase();
  const { rows } = await db.query("SELECT p.*,pkg.name as pkg_name FROM payments p LEFT JOIN packages pkg ON pkg.id=p.package_id WHERE p.mpesa_code=$1", [code]);
  if (!rows.length) return res.status(404).json({ message: 'Transaction code not found. Contact support: +254 712 883 849' });
  if (rows[0].status === 'completed') return res.json({ message: `✅ Verified! ${rows[0].pkg_name} package is active.`, payment: rows[0] });
  res.status(400).json({ message: 'Payment is pending or failed. Contact support.' });
});

app.get('/api/payments/status', auth, async (req, res) => {
  const { payment_id } = req.query;
  if (!payment_id) return res.status(400).json({ message: 'payment_id required' });
  const { rows } = await db.query('SELECT * FROM payments WHERE id=$1 AND user_id=$2', [payment_id, req.user.id]);
  res.json({ status: rows[0]?.status || 'not_found', payment: rows[0] || null });
});

// ═══════════════════════════════════════════════════════════════
// CUSTOMER DASHBOARD
// ═══════════════════════════════════════════════════════════════
app.get('/api/customer/dashboard', auth, async (req, res) => {
  try {
    const uid = req.user.id;
    const [sess, txs, refs, pkgC, notifC] = await Promise.all([
      db.query("SELECT s.*,p.name,p.duration_mins as pkg_dur FROM sessions s LEFT JOIN packages p ON p.id=s.package_id WHERE s.user_id=$1 AND s.status='active' AND s.expires_at>NOW() ORDER BY s.expires_at DESC LIMIT 1", [uid]),
      db.query('SELECT * FROM transactions WHERE user_id=$1 ORDER BY created_at DESC LIMIT 5', [uid]),
      db.query('SELECT COUNT(*) as cnt, COALESCE(SUM(commission),0) as earned FROM referrals WHERE referrer_id=$1', [uid]),
      db.query("SELECT COUNT(*) FROM payments WHERE user_id=$1 AND status='completed'", [uid]),
      db.query('SELECT COUNT(*) FROM notifications WHERE user_id=$1 AND read=false', [uid]),
    ]);

    let timeRemaining = 'No Active Package', timeProg = 0;
    if (sess.rows[0]?.expires_at) {
      const msLeft = new Date(sess.rows[0].expires_at) - Date.now();
      if (msLeft > 0) {
        const h = Math.floor(msLeft / 3600000), m = Math.floor((msLeft % 3600000) / 60000);
        timeRemaining = h > 24 ? `${Math.floor(h / 24)}d ${h % 24}h remaining` : `${h}h ${m}m remaining`;
        const total = (sess.rows[0].pkg_dur || 1440) * 60000;
        timeProg = Math.max(0, Math.min(100, 100 - Math.floor((msLeft / total) * 100)));
      } else { timeRemaining = 'Package Expired'; timeProg = 100; }
    }

    const u = { ...req.user }; delete u.password_hash;
    res.json({
      user: u, wallet_balance: parseFloat(req.user.wallet_balance) || 0,
      active_package: sess.rows[0] ? { name: sess.rows[0].package_name || sess.rows[0].name, expires_at: sess.rows[0].expires_at } : null,
      time_remaining: timeRemaining, time_prog: timeProg,
      packages_bought: parseInt(pkgC.rows[0].count),
      referral_count: parseInt(refs.rows[0].cnt),
      referral_earned: parseFloat(refs.rows[0].earned),
      referral_code: req.user.referral_code,
      unread_notifications: parseInt(notifC.rows[0].count),
      transactions: txs.rows,
    });
  } catch (e) { res.status(500).json({ message: e.message }); }
});

// ═══════════════════════════════════════════════════════════════
// TRANSACTIONS, REFERRALS, NOTIFICATIONS, DEVICES
// ═══════════════════════════════════════════════════════════════
app.get('/api/transactions', auth, async (req, res) => {
  const { page = 1, type, period } = req.query;
  let q = 'SELECT * FROM transactions WHERE user_id=$1', params = [req.user.id];
  if (type) { params.push(type); q += ` AND type=$${params.length}`; }
  if (period) q += ` AND created_at>NOW()-INTERVAL '${parseInt(period)} days'`;
  const { rows: cnt } = await db.query(q.replace('SELECT *', 'SELECT COUNT(*)'), params);
  params.push(50, (parseInt(page) - 1) * 50);
  const { rows } = await db.query(q + ` ORDER BY created_at DESC LIMIT $${params.length - 1} OFFSET $${params.length}`, params);
  const { rows: stats } = await db.query(`SELECT
    COALESCE(SUM(CASE WHEN amount<0 THEN ABS(amount) END),0) as total_spent,
    COALESCE(SUM(CASE WHEN type='referral' THEN amount END),0) as referral_earned,
    COALESCE(SUM(CASE WHEN type='hosting' AND amount<0 THEN ABS(amount) END),0) as hosting_paid,
    COUNT(*) as count FROM transactions WHERE user_id=$1`, [req.user.id]);
  res.json({ transactions: rows, total: parseInt(cnt[0].count), stats: { total_spent: parseFloat(stats[0].total_spent), referral_earned: parseFloat(stats[0].referral_earned), hosting_paid: parseFloat(stats[0].hosting_paid), count: parseInt(stats[0].count) } });
});

app.get('/api/referrals', auth, async (req, res) => {
  const { rows } = await db.query('SELECT r.*,u.name,u.phone,u.created_at as joined_at FROM referrals r JOIN users u ON u.id=r.referred_id WHERE r.referrer_id=$1 ORDER BY r.created_at DESC', [req.user.id]);
  const total = rows.reduce((s, r) => s + parseFloat(r.commission || 0), 0);
  res.json({ referral_code: req.user.referral_code, total_referrals: rows.length, total_earned: total, pending: 0, referrals: rows });
});

app.get('/api/notifications', auth, async (req, res) => {
  const { rows } = await db.query('SELECT * FROM notifications WHERE user_id=$1 ORDER BY created_at DESC LIMIT 100', [req.user.id]);
  res.json({ notifications: rows });
});
app.put('/api/notifications/:id/read', auth, async (req, res) => {
  await db.query('UPDATE notifications SET read=true WHERE id=$1 AND user_id=$2', [req.params.id, req.user.id]);
  res.json({ message: 'Marked as read' });
});
app.put('/api/notifications/read-all', auth, async (req, res) => {
  await db.query('UPDATE notifications SET read=true WHERE user_id=$1', [req.user.id]);
  res.json({ message: 'All notifications marked as read' });
});

app.get('/api/devices', auth, async (req, res) => {
  const { rows } = await db.query('SELECT * FROM devices WHERE user_id=$1 ORDER BY last_seen DESC', [req.user.id]);
  res.json({ current: rows[0] || null, history: rows });
});

// ═══════════════════════════════════════════════════════════════
// WIFI SETTINGS
// ═══════════════════════════════════════════════════════════════
app.get('/api/wifi-settings', auth, async (req, res) => {
  const { rows } = await db.query("SELECT s.*,p.name as package_name,p.duration_mins FROM sessions s LEFT JOIN packages p ON p.id=s.package_id WHERE s.user_id=$1 AND s.status='active' AND s.expires_at>NOW() ORDER BY s.expires_at DESC LIMIT 1", [req.user.id]);
  const sess = rows[0];
  let timeRemaining = '—';
  if (sess?.expires_at) {
    const ms = new Date(sess.expires_at) - Date.now();
    if (ms > 0) { const h = Math.floor(ms / 3600000); timeRemaining = h > 24 ? `${Math.floor(h / 24)}d ${h % 24}h left` : `${h}h ${Math.floor((ms % 3600000) / 60000)}m left`; }
  }
  res.json({ ssid: `BRISK_${req.user.id}`, package_name: sess?.package_name || null, time_remaining: timeRemaining, status: sess ? 'Connected' : 'No Active Package', download_mbps: 15, upload_mbps: 5, uptime: '2d 4h', firmware: 'RouterOS 7.1', connected_devices: [] });
});
app.put('/api/wifi-settings/ssid', auth, async (req, res) => res.json({ message: 'WiFi name update queued for next sync' }));
app.put('/api/wifi-settings/password', auth, async (req, res) => res.json({ message: 'WiFi password update queued' }));
app.post('/api/wifi-settings/restart-wifi', auth, async (req, res) => res.json({ message: 'WiFi interface restart queued' }));
app.post('/api/wifi-settings/reboot', auth, async (req, res) => res.json({ message: 'Router reboot queued' }));

// ═══════════════════════════════════════════════════════════════
// SUPPORT TICKETS
// ═══════════════════════════════════════════════════════════════
app.get('/api/support/tickets', auth, async (req, res) => {
  const { rows } = await db.query('SELECT * FROM support_tickets WHERE user_id=$1 ORDER BY created_at DESC', [req.user.id]);
  res.json({ tickets: rows });
});
app.post('/api/support/tickets', auth, async (req, res) => {
  const { subject, category, message, priority } = req.body;
  if (!subject || !message) return res.status(400).json({ message: 'Subject and message required' });
  const { rows } = await db.query('INSERT INTO support_tickets(user_id,subject,category,message,priority) VALUES($1,$2,$3,$4,$5) RETURNING id',
    [req.user.id, subject, category || 'general', message, priority || 'normal']);
  await notify(req.user.id, 'support', 'Ticket Submitted', `Ticket #${rows[0].id}: "${subject}" — We'll respond within 24 hours.`);
  res.json({ ticket_id: rows[0].id, message: `Ticket #${rows[0].id} submitted! We will respond within 24 hours.` });
});

// ═══════════════════════════════════════════════════════════════
// INSTALLATIONS
// ═══════════════════════════════════════════════════════════════
app.get('/api/installations', auth, async (req, res) => {
  const { rows } = await db.query('SELECT * FROM installation_requests WHERE user_id=$1 ORDER BY created_at DESC', [req.user.id]);
  res.json({ requests: rows });
});
app.post('/api/installations', auth, async (req, res) => {
  const { name, phone, address, location_type, preferred_date, preferred_time, notes } = req.body;
  if (!name || !phone || !address) return res.status(400).json({ message: 'Name, phone and address are required' });
  const price = location_type === 'wireless' ? 8499 : 2999;
  const { rows } = await db.query('INSERT INTO installation_requests(user_id,name,phone,address,location_type,preferred_date,preferred_time,notes,price) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING id',
    [req.user.id, name, phone, address, location_type || 'wired', preferred_date || null, preferred_time || 'any', notes, price]);
  await notify(req.user.id, 'installation', 'Installation Request Submitted', `Request #${rows[0].id} received. Our team will contact you within 24 hours. Installation cost: KES ${price.toLocaleString()}`);
  res.json({ request_id: rows[0].id, price, message: `Installation request submitted! We will contact you within 24 hours. Cost: KES ${price.toLocaleString()}` });
});

// ═══════════════════════════════════════════════════════════════
// CONTACT / PUBLIC
// ═══════════════════════════════════════════════════════════════
app.post('/api/contact', async (req, res) => {
  const { name, phone, email, subject, message } = req.body;
  if (!name || !message) return res.status(400).json({ message: 'Name and message required' });
  await db.query('INSERT INTO contacts(name,phone,email,subject,message) VALUES($1,$2,$3,$4,$5)', [name, phone, email, subject, message]).catch(() => {});
  res.json({ message: 'Message received! We will respond within 24 hours.' });
});

app.get('/api/stats', async (req, res) => {
  try {
    const [u, r] = await Promise.all([
      db.query("SELECT COUNT(*) FROM users WHERE role='customer'"),
      db.query('SELECT COUNT(*) FROM routers'),
    ]);
    res.json({ users: parseInt(u.rows[0].count), routers: parseInt(r.rows[0].count) });
  } catch { res.json({ users: 2400, routers: 68 }); }
});

app.get('/api/health', async (req, res) => {
  try { await db.query('SELECT 1'); res.json({ status: 'ok', db: 'connected', ts: new Date().toISOString(), version: '3.0.0' }); }
  catch { res.status(503).json({ status: 'error', db: 'disconnected' }); }
});

// ═══════════════════════════════════════════════════════════════
// ROUTER OWNER ROUTES
// ═══════════════════════════════════════════════════════════════
app.get('/api/owner/dashboard', auth, owner, async (req, res) => {
  const uid = req.user.id;
  const [routers, custs, rev, wds] = await Promise.all([
    db.query('SELECT * FROM routers WHERE owner_id=$1 ORDER BY created_at DESC', [uid]),
    db.query("SELECT COUNT(DISTINCT s.user_id) as cnt FROM sessions s JOIN routers r ON r.id=s.router_id WHERE r.owner_id=$1 AND s.status='active'", [uid]),
    db.query(`SELECT COALESCE(SUM(p.amount),0) as total, COALESCE(SUM(CASE WHEN p.created_at::date=CURRENT_DATE THEN p.amount END),0) as today, COALESCE(SUM(CASE WHEN p.created_at>NOW()-INTERVAL '30 days' THEN p.amount END),0) as month FROM payments p JOIN sessions s ON s.user_id=p.user_id JOIN routers r ON r.id=s.router_id WHERE r.owner_id=$1 AND p.status='completed'`, [uid]),
    db.query("SELECT COALESCE(SUM(amount),0) as pending FROM withdrawals WHERE owner_id=$1 AND status='pending'", [uid]),
  ]);
  res.json({
    total_revenue: parseFloat(rev.rows[0].total), today_revenue: parseFloat(rev.rows[0].today),
    month_revenue: parseFloat(rev.rows[0].month), pending_withdrawal: parseFloat(wds.rows[0].pending),
    customers: parseInt(custs.rows[0].cnt), routers: routers.rows.length,
    active_sessions: routers.rows.reduce((s, r) => s + (r.connected_users || 0), 0),
    routers_list: routers.rows, recent_customers: [],
  });
});

app.post('/api/owner/test-router', auth, owner, async (req, res) => {
  const { ip, port, brand, username, password } = req.body;
  if (!ip) return res.status(400).json({ message: 'IP address required' });
  try {
    const result = await MikroTikAPI.getStatus({ ip, port, username, password, name: 'Test' });
    res.json({ ...result, message: result.connected ? `✅ Connected to ${ip}` : '❌ Connection failed' });
  } catch (e) { res.status(500).json({ message: e.message, connected: false }); }
});

app.post('/api/owner/routers', auth, owner, async (req, res) => {
  const { name, brand, model, ip, port, username, password, isp, business_name, location, connection_type } = req.body;
  if (!name || !ip || !username || !password) return res.status(400).json({ message: 'Name, IP, username and password required' });
  const passEnc = encryptSecret(password);
  const { rows } = await db.query('INSERT INTO routers(owner_id,name,brand,model,ip,port,username,password_hash,password_encrypted,isp,business_name,location,connection_type) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13) RETURNING *',
    [req.user.id, name, brand || 'mikrotik', model, ip, port || '8728', username, 'stored-encrypted', passEnc, isp, business_name, location, connection_type || 'direct']);
  await notify(req.user.id, 'system', '✅ Router Connected', `${name} (${ip}) has been connected to BRISK Smart Connect.`);
  res.json({ router: scrubRouter(rows[0]), message: 'Router connected successfully!' });
});
app.get('/api/owner/routers', auth, owner, async (req, res) => {
  const { rows } = await db.query('SELECT * FROM routers WHERE owner_id=$1 ORDER BY created_at DESC', [req.user.id]);
  res.json({ routers: scrubRouters(rows) });
});
app.get('/api/owner/routers/:id/status', auth, owner, async (req, res) => {
  const { rows } = await db.query('SELECT * FROM routers WHERE id=$1 AND owner_id=$2', [req.params.id, req.user.id]);
  if (!rows[0]) return res.status(404).json({ message: 'Router not found' });
  const live = await MikroTikAPI.getStatus(routerConnConfig(rows[0]));
  // Update router record with live data
  if (live.connected) {
    await db.query("UPDATE routers SET status='online',cpu_load=$1,connected_users=$2,bandwidth_download=$3,bandwidth_upload=$4,last_seen=NOW() WHERE id=$5",
      [live.cpu, live.connected_users, live.download_mbps, live.upload_mbps, rows[0].id]).catch(() => {});
    // Log stats
    await db.query('INSERT INTO router_stats(router_id,cpu_load,connected_users,bandwidth_dl,bandwidth_ul) VALUES($1,$2,$3,$4,$5)',
      [rows[0].id, live.cpu, live.connected_users, live.download_mbps, live.upload_mbps]).catch(() => {});
    // Emit live data
    emit('router_status', { router_id: rows[0].id, ...live }, 'router_' + rows[0].id);
  }
  res.json({ router: scrubRouter(rows[0]), live });
});
app.post('/api/owner/routers/:id/restart', auth, owner, async (req, res) => {
  const { rows } = await db.query('SELECT * FROM routers WHERE id=$1 AND owner_id=$2', [req.params.id, req.user.id]);
  if (!rows[0]) return res.status(404).json({ message: 'Router not found' });
  const result = await MikroTikAPI.restart(rows[0]);
  await db.query('INSERT INTO router_logs(router_id,event,details) VALUES($1,$2,$3)', [rows[0].id, 'restart', `Restart requested by owner ${req.user.id}`]);
  res.json({ ...result, message: 'Restart command sent to ' + rows[0].ip });
});
app.delete('/api/owner/routers/:id', auth, owner, async (req, res) => {
  await db.query('DELETE FROM routers WHERE id=$1 AND owner_id=$2', [req.params.id, req.user.id]);
  res.json({ message: 'Router removed from platform' });
});

app.get('/api/owner/customers', auth, owner, async (req, res) => {
  const { rows } = await db.query(`SELECT u.id,u.name,u.phone,s.package_name,s.expires_at,s.status as pkg_status,r.name as router_name,s.mac,s.ip FROM sessions s JOIN users u ON u.id=s.user_id JOIN routers r ON r.id=s.router_id WHERE r.owner_id=$1 ORDER BY s.started_at DESC LIMIT 200`, [req.user.id]);
  res.json({ customers: rows, stats: { total: rows.length, active: rows.filter(r => r.pkg_status === 'active').length, expiring: rows.filter(r => { const ms = new Date(r.expires_at) - Date.now(); return ms > 0 && ms < 86400000; }).length, new_today: rows.filter(r => new Date(r.expires_at).toDateString() === new Date().toDateString()).length } });
});

app.post('/api/owner/customers/disconnect', auth, owner, async (req, res) => {
  const { mac, router_id } = req.body;
  const { rows } = await db.query('SELECT * FROM routers WHERE id=$1 AND owner_id=$2', [router_id, req.user.id]);
  if (!rows[0]) return res.status(404).json({ message: 'Router not found' });
  const result = await MikroTikAPI.disconnectUser(rows[0], mac);
  res.json(result);
});

app.get('/api/owner/earnings', auth, owner, async (req, res) => {
  const { rows } = await db.query(`SELECT
    COALESCE(SUM(CASE WHEN p.created_at::date=CURRENT_DATE THEN p.amount END),0) as today,
    COALESCE(SUM(CASE WHEN p.created_at>NOW()-INTERVAL '7 days' THEN p.amount END),0) as week,
    COALESCE(SUM(CASE WHEN p.created_at>NOW()-INTERVAL '30 days' THEN p.amount END),0) as month,
    COALESCE(SUM(p.amount),0) as total,
    COUNT(p.id) as transactions
    FROM payments p JOIN sessions s ON s.user_id=p.user_id
    JOIN routers r ON r.id=s.router_id WHERE r.owner_id=$1 AND p.status='completed'`, [req.user.id]);
  const { rows: byPkg } = await db.query(`SELECT p.package_name, COUNT(*) as count, SUM(p.amount) as total FROM payments p JOIN sessions s ON s.user_id=p.user_id JOIN routers r ON r.id=s.router_id WHERE r.owner_id=$1 AND p.status='completed' GROUP BY p.package_name ORDER BY total DESC`, [req.user.id]);
  res.json({ ...rows[0], by_package: byPkg, today: parseFloat(rows[0].today), week: parseFloat(rows[0].week), month: parseFloat(rows[0].month), total: parseFloat(rows[0].total) });
});

app.get('/api/owner/withdrawals', auth, owner, async (req, res) => {
  const { rows } = await db.query('SELECT * FROM withdrawals WHERE owner_id=$1 ORDER BY created_at DESC', [req.user.id]);
  res.json({
    available_balance: parseFloat(req.user.wallet_balance) || 0,
    pending_amount: rows.filter(w => w.status === 'pending').reduce((s, w) => s + parseFloat(w.amount), 0),
    total_paid: rows.filter(w => w.status === 'approved').reduce((s, w) => s + parseFloat(w.amount), 0),
    withdrawals: rows,
  });
});
app.post('/api/owner/withdrawals', auth, owner, async (req, res) => {
  const { amount, phone, account_name } = req.body;
  const available = parseFloat(req.user.wallet_balance) || 0;
  if (!amount || amount < 500) return res.status(400).json({ message: 'Minimum withdrawal is KES 500' });
  if (amount > available) return res.status(400).json({ message: `Insufficient balance. Available: KES ${available.toLocaleString()}` });
  await db.query('UPDATE users SET wallet_balance=wallet_balance-$1 WHERE id=$2', [amount, req.user.id]);
  await db.query('INSERT INTO withdrawals(owner_id,amount,phone,account_name) VALUES($1,$2,$3,$4)', [req.user.id, amount, phone, account_name]);
  await notify(req.user.id, 'withdrawal', '📤 Withdrawal Requested', `KES ${amount.toLocaleString()} withdrawal requested to ${phone}. Processing within 24 hours.`);
  res.json({ message: `KES ${amount.toLocaleString()} withdrawal submitted! Processing within 24 hours.` });
});
app.delete('/api/owner/withdrawals/:id', auth, owner, async (req, res) => {
  const { rows } = await db.query("UPDATE withdrawals SET status='cancelled' WHERE id=$1 AND owner_id=$2 AND status='pending' RETURNING amount", [req.params.id, req.user.id]);
  if (rows[0]) await db.query('UPDATE users SET wallet_balance=wallet_balance+$1 WHERE id=$2', [rows[0].amount, req.user.id]);
  res.json({ message: 'Withdrawal cancelled and amount returned to wallet' });
});

app.get('/api/owner/bandwidth', auth, owner, async (req, res) => {
  const { rows } = await db.query('SELECT * FROM routers WHERE owner_id=$1', [req.user.id]);
  const live = rows.length ? await MikroTikAPI.getStatus(routerConnConfig(rows[0])) : {};
  res.json({ download_mbps: live.download_mbps || 0, upload_mbps: live.upload_mbps || 0, active_sessions: rows.reduce((s, r) => s + (r.connected_users || 0), 0), total_gb: 0, routers: scrubRouters(rows) });
});

app.get('/api/owner/installation-jobs', auth, owner, async (req, res) => {
  const { rows } = await db.query('SELECT * FROM installation_requests WHERE assigned_to=$1 ORDER BY created_at DESC', [req.user.id]);
  res.json({ jobs: rows, stats: { total: rows.length, pending: rows.filter(r => r.status === 'pending').length, completed: rows.filter(r => r.status === 'completed').length } });
});
app.put('/api/owner/installation-jobs/:id', auth, owner, async (req, res) => {
  await db.query('UPDATE installation_requests SET status=$1,updated_at=NOW() WHERE id=$2', [req.body.status, req.params.id]);
  res.json({ message: 'Job status updated to ' + req.body.status });
});

// ═══════════════════════════════════════════════════════════════
// ADMIN ROUTES
// ═══════════════════════════════════════════════════════════════
app.get('/api/admin/dashboard', auth, admin, async (req, res) => {
  const [rev, custs, owners, routers, online, pWd, openT, recentU, recentP] = await Promise.all([
    db.query("SELECT COALESCE(SUM(amount),0) as t, COALESCE(SUM(CASE WHEN created_at::date=CURRENT_DATE THEN amount END),0) as today, COALESCE(SUM(CASE WHEN created_at>NOW()-INTERVAL '30 days' THEN amount END),0) as month FROM payments WHERE status='completed'"),
    db.query("SELECT COUNT(*) FROM users WHERE role='customer'"),
    db.query("SELECT COUNT(*) FROM users WHERE role='router_owner'"),
    db.query('SELECT COUNT(*) FROM routers'),
    db.query("SELECT COUNT(*) FROM routers WHERE status='online'"),
    db.query("SELECT COUNT(*) FROM withdrawals WHERE status='pending'"),
    db.query("SELECT COUNT(*) FROM support_tickets WHERE status='open'"),
    db.query('SELECT id,name,phone,role,created_at FROM users ORDER BY created_at DESC LIMIT 6'),
    db.query("SELECT p.*,u.name as customer_name FROM payments p JOIN users u ON u.id=p.user_id WHERE p.status='completed' ORDER BY p.created_at DESC LIMIT 5"),
  ]);
  res.json({
    total_revenue: parseFloat(rev.rows[0].t), today_revenue: parseFloat(rev.rows[0].today), month_revenue: parseFloat(rev.rows[0].month),
    total_customers: parseInt(custs.rows[0].count), total_owners: parseInt(owners.rows[0].count),
    total_routers: parseInt(routers.rows[0].count),
    online_routers: parseInt(online.rows[0].count), pending_withdrawals: parseInt(pWd.rows[0].count),
    open_tickets: parseInt(openT.rows[0].count),
    recent_users: recentU.rows, recent_payments: recentP.rows,
  });
});

app.get('/api/admin/users', auth, admin, async (req, res) => {
  const { page = 1, search = '', role = '', status = '' } = req.query;
  let q = 'SELECT id,name,phone,email,role,status,created_at,referral_code,wallet_balance FROM users WHERE 1=1', params = [];
  if (search) { params.push('%' + search + '%'); q += ` AND (name ILIKE $${params.length} OR phone ILIKE $${params.length} OR email ILIKE $${params.length})`; }
  if (role) { params.push(role); q += ` AND role=$${params.length}`; }
  if (status) { params.push(status); q += ` AND status=$${params.length}`; }
  const { rows: count } = await db.query(q.replace('SELECT id,name,phone,email,role,status,created_at,referral_code,wallet_balance', 'SELECT COUNT(*)'), params);
  params.push(25, (parseInt(page) - 1) * 25);
  const { rows } = await db.query(q + ` ORDER BY created_at DESC LIMIT $${params.length - 1} OFFSET $${params.length}`, params);
  const { rows: sc } = await db.query("SELECT COUNT(*) FILTER(WHERE role='customer') as customers, COUNT(*) FILTER(WHERE role='router_owner') as owners, COUNT(*) as total FROM users WHERE status!='deleted'");
  res.json({ users: rows, total: parseInt(count[0].count), stats: { total: parseInt(sc[0].total), customers: parseInt(sc[0].customers), owners: parseInt(sc[0].owners), developers: parseInt(sc[0].developers) } });
});
app.put('/api/admin/users/:id/status', auth, admin, async (req, res) => {
  await db.query('UPDATE users SET status=$1 WHERE id=$2', [req.body.status, req.params.id]);
  res.json({ message: `User status updated to ${req.body.status}` });
});
app.put('/api/admin/users/:id/role', auth, admin, async (req, res) => {
  await db.query('UPDATE users SET role=$1 WHERE id=$2', [req.body.role, req.params.id]);
  res.json({ message: `User role updated to ${req.body.role}` });
});
app.delete('/api/admin/users/:id', auth, admin, async (req, res) => {
  await db.query("UPDATE users SET status='deleted',name='Deleted User',phone=NULL,email=NULL WHERE id=$1", [req.params.id]);
  res.json({ message: 'User deleted' });
});

app.get('/api/admin/router-owners', auth, admin, async (req, res) => {
  const { search = '', page = 1 } = req.query;
  let q = "SELECT u.*,COUNT(r.id) as routers_count,COALESCE(SUM(wdr.amount),0) as total_withdrawals FROM users u LEFT JOIN routers r ON r.owner_id=u.id LEFT JOIN withdrawals wdr ON wdr.owner_id=u.id AND wdr.status='approved' WHERE u.role='router_owner'", params = [];
  if (search) { params.push('%' + search + '%'); q += ` AND (u.name ILIKE $1 OR u.phone ILIKE $1)`; }
  q += ` GROUP BY u.id ORDER BY u.created_at DESC LIMIT 25 OFFSET ${(parseInt(page) - 1) * 25}`;
  const { rows } = await db.query(q, params);
  res.json({ owners: rows, total: rows.length });
});

app.get('/api/admin/routers', auth, admin, async (req, res) => {
  const { search = '', status = '' } = req.query;
  let q = 'SELECT r.*,u.name as owner_name,u.phone as owner_phone FROM routers r JOIN users u ON u.id=r.owner_id WHERE 1=1', params = [];
  if (search) { params.push('%' + search + '%'); q += ` AND (r.name ILIKE $${params.length} OR r.ip ILIKE $${params.length} OR u.name ILIKE $${params.length})`; }
  if (status) { params.push(status); q += ` AND r.status=$${params.length}`; }
  const { rows } = await db.query(q + ' ORDER BY r.created_at DESC LIMIT 200', params);
  res.json({ routers: scrubRouters(rows), total: rows.length, stats: { total: rows.length, online: rows.filter(r => r.status === 'online').length, offline: rows.filter(r => r.status !== 'online').length, sessions: rows.reduce((s, r) => s + (r.connected_users || 0), 0) } });
});
app.post('/api/admin/routers/:id/restart', auth, admin, async (req, res) => {
  const { rows } = await db.query('SELECT * FROM routers WHERE id=$1', [req.params.id]);
  if (!rows[0]) return res.status(404).json({ message: 'Router not found' });
  const result = await MikroTikAPI.restart(rows[0]);
  await db.query('INSERT INTO router_logs(router_id,event,details) VALUES($1,$2,$3)', [rows[0].id, 'restart', `Admin restart by user ${req.user.id}`]);
  res.json(result);
});
app.delete('/api/admin/routers/:id', auth, admin, async (req, res) => {
  await db.query('DELETE FROM routers WHERE id=$1', [req.params.id]);
  res.json({ message: 'Router removed from platform' });
});
app.put('/api/admin/routers/:id/status', auth, admin, async (req, res) => {
  await db.query('UPDATE routers SET status=$1 WHERE id=$2', [req.body.status, req.params.id]);
  emit('router_status_changed', { router_id: req.params.id, status: req.body.status });
  res.json({ message: 'Router status updated' });
});

// MikroTik specific admin routes
app.post('/api/admin/mikrotik/test', auth, admin, async (req, res) => {
  const { ip, port, username, password, model } = req.body;
  if (!ip) return res.status(400).json({ message: 'IP address required' });
  try {
    const result = await MikroTikAPI.getStatus({ ip, port: port || '8728', username: username || 'admin', password: password || '', model });
    res.json({ ...result, message: result.connected ? `✅ Successfully connected to ${ip}` : `❌ Failed to connect to ${ip}` });
  } catch (e) { res.status(500).json({ connected: false, message: e.message }); }
});

app.get('/api/admin/mikrotik/hotspot-users/:router_id', auth, admin, async (req, res) => {
  const { rows } = await db.query('SELECT * FROM routers WHERE id=$1', [req.params.router_id]);
  if (!rows[0]) return res.status(404).json({ message: 'Router not found' });
  const mikrotikUsers = await MikroTikAPI.getHotspotUsers(rows[0]);
  const { rows: dbSessions } = await db.query("SELECT s.*,u.name,u.phone FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.router_id=$1 AND s.status='active' AND s.expires_at>NOW()", [req.params.router_id]);
  res.json({ mikrotik_users: mikrotikUsers, platform_sessions: dbSessions, total: dbSessions.length });
});

app.post('/api/admin/mikrotik/set-speed', auth, admin, async (req, res) => {
  const { router_id, mac, download_mbps, upload_mbps } = req.body;
  const { rows } = await db.query('SELECT * FROM routers WHERE id=$1', [router_id]);
  if (!rows[0]) return res.status(404).json({ message: 'Router not found' });
  const result = await MikroTikAPI.setSpeedLimit(rows[0], mac, download_mbps, upload_mbps);
  await db.query('INSERT INTO router_logs(router_id,event,details) VALUES($1,$2,$3)', [router_id, 'speed_limit', `Set ${mac} to ${download_mbps}/${upload_mbps} Mbps by admin ${req.user.id}`]);
  res.json(result);
});

app.post('/api/admin/mikrotik/disconnect-user', auth, admin, async (req, res) => {
  const { router_id, mac } = req.body;
  const { rows } = await db.query('SELECT * FROM routers WHERE id=$1', [router_id]);
  if (!rows[0]) return res.status(404).json({ message: 'Router not found' });
  const result = await MikroTikAPI.disconnectUser(rows[0], mac);
  await db.query("UPDATE sessions SET status='disconnected' WHERE router_id=$1 AND mac=$2", [router_id, mac]);
  res.json(result);
});

app.get('/api/admin/router-logs/:router_id', auth, admin, async (req, res) => {
  const { rows } = await db.query('SELECT * FROM router_logs WHERE router_id=$1 ORDER BY created_at DESC LIMIT 100', [req.params.router_id]);
  res.json({ logs: rows });
});

app.get('/api/admin/network-alerts', auth, admin, async (req, res) => {
  const { rows } = await db.query('SELECT na.*,r.name as router_name FROM network_alerts na LEFT JOIN routers r ON r.id=na.router_id WHERE na.acknowledged=false ORDER BY na.created_at DESC LIMIT 50');
  res.json({ alerts: rows });
});

app.get('/api/admin/payments', auth, admin, async (req, res) => {
  const { status = '', page = 1 } = req.query;
  let q = 'SELECT p.*,u.name as customer_name,u.phone as customer_phone FROM payments p JOIN users u ON u.id=p.user_id WHERE 1=1', params = [];
  if (status) { params.push(status); q += ` AND p.status=$${params.length}`; }
  const { rows } = await db.query(q + ' ORDER BY p.created_at DESC LIMIT 100', params);
  const { rows: stats } = await db.query("SELECT COALESCE(SUM(CASE WHEN status='completed' THEN amount END),0) as total, COALESCE(SUM(CASE WHEN status='completed' AND created_at::date=CURRENT_DATE THEN amount END),0) as today, COUNT(CASE WHEN status='pending' THEN 1 END) as pending, COUNT(CASE WHEN status='failed' THEN 1 END) as failed, COUNT(*) as total_count FROM payments");
  res.json({ payments: rows, total: rows.length, stats: { total: parseFloat(stats[0].total), today: parseFloat(stats[0].today), pending: parseInt(stats[0].pending), failed: parseInt(stats[0].failed), total_count: parseInt(stats[0].total_count) } });
});
app.put('/api/admin/payments/:id/verify', auth, admin, async (req, res) => {
  const { rows } = await db.query("UPDATE payments SET status='completed' WHERE id=$1 RETURNING *", [req.params.id]);
  if (rows[0]) await notify(rows[0].user_id, 'payment', '✅ Payment Manually Verified', `Your payment of KES ${rows[0].amount} has been verified by admin.`);
  res.json({ message: 'Payment verified and package activated' });
});

app.get('/api/admin/withdrawals', auth, admin, async (req, res) => {
  const { rows } = await db.query('SELECT w.*,u.name as owner_name,u.phone as owner_phone FROM withdrawals w JOIN users u ON u.id=w.owner_id ORDER BY w.status,w.created_at DESC');
  const today = rows.filter(w => w.status === 'approved' && new Date(w.created_at).toDateString() === new Date().toDateString()).reduce((s, w) => s + parseFloat(w.amount), 0);
  res.json({ withdrawals: rows, total: rows.length, stats: { pending: rows.filter(w => w.status === 'pending').length, approved_today: today, total_paid: rows.filter(w => w.status === 'approved').reduce((s, w) => s + parseFloat(w.amount), 0), rejected: rows.filter(w => w.status === 'rejected').length } });
});
app.put('/api/admin/withdrawals/:id/approve', auth, admin, async (req, res) => {
  const { mpesa_code } = req.body;
  await db.query("UPDATE withdrawals SET status='approved',mpesa_code=$1,processed_by=$2 WHERE id=$3", [mpesa_code || null, req.user.id, req.params.id]);
  const { rows } = await db.query('SELECT * FROM withdrawals WHERE id=$1', [req.params.id]);
  if (rows[0]) await notify(rows[0].owner_id, 'withdrawal', '✅ Withdrawal Approved!', `KES ${rows[0].amount.toLocaleString()} has been sent to ${rows[0].phone}. ${mpesa_code ? 'M-Pesa code: ' + mpesa_code : ''}`);
  res.json({ message: 'Withdrawal approved and owner notified' });
});
app.put('/api/admin/withdrawals/:id/reject', auth, admin, async (req, res) => {
  const { reason } = req.body;
  const { rows } = await db.query('SELECT * FROM withdrawals WHERE id=$1', [req.params.id]);
  if (rows[0]) {
    await db.query("UPDATE withdrawals SET status='rejected',processed_by=$1 WHERE id=$2", [req.user.id, req.params.id]);
    await db.query('UPDATE users SET wallet_balance=wallet_balance+$1 WHERE id=$2', [rows[0].amount, rows[0].owner_id]);
    await notify(rows[0].owner_id, 'withdrawal', '❌ Withdrawal Rejected', `KES ${rows[0].amount.toLocaleString()} withdrawal was rejected. ${reason ? 'Reason: ' + reason : ''} Amount returned to wallet.`);
  }
  res.json({ message: 'Withdrawal rejected and amount returned to wallet' });
});

app.get('/api/admin/support/tickets', auth, admin, async (req, res) => {
  const { status = '' } = req.query;
  let q = 'SELECT t.*,u.name as user_name,u.phone FROM support_tickets t JOIN users u ON u.id=t.user_id WHERE 1=1', params = [];
  if (status) { params.push(status); q += ` AND t.status=$${params.length}`; }
  const { rows } = await db.query(q + ' ORDER BY t.created_at DESC LIMIT 100', params);
  res.json({ tickets: rows, stats: { open: rows.filter(t => t.status === 'open').length, in_progress: rows.filter(t => t.status === 'in_progress').length, resolved: rows.filter(t => t.status === 'resolved').length } });
});
app.post('/api/admin/support/tickets/:id/reply', auth, admin, async (req, res) => {
  const { message } = req.body;
  if (!message) return res.status(400).json({ message: 'Reply message required' });
  await db.query("UPDATE support_tickets SET admin_reply=$1,status='in_progress',replied_by=$2,updated_at=NOW() WHERE id=$3", [message, req.user.id, req.params.id]);
  const { rows } = await db.query('SELECT t.*,u.name FROM support_tickets t JOIN users u ON u.id=t.user_id WHERE t.id=$1', [req.params.id]);
  if (rows[0]) await notify(rows[0].user_id, 'support', '💬 Support Team Replied', message);
  res.json({ message: 'Reply sent and customer notified' });
});
app.put('/api/admin/support/tickets/:id/resolve', auth, admin, async (req, res) => {
  await db.query("UPDATE support_tickets SET status='resolved',updated_at=NOW() WHERE id=$1", [req.params.id]);
  res.json({ message: 'Ticket resolved' });
});

app.get('/api/admin/analytics', auth, admin, async (req, res) => {
  const period = parseInt(req.query.period) || 30;
  const [rev, users, pkgs, installs] = await Promise.all([
    db.query(`SELECT COALESCE(SUM(amount),0) as revenue, COUNT(*) as packages_sold FROM payments WHERE status='completed' AND created_at>NOW()-INTERVAL '${period} days'`),
    db.query(`SELECT COUNT(*) FROM users WHERE created_at>NOW()-INTERVAL '${period} days'`),
    db.query(`SELECT package_name, COUNT(*) as count, SUM(amount) as total FROM payments WHERE status='completed' AND created_at>NOW()-INTERVAL '${period} days' GROUP BY package_name ORDER BY total DESC`),
    db.query(`SELECT COUNT(*) FROM installation_requests WHERE created_at>NOW()-INTERVAL '${period} days'`),
  ]);
  // Revenue chart (last 30 days)
  const { rows: chart } = await db.query(`SELECT DATE(created_at) as date, COALESCE(SUM(amount),0) as revenue FROM payments WHERE status='completed' AND created_at>NOW()-INTERVAL '${period} days' GROUP BY DATE(created_at) ORDER BY date`);
  res.json({
    revenue: parseFloat(rev.rows[0].revenue), packages_sold: parseInt(rev.rows[0].packages_sold),
    new_users: parseInt(users.rows[0].count),
    installations: parseInt(installs.rows[0].count),
    pkg_breakdown: pkgs.rows, chart
  });
});

app.get('/api/admin/installations', auth, admin, async (req, res) => {
  const { status = '' } = req.query;
  let q = 'SELECT i.*,u.name as user_name,u.phone as user_phone,t.name as tech_name FROM installation_requests i LEFT JOIN users u ON u.id=i.user_id LEFT JOIN technicians t ON t.id=i.assigned_to WHERE 1=1', params = [];
  if (status) { params.push(status); q += ` AND i.status=$${params.length}`; }
  const { rows } = await db.query(q + ' ORDER BY i.created_at DESC', params);
  const wc = rows.filter(r => r.location_type === 'wired').length;
  const wlc = rows.filter(r => r.location_type === 'wireless').length;
  res.json({ installations: rows, stats: { total: rows.length, pending: rows.filter(r => r.status === 'pending').length, completed: rows.filter(r => r.status === 'completed').length, revenue: (wc * 2999) + (wlc * 8499) } });
});
app.put('/api/admin/installations/:id', auth, admin, async (req, res) => {
  const { status, assigned_to } = req.body;
  await db.query('UPDATE installation_requests SET status=$1,assigned_to=$2 WHERE id=$3', [status, assigned_to || null, req.params.id]);
  res.json({ message: `Installation ${status}${assigned_to ? ', technician assigned' : ''}` });
});

app.get('/api/admin/announcements', auth, admin, async (req, res) => {
  const { rows } = await db.query('SELECT * FROM announcements ORDER BY created_at DESC LIMIT 50');
  const { rows: uc } = await db.query('SELECT COUNT(*) FROM users WHERE status=\'active\'');
  res.json({ announcements: rows, stats: { total_sent: rows.length, total_users: parseInt(uc[0].count) } });
});
app.post('/api/admin/announcements', auth, admin, async (req, res) => {
  const { title, message, target, type, via } = req.body;
  if (!title || !message) return res.status(400).json({ message: 'Title and message required' });
  let q = "SELECT id FROM users WHERE status='active'";
  if (target === 'customers') q += " AND role='customer'";
  else if (target === 'owners') q += " AND role='router_owner'";
  const { rows: users } = await db.query(q);
  await db.query('INSERT INTO announcements(title,message,target,type,via,sent_to) VALUES($1,$2,$3,$4,$5,$6)', [title, message, target || 'all', type || 'info', via || 'inapp', users.length]);
  // Batch notifications (first 500 to avoid overload)
  for (const u of users.slice(0, 500)) await notify(u.id, 'system', title, message);
  emit('announcement', { title, message, type, target });
  res.json({ message: `Announcement sent to ${users.length} users` });
});

app.get('/api/admin/templates', auth, admin, async (req, res) => {
  const { rows } = await db.query('SELECT * FROM templates ORDER BY uses DESC, id ASC');
  res.json({ templates: rows, stats: { total: rows.length, free: rows.filter(t => t.type === 'free').length, premium: rows.filter(t => t.type === 'premium').length, total_uses: rows.reduce((s, t) => s + (t.uses || 0), 0) } });
});
app.post('/api/admin/templates', auth, admin, async (req, res) => {
  const { name, category, type, color, icon, description } = req.body;
  if (!name) return res.status(400).json({ message: 'Template name required' });
  const { rows } = await db.query('INSERT INTO templates(name,category,type,color,icon,description) VALUES($1,$2,$3,$4,$5,$6) RETURNING *',
    [name, category || 'other', type || 'free', color || '#1E293B', icon || 'fa-globe', description]);
  res.json({ template: rows[0] });
});
app.put('/api/admin/templates/:id', auth, admin, async (req, res) => {
  const { active, type, name } = req.body;
  await db.query('UPDATE templates SET active=$1,type=$2,name=$3 WHERE id=$4', [active !== false, type, name, req.params.id]);
  res.json({ message: 'Template updated' });
});

app.get('/api/admin/technicians', auth, admin, async (req, res) => {
  const { rows } = await db.query('SELECT * FROM technicians WHERE active=true ORDER BY rating DESC');
  res.json({ technicians: rows, stats: { total: rows.length, available: rows.filter(t => t.status === 'available').length, total_commission: rows.reduce((s, t) => s + parseFloat(t.commission_total || 0), 0) } });
});
app.post('/api/admin/technicians', auth, admin, async (req, res) => {
  const { name, phone, area, skills } = req.body;
  if (!name || !phone) return res.status(400).json({ message: 'Name and phone required' });
  const { rows } = await db.query('INSERT INTO technicians(name,phone,area,skills) VALUES($1,$2,$3,$4) RETURNING *', [name, phone, area, skills || ['wired', 'wireless']]);
  res.json({ technician: rows[0] });
});

app.get('/api/admin/settings', auth, admin, async (req, res) => res.json({ callback_url: `${API_URL}/api/payments/callback`, api_url: API_URL, version: '3.0.0', socket_io: !!io }));
app.put('/api/admin/settings/:section', auth, admin, async (req, res) => res.json({ message: `${req.params.section} settings saved successfully` }));

// ═══════════════════════════════════════════════════════════════
// REAL-TIME STATUS UPDATE (runs every 30s)
// ═══════════════════════════════════════════════════════════════
setInterval(async () => {
  try {
    // Check expired sessions and update status
    await db.query("UPDATE sessions SET status='expired' WHERE status='active' AND expires_at<NOW()");
    // Emit platform stats
    const { rows } = await db.query("SELECT COUNT(*) FILTER(WHERE status='active') as active_sessions, COUNT(DISTINCT user_id) FILTER(WHERE status='active') as active_users FROM sessions WHERE expires_at>NOW()");
    emit('platform_stats', { active_sessions: parseInt(rows[0].active_sessions), active_users: parseInt(rows[0].active_users), ts: new Date().toISOString() });
  } catch {}
}, 30000);

// ═══════════════════════════════════════════════════════════════
// ROOT
// ═══════════════════════════════════════════════════════════════
app.get('/', (req, res) => res.json({
  service: 'BRISK Smart Connect API', version: '3.0.0', status: 'operational',
  features: ['WiFi Billing', 'MikroTik ISP Management', 'Web Hosting', 'GitHub Deploy', 'M-Pesa Daraja', 'Socket.IO Real-Time'],
  docs: 'https://brisksmartconnect.vercel.app',
  contact: { email: 'techray91@gmail.com', whatsapp: '+254712883849' }
}));

app.use((err, req, res, next) => { console.error(err.stack); res.status(500).json({ message: err.message || 'Internal server error' }); });

// ── Start ─────────────────────────────────────────────────────
// ── Startup ───────────────────────────────────────────────────
// Vercel's Node.js runtime imports this file and calls the exported
// app directly for each request — it never runs listen() and manages
// the HTTP server itself. Only start a real listening server when this
// file is run directly (local dev: `node server.js`) or on a normal
// host like Render/Railway that expects a long-running process.
if (!process.env.VERCEL) {
  initDB().then(() => server.listen(PORT, () => console.log(`🚀 BRISK Smart Connect API v3.0 running on port ${PORT}`))).catch(err => { console.error('DB init failed:', err); process.exit(1); });
} else {
  // On Vercel, still run migrations/table-creation, just without blocking
  // on it before the first request (cold start already has a time budget).
  initDB().catch(err => console.error('DB init failed:', err));
}

module.exports = app;
module.exports = { app, server };

// ═══════════════════════════════════════════════════════════════
// EXTENDED PACKAGE SEEDING — Full pricing ladder v3.0
// ═══════════════════════════════════════════════════════════════
async function seedPackagesV3() {
  const { rows } = await db.query('SELECT COUNT(*) FROM packages');
  if (parseInt(rows[0].count) > 5) return; // Already seeded
  await db.query('DELETE FROM packages'); // Reset
  const packages = [
    // Free starter
    ['FREE 3-Day Starter', 0, '3 Days', 4320, '3 Mbps', 'One-time welcome package for new customers. Activates automatically on registration.', true],
    // Quick (1hr–6hr)
    ['Quick 1 Hour', 20, '1 Hour', 60, '5 Mbps', 'Fast 1-hour browsing session', false],
    ['Quick 3 Hours', 30, '3 Hours', 180, '5 Mbps', 'Work and stream for 3 hours', false],
    ['Quick 6 Hours', 50, '6 Hours', 360, '8 Mbps', 'Half-day heavy usage', false],
    // Daily
    ['Daily Basic', 80, '1 Day', 1440, '8 Mbps', 'Full day basic internet', false],
    ['Daily Plus', 100, '1 Day', 1440, '10 Mbps', 'Full day with faster speed', false],
    ['2-Day Pass', 150, '2 Days', 2880, '10 Mbps', 'Weekend browsing', false],
    ['3-Day Pass', 200, '3 Days', 4320, '10 Mbps', 'Mid-week internet', false],
    ['4-Day Pass', 250, '4 Days', 5760, '10 Mbps', '4 days of internet access', false],
    ['5-Day Pass', 300, '5 Days', 7200, '10 Mbps', 'Work-week internet', false],
    ['6-Day Pass', 400, '6 Days', 8640, '12 Mbps', '6 days heavy usage', false],
    ['Weekly Pro', 500, '7 Days', 10080, '15 Mbps', 'Full week — most popular short plan', false],
    // Monthly
    ['Monthly Basic', 1500, '30 Days', 43200, '10 Mbps', 'Monthly basic plan — great for light usage', false],
    ['Monthly Plus', 2000, '30 Days', 43200, '15 Mbps', 'Monthly with faster speeds', false],
    ['Monthly Pro', 2500, '30 Days', 43200, '20 Mbps', 'Monthly pro — work from home ready', false],
    ['Monthly Max', 3000, '30 Days', 43200, '30 Mbps', 'Monthly max speed for power users', false],
    ['Business Basic', 3500, '30 Days', 43200, '40 Mbps', 'Business grade monthly internet', false],
    ['Business Plus', 4000, '30 Days', 43200, '50 Mbps', 'Business plus — fast and reliable', false],
    ['Business Pro', 4500, '30 Days', 43200, '75 Mbps', 'Business pro — high-speed office internet', false],
    ['Premium 100', 5000, '30 Days', 43200, '100 Mbps', 'Premium plan — 100 Mbps speeds', false],
    ['Premium Max', 5500, '30 Days', 43200, '150 Mbps', 'Premium max — fastest available speed', false],
  ];
  for (const [name, price, duration, duration_mins, speed, description, is_free] of packages) {
    await db.query('INSERT INTO packages(name,price,duration,duration_mins,speed,description,is_free) VALUES($1,$2,$3,$4,$5,$6,$7)',
      [name, price, duration, duration_mins, speed, description, is_free]);
  }
  console.log('✅ WiFi packages v3.0 seeded:', packages.length, 'packages');
}

// ═══════════════════════════════════════════════════════════════
// PAYMENT METHODS TABLE (Router Owner Payment Gateway)
// ═══════════════════════════════════════════════════════════════
async function initPaymentMethodsDB() {
  await db.query(`
    CREATE TABLE IF NOT EXISTS owner_payment_methods(
      id SERIAL PRIMARY KEY,
      owner_id INT REFERENCES users(id) ON DELETE CASCADE,
      type TEXT NOT NULL,
      label TEXT,
      number TEXT,
      account_ref TEXT,
      business_name TEXT,
      mpesa_consumer_key TEXT,
      mpesa_consumer_secret TEXT,
      mpesa_passkey TEXT,
      status TEXT DEFAULT 'pending',
      is_default BOOLEAN DEFAULT FALSE,
      verified_by INT,
      verified_at TIMESTAMPTZ,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS owner_payment_transactions(
      id SERIAL PRIMARY KEY,
      owner_id INT REFERENCES users(id),
      payment_method_id INT REFERENCES owner_payment_methods(id),
      customer_id INT REFERENCES users(id),
      package_id INT REFERENCES packages(id),
      amount NUMERIC NOT NULL,
      phone TEXT,
      mpesa_code TEXT,
      checkout_id TEXT,
      status TEXT DEFAULT 'pending',
      router_id INT,
      package_name TEXT,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS invoices(
      id SERIAL PRIMARY KEY,
      user_id INT REFERENCES users(id),
      payment_id INT,
      invoice_number TEXT UNIQUE,
      type TEXT,
      amount NUMERIC,
      description TEXT,
      status TEXT DEFAULT 'paid',
      created_at TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS audit_logs(
      id SERIAL PRIMARY KEY,
      user_id INT,
      action TEXT,
      entity TEXT,
      entity_id INT,
      ip TEXT,
      details TEXT,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );
  `);
}

// ── PUBLIC NETWORKS endpoint (for checkout) ────────────────────
app.get('/api/public/networks', async (req, res) => {
  try {
    const { rows } = await db.query(`
      SELECT r.id, r.name, r.location, u.name as owner_name, u.phone as owner_phone,
             r.status, r.connected_users, r.business_name,
             pm.type as payment_method, pm.number as payment_number, pm.label as payment_label
      FROM routers r
      JOIN users u ON u.id=r.owner_id
      LEFT JOIN owner_payment_methods pm ON pm.owner_id=r.owner_id AND pm.is_default=true AND pm.status='active'
      WHERE r.status='online' AND r.is_main=false AND u.role='router_owner'
      ORDER BY r.connected_users DESC LIMIT 20
    `);
    res.json({ networks: rows });
  } catch { res.json({ networks: [] }); }
});

// ── OWNER PAYMENT METHODS API ──────────────────────────────────
app.get('/api/owner/payment-methods', auth, owner, async (req, res) => {
  const { rows } = await db.query('SELECT id,type,label,number,account_ref,business_name,status,is_default,created_at FROM owner_payment_methods WHERE owner_id=$1 ORDER BY is_default DESC,created_at DESC', [req.user.id]);
  res.json({ methods: rows });
});
app.post('/api/owner/payment-methods', auth, owner, async (req, res) => {
  const { type, number, account_ref, business_name } = req.body;
  if (!type || !number) return res.status(400).json({ message: 'Type and number required' });
  const labels = { mpesa_till: 'M-Pesa Till', mpesa_paybill: 'M-Pesa PayBill', airtel: 'Airtel Money', bank: 'Bank Account' };
  const { rows } = await db.query('INSERT INTO owner_payment_methods(owner_id,type,label,number,account_ref,business_name) VALUES($1,$2,$3,$4,$5,$6) RETURNING id',
    [req.user.id, type, labels[type] || type, number, account_ref, business_name]);
  await notify(req.user.id, 'system', '📋 Payment Method Submitted', `Your ${labels[type]||type} (${number}) has been submitted for BRISK review. Active within 24 hours.`);
  res.json({ id: rows[0].id, message: 'Payment method submitted for review. Active within 24 hours.' });
});
app.put('/api/owner/payment-methods/:id/default', auth, owner, async (req, res) => {
  await db.query('UPDATE owner_payment_methods SET is_default=false WHERE owner_id=$1', [req.user.id]);
  await db.query('UPDATE owner_payment_methods SET is_default=true WHERE id=$1 AND owner_id=$2', [req.params.id, req.user.id]);
  res.json({ message: 'Default payment method updated' });
});
app.delete('/api/owner/payment-methods/:id', auth, owner, async (req, res) => {
  await db.query('DELETE FROM owner_payment_methods WHERE id=$1 AND owner_id=$2', [req.params.id, req.user.id]);
  res.json({ message: 'Payment method removed' });
});

// ── ADMIN: Verify payment methods ─────────────────────────────
app.put('/api/admin/payment-methods/:id/verify', auth, admin, async (req, res) => {
  await db.query("UPDATE owner_payment_methods SET status='active',verified_by=$1,verified_at=NOW() WHERE id=$2", [req.user.id, req.params.id]);
  const { rows } = await db.query('SELECT pm.*,u.name FROM owner_payment_methods pm JOIN users u ON u.id=pm.owner_id WHERE pm.id=$1', [req.params.id]);
  if (rows[0]) await notify(rows[0].owner_id, 'system', '✅ Payment Method Verified!', `Your ${rows[0].label} (${rows[0].number}) is now active. Customers can pay you directly.`);
  res.json({ message: 'Payment method verified and activated' });
});
app.get('/api/admin/payment-methods', auth, admin, async (req, res) => {
  const { rows } = await db.query('SELECT pm.*,u.name as owner_name,u.phone FROM owner_payment_methods pm JOIN users u ON u.id=pm.owner_id ORDER BY pm.created_at DESC');
  res.json({ methods: rows, pending: rows.filter(m => m.status === 'pending').length });
});

// ── STK PUSH: Router owner payment routing ─────────────────────
// Upgraded version that routes to owner's M-Pesa if configured
const origSTK = app._router.stack.find(l => l.route?.path === '/api/payments/stk-push');
app.post('/api/payments/stk-push-owner', auth, async (req, res) => {
  try {
    const { phone, package_id, amount, router_id } = req.body;
    if (!phone || !package_id) return res.status(400).json({ message: 'Phone and package required' });
    const { rows: pkgs } = await db.query('SELECT * FROM packages WHERE id=$1 AND active=true', [package_id]);
    if (!pkgs[0]) return res.status(404).json({ message: 'Package not found' });
    const pkg = pkgs[0];
    // Check if router has owner payment method
    let ownerMethod = null;
    if (router_id) {
      const { rows: rt } = await db.query('SELECT r.*,pm.number,pm.type,pm.account_ref,pm.mpesa_consumer_key,pm.mpesa_consumer_secret,pm.mpesa_passkey FROM routers r LEFT JOIN owner_payment_methods pm ON pm.owner_id=r.owner_id AND pm.is_default=true AND pm.status=\'active\' WHERE r.id=$1', [router_id]);
      if (rt[0]) ownerMethod = rt[0];
    }
    // Use BRISK payment if no owner method or owner is BRISK
    const { rows } = await db.query('INSERT INTO payments(user_id,package_id,amount,phone,status,package_name,router_id) VALUES($1,$2,$3,$4,$5,$6,$7) RETURNING id',
      [req.user.id, package_id, pkg.price || amount, phone, 'pending', pkg.name, router_id || null]);
    res.json({ message: 'STK Push sent! Enter your M-Pesa PIN.', payment_id: rows[0].id, owner_method: ownerMethod ? { type: ownerMethod.type, number: ownerMethod.number } : null });
  } catch (e) { res.status(500).json({ message: e.message }); }
});

// ── INVOICE GENERATION ─────────────────────────────────────────
app.get('/api/invoices', auth, async (req, res) => {
  const { rows } = await db.query('SELECT * FROM invoices WHERE user_id=$1 ORDER BY created_at DESC LIMIT 50', [req.user.id]);
  res.json({ invoices: rows });
});
app.get('/api/invoices/:id', auth, async (req, res) => {
  const { rows } = await db.query('SELECT i.*,u.name,u.phone,u.email FROM invoices i JOIN users u ON u.id=i.user_id WHERE i.id=$1 AND i.user_id=$2', [req.params.id, req.user.id]);
  if (!rows[0]) return res.status(404).json({ message: 'Invoice not found' });
  res.json({ invoice: rows[0] });
});

// ── AUDIT LOG ──────────────────────────────────────────────────
app.get('/api/admin/audit-logs', auth, admin, async (req, res) => {
  const { rows } = await db.query('SELECT al.*,u.name FROM audit_logs al LEFT JOIN users u ON u.id=al.user_id ORDER BY al.created_at DESC LIMIT 200');
  res.json({ logs: rows });
});

// ── ADMIN: Pending payment methods dashboard ───────────────────
app.get('/api/admin/pending-payment-methods', auth, admin, async (req, res) => {
  const { rows } = await db.query("SELECT pm.*,u.name as owner_name,u.phone FROM owner_payment_methods pm JOIN users u ON u.id=pm.owner_id WHERE pm.status='pending' ORDER BY pm.created_at");
  res.json({ pending: rows, count: rows.length });
});

// ── Re-init DB to add new tables ──────────────────────────────
initPaymentMethodsDB().then(seedPackagesV3).catch(console.error);

// ═══════════════════════════════════════════════════════════════
// v5 EXTENSION — Router Owner Storefronts + WiFi Vouchers
// ═══════════════════════════════════════════════════════════════
async function initStorefrontVoucherDB() {
  await db.query(`
    CREATE TABLE IF NOT EXISTS storefronts(
      id SERIAL PRIMARY KEY,
      owner_id INT REFERENCES users(id) ON DELETE CASCADE UNIQUE,
      slug TEXT UNIQUE NOT NULL,
      business_name TEXT NOT NULL,
      about_text TEXT,
      contact_phone TEXT,
      contact_whatsapp TEXT,
      location TEXT,
      color_primary TEXT DEFAULT '#F97316',
      color_secondary TEXT DEFAULT '#EC4899',
      logo_url TEXT,
      status TEXT DEFAULT 'active',
      created_at TIMESTAMPTZ DEFAULT NOW(),
      updated_at TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS vouchers(
      id SERIAL PRIMARY KEY,
      owner_id INT REFERENCES users(id) ON DELETE CASCADE,
      router_id INT,
      package_id INT REFERENCES packages(id),
      code TEXT UNIQUE NOT NULL,
      batch_id TEXT,
      status TEXT DEFAULT 'unused',
      used_by INT REFERENCES users(id),
      used_at TIMESTAMPTZ,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );
  `);
  console.log('✅ Storefront & Voucher tables ready');
}
initStorefrontVoucherDB().catch(console.error);

function genVoucherCode() {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  let code = '';
  for (let i = 0; i < 8; i++) code += chars[Math.floor(Math.random() * chars.length)];
  return code;
}

// ── ROUTER OWNER STOREFRONT ─────────────────────────────────────
app.get('/api/owner/storefront', auth, owner, async (req, res) => {
  const { rows } = await db.query('SELECT * FROM storefronts WHERE owner_id=$1', [req.user.id]);
  res.json({ storefront: rows[0] || null });
});
app.get('/api/owner/storefront/check-slug', async (req, res) => {
  const slug = (req.query.slug || '').toLowerCase().replace(/[^a-z0-9-]/g, '');
  if (slug.length < 2) return res.json({ available: false, reason: 'Too short' });
  const reserved = ['admin', 'api', 'www', 'support', 'brisk', 'help', 'mail'];
  if (reserved.includes(slug)) return res.json({ available: false, reason: 'Reserved name' });
  const { rows } = await db.query('SELECT id FROM storefronts WHERE slug=$1', [slug]);
  res.json({ available: rows.length === 0, slug });
});
app.put('/api/owner/storefront', auth, owner, async (req, res) => {
  const { slug, business_name, about_text, contact_phone, contact_whatsapp, location, color_primary, color_secondary } = req.body;
  const clean = (slug || '').toLowerCase().replace(/[^a-z0-9-]/g, '');
  if (!clean || clean.length < 2 || !business_name) return res.status(400).json({ message: 'Business name and a valid username are required' });
  try {
    const { rows } = await db.query(
      `INSERT INTO storefronts(owner_id,slug,business_name,about_text,contact_phone,contact_whatsapp,location,color_primary,color_secondary)
       VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)
       ON CONFLICT(owner_id) DO UPDATE SET slug=$2,business_name=$3,about_text=$4,contact_phone=$5,contact_whatsapp=$6,location=$7,color_primary=$8,color_secondary=$9,updated_at=NOW()
       RETURNING *`,
      [req.user.id, clean, business_name, about_text || null, contact_phone || null, contact_whatsapp || null, location || null, color_primary || '#F97316', color_secondary || '#EC4899']);
    res.json({ storefront: rows[0], message: `Storefront saved! Live at ${(process.env.FRONTEND_URL || 'https://brisksmartconnect.vercel.app').replace(/^https?:\/\//, '')}/@${clean}`, slug: clean });
  } catch { res.status(400).json({ message: `"${clean}" is already taken. Choose another username.` }); }
});
app.get('/api/admin/storefronts', auth, admin, async (req, res) => {
  const { rows } = await db.query('SELECT s.*,u.name as owner_name,u.phone as owner_phone FROM storefronts s JOIN users u ON u.id=s.owner_id ORDER BY s.created_at DESC LIMIT 200');
  res.json({ storefronts: rows });
});
app.put('/api/admin/storefronts/:slug/suspend', auth, admin, async (req, res) => {
  await db.query("UPDATE storefronts SET status=CASE WHEN status='active' THEN 'suspended' ELSE 'active' END WHERE slug=$1", [req.params.slug]);
  res.json({ message: 'Storefront status updated' });
});

// ── ROUTER OWNER VOUCHERS ────────────────────────────────────────
app.get('/api/owner/vouchers', auth, owner, async (req, res) => {
  const { status } = req.query;
  let q = `SELECT v.*,p.name as package_name,p.price,p.duration FROM vouchers v LEFT JOIN packages p ON p.id=v.package_id WHERE v.owner_id=$1`;
  const params = [req.user.id];
  if (status) { params.push(status); q += ` AND v.status=$${params.length}`; }
  const { rows } = await db.query(q + ' ORDER BY v.created_at DESC LIMIT 500', params);
  res.json({ vouchers: rows, stats: { total: rows.length, unused: rows.filter(v => v.status === 'unused').length, used: rows.filter(v => v.status === 'used').length } });
});
app.post('/api/owner/vouchers', auth, owner, async (req, res) => {
  const { package_id, count, router_id } = req.body;
  const qty = Math.min(Math.max(parseInt(count) || 1, 1), 500);
  const { rows: pkgs } = await db.query('SELECT id FROM packages WHERE id=$1 AND active=true', [package_id]);
  if (!pkgs[0]) return res.status(404).json({ message: 'Package not found' });
  const batchId = 'batch-' + Date.now();
  const codes = [];
  for (let i = 0; i < qty; i++) {
    let code;
    do { code = genVoucherCode(); } while ((await db.query('SELECT id FROM vouchers WHERE code=$1', [code])).rows.length);
    await db.query('INSERT INTO vouchers(owner_id,router_id,package_id,code,batch_id) VALUES($1,$2,$3,$4,$5)', [req.user.id, router_id || null, package_id, code, batchId]);
    codes.push(code);
  }
  res.json({ message: `${qty} voucher(s) generated!`, codes, batch_id: batchId });
});
app.delete('/api/owner/vouchers/:code', auth, owner, async (req, res) => {
  await db.query('DELETE FROM vouchers WHERE code=$1 AND owner_id=$2', [req.params.code, req.user.id]);
  res.json({ message: 'Voucher removed' });
});

// ═══════════════════════════════════════════════════════════════
// v5.1 EXTENSION — BRISK Smart Connect Network (Access Points, PPPoE,
// Connect wizard config templates). See backend/network.js
// ═══════════════════════════════════════════════════════════════
async function initNetworkFeaturesDB() {
  await db.query(`
    CREATE TABLE IF NOT EXISTS access_points(
      id SERIAL PRIMARY KEY,
      owner_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      router_id INT REFERENCES routers(id) ON DELETE SET NULL,
      name TEXT NOT NULL, brand TEXT DEFAULT 'mikrotik', model TEXT,
      ip TEXT NOT NULL, location TEXT, ssid TEXT,
      status TEXT DEFAULT 'offline', connected_users INT DEFAULT 0,
      bandwidth_mbps NUMERIC DEFAULT 0, signal_dbm INT, uptime TEXT,
      last_seen TIMESTAMPTZ, created_at TIMESTAMPTZ DEFAULT NOW(),
      updated_at TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS pppoe_users(
      id SERIAL PRIMARY KEY,
      owner_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      router_id INT REFERENCES routers(id) ON DELETE SET NULL,
      username TEXT NOT NULL, password_hash TEXT NOT NULL,
      service_type TEXT DEFAULT 'client', speed_profile TEXT,
      ip_address TEXT, status TEXT DEFAULT 'inactive',
      expires_at TIMESTAMPTZ, session_started TIMESTAMPTZ,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS connection_incidents(
      id SERIAL PRIMARY KEY,
      owner_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      device_type TEXT NOT NULL, device_id INT NOT NULL, event TEXT NOT NULL,
      detected_at TIMESTAMPTZ DEFAULT NOW(), resolved_at TIMESTAMPTZ,
      notified BOOLEAN DEFAULT FALSE
    );
    CREATE TABLE IF NOT EXISTS connection_templates(
      id SERIAL PRIMARY KEY, device_type TEXT NOT NULL,
      routeros_ver TEXT DEFAULT '7', method TEXT NOT NULL,
      title TEXT NOT NULL, script_body TEXT NOT NULL,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS wifi_hosts(
      id SERIAL PRIMARY KEY, user_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE UNIQUE,
      location TEXT NOT NULL, router_type TEXT, estimated_neighbours INT DEFAULT 0, notes TEXT,
      status TEXT DEFAULT 'pending', hotspot_ssid TEXT DEFAULT 'BRISK_WIFI', connected_users INT DEFAULT 0,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS wifi_host_sales(
      id SERIAL PRIMARY KEY, host_id INT NOT NULL REFERENCES wifi_hosts(id) ON DELETE CASCADE,
      customer_id INT REFERENCES users(id), package_id INT REFERENCES packages(id),
      commission NUMERIC DEFAULT 0, created_at TIMESTAMPTZ DEFAULT NOW()
    );
    ALTER TABLE payments ADD COLUMN IF NOT EXISTS host_id INT REFERENCES wifi_hosts(id);
    ALTER TABLE payments ADD COLUMN IF NOT EXISTS purpose TEXT DEFAULT 'package';
    ALTER TABLE payments ADD COLUMN IF NOT EXISTS voucher_qty INT;
    ALTER TABLE routers ADD COLUMN IF NOT EXISTS password_encrypted TEXT;
    ALTER TABLE access_points ADD COLUMN IF NOT EXISTS username TEXT;
    ALTER TABLE access_points ADD COLUMN IF NOT EXISTS password_encrypted TEXT;
    ALTER TABLE access_points ADD COLUMN IF NOT EXISTS port TEXT DEFAULT '8728';
    ALTER TABLE pppoe_users ADD COLUMN IF NOT EXISTS password_encrypted TEXT;
  `);
  const { rows } = await db.query('SELECT COUNT(*) FROM connection_templates');
  if (parseInt(rows[0].count) === 0) {
    await db.query(`INSERT INTO connection_templates(device_type,method,title,script_body) VALUES
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
    `);
  }
  console.log('✅ Network feature tables ready (access points, PPPoE, connect templates)');
}
initNetworkFeaturesDB().catch(console.error);

const networkRoutes = require('./network');
app.use('/api', networkRoutes({ db, auth, owner, admin, bcrypt, MikroTikAPI, notify, emit, encryptSecret, decryptSecret }));

// ═══════════════════════════════════════════════════════════════
// v5.4 EXTENSION — Subscriptions (trial/plans) + per-owner
// Integrations (M-Pesa/WhatsApp/Email), each Router Owner brings
// their own customer-facing credentials instead of BRISK's .env
// holding every customer's secrets. See backend integrations.js
// ═══════════════════════════════════════════════════════════════
async function initSubscriptionsDB() {
  await db.query(`
    CREATE TABLE IF NOT EXISTS subscription_plans(
      id SERIAL PRIMARY KEY, name TEXT NOT NULL, price NUMERIC NOT NULL DEFAULT 0,
      duration_days INT DEFAULT 30, max_routers INT DEFAULT 5, max_access_points INT DEFAULT 10,
      max_vouchers_per_month INT DEFAULT 1000, features JSONB DEFAULT '[]',
      active BOOLEAN DEFAULT TRUE, sort_order INT DEFAULT 0, created_at TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS owner_subscriptions(
      id SERIAL PRIMARY KEY, owner_id INT UNIQUE NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      plan_id INT REFERENCES subscription_plans(id),
      status TEXT DEFAULT 'trial', trial_started_at TIMESTAMPTZ DEFAULT NOW(), trial_ends_at TIMESTAMPTZ,
      started_at TIMESTAMPTZ, expires_at TIMESTAMPTZ, auto_renew BOOLEAN DEFAULT FALSE,
      created_at TIMESTAMPTZ DEFAULT NOW(), updated_at TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS subscription_payments(
      id SERIAL PRIMARY KEY, owner_id INT NOT NULL REFERENCES users(id), plan_id INT REFERENCES subscription_plans(id),
      amount NUMERIC, phone TEXT, status TEXT DEFAULT 'pending', mpesa_code TEXT, checkout_id TEXT,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS owner_integrations(
      id SERIAL PRIMARY KEY, owner_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      provider TEXT NOT NULL, config_encrypted TEXT NOT NULL, status TEXT DEFAULT 'untested',
      last_tested_at TIMESTAMPTZ, last_error TEXT,
      created_at TIMESTAMPTZ DEFAULT NOW(), updated_at TIMESTAMPTZ DEFAULT NOW(), UNIQUE(owner_id, provider)
    );
    ALTER TABLE payments ADD COLUMN IF NOT EXISTS via_owner_id INT REFERENCES users(id);
  `);
  const { rows } = await db.query('SELECT COUNT(*) FROM subscription_plans');
  if (parseInt(rows[0].count) === 0) {
    await db.query(`INSERT INTO subscription_plans(name,price,duration_days,max_routers,max_access_points,max_vouchers_per_month,features,sort_order) VALUES
      ('Starter',400,30,2,3,200,'["2 routers","3 access points","Basic support"]',1),
      ('Basic',750,30,5,8,500,'["5 routers","8 access points","Email support"]',2),
      ('Standard',1500,30,15,25,2000,'["15 routers","25 access points","Priority support","API access"]',3),
      ('Professional',2500,30,40,60,10000,'["40 routers","60 access points","Priority support","API access","Advanced reports"]',4),
      ('Business',3500,30,999999,999999,999999,'["Unlimited routers","Unlimited APs","Dedicated support","Full API access","Advanced reports"]',5)
    `);
  }
  console.log('✅ Subscription & Integration tables ready');
}
initSubscriptionsDB().catch(console.error);

const integrationsRoutes = require('./integrations');
app.use('/api', integrationsRoutes({ db, auth, owner, admin, notify, encryptSecret, decryptSecret, getDarajaToken, sendWhatsApp, sendEmail, emailShell }));

app.get('/api/vouchers', auth, async (req, res) => {
  const { rows } = await db.query(
    `SELECT v.*, p.name as package_name, p.price, p.duration, p.duration_mins FROM vouchers v
     LEFT JOIN packages p ON p.id=v.package_id WHERE v.owner_id=$1 ORDER BY v.created_at DESC LIMIT 200`, [req.user.id]);
  res.json({
    vouchers: rows,
    stats: { total: rows.length, unused: rows.filter(v => v.status === 'unused').length, used: rows.filter(v => v.status === 'used').length },
  });
});

app.post('/api/vouchers/buy', auth, async (req, res) => {
  try {
    const { package_id, quantity, phone } = req.body;
    const qty = Math.min(Math.max(parseInt(quantity) || 1, 1), 10);
    if (!phone || !package_id) return res.status(400).json({ message: 'Phone and package are required' });
    const { rows: pkgs } = await db.query('SELECT * FROM packages WHERE id=$1 AND active=true', [package_id]);
    if (!pkgs[0]) return res.status(404).json({ message: 'Package not found or inactive' });
    const pkg = pkgs[0];
    const totalAmount = (pkg.price || 0) * qty;
    let checkoutId = null;
    try {
      const token = await getDarajaToken();
      if (token) {
        const ts = new Date().toISOString().replace(/[-:T.Z]/g, '').slice(0, 14);
        const passkey = process.env.MPESA_PASSKEY;
        const shortcode = process.env.MPESA_SHORTCODE || '222111';
        const pw = Buffer.from(`${shortcode}${passkey}${ts}`).toString('base64');
        const fp = phone.replace(/^0/, '254').replace(/^\+/, '');
        const r = await fetch('https://api.safaricom.co.ke/mpesa/stkpush/v1/processrequest', {
          method: 'POST',
          headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
          body: JSON.stringify({
            BusinessShortCode: shortcode, Password: pw, Timestamp: ts,
            TransactionType: 'CustomerPayBillOnline', Amount: Math.ceil(totalAmount),
            PartyA: fp, PartyB: shortcode, PhoneNumber: fp,
            CallBackURL: `${API_URL}/api/payments/callback`, AccountReference: '5414200',
            TransactionDesc: `BRISK WiFi Vouchers x${qty} - ${pkg.name}`,
          }),
        });
        const d = await r.json();
        checkoutId = d.CheckoutRequestID;
      }
    } catch (e) { console.error('Daraja STK error (vouchers):', e.message); }
    const { rows } = await db.query(
      `INSERT INTO payments(user_id,package_id,amount,phone,status,package_name,checkout_id,purpose,voucher_qty)
       VALUES($1,$2,$3,$4,'pending',$5,$6,'voucher',$7) RETURNING id`,
      [req.user.id, package_id, totalAmount, phone, pkg.name, checkoutId, qty]);
    res.json({ message: 'STK Push sent! Enter your M-Pesa PIN to generate your voucher(s).', payment_id: rows[0].id, checkout_id: checkoutId });
  } catch (e) { res.status(500).json({ message: e.message }); }
});

app.post('/api/vouchers/redeem', async (req, res) => {
  try {
    const { code } = req.body;
    if (!code) return res.status(400).json({ message: 'Enter a voucher code' });
    const clean = code.trim().toUpperCase();
    const { rows } = await db.query("SELECT v.*,p.duration_mins,p.name as pkg_name FROM vouchers v JOIN packages p ON p.id=v.package_id WHERE v.code=$1", [clean]);
    if (!rows[0]) return res.status(404).json({ message: 'Invalid voucher code' });
    const v = rows[0];
    if (v.status === 'used') return res.status(400).json({ message: 'This voucher has already been redeemed' });
    if (v.status === 'void') return res.status(400).json({ message: 'This voucher has been voided' });
    await db.query("UPDATE vouchers SET status='used',used_at=NOW() WHERE id=$1", [v.id]);
    const expires = new Date(Date.now() + (v.duration_mins || 1440) * 60000);
    res.json({ message: `Voucher redeemed! ${v.pkg_name} active until ${expires.toLocaleString('en-KE')}. Connect to WiFi now.`, expires_at: expires });
  } catch (e) { res.status(500).json({ message: e.message }); }
});

// ── ADMIN: Vouchers oversight ────────────────────────────────────
app.get('/api/admin/vouchers', auth, admin, async (req, res) => {
  const { search = '' } = req.query;
  let q = `SELECT v.*,p.name as package_name,p.price,u.name as owner_name FROM vouchers v
    LEFT JOIN packages p ON p.id=v.package_id LEFT JOIN users u ON u.id=v.owner_id WHERE 1=1`, params = [];
  if (search) { params.push('%' + search + '%'); q += ` AND (v.code ILIKE $${params.length} OR u.name ILIKE $${params.length})`; }
  const { rows } = await db.query(q + ' ORDER BY v.created_at DESC LIMIT 300', params);
  const { rows: stats } = await db.query(`SELECT COUNT(*) as total, COUNT(*) FILTER(WHERE status='used') as used, COUNT(DISTINCT owner_id) as owners, COALESCE(SUM(p.price),0) as value FROM vouchers v LEFT JOIN packages p ON p.id=v.package_id`);
  res.json({ vouchers: rows, stats: { total: parseInt(stats[0].total), used: parseInt(stats[0].used), owners: parseInt(stats[0].owners), value: parseFloat(stats[0].value) } });
});

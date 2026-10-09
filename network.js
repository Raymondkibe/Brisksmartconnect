'use strict';
// ════════════════════════════════════════════════════════════════
//  BRISK Smart Connect — Network / Connect Wizard module
//  Mounted from server.js:
//    const networkRoutes = require('./network');
//    app.use('/api', networkRoutes({ db, auth, owner, admin, bcrypt,
//      MikroTikAPI, notify, emit }));
//
//  Nothing here touches or replaces existing routes in server.js —
//  it only ADDS new endpoints under /api/owner/access-points,
//  /api/owner/pppoe-users, /api/owner/connect/*, /api/owner/network,
//  /api/connection-help/*.
// ════════════════════════════════════════════════════════════════
const express = require('express');

module.exports = function networkRoutes({ db, auth, owner, admin, bcrypt, MikroTikAPI, notify, emit, encryptSecret, decryptSecret }) {
  const router = express.Router();
  // Access point rows carry password_encrypted internally so BRISK can
  // reconnect later — strip it before it ever reaches the browser.
  function scrubAP(a) { if (!a) return a; const { password_encrypted, ...safe } = a; return safe; }
  function scrubAPs(list) { return (list || []).map(scrubAP); }
  function apConnConfig(a) { return { ...a, password: decryptSecret(a.password_encrypted) }; }

  // ── DEVICE COMPATIBILITY / OPTIONS (Connect wizard, step 1 & 2) ─
  const DEVICE_TYPES = [
    { id: 'mikrotik_router', label: 'MikroTik Router', brand: 'mikrotik' },
    { id: 'mikrotik_hotspot', label: 'MikroTik Hotspot', brand: 'mikrotik' },
    { id: 'mikrotik_pppoe', label: 'MikroTik PPPoE', brand: 'mikrotik' },
    { id: 'access_point', label: 'Access Point', brand: 'generic' },
    { id: 'omada', label: 'TP-Link Omada', brand: 'omada' },
    { id: 'unifi', label: 'Ubiquiti UniFi', brand: 'unifi' },
    { id: 'openwrt', label: 'OpenWrt', brand: 'openwrt' },
    { id: 'custom', label: 'Other / Custom Router', brand: 'other' },
  ];
  const CONNECTION_METHODS = [
    { id: 'local', label: 'Local Network' },
    { id: 'public_ip', label: 'Public IP' },
    { id: 'vpn', label: 'VPN' },
    { id: 'wireguard', label: 'WireGuard' },
    { id: 'api', label: 'API' },
    { id: 'rest_api', label: 'REST API' },
    { id: 'manual', label: 'Manual Configuration' },
  ];
  const MIKROTIK_MODELS = ['hAP', 'hAP ac', 'hAP ac2/ac3', 'hEX', 'hEX S', 'RB series', 'CRS series', 'CCR series', 'RB5009', 'CHR (Cloud Hosted Router)', 'Other RouterOS device'];

  router.get('/owner/connect/options', auth, owner, (req, res) => {
    res.json({ device_types: DEVICE_TYPES, connection_methods: CONNECTION_METHODS, mikrotik_models: MIKROTIK_MODELS });
  });

  // ── STEP 3: Generate configuration script from a tested template ─
  // Never accepts arbitrary script text from the client — only picks
  // a template by (device_type, method) and fills in placeholders.
  router.post('/owner/connect/script', auth, owner, async (req, res) => {
    const { device_type, method, router_ip, interface: iface, api_port } = req.body;
    if (!device_type || !method) return res.status(400).json({ message: 'device_type and method are required' });
    const templateKey = device_type === 'mikrotik_router' ? 'mikrotik_api'
      : ['mikrotik_hotspot', 'mikrotik_pppoe'].includes(device_type) ? device_type
      : method === 'wireguard' ? 'mikrotik_wireguard' : 'mikrotik_api';
    const { rows } = await db.query('SELECT * FROM connection_templates WHERE device_type=$1 ORDER BY id DESC LIMIT 1', [templateKey]);
    if (!rows[0]) return res.status(404).json({ message: 'No tested template available for that combination yet' });
    const apiUser = 'brisk_' + Math.random().toString(36).slice(2, 8);
    const apiPass = Math.random().toString(36).slice(2, 10) + Math.random().toString(36).slice(2, 6).toUpperCase();
    const filled = rows[0].script_body
      .replace(/{{ROUTER_IP}}/g, router_ip || '192.168.88.1')
      .replace(/{{INTERFACE}}/g, iface || 'ether1')
      .replace(/{{API_USER}}/g, apiUser)
      .replace(/{{API_PASSWORD}}/g, apiPass)
      .replace(/{{API_PORT}}/g, api_port || '8728')
      .replace(/{{BRISK_SERVER_IP}}/g, process.env.BRISK_SERVER_IP || '<BRISK will show this after deployment>')
      .replace(/{{WG_PRIVATE_KEY}}/g, '<generate on router: /interface wireguard print>')
      .replace(/{{BRISK_WG_PUBLIC_KEY}}/g, process.env.BRISK_WG_PUBLIC_KEY || '<contact support for BRISK WireGuard public key>');
    res.json({ title: rows[0].title, script: filled, suggested_api_user: apiUser, suggested_api_password: apiPass,
      instructions: ['Open WinBox and connect to your router', 'Open Terminal', 'Paste the script below', 'Press Enter to apply', 'Return to BRISK and click Test Connection'] });
  });

  // ── STEP 3b: "Scan for routers" — BRISK's cloud backend cannot see
  // a router owner's local LAN directly. Be honest about that instead
  // of faking a scan: this only works if/when a local BRISK agent or
  // the router itself reports in. For now, return known devices only.
  router.post('/owner/connect/scan', auth, owner, async (req, res) => {
    const { rows } = await db.query("SELECT id,name,ip,'router' as kind FROM routers WHERE owner_id=$1 AND status='online' UNION ALL SELECT id,name,ip,'access_point' as kind FROM access_points WHERE owner_id=$1 AND status='online'", [req.user.id]);
    res.json({
      found: rows,
      note: rows.length
        ? 'Showing devices already connected to your BRISK account. Automatic LAN discovery of brand-new devices requires the BRISK local network agent — enter new devices manually below for now.'
        : 'No BRISK-connected devices found yet. Automatic LAN scanning of brand-new hardware requires the BRISK local network agent (coming soon) — add your router manually using its IP address for now.',
    });
  });

  // ── STEP 5: Test connection (reuses MikroTikAPI, real if configured) ─
  router.post('/owner/connect/test', auth, owner, async (req, res) => {
    const { ip, port, username, password } = req.body;
    if (!ip) return res.status(400).json({ message: 'IP address required' });
    const live = await MikroTikAPI.getStatus({ ip, port, username, password, name: 'Test' });
    const checks = {
      router_reachable: !!live.connected,
      api_available: !!live.connected,
      credentials_valid: !!live.connected,
      routeros_version: live.version || null,
      identity: live.identity || null,
      hotspot_available: !!live.connected,
      internet_interface: live.connected ? (live.interfaces || [])[0] || null : null,
    };
    res.json({ connected: !!live.connected, checks, message: live.connected ? '✓ Router Connected' : 'Router did not respond — check power, cable, IP address and firewall rules' });
  });

  // ══════════════════════ ACCESS POINTS ═══════════════════════════
  router.get('/owner/access-points', auth, owner, async (req, res) => {
    const { rows } = await db.query('SELECT * FROM access_points WHERE owner_id=$1 ORDER BY created_at DESC', [req.user.id]);
    res.json({
      access_points: scrubAPs(rows),
      stats: {
        total: rows.length,
        online: rows.filter(a => a.status === 'online').length,
        users: rows.reduce((s, a) => s + (a.connected_users || 0), 0),
        bandwidth_mbps: rows.reduce((s, a) => s + Number(a.bandwidth_mbps || 0), 0),
      },
    });
  });

  router.post('/owner/access-points', auth, owner, async (req, res) => {
    const { name, brand, model, ip, location, ssid, router_id, username, password, port } = req.body;
    if (!name || !ip) return res.status(400).json({ message: 'Name and IP address required' });
    const passEnc = password ? encryptSecret(password) : null;
    const { rows } = await db.query(
      `INSERT INTO access_points(owner_id,router_id,name,brand,model,ip,location,ssid,username,password_encrypted,port) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) RETURNING *`,
      [req.user.id, router_id || null, name, brand || 'mikrotik', model || null, ip, location || null, ssid || null, username || null, passEnc, port || '8728']);
    await notify(req.user.id, 'system', '✅ Access Point Added', `${name} (${ip}) was added to your network.`);
    res.json({ access_point: scrubAP(rows[0]), message: 'Access point added — click Test to verify it is reachable.' });
  });

  router.put('/owner/access-points/:id', auth, owner, async (req, res) => {
    const { name, location, ssid, router_id, username, password, port } = req.body;
    const passEnc = password ? encryptSecret(password) : null;
    const { rows } = await db.query(
      `UPDATE access_points SET name=COALESCE($1,name),location=COALESCE($2,location),ssid=COALESCE($3,ssid),router_id=COALESCE($4,router_id),
       username=COALESCE($5,username),password_encrypted=COALESCE($6,password_encrypted),port=COALESCE($7,port),updated_at=NOW()
       WHERE id=$8 AND owner_id=$9 RETURNING *`,
      [name, location, ssid, router_id, username || null, passEnc, port || null, req.params.id, req.user.id]);
    if (!rows[0]) return res.status(404).json({ message: 'Access point not found' });
    res.json({ access_point: scrubAP(rows[0]), message: 'Access point updated' });
  });

  router.post('/owner/access-points/:id/test', auth, owner, async (req, res) => {
    const { rows } = await db.query('SELECT * FROM access_points WHERE id=$1 AND owner_id=$2', [req.params.id, req.user.id]);
    if (!rows[0]) return res.status(404).json({ message: 'Access point not found' });
    const live = await MikroTikAPI.getStatus(apConnConfig(rows[0]));
    await db.query("UPDATE access_points SET status=$1,connected_users=$2,bandwidth_mbps=$3,last_seen=NOW() WHERE id=$4",
      [live.connected ? 'online' : 'offline', live.connected_users || 0, live.download_mbps || 0, rows[0].id]).catch(() => {});
    emit('ap_status', { ap_id: rows[0].id, ...live }, 'router_' + (rows[0].router_id || 0));
    res.json({ access_point: scrubAP({ ...rows[0], status: live.connected ? 'online' : 'offline' }), live });
  });

  router.delete('/owner/access-points/:id', auth, owner, async (req, res) => {
    await db.query('DELETE FROM access_points WHERE id=$1 AND owner_id=$2', [req.params.id, req.user.id]);
    res.json({ message: 'Access point removed' });
  });

  // Admin oversight of every AP across all router owners
  router.get('/admin/access-points', auth, admin, async (req, res) => {
    const { rows } = await db.query(`SELECT a.*, u.name as owner_name FROM access_points a JOIN users u ON u.id=a.owner_id ORDER BY a.created_at DESC LIMIT 500`);
    res.json({ access_points: scrubAPs(rows) });
  });

  // ══════════════════════ PPPoE USERS ═════════════════════════════
  router.get('/owner/pppoe-users', auth, owner, async (req, res) => {
    const { rows } = await db.query('SELECT id,username,service_type,speed_profile,ip_address,status,expires_at,session_started,created_at FROM pppoe_users WHERE owner_id=$1 ORDER BY created_at DESC', [req.user.id]);
    res.json({ users: rows, stats: { total: rows.length, active: rows.filter(u => u.status === 'active').length } });
  });

  router.post('/owner/pppoe-users', auth, owner, async (req, res) => {
    const { username, password, service_type, speed_profile, router_id, expires_at } = req.body;
    if (!username || !password) return res.status(400).json({ message: 'Username and password required' });
    const passEnc = encryptSecret(password);
    const { rows } = await db.query(
      `INSERT INTO pppoe_users(owner_id,router_id,username,password_encrypted,service_type,speed_profile,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7) RETURNING id,username,service_type,speed_profile,status,expires_at,created_at`,
      [req.user.id, router_id || null, username, passEnc, service_type || 'client', speed_profile || null, expires_at || null]);
    res.json({ user: rows[0], message: 'PPPoE user created. Push it to the router from Routers → PPPoE.' });
  });

  // Owner needs to relay this password to their customer / router config,
  // so (unlike a login password) it must be revealable — but only to the
  // owner who created it, and only via an explicit action, never in lists.
  router.get('/owner/pppoe-users/:id/reveal', auth, owner, async (req, res) => {
    const { rows } = await db.query('SELECT password_encrypted FROM pppoe_users WHERE id=$1 AND owner_id=$2', [req.params.id, req.user.id]);
    if (!rows[0]) return res.status(404).json({ message: 'PPPoE user not found' });
    res.json({ password: decryptSecret(rows[0].password_encrypted) });
  });

  router.delete('/owner/pppoe-users/:id', auth, owner, async (req, res) => {
    await db.query('DELETE FROM pppoe_users WHERE id=$1 AND owner_id=$2', [req.params.id, req.user.id]);
    res.json({ message: 'PPPoE user removed' });
  });

  // ══════════════════════ MY NETWORK (tree/overview) ══════════════
  router.get('/owner/network', auth, owner, async (req, res) => {
    const [routers, aps, pppoe] = await Promise.all([
      db.query('SELECT * FROM routers WHERE owner_id=$1 ORDER BY created_at ASC', [req.user.id]),
      db.query('SELECT * FROM access_points WHERE owner_id=$1 ORDER BY created_at ASC', [req.user.id]),
      db.query("SELECT COUNT(*) FILTER(WHERE status='active') as active FROM pppoe_users WHERE owner_id=$1", [req.user.id]),
    ]);
    const tree = routers.rows.map(r => ({ ...r, access_points: aps.rows.filter(a => a.router_id === r.id) }));
    const unassignedAps = aps.rows.filter(a => !a.router_id);
    res.json({
      tree, unassigned_access_points: unassignedAps,
      summary: {
        routers: routers.rows.length, routers_online: routers.rows.filter(r => r.status === 'online').length,
        access_points: aps.rows.length, access_points_online: aps.rows.filter(a => a.status === 'online').length,
        connected_users: routers.rows.reduce((s, r) => s + (r.connected_users || 0), 0) + aps.rows.reduce((s, a) => s + (a.connected_users || 0), 0),
        pppoe_active: parseInt(pppoe.rows[0].active) || 0,
      },
    });
  });

  // ══════════════════════ CONNECTION HELP ═════════════════════════
  const HELP_TOPICS = {
    router_offline: { title: 'Router offline', steps: ['Check the router has power (LEDs lit)', 'Check the Ethernet/fibre cable into the router', 'Check your ISP connection is up', 'Power-cycle the router and wait 2 minutes', 'Run Test Connection again from Routers'] },
    internet_not_working: { title: 'Internet not working', steps: ['Confirm the router itself is online in BRISK', 'Check the WAN/internet interface status', 'Contact your ISP to confirm there is no outage', 'Check for cut or loose cabling'] },
    hotspot_not_opening: { title: 'Hotspot not opening', steps: ['Confirm the hotspot service is enabled on the router', 'Check the device is joined to the correct WiFi network', 'Try loading a plain http:// site to trigger the captive portal', 'Restart the router\'s hotspot interface'] },
    payment_no_internet: { title: 'Payment completed but no internet', steps: ['Wait 30 seconds for the session to activate', 'Reconnect to the WiFi network', 'Check Transactions to confirm payment was completed', 'Contact support with the M-Pesa code if it persists'] },
    voucher_not_working: { title: 'Voucher not working', steps: ['Check the code was typed exactly as printed', 'Confirm the voucher has not already been used or expired', 'Ask the router owner to check its status in Vouchers'] },
    ap_offline: { title: 'AP offline', steps: ['Check power/PoE to the access point', 'Check the cable back to its router', 'Confirm the router it depends on is online', 'Restart the AP from Access Points'] },
    pppoe_problem: { title: 'PPPoE problem', steps: ['Confirm the PPPoE username/password are correct', 'Check the account has not expired', 'Confirm the PPPoE service is running on the router'] },
    slow_connection: { title: 'Slow connection', steps: ['Check how many devices are sharing the connection', 'Check the speed profile assigned to the package', 'Test at a different time of day to rule out congestion', 'Check the router\'s bandwidth graph for saturation'] },
    captive_portal_problem: { title: 'Captive portal problem', steps: ['Clear the browser cache or try another browser', 'Try a different device to isolate the issue', 'Confirm DNS is set on the hotspot profile'] },
  };

  router.get('/connection-help/topics', (req, res) => res.json({ topics: Object.entries(HELP_TOPICS).map(([id, v]) => ({ id, title: v.title })) }));

  router.post('/connection-help/diagnose', auth, async (req, res) => {
    const { issue } = req.body;
    const topic = HELP_TOPICS[issue];
    if (!topic) return res.status(400).json({ message: 'Unknown issue', topics: Object.keys(HELP_TOPICS) });
    res.json({ title: topic.title, steps: topic.steps });
  });

  // ══════════════════════ WIFI HOST (customer shares connection, earns 10%) ══
  router.get('/wifi-host/dashboard', auth, async (req, res) => {
    const { rows } = await db.query('SELECT * FROM wifi_hosts WHERE user_id=$1', [req.user.id]);
    const host = rows[0] || null;
    const salesQ = host ? await db.query('SELECT s.*, u.name as customer_name, p.name as package_name FROM wifi_host_sales s LEFT JOIN users u ON u.id=s.customer_id LEFT JOIN packages p ON p.id=s.package_id WHERE s.host_id=$1 ORDER BY s.created_at DESC LIMIT 20', [host.id]) : { rows: [] };
    const totalsQ = host ? await db.query("SELECT COALESCE(SUM(commission),0) as total, COALESCE(SUM(commission) FILTER(WHERE created_at::date=CURRENT_DATE),0) as today, COALESCE(SUM(commission) FILTER(WHERE created_at>=date_trunc('month',NOW())),0) as month, COUNT(*) as sales FROM wifi_host_sales WHERE host_id=$1", [host.id]) : { rows: [{ total: 0, today: 0, month: 0, sales: 0 }] };
    const t = totalsQ.rows[0];
    res.json({
      is_host: !!host, host_status: host?.status, location: host?.location, hotspot_ssid: host?.hotspot_ssid || 'BRISK_WIFI',
      connected_users: host?.connected_users || 0, hotspot_status: host?.status === 'active' ? 'Online' : 'Offline',
      wallet_balance: parseFloat(req.user.wallet_balance) || 0,
      total_earnings: parseFloat(t.total) || 0, today_earnings: parseFloat(t.today) || 0, month_earnings: parseFloat(t.month) || 0, total_sales: parseInt(t.sales) || 0,
      recent_sales: salesQ.rows,
    });
  });

  router.post('/wifi-host/apply', auth, async (req, res) => {
    const { location, router_type, estimated_neighbours, notes } = req.body;
    if (!location) return res.status(400).json({ message: 'Location is required' });
    const existing = await db.query('SELECT id FROM wifi_hosts WHERE user_id=$1', [req.user.id]);
    if (existing.rows[0]) return res.status(400).json({ message: 'You already have a WiFi Host application on file' });
    await db.query('INSERT INTO wifi_hosts(user_id,location,router_type,estimated_neighbours,notes) VALUES($1,$2,$3,$4,$5)',
      [req.user.id, location, router_type || null, estimated_neighbours || 0, notes || null]);
    await notify(req.user.id, 'system', '📋 WiFi Host Application Received', 'We will contact you via WhatsApp within 24 hours to complete setup.');
    res.json({ message: 'Application submitted! BRISK will contact you within 24 hours.' });
  });

  router.post('/wifi-host/withdraw', auth, async (req, res) => {
    const { amount, phone, account_name } = req.body;
    const available = parseFloat(req.user.wallet_balance) || 0;
    if (!amount || amount < 500) return res.status(400).json({ message: 'Minimum withdrawal is KES 500' });
    if (amount > available) return res.status(400).json({ message: 'Amount exceeds your available wallet balance' });
    if (!phone || !account_name) return res.status(400).json({ message: 'Phone and account name required' });
    await db.query('UPDATE users SET wallet_balance=wallet_balance-$1 WHERE id=$2', [amount, req.user.id]);
    await db.query('INSERT INTO withdrawals(owner_id,amount,phone,account_name) VALUES($1,$2,$3,$4)', [req.user.id, amount, phone, account_name]);
    await notify(req.user.id, 'withdrawal', '📤 Withdrawal Requested', `KES ${Number(amount).toLocaleString()} withdrawal requested to ${phone}. Processing within 24 hours.`);
    res.json({ message: `KES ${Number(amount).toLocaleString()} withdrawal submitted! Processing within 24 hours.` });
  });

  return router;
};

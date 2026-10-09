'use strict';
// ════════════════════════════════════════════════════════════════
//  BRISK Smart Connect — Integrations & Subscriptions module
//  Mounted from server.js:
//    const integrationsRoutes = require('./integrations');
//    app.use('/api', integrationsRoutes({ db, auth, owner, admin, notify,
//      encryptSecret, decryptSecret, getDarajaToken, sendWhatsApp,
//      sendEmail, emailShell }));
//
//  Design principle (per the architecture doc): BRISK's own .env only
//  holds BRISK's platform-level credentials. Each Router Owner's own
//  M-Pesa/WhatsApp/Email credentials — for THEIR customers — live here,
//  encrypted at rest, never returned to the frontend in full.
// ════════════════════════════════════════════════════════════════
const express = require('express');

module.exports = function integrationsRoutes({ db, auth, owner, admin, notify, encryptSecret, decryptSecret, getDarajaToken, sendWhatsApp, sendEmail, emailShell }) {
  const router = express.Router();

  function mask(str) { if (!str) return null; const s = String(str); return s.length <= 6 ? '••••••' : s.slice(0, 3) + '••••••' + s.slice(-3); }

  // ══════════════════════ INTEGRATIONS (M-Pesa / WhatsApp / Email) ═
  router.get('/owner/integrations', auth, owner, async (req, res) => {
    const { rows } = await db.query('SELECT provider,status,last_tested_at,last_error,updated_at FROM owner_integrations WHERE owner_id=$1', [req.user.id]);
    const byProvider = {}; rows.forEach(r => byProvider[r.provider] = r);
    res.json({
      mpesa: byProvider.mpesa || { status: 'not_configured' },
      whatsapp: byProvider.whatsapp || { status: 'not_configured' },
      email: byProvider.email || { status: 'not_configured' },
    });
  });

  router.post('/owner/integrations/mpesa', auth, owner, async (req, res) => {
    const { provider_type, consumer_key, consumer_secret, shortcode, passkey } = req.body;
    if (!consumer_key || !consumer_secret || !shortcode || !passkey) return res.status(400).json({ message: 'All M-Pesa fields are required' });
    const enc = encryptSecret(JSON.stringify({ provider_type: provider_type || 'paybill', consumer_key, consumer_secret, shortcode, passkey }));
    await db.query(`INSERT INTO owner_integrations(owner_id,provider,config_encrypted,status) VALUES($1,'mpesa',$2,'untested')
      ON CONFLICT(owner_id,provider) DO UPDATE SET config_encrypted=$2,status='untested',updated_at=NOW()`, [req.user.id, enc]);
    res.json({ message: 'M-Pesa details saved. Click Test Connection to verify them.' });
  });

  router.post('/owner/integrations/mpesa/test', auth, owner, async (req, res) => {
    const { rows } = await db.query("SELECT config_encrypted FROM owner_integrations WHERE owner_id=$1 AND provider='mpesa'", [req.user.id]);
    if (!rows[0]) return res.status(404).json({ message: 'Configure M-Pesa first' });
    const cfg = JSON.parse(decryptSecret(rows[0].config_encrypted));
    const token = await getDarajaToken(cfg.consumer_key, cfg.consumer_secret);
    const ok = !!token;
    await db.query("UPDATE owner_integrations SET status=$1,last_tested_at=NOW(),last_error=$2 WHERE owner_id=$3 AND provider='mpesa'",
      [ok ? 'connected' : 'failed', ok ? null : 'Could not authenticate with Safaricom Daraja — check your Consumer Key/Secret', req.user.id]);
    res.json({ connected: ok, message: ok ? '✓ Connected to Safaricom Daraja' : 'Could not authenticate — check your credentials' });
  });

  router.post('/owner/integrations/whatsapp', auth, owner, async (req, res) => {
    const { phone_number_id, business_account_id, access_token, verify_token } = req.body;
    if (!phone_number_id || !access_token) return res.status(400).json({ message: 'Phone Number ID and Access Token are required' });
    const enc = encryptSecret(JSON.stringify({ phone_number_id, business_account_id, access_token, verify_token }));
    await db.query(`INSERT INTO owner_integrations(owner_id,provider,config_encrypted,status) VALUES($1,'whatsapp',$2,'untested')
      ON CONFLICT(owner_id,provider) DO UPDATE SET config_encrypted=$2,status='untested',updated_at=NOW()`, [req.user.id, enc]);
    res.json({ message: 'WhatsApp details saved. Click Test WhatsApp to send yourself a test message.' });
  });

  router.post('/owner/integrations/whatsapp/test', auth, owner, async (req, res) => {
    const { rows } = await db.query("SELECT config_encrypted FROM owner_integrations WHERE owner_id=$1 AND provider='whatsapp'", [req.user.id]);
    if (!rows[0]) return res.status(404).json({ message: 'Configure WhatsApp first' });
    const cfg = JSON.parse(decryptSecret(rows[0].config_encrypted));
    if (!req.user.phone) return res.status(400).json({ message: 'Add a phone number to your account to receive the test message' });
    const result = await sendWhatsApp(req.user.phone, '✅ This is a test message from your BRISK Smart Connect WhatsApp integration. If you received this, it works!', { token: cfg.access_token, phoneId: cfg.phone_number_id });
    await db.query("UPDATE owner_integrations SET status=$1,last_tested_at=NOW(),last_error=$2 WHERE owner_id=$3 AND provider='whatsapp'",
      [result.sent ? 'connected' : 'failed', result.sent ? null : (result.error || 'Send failed'), req.user.id]);
    res.json({ connected: result.sent, message: result.sent ? '✓ Test message sent — check your WhatsApp' : ('Failed: ' + (result.error || 'unknown error')) });
  });

  router.post('/owner/integrations/email', auth, owner, async (req, res) => {
    const { provider_type, api_key, from_email, from_name, smtp_host, smtp_port, smtp_user, smtp_pass, smtp_encryption } = req.body;
    if (!from_email) return res.status(400).json({ message: 'From email address is required' });
    if (provider_type === 'smtp' && (!smtp_host || !smtp_user || !smtp_pass)) return res.status(400).json({ message: 'SMTP host, username and password are required' });
    if (provider_type !== 'smtp' && !api_key) return res.status(400).json({ message: 'Resend API key is required' });
    const enc = encryptSecret(JSON.stringify({ provider_type: provider_type || 'resend', api_key, from_email, from_name, smtp_host, smtp_port, smtp_user, smtp_pass, smtp_encryption }));
    await db.query(`INSERT INTO owner_integrations(owner_id,provider,config_encrypted,status) VALUES($1,'email',$2,'untested')
      ON CONFLICT(owner_id,provider) DO UPDATE SET config_encrypted=$2,status='untested',updated_at=NOW()`, [req.user.id, enc]);
    res.json({ message: 'Email details saved. Click Test Email to send yourself a test.' });
  });

  router.post('/owner/integrations/email/test', auth, owner, async (req, res) => {
    const { rows } = await db.query("SELECT config_encrypted FROM owner_integrations WHERE owner_id=$1 AND provider='email'", [req.user.id]);
    if (!rows[0]) return res.status(404).json({ message: 'Configure email first' });
    const cfg = JSON.parse(decryptSecret(rows[0].config_encrypted));
    if (!req.user.email) return res.status(400).json({ message: 'Add an email address to your account to receive the test' });
    if (cfg.provider_type === 'smtp') {
      // Real SMTP sending requires a mail library (nodemailer) not currently
      // a dependency of this backend. Rather than fake a success, we're
      // honest that SMTP is stored but not yet live-tested — Resend works today.
      return res.json({ connected: false, message: 'SMTP is saved but live-testing SMTP isn\'t wired up yet — use Resend for a fully working test today.' });
    }
    const result = await sendEmail(req.user.email, 'BRISK Smart Connect — Test Email',
      emailShell('Test Email', '<p>This is a test message from your BRISK Smart Connect email integration. If you received this, it works!</p>'),
      { apiKey: cfg.api_key, from: `${cfg.from_name || 'WiFi Business'} <${cfg.from_email}>` });
    await db.query("UPDATE owner_integrations SET status=$1,last_tested_at=NOW(),last_error=$2 WHERE owner_id=$3 AND provider='email'",
      [result.sent ? 'connected' : 'failed', result.sent ? null : (result.error || 'Send failed'), req.user.id]);
    res.json({ connected: result.sent, message: result.sent ? '✓ Test email sent — check your inbox' : ('Failed: ' + (result.error || 'unknown error')) });
  });

  router.delete('/owner/integrations/:provider', auth, owner, async (req, res) => {
    if (!['mpesa', 'whatsapp', 'email'].includes(req.params.provider)) return res.status(400).json({ message: 'Unknown provider' });
    await db.query('DELETE FROM owner_integrations WHERE owner_id=$1 AND provider=$2', [req.user.id, req.params.provider]);
    res.json({ message: 'Integration removed' });
  });

  // ══════════════════════ SUBSCRIPTIONS (Router Owner) ════════════
  router.get('/subscription-plans', async (req, res) => {
    const { rows } = await db.query('SELECT * FROM subscription_plans WHERE active=true ORDER BY sort_order ASC');
    res.json({ plans: rows });
  });

  router.get('/owner/subscription', auth, owner, async (req, res) => {
    const { rows } = await db.query('SELECT s.*, p.name as plan_name, p.price as plan_price, p.max_routers, p.max_access_points, p.max_vouchers_per_month, p.features FROM owner_subscriptions s LEFT JOIN subscription_plans p ON p.id=s.plan_id WHERE s.owner_id=$1', [req.user.id]);
    let sub = rows[0];
    if (!sub) return res.json({ subscription: null, days_remaining: 0 });
    // Compute live status (trial/active expiring naturally over time)
    const now = new Date();
    let status = sub.status;
    let endDate = sub.status === 'trial' ? sub.trial_ends_at : sub.expires_at;
    let daysRemaining = endDate ? Math.max(0, Math.ceil((new Date(endDate) - now) / 86400000)) : 0;
    if (status === 'trial' && endDate && now > new Date(endDate)) status = 'expired';
    if (status === 'active' && endDate) {
      if (now > new Date(endDate)) status = 'expired';
      else if (daysRemaining <= 3) status = 'expiring';
    }
    if (status !== sub.status) { await db.query('UPDATE owner_subscriptions SET status=$1,updated_at=NOW() WHERE id=$2', [status, sub.id]); sub.status = status; }
    res.json({ subscription: sub, days_remaining: daysRemaining });
  });

  router.post('/owner/subscription/subscribe', auth, owner, async (req, res) => {
    const { plan_id, phone } = req.body;
    const { rows: plans } = await db.query('SELECT * FROM subscription_plans WHERE id=$1 AND active=true', [plan_id]);
    if (!plans[0]) return res.status(404).json({ message: 'Plan not found' });
    if (!phone) return res.status(400).json({ message: 'Phone number required' });
    const plan = plans[0];
    // Subscriptions are ALWAYS billed on BRISK's own platform M-Pesa —
    // never the owner's — since this is what the owner pays BRISK.
    let checkoutId = null;
    try {
      const token = await getDarajaToken();
      if (token) {
        const ts = new Date().toISOString().replace(/[-:T.Z]/g, '').slice(0, 14);
        const shortcode = process.env.MPESA_SHORTCODE || '222111';
        const pw = Buffer.from(`${shortcode}${process.env.MPESA_PASSKEY}${ts}`).toString('base64');
        const fp = phone.replace(/^0/, '254').replace(/^\+/, '');
        const r = await fetch('https://api.safaricom.co.ke/mpesa/stkpush/v1/processrequest', {
          method: 'POST',
          headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
          body: JSON.stringify({ BusinessShortCode: shortcode, Password: pw, Timestamp: ts, TransactionType: 'CustomerPayBillOnline', Amount: plan.price, PartyA: fp, PartyB: shortcode, PhoneNumber: fp, CallBackURL: `${process.env.API_URL || ''}/api/payments/callback`, AccountReference: '5414200', TransactionDesc: `BRISK Subscription - ${plan.name}` }),
        });
        const d = await r.json();
        checkoutId = d.CheckoutRequestID;
      }
    } catch (e) { console.error('Daraja STK error (subscription):', e.message); }
    const { rows } = await db.query('INSERT INTO subscription_payments(owner_id,plan_id,amount,phone,checkout_id) VALUES($1,$2,$3,$4,$5) RETURNING id',
      [req.user.id, plan.id, plan.price, phone, checkoutId]);
    res.json({ message: 'STK Push sent! Enter your M-Pesa PIN to activate your subscription.', payment_id: rows[0].id, is_subscription_payment: true });
  });

  router.get('/subscription-payments/:id/status', auth, owner, async (req, res) => {
    const { rows } = await db.query('SELECT * FROM subscription_payments WHERE id=$1 AND owner_id=$2', [req.params.id, req.user.id]);
    res.json({ status: rows[0]?.status || 'not_found' });
  });

  // ══════════════════════ ADMIN: PLAN MANAGEMENT ══════════════════
  router.get('/admin/subscription-plans', auth, admin, async (req, res) => {
    const { rows } = await db.query('SELECT * FROM subscription_plans ORDER BY sort_order ASC');
    res.json({ plans: rows });
  });
  router.post('/admin/subscription-plans', auth, admin, async (req, res) => {
    const { name, price, duration_days, max_routers, max_access_points, max_vouchers_per_month, features, sort_order } = req.body;
    if (!name || price == null) return res.status(400).json({ message: 'Name and price required' });
    const { rows } = await db.query(`INSERT INTO subscription_plans(name,price,duration_days,max_routers,max_access_points,max_vouchers_per_month,features,sort_order)
      VALUES($1,$2,$3,$4,$5,$6,$7,$8) RETURNING *`,
      [name, price, duration_days || 30, max_routers || 5, max_access_points || 10, max_vouchers_per_month || 1000, JSON.stringify(features || []), sort_order || 99]);
    res.json({ plan: rows[0], message: 'Plan created' });
  });
  router.put('/admin/subscription-plans/:id', auth, admin, async (req, res) => {
    const { name, price, duration_days, max_routers, max_access_points, max_vouchers_per_month, features, active, sort_order } = req.body;
    const { rows } = await db.query(`UPDATE subscription_plans SET name=COALESCE($1,name),price=COALESCE($2,price),duration_days=COALESCE($3,duration_days),
      max_routers=COALESCE($4,max_routers),max_access_points=COALESCE($5,max_access_points),max_vouchers_per_month=COALESCE($6,max_vouchers_per_month),
      features=COALESCE($7,features),active=COALESCE($8,active),sort_order=COALESCE($9,sort_order) WHERE id=$10 RETURNING *`,
      [name, price, duration_days, max_routers, max_access_points, max_vouchers_per_month, features ? JSON.stringify(features) : null, active, sort_order, req.params.id]);
    if (!rows[0]) return res.status(404).json({ message: 'Plan not found' });
    res.json({ plan: rows[0], message: 'Plan updated' });
  });
  router.delete('/admin/subscription-plans/:id', auth, admin, async (req, res) => {
    await db.query('UPDATE subscription_plans SET active=false WHERE id=$1', [req.params.id]);
    res.json({ message: 'Plan deactivated' });
  });
  router.get('/admin/subscriptions', auth, admin, async (req, res) => {
    const { rows } = await db.query(`SELECT s.*, u.name as owner_name, u.phone as owner_phone, p.name as plan_name FROM owner_subscriptions s
      JOIN users u ON u.id=s.owner_id LEFT JOIN subscription_plans p ON p.id=s.plan_id ORDER BY s.created_at DESC LIMIT 200`);
    res.json({ subscriptions: rows });
  });

  return router;
};

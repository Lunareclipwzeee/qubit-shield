'use strict';
const express = require('express');
const crypto  = require('crypto');
const path    = require('path');
const https   = require('https');
const { QubitShield } = require('./src/sdk/index');

const app  = express();
const PORT = process.env.PORT || 3000;
const RESEND_API_KEY = process.env.RESEND_API_KEY || '';

app.use(express.json({ limit: '10mb' }));
app.use(express.static(path.join(__dirname, 'public')));
app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  if (req.method === 'OPTIONS') return res.sendStatus(200);
  next();
});

const companies = new Map();
const usageLog  = [];

function generateKey() { return 'qs_live_' + crypto.randomBytes(16).toString('hex'); }
function getCompanyByKey(key) { return companies.get(key) || null; }
function getCompanyByEmail(email) { for (const c of companies.values()) if (c.email===email) return c; return null; }
function logUsage(key, action, ms) { usageLog.push({ api_key:key, action, ms, created_at:new Date().toISOString() }); }
function getStats(key) {
  const all = usageLog.filter(u=>u.api_key===key);
  const now = new Date();
  const ms  = new Date(now.getFullYear(),now.getMonth(),1);
  return { totalEncryptions:all.length, thisMonth:all.filter(u=>new Date(u.created_at)>=ms).length, byAction:[], recentActivity:all.slice(-10).reverse() };
}
function isPilotActive(c) { return new Date(c.pilot_end)>new Date(); }
function daysLeft(c) { return Math.max(0,Math.ceil((new Date(c.pilot_end)-new Date())/(1000*60*60*24))); }

async function sendEmail(to, name, company, apiKey) {
  return new Promise((resolve, reject) => {
    const emailHtml = `<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0"></head>
<body style="margin:0;padding:0;background:#020812;font-family:Arial,sans-serif;">
<table width="100%" cellpadding="0" cellspacing="0" style="background:#020812;padding:40px 0;">
<tr><td align="center">
<table width="600" cellpadding="0" cellspacing="0" style="background:#060f1e;border:1px solid rgba(6,182,212,0.2);max-width:600px;">

<tr><td style="padding:40px;border-bottom:1px solid rgba(6,182,212,0.15);text-align:center;">
<div style="font-family:Arial,sans-serif;font-weight:200;font-size:22px;letter-spacing:8px;text-transform:uppercase;color:#64748b;">QUBIT</div>
<div style="font-family:Arial,sans-serif;font-weight:700;font-size:28px;letter-spacing:4px;text-transform:uppercase;color:#06b6d4;margin-top:4px;">SHIELD</div>
<div style="font-size:11px;letter-spacing:3px;text-transform:uppercase;color:#64748b;margin-top:4px;">A LUNARECLIPSE Technology</div>
</td></tr>

<tr><td style="padding:40px;">
<p style="font-size:22px;color:#f0f6ff;margin:0 0 8px;">Welcome, ${name}! 🛡️</p>
<p style="font-size:14px;color:#64748b;margin:0 0 32px;">Your Free Pilot is now active for <strong style="color:#f0f6ff;">${company}</strong>. Your API key is below. Keep it private and secure.</p>

<div style="background:#0a1628;border:1px solid rgba(6,182,212,0.3);padding:24px;margin-bottom:8px;">
<div style="font-size:10px;letter-spacing:3px;text-transform:uppercase;color:#06b6d4;margin-bottom:12px;">Your API Key</div>
<div style="font-family:'Courier New',monospace;font-size:14px;color:#f0f6ff;word-break:break-all;letter-spacing:1px;">${apiKey}</div>
</div>
<p style="font-size:11px;color:#64748b;margin:0 0 32px;">⚠️ Never share this key. Do not commit it to GitHub.</p>

<table width="100%" cellpadding="0" cellspacing="0" style="margin-bottom:32px;">
<tr>
<td width="33%" style="text-align:center;background:#0a1628;border:1px solid rgba(6,182,212,0.15);padding:20px;">
<div style="font-size:24px;font-weight:200;color:#06b6d4;">256-bit</div>
<div style="font-size:10px;letter-spacing:2px;text-transform:uppercase;color:#64748b;margin-top:4px;">Quantum Key</div>
</td>
<td width="1" style="background:rgba(6,182,212,0.15);"></td>
<td width="33%" style="text-align:center;background:#0a1628;border:1px solid rgba(6,182,212,0.15);padding:20px;">
<div style="font-size:24px;font-weight:200;color:#06b6d4;">STEANE-7</div>
<div style="font-size:10px;letter-spacing:2px;text-transform:uppercase;color:#64748b;margin-top:4px;">Error Correction</div>
</td>
<td width="1" style="background:rgba(6,182,212,0.15);"></td>
<td width="33%" style="text-align:center;background:#0a1628;border:1px solid rgba(6,182,212,0.15);padding:20px;">
<div style="font-size:24px;font-weight:200;color:#06b6d4;">₹0</div>
<div style="font-size:10px;letter-spacing:2px;text-transform:uppercase;color:#64748b;margin-top:4px;">Upfront Cost</div>
</td>
</tr>
</table>

<p style="font-size:14px;color:#f0f6ff;margin:0 0 16px;font-weight:600;">Get started in 2 steps:</p>
<div style="background:#0a1628;border:1px solid rgba(6,182,212,0.15);padding:20px;margin-bottom:8px;">
<p style="font-family:'Courier New',monospace;font-size:13px;color:#06b6d4;margin:0 0 12px;">npm install qubit-shield-sdk</p>
<p style="font-family:'Courier New',monospace;font-size:12px;color:#f0f6ff;margin:0;line-height:1.8;">const { QubitShield } = require('qubit-shield-sdk');<br>const qs = new QubitShield({<br>&nbsp;&nbsp;apiKey: '${apiKey}'<br>});<br><br>const { envelope } = await qs.encrypt('your data');<br>const { text } = await qs.decrypt(envelope);</p>
</div>

<div style="text-align:center;margin-top:32px;">
<a href="https://qubitshield.netlify.app/dashboard" style="display:inline-block;background:#06b6d4;color:#020812;padding:14px 32px;text-decoration:none;font-size:12px;letter-spacing:2px;text-transform:uppercase;font-weight:600;">View Dashboard</a>
</div>
</td></tr>

<tr><td style="padding:24px 40px;border-top:1px solid rgba(6,182,212,0.15);text-align:center;">
<p style="font-size:11px;color:#64748b;margin:0;">Questions? <a href="mailto:murthybondu7@gmail.com" style="color:#06b6d4;">murthybondu7@gmail.com</a></p>
<p style="font-size:11px;color:#64748b;margin:8px 0 0;">© 2026 QUBIT Shield · A LUNARECLIPSE Technology</p>
</td></tr>

</table>
</td></tr>
</table>
</body>
</html>`;

    const payload = JSON.stringify({
      from: 'QUBIT Shield <onboarding@resend.dev>',
      to: [to],
      subject: `Your QUBIT Shield API Key — Welcome, ${name}!`,
      html: emailHtml
    });

    const options = {
      hostname: 'api.resend.com',
      path: '/emails',
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${RESEND_API_KEY}`,
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(payload)
      }
    };

    const req2 = https.request(options, r => {
      let data = '';
      r.on('data', d => data += d);
      r.on('end', () => {
        if (r.statusCode === 200 || r.statusCode === 201) resolve(JSON.parse(data));
        else reject(new Error('Email failed: ' + data));
      });
    });
    req2.on('error', reject);
    req2.write(payload);
    req2.end();
  });
}

function authenticate(req, res, next) {
  const token = (req.headers['authorization']||'').replace('Bearer ','').trim();
  if (!token||!token.startsWith('qs_')) return res.status(401).json({ ok:false, error:'Unauthorized' });
  const company = getCompanyByKey(token);
  if (!company) return res.status(401).json({ ok:false, error:'API key not found — sign up at qubit-shield.onrender.com/signup' });
  if (!isPilotActive(company)) return res.status(402).json({ ok:false, error:'Pilot expired — upgrade plan' });
  try { req.qs = new QubitShield({ apiKey:token }); } catch(e) { return res.status(401).json({ ok:false, error:'Invalid API key' }); }
  req.company = company;
  next();
}

app.get('/signup', (req,res) => res.sendFile(path.join(__dirname,'public','signup.html')));
app.get('/dashboard', (req,res) => res.sendFile(path.join(__dirname,'public','dashboard.html')));

app.post('/platform/signup', async (req, res) => {
  try {
    const { name, email, company, role } = req.body;
    if (!name||!email||!company) return res.status(400).json({ ok:false, error:'name, email, and company are required' });
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return res.status(400).json({ ok:false, error:'Invalid email address' });
    if (getCompanyByEmail(email)) return res.status(409).json({ ok:false, error:'Email already registered' });
    const apiKey   = generateKey();
    const pilotEnd = new Date(Date.now()+30*24*60*60*1000).toISOString();
    const record   = { name, email, company, role:role||'CTO', api_key:apiKey, plan:'pilot', status:'active', pilot_end:pilotEnd, created_at:new Date().toISOString() };
    companies.set(apiKey, record);
    logUsage(apiKey, 'signup', 0);
    try { await sendEmail(email, name, company, apiKey); } catch(e) { console.error('Email error:', e.message); }
    res.status(201).json({ ok:true, message:'API key sent to '+email+'. Check your inbox.', plan:'pilot', pilotDays:30, pilotEnd, dashboard:'/dashboard' });
  } catch(err) { res.status(400).json({ ok:false, error:err.message }); }
});

app.get('/platform/dashboard', (req, res) => {
  const apiKey = req.query.key||(req.headers['authorization']||'').replace('Bearer ','').trim();
  if (!apiKey) return res.status(401).json({ ok:false, error:'API key required' });
  const company = getCompanyByKey(apiKey);
  if (!company) return res.status(404).json({ ok:false, error:'API key not found' });
  const usage = getStats(apiKey);
  const dl    = daysLeft(company);
  res.json({ ok:true, account:{ name:company.name, email:company.email, company:company.company, apiKey:company.api_key, plan:company.plan, status:isPilotActive(company)?'active':'expired', pilotDaysRemaining:dl, pilotEnd:company.pilot_end, memberSince:company.created_at }, usage, billing:{ currentPlan:company.plan, estimatedBill:0, currency:'INR', nextBillingDate:company.pilot_end } });
});

app.get('/', (req,res) => res.json({ name:'QUBIT Shield API', version:'1.0.0', company:'LUNARECLIPSE', signup:'/signup', dashboard:'/dashboard' }));

app.get('/v1/health', (req,res) => res.json({ ok:true, status:'operational', version:'1.0.0', engine:'QubitShield-v1', algorithms:['QKD-BB84','AES-256-GCM','STEANE-7-QEC'], timestamp:new Date().toISOString(), uptime:Math.floor(process.uptime()), totalCompanies:companies.size }));

app.post('/v1/encrypt', authenticate, async (req,res) => {
  const start=Date.now();
  try {
    const { payload }=req.body;
    if (!payload) return res.status(400).json({ ok:false, error:'payload is required' });
    const result=await req.qs.encrypt(typeof payload==='string'?payload:JSON.stringify(payload));
    logUsage(req.company.api_key,'encrypt',Date.now()-start);
    res.json({ ok:true, sessionId:result.sessionId, envelope:result.envelope, algorithm:result.envelope.algorithm, encoding:result.envelope.encoding, timeMs:result.envelope.timeMs });
  } catch(err) { res.status(400).json({ ok:false, error:err.message }); }
});

app.post('/v1/decrypt', authenticate, async (req,res) => {
  const start=Date.now();
  try {
    const { envelope }=req.body;
    if (!envelope) return res.status(400).json({ ok:false, error:'envelope is required' });
    const result=await req.qs.decrypt(envelope);
    logUsage(req.company.api_key,'decrypt',Date.now()-start);
    res.json({ ok:true, text:result.text, sessionId:result.sessionId, errorsFound:result.errorsFound });
  } catch(err) { res.status(400).json({ ok:false, error:err.message }); }
});

app.post('/v1/detect', authenticate, async (req,res) => {
  const start=Date.now();
  try {
    const { envelope }=req.body;
    if (!envelope) return res.status(400).json({ ok:false, error:'envelope is required' });
    const result=await req.qs.detect(envelope);
    logUsage(req.company.api_key,'detect',Date.now()-start);
    res.json({ ok:true, tampered:result.tampered, score:result.score, reason:result.reason });
  } catch(err) { res.status(400).json({ ok:false, error:err.message }); }
});

app.post('/v1/sign', authenticate, (req,res) => {
  try {
    const { data }=req.body;
    if (!data) return res.status(400).json({ ok:false, error:'data is required' });
    logUsage(req.company.api_key,'sign',0);
    res.json({ ok:true, ...req.qs.sign(data) });
  } catch(err) { res.status(400).json({ ok:false, error:err.message }); }
});

app.post('/v1/verify', authenticate, (req,res) => {
  try {
    const { data, signature }=req.body;
    if (!data||!signature) return res.status(400).json({ ok:false, error:'data and signature required' });
    logUsage(req.company.api_key,'verify',0);
    res.json({ ok:true, ...req.qs.verify(data,signature) });
  } catch(err) { res.status(400).json({ ok:false, error:err.message }); }
});

app.use((req,res) => res.status(404).json({ ok:false, error:'Not found' }));

app.listen(PORT, () => {
  console.log('');
  console.log('╔══════════════════════════════════════════╗');
  console.log('║   QUBIT SHIELD PLATFORM — OPERATIONAL    ║');
  console.log('║   LUNARECLIPSE · v1.0.0                  ║');
  console.log(`║   http://localhost:${PORT}                  ║`);
  console.log('╚══════════════════════════════════════════╝');
  console.log('');
});

module.exports = app;

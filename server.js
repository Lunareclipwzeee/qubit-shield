'use strict';
const express = require('express');
const crypto  = require('crypto');
const path    = require('path');
const https   = require('https');
const { Pool } = require('pg');
const { EigenLock } = require('./src/sdk/index');
let pqcEngine = null;
async function getPQC() {
  if (!pqcEngine) {
    const { pqcEncrypt, pqcDecrypt, pqcDetect } = await import('./src/pqc-engine.mjs');
    pqcEngine = { pqcEncrypt, pqcDecrypt, pqcDetect };
  }
  return pqcEngine;
}

let mldsaEngine = null;
async function getMLDSA() {
  if (!mldsaEngine) {
    const { mldsaSign, mldsaVerify } = await import('./src/mldsa-engine.mjs');
    mldsaEngine = { mldsaSign, mldsaVerify };
  }
  return mldsaEngine;
}
const { EigenVault }    = require('./src/vault');
const { EigenSentinel } = require('./src/sentinel');


// ── Rate Limiting ──────────────────────────────────────────
const rateLimitStore = new Map();

function rateLimit(maxRequests, windowMs) {
  return (req, res, next) => {
    const key = (req.headers['authorization'] || '').replace('Bearer ','').trim() || req.ip;
    const now = Date.now();
    const windowStart = now - windowMs;
    if (!rateLimitStore.has(key)) rateLimitStore.set(key, []);
    const requests = rateLimitStore.get(key).filter(t => t > windowStart);
    requests.push(now);
    rateLimitStore.set(key, requests);
    res.setHeader('X-RateLimit-Limit', maxRequests);
    res.setHeader('X-RateLimit-Remaining', Math.max(0, maxRequests - requests.length));
    res.setHeader('X-RateLimit-Reset', new Date(now + windowMs).toISOString());
    if (requests.length > maxRequests) {
      return res.status(429).json({
        ok: false,
        error: 'Rate limit exceeded. Max ' + maxRequests + ' requests per ' + (windowMs/60000) + ' minutes.',
        retryAfter: Math.ceil(windowMs/1000)
      });
    }
    next();
  };
}
setInterval(() => {
  const cutoff = Date.now() - 60*60*1000;
  for (const [key, times] of rateLimitStore.entries()) {
    const fresh = times.filter(t => t > cutoff);
    if (fresh.length === 0) rateLimitStore.delete(key);
    else rateLimitStore.set(key, fresh);
  }
}, 5*60*1000);
// ───────────────────────────────────────────────────────────
process.on('uncaughtException', err => { console.error('UNCAUGHT:', err.message); });
process.on('unhandledRejection', err => { console.error('UNHANDLED:', err.message); });
const app  = express();
const PORT = parseInt(process.env.PORT) || 8080;
console.log('Starting on PORT:', PORT);
const RESEND_API_KEY = process.env.RESEND_API_KEY || '';

// PostgreSQL
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL && process.env.DATABASE_URL.includes('railway') ? { rejectUnauthorized: false } : false
});

async function initDb() {
  console.log('Connecting to DB:', process.env.DATABASE_URL ? 'URL found' : 'NO URL');
  await pool.query(`
    CREATE TABLE IF NOT EXISTS companies (
      id SERIAL PRIMARY KEY,
      name TEXT NOT NULL,
      email TEXT UNIQUE NOT NULL,
      company TEXT NOT NULL,
      role TEXT DEFAULT 'CTO',
      api_key TEXT UNIQUE NOT NULL,
      plan TEXT DEFAULT 'pilot',
      status TEXT DEFAULT 'active',
      pilot_end TIMESTAMPTZ NOT NULL,
      created_at TIMESTAMPTZ DEFAULT NOW(),
      last_seen TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS usage_log (
      id SERIAL PRIMARY KEY,
      api_key TEXT NOT NULL,
      action TEXT NOT NULL,
      ms INTEGER DEFAULT 0,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE INDEX IF NOT EXISTS idx_usage_key ON usage_log(api_key);
  `);
  console.log('Database ready');
}
initDb().catch(console.error);

app.use(express.json({ limit: '10mb' }));
app.use(express.static(path.join(__dirname, 'public')));
app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  if (req.method === 'OPTIONS') return res.sendStatus(200);
  next();
});

function generateKey() { return 'el_live_' + crypto.randomBytes(16).toString('hex'); }
async function getCompanyByKey(key) { const r=await pool.query('SELECT * FROM companies WHERE api_key=$1',[key]); return r.rows[0]||null; }
async function getCompanyByEmail(email) { const r=await pool.query('SELECT * FROM companies WHERE email=$1',[email]); return r.rows[0]||null; }
async function createCompany({name,email,company,role,apiKey}) {
  const pilotEnd=new Date(Date.now()+30*24*60*60*1000);
  const r=await pool.query('INSERT INTO companies (name,email,company,role,api_key,pilot_end) VALUES ($1,$2,$3,$4,$5,$6) RETURNING *',[name,email,company,role||'CTO',apiKey,pilotEnd]);
  return r.rows[0];
}
async function logUsage(key,action,ms) {
  try {
    await pool.query('INSERT INTO usage_log (api_key,action,ms) VALUES ($1,$2,$3)',[key,action,ms]);
    await pool.query('UPDATE companies SET last_seen=NOW() WHERE api_key=$1',[key]);
  } catch(e) { console.error('logUsage error:',e.message); }
}
async function getStats(key) {
  const total=await pool.query('SELECT COUNT(*) FROM usage_log WHERE api_key=$1',[key]);
  const month=await pool.query("SELECT COUNT(*) FROM usage_log WHERE api_key=$1 AND created_at>=date_trunc('month',NOW())",[key]);
  const recent=await pool.query('SELECT * FROM usage_log WHERE api_key=$1 ORDER BY created_at DESC LIMIT 10',[key]);
  return { totalEncryptions:parseInt(total.rows[0].count), thisMonth:parseInt(month.rows[0].count), byAction:[], recentActivity:recent.rows };
}
function isPilotActive(c) { return new Date(c.pilot_end)>new Date(); }
function daysLeft(c) { return Math.max(0,Math.ceil((new Date(c.pilot_end)-new Date())/(1000*60*60*24))); }

async function sendEmail(to,name,company,apiKey) {
  return new Promise((resolve,reject)=>{
    const html=`<!DOCTYPE html><html><body style="margin:0;padding:0;background:#020812;font-family:Arial,sans-serif;"><table width="100%" cellpadding="0" cellspacing="0" style="background:#020812;padding:40px 0;"><tr><td align="center"><table width="600" cellpadding="0" cellspacing="0" style="background:#060f1e;border:1px solid rgba(6,182,212,0.2);max-width:600px;"><tr><td style="padding:40px;border-bottom:1px solid rgba(6,182,212,0.15);text-align:center;"><div style="font-size:22px;letter-spacing:8px;text-transform:uppercase;color:#64748b;">QUBIT</div><div style="font-size:28px;letter-spacing:4px;text-transform:uppercase;color:#06b6d4;margin-top:4px;">SHIELD</div><div style="font-size:11px;letter-spacing:3px;color:#64748b;margin-top:4px;">A LUNARECLIPSE Technology</div></td></tr><tr><td style="padding:40px;"><p style="font-size:22px;color:#f0f6ff;margin:0 0 8px;">Welcome, ${name}! 🛡️</p><p style="font-size:14px;color:#64748b;margin:0 0 32px;">Your Free Pilot is now active for <strong style="color:#f0f6ff;">${company}</strong>. Your API key is below.</p><div style="background:#0a1628;border:1px solid rgba(6,182,212,0.3);padding:24px;margin-bottom:8px;"><div style="font-size:10px;letter-spacing:3px;text-transform:uppercase;color:#06b6d4;margin-bottom:12px;">Your API Key</div><div style="font-family:'Courier New',monospace;font-size:14px;color:#f0f6ff;word-break:break-all;">${apiKey}</div></div><p style="font-size:11px;color:#64748b;margin:0 0 32px;">⚠️ Never share this key. Do not commit it to GitHub.</p><table width="100%" cellpadding="0" cellspacing="0" style="margin-bottom:32px;"><tr><td width="33%" style="text-align:center;background:#0a1628;border:1px solid rgba(6,182,212,0.15);padding:20px;"><div style="font-size:24px;color:#06b6d4;">256-bit</div><div style="font-size:10px;letter-spacing:2px;text-transform:uppercase;color:#64748b;margin-top:4px;">Quantum Key</div></td><td width="1" style="background:rgba(6,182,212,0.15);"></td><td width="33%" style="text-align:center;background:#0a1628;border:1px solid rgba(6,182,212,0.15);padding:20px;"><div style="font-size:24px;color:#06b6d4;">NIST</div><div style="font-size:10px;letter-spacing:2px;text-transform:uppercase;color:#64748b;margin-top:4px;">Certified</div></td><td width="1" style="background:rgba(6,182,212,0.15);"></td><td width="33%" style="text-align:center;background:#0a1628;border:1px solid rgba(6,182,212,0.15);padding:20px;"><div style="font-size:24px;color:#06b6d4;">₹0</div><div style="font-size:10px;letter-spacing:2px;text-transform:uppercase;color:#64748b;margin-top:4px;">Upfront Cost</div></td></tr></table><p style="font-size:14px;color:#f0f6ff;margin:0 0 16px;font-weight:600;">Get started in 2 steps:</p><div style="background:#0a1628;border:1px solid rgba(6,182,212,0.15);padding:20px;margin-bottom:8px;"><p style="font-family:'Courier New',monospace;font-size:13px;color:#06b6d4;margin:0 0 12px;">npm install eigenlock-sdk</p><p style="font-family:'Courier New',monospace;font-size:12px;color:#f0f6ff;margin:0;line-height:1.8;">const { EigenLock } = require('eigenlock-sdk');<br>const qs = new EigenLock({ apiKey: '${apiKey}' });<br><br>const { envelope } = await qs.encrypt('your data');<br>const { text } = await qs.decrypt(envelope);</p></div><div style="text-align:center;margin-top:32px;"><a href="https://eigenlock.in/dashboard?key=${apiKey}" style="display:inline-block;background:#06b6d4;color:#020812;padding:14px 32px;text-decoration:none;font-size:12px;letter-spacing:2px;text-transform:uppercase;font-weight:600;">View Dashboard</a></div></td></tr><tr><td style="padding:24px 40px;border-top:1px solid rgba(6,182,212,0.15);text-align:center;"><p style="font-size:11px;color:#64748b;margin:0;">Questions? <a href="mailto:pilots@eigenlock.in" style="color:#06b6d4;">pilots@eigenlock.in</a></p><p style="font-size:11px;color:#64748b;margin:8px 0 0;">© 2026 EIGENLOCK · A LUNARECLIPSE Technology</p></td></tr></table></td></tr></table></body></html>`;
    const adminHtml=`<p>New signup from <b>${name}</b> (${to}) — ${company}<br>API Key: <b>${apiKey}</b><br>Forward this email to the customer.</p>${html}`;
    const payload=JSON.stringify({from:'EIGENLOCK <onboarding@resend.dev>',to:['murthybondu7@gmail.com'],subject:`[EIGENLOCK Signup] ${name} — ${to}`,html:adminHtml});
    const options={hostname:'api.resend.com',path:'/emails',method:'POST',headers:{'Authorization':`Bearer ${RESEND_API_KEY}`,'Content-Type':'application/json','Content-Length':Buffer.byteLength(payload)}};
    const req2=https.request(options,r=>{let d='';r.on('data',x=>d+=x);r.on('end',()=>{if(r.statusCode===200||r.statusCode===201)resolve(JSON.parse(d));else reject(new Error('Email failed: '+d));});});
    req2.on('error',reject);req2.write(payload);req2.end();
  });
}

// Demo key — works for everyone
const DEMO_KEY = 'el_demo_eigenlock_2026';
const DEMO_KEY_OLD = 'qs_demo_lunareclipse_2026';


// ── Pilot Expiry Notifications ─────────────────────────────
async function sendEmail(to, subject, html) {
  const payload = JSON.stringify({
    from: 'EIGENLOCK <onboarding@resend.dev>',
    to: [to],
    reply_to: 'pilots@eigenlock.in',
    subject,
    html
  });
  return new Promise((resolve, reject) => {
    const https = require('https');
    const options = {
      hostname: 'api.resend.com',
      path: '/emails',
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${process.env.RESEND_API_KEY}`,
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(payload)
      }
    };
    const r = https.request(options, res => {
      let d = '';
      res.on('data', x => d += x);
      res.on('end', () => resolve(d));
    });
    r.on('error', reject);
    r.write(payload);
    r.end();
  });
}

async function checkPilotExpiry(company) {
  if (company.plan !== 'pilot') return;
  const pilotEnd = new Date(company.pilot_end);
  const now = new Date();
  const daysLeft = Math.ceil((pilotEnd - now) / (1000 * 60 * 60 * 24));

  // Already notified — check database flag
  const notifKey = `notif_${daysLeft}`;
  
  if (daysLeft === 3 && !company[notifKey]) {
    // 3 days warning
    await pool.query('UPDATE companies SET notified_3day=$1 WHERE api_key=$2', [true, company.api_key]);
    await sendEmail(
      company.email,
      'EIGENLOCK — Your free pilot expires in 3 days',
      `<div style="background:#020812;padding:40px;font-family:Arial,sans-serif;color:#f0f6ff;">
        <h2 style="color:#06b6d4;">Your EIGENLOCK pilot expires in 3 days</h2>
        <p>Hi ${company.name},</p>
        <p>Your 30-day free pilot for <strong>${company.company}</strong> expires on <strong>${pilotEnd.toDateString()}</strong>.</p>
        <p>To continue using EIGENLOCK, choose a plan before your pilot ends.</p>
        <a href="https://eigenlock.in/upgrade?key=${company.api_key}&expired=false" 
           style="display:inline-block;background:#06b6d4;color:#020812;padding:14px 32px;text-decoration:none;font-weight:600;margin:16px 0;">
          Choose Your Plan →
        </a>
        <p style="color:#64748b;font-size:12px;">Questions? Reply to this email or contact pilots@eigenlock.in</p>
        <p style="color:#64748b;font-size:11px;">© 2026 EIGENLOCK · A LUNARECLIPSE Technology</p>
      </div>`
    );
  } else if (daysLeft === 1 && !company.notified_1day) {
    // 1 day warning
    await pool.query('UPDATE companies SET notified_1day=$1 WHERE api_key=$2', [true, company.api_key]);
    await sendEmail(
      company.email,
      'EIGENLOCK — Your free pilot expires TOMORROW',
      `<div style="background:#020812;padding:40px;font-family:Arial,sans-serif;color:#f0f6ff;">
        <h2 style="color:#ef4444;">Your EIGENLOCK pilot expires tomorrow!</h2>
        <p>Hi ${company.name},</p>
        <p>Your free pilot expires <strong>tomorrow</strong>. After that your API key will stop working.</p>
        <a href="https://eigenlock.in/upgrade?key=${company.api_key}&expired=false"
           style="display:inline-block;background:#06b6d4;color:#020812;padding:14px 32px;text-decoration:none;font-weight:600;margin:16px 0;">
          Upgrade Now →
        </a>
        <p style="color:#64748b;font-size:12px;">Questions? pilots@eigenlock.in</p>
        <p style="color:#64748b;font-size:11px;">© 2026 EIGENLOCK · A LUNARECLIPSE Technology</p>
      </div>`
    );
  } else if (daysLeft <= 0 && !company.notified_expired) {
    // Expired
    await pool.query('UPDATE companies SET notified_expired=$1 WHERE api_key=$2', [true, company.api_key]);
    await sendEmail(
      company.email,
      'EIGENLOCK — Your free pilot has expired',
      `<div style="background:#020812;padding:40px;font-family:Arial,sans-serif;color:#f0f6ff;">
        <h2 style="color:#ef4444;">Your EIGENLOCK pilot has expired</h2>
        <p>Hi ${company.name},</p>
        <p>Your 30-day free pilot has ended. Your API key is currently paused.</p>
        <p>Choose a plan to continue protecting your data with post-quantum encryption.</p>
        <a href="https://eigenlock.in/upgrade?key=${company.api_key}&expired=true"
           style="display:inline-block;background:#06b6d4;color:#020812;padding:14px 32px;text-decoration:none;font-weight:600;margin:16px 0;">
          Choose Your Plan →
        </a>
        <p style="color:#64748b;font-size:12px;">Questions? pilots@eigenlock.in</p>
        <p style="color:#64748b;font-size:11px;">© 2026 EIGENLOCK · A LUNARECLIPSE Technology</p>
      </div>`
    );
  }
}
// ───────────────────────────────────────────────────────────

async function authenticate(req,res,next) {
  const token=(req.headers['authorization']||'').replace('Bearer ','').trim();
  if(!token||(!token.startsWith('qs_')&&!token.startsWith('el_'))) return res.status(401).json({ok:false,error:'Unauthorized'});
  if(token===DEMO_KEY||token===DEMO_KEY_OLD||token==='qs_demo_lunareclipse_2026'){
    req.company={api_key:DEMO_KEY,name:'Demo',email:'demo@qubitshield.com',company:'Demo User',plan:'pilot',pilot_end:new Date(Date.now()+365*24*60*60*1000)};
    try{req.qs=new EigenLock({apiKey:token});}catch(e){}
    return next();
  }
  const company=await getCompanyByKey(token);
  if(!company) return res.status(401).json({ok:false,error:'API key not found — sign up at eigenlock.in/signup'});
  checkPilotExpiry(company).catch(()=>{});
  if(!isPilotActive(company)) return res.status(402).json({ok:false,error:'Pilot expired — choose a plan to continue',upgradeUrl:`/upgrade?key=${token}&expired=true`});
  try { req.qs=new EigenLock({apiKey:token}); } catch(e) { return res.status(401).json({ok:false,error:'Invalid API key'}); }
  req.company=company;
  next();
}

function requireVault(req,res,next) {
  if(['pilot','shield','enterprise'].includes(req.company.plan)) return next();
  return res.status(403).json({ok:false,error:'EIGEN Vault requires Shield or Enterprise plan'});
}

app.get('/signup',(req,res)=>res.sendFile(path.join(__dirname,'public','signup.html')));
app.get('/dashboard',(req,res)=>res.sendFile(path.join(__dirname,'public','dashboard.html')));
app.get('/upgrade',(req,res)=>res.sendFile(path.join(__dirname,'public','upgrade.html')));
app.get('/admin',(req,res)=>res.sendFile(path.join(__dirname,'public','admin.html')));

app.post('/platform/signup',async(req,res)=>{
  try{
    const{name,email,company,role}=req.body;
    if(!name||!email||!company) return res.status(400).json({ok:false,error:'name, email, and company are required'});
    if(!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return res.status(400).json({ok:false,error:'Invalid email'});
    if(await getCompanyByEmail(email)) return res.status(409).json({ok:false,error:'Email already registered'});
    const apiKey=generateKey();
    const record=await createCompany({name,email,company,role,apiKey});
    await logUsage(apiKey,'signup',0);
    try {
      const welcomeHtml = `<!DOCTYPE html>
<html><head><meta charset="UTF-8"></head>
<body style="margin:0;padding:0;background-color:#ffffff;font-family:Arial,sans-serif;">
<table width="100%" cellpadding="0" cellspacing="0" bgcolor="#ffffff">
<tr><td align="center" style="padding:40px 20px;">
<table width="560" cellpadding="0" cellspacing="0" style="border:2px solid #06b6d4;">
<tr><td style="background-color:#06b6d4;padding:24px 40px;">
<h1 style="font-size:24px;color:#000000;margin:0;font-weight:bold;">EIGENLOCK</h1>
<p style="font-size:12px;color:#000000;margin:4px 0 0;">Post-Quantum Security Platform · NIST FIPS 203</p>
</td></tr>
<tr><td style="background-color:#ffffff;padding:40px;">
<p style="font-size:16px;color:#000000;margin:0 0 16px;">Hi ${name},</p>
<p style="font-size:14px;color:#333333;margin:0 0 24px;">Your 30-day free pilot for <strong>${company}</strong> is now active.</p>
<table width="100%" cellpadding="0" cellspacing="0" style="border:2px solid #06b6d4;margin-bottom:24px;">
<tr><td style="background-color:#f0f9ff;padding:20px;">
<p style="font-size:11px;color:#666666;margin:0 0 8px;text-transform:uppercase;letter-spacing:1px;">YOUR API KEY</p>
<p style="font-family:Courier New,monospace;font-size:14px;color:#0891b2;margin:0;word-break:break-all;"><strong>${apiKey}</strong></p>
</td></tr>
</table>
<p style="font-size:14px;color:#000000;margin:0 0 12px;"><strong>Next steps:</strong></p>
<p style="font-size:13px;color:#333333;margin:0 0 8px;">1. Save your API key above</p>
<p style="font-size:13px;color:#333333;margin:0 0 8px;">2. Visit eigenlock.in/dashboard and enter your API key</p>
<p style="font-size:13px;color:#333333;margin:0 0 24px;">3. Reply to this email for integration support</p>
<table width="100%" cellpadding="0" cellspacing="0">
<tr><td align="center" style="padding:16px 0;">
<a href="https://eigenlock.in/dashboard?key=${apiKey}" style="display:inline-block;background-color:#06b6d4;color:#000000;padding:14px 32px;text-decoration:none;font-size:13px;font-weight:bold;text-transform:uppercase;letter-spacing:1px;">View Dashboard</a>
</td></tr>
</table>
</td></tr>
<tr><td style="background-color:#f5f5f5;padding:20px 40px;text-align:center;border-top:1px solid #dddddd;">
<p style="font-size:11px;color:#666666;margin:0;">Questions? eigenlock@gmail.com</p>
<p style="font-size:11px;color:#666666;margin:8px 0 0;">© 2026 EIGENLOCK · A LUNARECLIPSE Technology</p>
</td></tr>
</table>
</td></tr>
</table>
</body></html>`;
      await sendEmail(email, 'Welcome to EIGENLOCK — Your API Key Inside', welcomeHtml);
    } catch(e) { console.error('Email error:',e.message); }
    res.status(201).json({ok:true,message:'API key sent to '+email+'. Check your inbox.',plan:'pilot',pilotDays:30,pilotEnd:record.pilot_end,dashboard:'/dashboard'});
  }catch(err){res.status(400).json({ok:false,error:err.message});}
});

app.get('/platform/dashboard',async(req,res)=>{
  const apiKey=req.query.key||(req.headers['authorization']||'').replace('Bearer ','').trim();
  if(!apiKey) return res.status(401).json({ok:false,error:'API key required'});
  const company=await getCompanyByKey(apiKey);
  if(!company) return res.status(404).json({ok:false,error:'API key not found'});
  const usage=await getStats(apiKey);
  const dl=daysLeft(company);
  res.json({ok:true,account:{name:company.name,email:company.email,company:company.company,apiKey:company.api_key,plan:company.plan,status:isPilotActive(company)?'active':'expired',pilotDaysRemaining:dl,pilotEnd:company.pilot_end,memberSince:company.created_at},usage,billing:{currentPlan:company.plan,estimatedBill:0,currency:'INR',nextBillingDate:company.pilot_end}});
});

app.get('/',(req,res)=>res.json({name:'EIGENLOCK API',version:'1.0.0',company:'LUNARECLIPSE',signup:'https://eigenlock.in/signup',dashboard:'https://eigenlock.in/dashboard',api:'https://eigenlock-api.up.railway.app'}));

app.get('/v1/version',(req,res)=>res.json({node:process.version,platform:process.platform,arch:process.arch}));

app.get('/v1/health',async(req,res)=>{
  const r=await pool.query('SELECT COUNT(*) FROM companies');
  res.json({ok:true,status:'operational',version:'1.0.0',engine:'EIGENLOCK-v1',algorithms:['CRYSTALS-Kyber-768','AES-256-GCM','CRYSTALS-Dilithium-3'],timestamp:new Date().toISOString(),uptime:Math.floor(process.uptime()),totalCompanies:parseInt(r.rows[0].count)});
});

app.post('/v1/encrypt', rateLimit(60, 60*1000),authenticate,async(req,res)=>{
  const start=Date.now();
  try{
    const{payload}=req.body;
    if(!payload) return res.status(400).json({ok:false,error:'payload is required'});
    const data=typeof payload==='string'?payload:JSON.stringify(payload);
    const {pqcEncrypt}=await getPQC();
    const result=await pqcEncrypt(data);
    const timeMs=Date.now()-start;
    await logUsage(req.company.api_key,'encrypt',timeMs);
    res.json({ok:true,sessionId:'el_'+require('crypto').randomBytes(16).toString('hex'),envelope:result.envelope,algorithm:result.algorithm,standard:result.standard,keySize:result.keySize,cipherSize:result.cipherSize,timeMs});
  }catch(err){res.status(400).json({ok:false,error:err.message});}
});

app.post('/v1/decrypt', rateLimit(60, 60*1000),authenticate,async(req,res)=>{
  const start=Date.now();
  try{
    const{envelope}=req.body;
    if(!envelope) return res.status(400).json({ok:false,error:'envelope is required'});
    const{pqcDecrypt}=await getPQC();
    const text=await pqcDecrypt(envelope);
    const timeMs=Date.now()-start;
    await logUsage(req.company.api_key,'decrypt',timeMs);
    res.json({ok:true,text,algorithm:'ML-KEM-768+AES-256-GCM',standard:'NIST FIPS 203',timeMs});
  }catch(err){res.status(400).json({ok:false,error:err.message});}
});

app.post('/v1/detect', rateLimit(60, 60*1000),authenticate,async(req,res)=>{
  const start=Date.now();
  try{
    const{envelope}=req.body;
    if(!envelope) return res.status(400).json({ok:false,error:'envelope is required'});
    const{pqcDetect}=await getPQC();
    const result=await pqcDetect(envelope);
    const timeMs=Date.now()-start;
    await logUsage(req.company.api_key,'detect',timeMs);
    res.json({ok:true,tampered:result.tampered,score:result.score,reason:result.reason,algorithm:'ML-KEM-768',standard:'NIST FIPS 203',timeMs});
  }catch(err){res.status(400).json({ok:false,error:err.message});}
});

app.post('/v1/sign', rateLimit(60, 60*1000),authenticate,async(req,res)=>{
  try{
    const{data}=req.body;
    if(!data) return res.status(400).json({ok:false,error:'data is required'});
    const sig=require('crypto').createHmac('sha256',req.company.api_key).update(data).digest('hex');
    await logUsage(req.company.api_key,'sign',0);
    res.json({ok:true,signature:sig,algorithm:'HMAC-SHA256',standard:'ML-DSA-65 coming in v2.0'});
  }catch(err){res.status(400).json({ok:false,error:err.message});}
});

app.post('/v1/verify', rateLimit(60, 60*1000),authenticate,async(req,res)=>{
  try{
    const{data,signature}=req.body;
    if(!data||!signature) return res.status(400).json({ok:false,error:'data and signature required'});
    const expected=require('crypto').createHmac('sha256',req.company.api_key).update(data).digest('hex');
    const valid = signature === expected;
    await logUsage(req.company.api_key,'verify',0);
    res.json({ok:true,valid,algorithm:'HMAC-SHA256',standard:'ML-DSA-65 coming in v2.0'});
  }catch(err){res.status(400).json({ok:false,error:err.message});}
});

app.post('/v1/vault/credential',authenticate,requireVault,async(req,res)=>{
  try{
    const{subject,scope,ttl,metadata}=req.body;
    if(!subject) return res.status(400).json({ok:false,error:'subject is required'});
    if(!scope) return res.status(400).json({ok:false,error:'scope is required'});
    const result=EigenVault.generateCredential({subject,scope,ttlSeconds:ttl||300,apiKey:req.company.api_key,metadata:metadata||{}});
    await logUsage(req.company.api_key,'vault_generate',0);
    res.status(201).json({ok:true,credentialId:result.credentialId,signature:result.credential.signature,publicKey:result.credential.publicKey,algorithm:result.credential.algorithm,subject:result.credential.subject,scope:result.credential.scope,expiresIn:result.expiresIn,expiresAt:result.expiresAt,singleUse:true});
  }catch(err){res.status(400).json({ok:false,error:err.message});}
});

app.post('/v1/vault/verify',authenticate,requireVault,async(req,res)=>{
  try{
    const{credentialId,signature}=req.body;
    if(!credentialId||!signature) return res.status(400).json({ok:false,error:'credentialId and signature required'});
    const result=EigenVault.verifyCredential(credentialId,signature);
    await logUsage(req.company.api_key,'vault_verify',0);
    res.json({ok:true,...result});
  }catch(err){res.status(400).json({ok:false,error:err.message});}
});

app.post('/v1/vault/revoke',authenticate,requireVault,async(req,res)=>{
  try{
    const{credentialId}=req.body;
    if(!credentialId) return res.status(400).json({ok:false,error:'credentialId is required'});
    const result=EigenVault.revokeCredential(credentialId,req.company.api_key);
    await logUsage(req.company.api_key,'vault_revoke',0);
    res.json({ok:true,...result});
  }catch(err){res.status(400).json({ok:false,error:err.message});}
});

app.get('/v1/vault/credentials',authenticate,requireVault,(req,res)=>{
  try{
    const result=EigenVault.listCredentials(req.company.api_key);
    res.json({ok:true,...result});
  }catch(err){res.status(400).json({ok:false,error:err.message});}
});

app.get('/v1/vault/stats',authenticate,requireVault,(req,res)=>{
  try{
    const stats=EigenVault.stats(req.company.api_key);
    res.json({ok:true,stats});
  }catch(err){res.status(400).json({ok:false,error:err.message});}
});


// ═══════════════════════════════════════════
//  QUBIT SENTINEL ROUTES
//  Available on: Enterprise plan (₹10L)
// ═══════════════════════════════════════════
function requireSentinel(req,res,next){
  if(['pilot','enterprise'].includes(req.company.plan)) return next();
  return res.status(403).json({ok:false,error:'EIGEN Sentinel requires Enterprise plan',upgrade:'mailto:pilots@eigenlock.in?subject=Upgrade to Enterprise'});
}
app.post('/v1/sentinel/monitor',authenticate,requireSentinel,async(req,res)=>{
  try{
    const{objectId,data,label,ttl,alertThreshold}=req.body;
    const result=EigenSentinel.monitor({objectId,data,label,apiKey:req.company.api_key,ttlSeconds:ttl||3600,alertThreshold:alertThreshold||0.25});
    await logUsage(req.company.api_key,'sentinel_monitor',0);
    res.status(201).json({ok:true,...result});
  }catch(err){res.status(400).json({ok:false,error:err.message});}
});
app.post('/v1/sentinel/scan',authenticate,requireSentinel,async(req,res)=>{
  try{
    const{objectId,currentData}=req.body;
    if(!objectId||currentData===undefined) return res.status(400).json({ok:false,error:'objectId and currentData required'});
    const result=EigenSentinel.scan({objectId,currentData,apiKey:req.company.api_key});
    await logUsage(req.company.api_key,'sentinel_scan',0);
    res.json({ok:true,...result});
  }catch(err){res.status(400).json({ok:false,error:err.message});}
});
app.get('/v1/sentinel/alerts',authenticate,requireSentinel,async(req,res)=>{
  try{
    const result=EigenSentinel.getAlerts(req.company.api_key,{status:req.query.status||'all',limit:parseInt(req.query.limit)||50});
    res.json({ok:true,...result});
  }catch(err){res.status(400).json({ok:false,error:err.message});}
});
app.post('/v1/sentinel/resolve',authenticate,requireSentinel,async(req,res)=>{
  try{
    const{alertId,resolution}=req.body;
    if(!alertId) return res.status(400).json({ok:false,error:'alertId is required'});
    const result=EigenSentinel.resolveAlert(alertId,req.company.api_key,resolution);
    res.json({ok:true,...result});
  }catch(err){res.status(400).json({ok:false,error:err.message});}
});
app.get('/v1/sentinel/monitored',authenticate,requireSentinel,(req,res)=>{
  try{
    const result=EigenSentinel.listMonitored(req.company.api_key);
    res.json({ok:true,...result});
  }catch(err){res.status(400).json({ok:false,error:err.message});}
});
app.get('/v1/sentinel/stats',authenticate,requireSentinel,(req,res)=>{
  try{
    const stats=EigenSentinel.stats(req.company.api_key);
    res.json({ok:true,stats});
  }catch(err){res.status(400).json({ok:false,error:err.message});}
});


app.get('/admin/getkey',async(req,res)=>{
  const secret=req.query.secret;
  if(secret!=='lunareclipse_admin_2026') return res.status(401).json({ok:false});
  const email=req.query.email;
  if(!email) return res.status(400).json({ok:false,error:'email required'});
  const company=await getCompanyByEmail(email);
  if(!company) return res.status(404).json({ok:false,error:'not found'});
  res.json({ok:true,apiKey:company.api_key,name:company.name,company:company.company,pilotEnd:company.pilot_end});
});


// POST /platform/upgrade-request — Customer requests plan upgrade
app.post('/platform/upgrade-request',async(req,res)=>{
  try{
    const{apiKey,email,company,plan,price,message}=req.body;
    if(!apiKey||!email||!plan) return res.status(400).json({ok:false,error:'apiKey, email and plan required'});
    const c=await getCompanyByKey(apiKey);
    if(!c) return res.status(404).json({ok:false,error:'API key not found'});

    // Send email to you
    const html=`<div style="background:#020812;padding:40px;font-family:Arial,sans-serif;color:#f0f6ff;">
      <h2 style="color:#06b6d4;">New Plan Upgrade Request</h2>
      <p><strong>Company:</strong> ${company}</p>
      <p><strong>Email:</strong> ${email}</p>
      <p><strong>API Key:</strong> ${apiKey}</p>
      <p><strong>Requested Plan:</strong> ${plan} — ${price}</p>
      <p><strong>Message:</strong> ${message||'None'}</p>
      <hr style="border-color:rgba(6,182,212,0.2);margin:24px 0;"/>
      <p style="color:#64748b;font-size:12px;">To activate this plan, run:<br>
      <code style="color:#06b6d4;">curl -X POST ${process.env.RAILWAY_PUBLIC_DOMAIN||'https://eigenlock-sdk-production.up.railway.app'}/admin/setplan?secret=lunareclipse_admin_2026&apiKey=${apiKey}&plan=${plan}</code></p>
    </div>`;

    const payload=JSON.stringify({from:'EIGENLOCK <onboarding@resend.dev>',to:['pilots@eigenlock.in'],reply_to:'pilots@eigenlock.in',subject:`EIGENLOCK — Plan Upgrade Request: ${plan} from ${company}`,html});
    await new Promise((resolve,reject)=>{
      const https=require('https');
      const options={hostname:'api.resend.com',path:'/emails',method:'POST',headers:{'Authorization':`Bearer ${process.env.RESEND_API_KEY}`,'Content-Type':'application/json','Content-Length':Buffer.byteLength(payload)}};
      const r=https.request(options,res=>{let d='';res.on('data',x=>d+=x);res.on('end',()=>resolve(d));});
      r.on('error',reject);r.write(payload);r.end();
    });

    res.json({ok:true,message:'Upgrade request sent. We will activate your plan within 24 hours.'});
  }catch(err){res.status(400).json({ok:false,error:err.message});}
});

// POST /admin/setplan — Activate a plan for a customer
app.post('/admin/setplan',async(req,res)=>{
  const secret=req.query.secret||req.body.secret;
  if(secret!=='lunareclipse_admin_2026') return res.status(401).json({ok:false});
  const{apiKey,plan}=req.query.apiKey?req.query:req.body;
  if(!apiKey||!plan) return res.status(400).json({ok:false,error:'apiKey and plan required'});
  const validPlans=['starter','shield','enterprise'];
  if(!validPlans.includes(plan)) return res.status(400).json({ok:false,error:'Invalid plan. Use: starter, shield, enterprise'});
  await pool.query('UPDATE companies SET plan=$1,status=$2 WHERE api_key=$3',[plan,'active',apiKey]);
  const company=await getCompanyByKey(apiKey);
  res.json({ok:true,message:`Plan updated to ${plan}`,company:company.name,email:company.email,plan:company.plan});
});


app.post('/platform/early-access',async(req,res)=>{
  try{
    const{name,email,company,message}=req.body;
    if(!name||!email) return res.status(400).json({ok:false,error:'name and email required'});
    const html=`<div style="background:#020812;padding:40px;font-family:Arial,sans-serif;color:#f0f6ff;">
      <h2 style="color:#06b6d4;">New Early Access Interest</h2>
      <p><strong>Name:</strong> ${name}</p>
      <p><strong>Email:</strong> ${email}</p>
      <p><strong>Company:</strong> ${company||'Not provided'}</p>
      <p><strong>Message:</strong> ${message||'None'}</p>
    </div>`;
    const payload=JSON.stringify({from:'EIGENLOCK <onboarding@resend.dev>',to:['murthybondu7@gmail.com'],reply_to:'pilots@eigenlock.in',subject:`EIGENLOCK Early Access — ${name} from ${company||'Unknown'}`,html});
    await new Promise((resolve,reject)=>{
      const https=require('https');
      const options={hostname:'api.resend.com',path:'/emails',method:'POST',headers:{'Authorization':`Bearer ${process.env.RESEND_API_KEY}`,'Content-Type':'application/json','Content-Length':Buffer.byteLength(payload)}};
      const r=https.request(options,res=>{let d='';res.on('data',x=>d+=x);res.on('end',()=>resolve(d));});
      r.on('error',reject);r.write(payload);r.end();
    });
    res.json({ok:true,message:'Received. We will reach out within 24 hours.'});
  }catch(err){res.status(400).json({ok:false,error:err.message});}
});


app.get('/admin/companies',async(req,res)=>{
  const secret=req.query.secret;
  if(secret!=='lunareclipse_admin_2026') return res.status(401).json({ok:false});
  try{
    const result=await pool.query(
      'SELECT name,email,company,role,plan,status,pilot_end,created_at FROM companies ORDER BY created_at DESC'
    );
    const companies=result.rows.map(r=>({
      name:r.name,
      email:r.email,
      company:r.company,
      role:r.role,
      plan:r.plan,
      status:r.status,
      pilotEnd:r.pilot_end,
      signedUp:r.created_at,
      daysLeft:Math.ceil((new Date(r.pilot_end)-new Date())/(1000*60*60*24))
    }));
    res.json({
      ok:true,
      total:companies.length,
      active:companies.filter(c=>c.daysLeft>0).length,
      expired:companies.filter(c=>c.daysLeft<=0).length,
      paid:companies.filter(c=>c.plan!=='pilot').length,
      companies
    });
  }catch(err){res.status(400).json({ok:false,error:err.message});}
});


app.delete('/admin/deletecompany',async(req,res)=>{
  const secret=req.query.secret;
  if(secret!=='lunareclipse_admin_2026') return res.status(401).json({ok:false});
  const email=req.query.email;
  if(!email) return res.status(400).json({ok:false,error:'email required'});
  try{
    const result=await pool.query('DELETE FROM companies WHERE email=$1',[email]);
    if(result.rowCount===0) return res.status(404).json({ok:false,error:'Company not found'});
    res.json({ok:true,message:'Deleted: '+email});
  }catch(err){res.status(400).json({ok:false,error:err.message});}
});

app.use((req,res)=>res.status(404).json({ok:false,error:'Not found'}));

app.listen(PORT,'0.0.0.0',()=>{
  console.log('');
  console.log('╔══════════════════════════════════════════╗');
  console.log('║   EIGENLOCK PLATFORM — OPERATIONAL    ║');
  console.log('║   LUNARECLIPSE · v1.0.0                  ║');
  console.log(`║   http://localhost:${PORT}                  ║`);
  console.log('╚══════════════════════════════════════════╝');
  console.log('');
});

module.exports = app;

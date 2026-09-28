import 'dotenv/config';
import express from 'express';
import cookieParser from 'cookie-parser';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import multer from 'multer';
import QRCode from 'qrcode';
import nodemailer from 'nodemailer';
import helmet from 'helmet';
import cors from 'cors';
import rateLimit from 'express-rate-limit';
import Database from 'better-sqlite3';
import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PORT = Number(process.env.PORT || 3000);
const APP_URL = process.env.APP_URL || `http://localhost:${PORT}`;
const JWT_SECRET = process.env.JWT_SECRET || 'dev-only-change-me';
const SHOP_NAME = process.env.SHOP_NAME || 'PixelCraft Studio';
const uploadDir = path.join(__dirname, 'storage', 'uploads');
fs.mkdirSync(uploadDir, { recursive: true });
const db = new Database(path.join(__dirname, 'storage', 'app.db'));
db.pragma('journal_mode = WAL');
db.exec(`
CREATE TABLE IF NOT EXISTS users (
 id INTEGER PRIMARY KEY AUTOINCREMENT, full_name TEXT NOT NULL, shop_name TEXT NOT NULL,
 email TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL, phone TEXT, verified INTEGER DEFAULT 0,
 temp_mail_address TEXT, created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS otps (
 id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, purpose TEXT NOT NULL,
 code_hash TEXT NOT NULL, expires_at INTEGER NOT NULL, attempts INTEGER DEFAULT 0,
 created_at INTEGER NOT NULL, FOREIGN KEY(user_id) REFERENCES users(id)
);
CREATE TABLE IF NOT EXISTS products (
 id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, product_code TEXT UNIQUE NOT NULL,
 customer_name TEXT NOT NULL, product_name TEXT NOT NULL, category TEXT DEFAULT 'সাধারণ',
 file_name TEXT NOT NULL, mime_type TEXT NOT NULL, qr_data TEXT NOT NULL, status TEXT DEFAULT 'active',
 print_limit INTEGER DEFAULT 5, print_count INTEGER DEFAULT 0, session_count INTEGER DEFAULT 0,
 expiry_at TEXT, created_at TEXT DEFAULT CURRENT_TIMESTAMP, FOREIGN KEY(user_id) REFERENCES users(id)
);
CREATE TABLE IF NOT EXISTS product_activity (id INTEGER PRIMARY KEY AUTOINCREMENT, product_id INTEGER NOT NULL, action TEXT NOT NULL, details TEXT, created_at TEXT DEFAULT CURRENT_TIMESTAMP, FOREIGN KEY(product_id) REFERENCES products(id));
CREATE TABLE IF NOT EXISTS print_jobs (id INTEGER PRIMARY KEY AUTOINCREMENT, product_id INTEGER NOT NULL, session_id TEXT, copies INTEGER DEFAULT 1, paper TEXT DEFAULT 'A4', photo_size TEXT DEFAULT '35x45 mm', status TEXT DEFAULT 'READY', created_at TEXT DEFAULT CURRENT_TIMESTAMP, completed_at TEXT, FOREIGN KEY(product_id) REFERENCES products(id));
CREATE TABLE IF NOT EXISTS print_settings (product_id INTEGER PRIMARY KEY, paper TEXT DEFAULT 'A4', photo_size TEXT DEFAULT '35x45 mm', unit TEXT DEFAULT 'mm', orientation TEXT DEFAULT 'portrait', margin_top REAL DEFAULT 5, margin_bottom REAL DEFAULT 5, margin_left REAL DEFAULT 5, margin_right REAL DEFAULT 5, gap_horizontal REAL DEFAULT 2, gap_vertical REAL DEFAULT 2, copies INTEGER DEFAULT 1, fit TEXT DEFAULT 'fit', dpi INTEGER DEFAULT 300, border INTEGER DEFAULT 0, crop_marks INTEGER DEFAULT 0, FOREIGN KEY(product_id) REFERENCES products(id));
CREATE TABLE IF NOT EXISTS shops (user_id INTEGER PRIMARY KEY, logo_file TEXT, address TEXT, website TEXT, facebook TEXT, instagram TEXT, business_description TEXT, theme TEXT DEFAULT 'light', FOREIGN KEY(user_id) REFERENCES users(id));
CREATE TABLE IF NOT EXISTS print_sessions (
 id TEXT PRIMARY KEY, product_id INTEGER NOT NULL, expires_at INTEGER NOT NULL,
 used INTEGER DEFAULT 0, created_at INTEGER NOT NULL, FOREIGN KEY(product_id) REFERENCES products(id)
);
`);
try { db.exec("ALTER TABLE products ADD COLUMN deleted_at TEXT"); } catch {}
try { db.exec("ALTER TABLE products ADD COLUMN privacy TEXT DEFAULT 'PRINT-ONLY'"); } catch {}

const app = express();
app.use(helmet({ crossOriginResourcePolicy: { policy: 'cross-origin' } }));
app.use(cors({ origin: true, credentials: true }));
app.use(rateLimit({ windowMs: 15 * 60 * 1000, limit: 300, standardHeaders: 'draft-7', legacyHeaders: false }));
app.use(express.json({ limit: '2mb' }));
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 20, message: { error: 'অনেকবার চেষ্টা হয়েছে, কিছুক্ষণ পরে আবার চেষ্টা করুন' } });
app.use(express.static(path.join(__dirname, 'public')));
const upload = multer({
  dest: uploadDir,
  limits: { fileSize: 10 * 1024 * 1024 },
  fileFilter: (req, file, cb) => cb(null, /^image\/(jpeg|png|webp)$/.test(file.mimetype))
});

const sha256 = value => crypto.createHash('sha256').update(value).digest('hex');
const randomCode = () => String(Math.floor(100000 + Math.random() * 900000));
const productCode = () => `PH-${new Date().getFullYear()}-${String(Date.now()).slice(-6)}`;
const tokenFor = user => jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '7d' });
function auth(req, res, next) {
  try { const raw = req.cookies.spp_session; if (!raw) return res.status(401).json({ error: 'লগইন প্রয়োজন' }); req.user = jwt.verify(raw, JWT_SECRET); next(); }
  catch { res.status(401).json({ error: 'সেশন শেষ হয়েছে, আবার লগইন করুন' }); }
}
function userById(id) { return db.prepare('SELECT id, full_name, shop_name, email, phone, verified, temp_mail_address FROM users WHERE id = ?').get(id); }
function activeOtp(userId, purpose = 'verify') { return db.prepare('SELECT * FROM otps WHERE user_id = ? AND purpose = ? ORDER BY id DESC LIMIT 1').get(userId, purpose); }

async function createTempMail() {
  try {
    const r = await fetch('https://www.1secmail.com/api/v1/?action=genRandomMailbox&count=1');
    const data = await r.json();
    return Array.isArray(data) ? data[0] : null;
  } catch { return null; }
}
async function pollTempMail(address) {
  if (!address || !address.includes('@')) return [];
  const [login, domain] = address.split('@');
  try {
    const r = await fetch(`https://www.1secmail.com/api/v1/?action=getMessages&login=${encodeURIComponent(login)}&domain=${encodeURIComponent(domain)}`);
    return r.ok ? await r.json() : [];
  } catch { return []; }
}
async function sendOtpEmail(user, code) {
  const subject = 'আপনার Secure Print verification code';
  const html = `<div style="font-family:Arial"><h2>${SHOP_NAME}</h2><p>আপনার verification code:</p><strong style="font-size:28px;letter-spacing:8px">${code}</strong><p>কোডটি ১০ মিনিট কার্যকর থাকবে।</p></div>`;
  if (process.env.SMTP_HOST && process.env.SMTP_USER) {
    const transporter = nodemailer.createTransport({ host: process.env.SMTP_HOST, port: Number(process.env.SMTP_PORT || 587), secure: Number(process.env.SMTP_PORT) === 465, auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS } });
    await transporter.sendMail({ from: process.env.SMTP_FROM || process.env.SMTP_USER, to: user.email, subject, html });
    return { sent: true, preview: false };
  }
  // Local mode: never expose the OTP in production responses; store a dev-only mailbox record.
  db.prepare('INSERT INTO otps (user_id, purpose, code_hash, expires_at, attempts, created_at) VALUES (?, ?, ?, ?, 0, ?)').run(user.id, 'dev-copy', sha256(code), Date.now() + 10 * 60 * 1000, Date.now());
  return { sent: false, preview: true };
}
async function issueOtp(user, purpose = 'verify') {
  const code = randomCode();
  db.prepare('UPDATE otps SET expires_at = 0 WHERE user_id = ? AND purpose = ?').run(user.id, purpose);
  db.prepare('INSERT INTO otps (user_id, purpose, code_hash, expires_at, attempts, created_at) VALUES (?, ?, ?, ?, 0, ?)').run(user.id, purpose, sha256(code), Date.now() + 10 * 60 * 1000, Date.now());
  const result = await sendOtpEmail(user, code);
  return { ...result, code: result.preview ? code : undefined };
}

app.get('/api/health', (req, res) => res.json({ ok: true, service: 'secure-print-platform', mode: 'local' }));
app.get('/api/me', auth, (req, res) => res.json({ user: userById(req.user.id) }));
app.post('/api/auth/signup', authLimiter, async (req, res) => {
  const { fullName, shopName, email, password, confirmPassword, phone } = req.body;
  if (!fullName || !shopName || !email || !password || password !== confirmPassword) return res.status(400).json({ error: 'সব তথ্য সঠিকভাবে পূরণ করুন' });
  if (password.length < 8) return res.status(400).json({ error: 'পাসওয়ার্ড কমপক্ষে ৮ অক্ষরের হতে হবে' });
  const normalized = email.trim().toLowerCase();
  if (db.prepare('SELECT id FROM users WHERE email = ?').get(normalized)) return res.status(409).json({ error: 'এই ইমেইল আগে থেকেই নিবন্ধিত' });
  const tempMail = await createTempMail();
  const info = db.prepare('INSERT INTO users (full_name, shop_name, email, password_hash, phone, temp_mail_address) VALUES (?, ?, ?, ?, ?, ?)').run(fullName.trim(), shopName.trim(), normalized, await bcrypt.hash(password, 12), phone || '', tempMail);
  const user = userById(info.lastInsertRowid);
  const otp = await issueOtp(user);
  res.status(201).json({ message: 'Verification code পাঠানো হয়েছে', userId: user.id, email: user.email, tempMail: tempMail || null, devCode: otp.code || null, devMailbox: !otp.sent });
});
app.post('/api/auth/forgot-password', authLimiter, async (req, res) => { const user = db.prepare('SELECT * FROM users WHERE email = ?').get(String(req.body.email || '').trim().toLowerCase()); if (!user) return res.json({ message: 'যদি account থাকে, reset code পাঠানো হয়েছে' }); const result = await issueOtp(user, 'reset'); res.json({ message: 'Password reset code পাঠানো হয়েছে', userId: user.id, devCode: result.code || null }); });
app.post('/api/auth/reset-password', authLimiter, async (req, res) => { const user = db.prepare('SELECT * FROM users WHERE id = ?').get(Number(req.body.userId)); const otp = activeOtp(Number(req.body.userId), 'reset'); if (!user || !otp || otp.expires_at < Date.now() || otp.attempts >= 5 || sha256(String(req.body.code)) !== otp.code_hash) return res.status(400).json({ error: 'Reset code অবৈধ বা মেয়াদোত্তীর্ণ' }); if (!req.body.password || String(req.body.password).length < 8) return res.status(400).json({ error: 'নতুন পাসওয়ার্ড কমপক্ষে ৮ অক্ষরের হতে হবে' }); db.prepare('UPDATE users SET password_hash = ? WHERE id = ?').run(await bcrypt.hash(req.body.password, 12), user.id); db.prepare('UPDATE otps SET expires_at = 0 WHERE id = ?').run(otp.id); res.json({ message: 'Password reset সফল হয়েছে' }); });
app.post('/api/auth/resend', async (req, res) => {
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(Number(req.body.userId));
  if (!user) return res.status(404).json({ error: 'অ্যাকাউন্ট পাওয়া যায়নি' });
  const last = activeOtp(user.id, 'verify');
  if (last && Date.now() - last.created_at < 30_000) return res.status(429).json({ error: '৩০ সেকেন্ড পরে আবার চেষ্টা করুন' });
  const result = await issueOtp(user); res.json({ message: 'নতুন কোড পাঠানো হয়েছে', devCode: result.code || null, tempMail: user.temp_mail_address });
});
app.post('/api/auth/verify', (req, res) => {
  const { userId, code } = req.body; const user = db.prepare('SELECT * FROM users WHERE id = ?').get(Number(userId)); const otp = activeOtp(Number(userId), 'verify');
  if (!user || !otp || otp.expires_at < Date.now() || otp.attempts >= 5) return res.status(400).json({ error: 'কোডটি মেয়াদোত্তীর্ণ বা অবৈধ' });
  if (sha256(String(code)) !== otp.code_hash) { db.prepare('UPDATE otps SET attempts = attempts + 1 WHERE id = ?').run(otp.id); return res.status(400).json({ error: 'ভুল verification code' }); }
  db.prepare('UPDATE users SET verified = 1 WHERE id = ?').run(user.id); db.prepare('UPDATE otps SET expires_at = 0 WHERE id = ?').run(otp.id); res.cookie('spp_session', tokenFor(user), { httpOnly: true, sameSite: 'lax', secure: false, maxAge: 7 * 86400000 }); res.json({ message: 'ইমেইল ভেরিফাই হয়েছে' });
});
app.post('/api/auth/login', authLimiter, async (req, res) => {
  const user = db.prepare('SELECT * FROM users WHERE email = ?').get(String(req.body.email || '').trim().toLowerCase());
  if (!user || !(await bcrypt.compare(req.body.password || '', user.password_hash))) return res.status(401).json({ error: 'ইমেইল বা পাসওয়ার্ড সঠিক নয়' });
  if (!user.verified) return res.status(403).json({ error: 'অ্যাকাউন্ট ভেরিফাই করুন', userId: user.id });
  res.cookie('spp_session', tokenFor(user), { httpOnly: true, sameSite: 'lax', secure: false, maxAge: req.body.remember ? 30 * 86400000 : 7 * 86400000 }); res.json({ user: userById(user.id) });
});
app.post('/api/auth/logout', (req, res) => { res.clearCookie('spp_session'); res.json({ ok: true }); });
app.get('/api/dev-mailbox/:userId', async (req, res) => {
  const user = db.prepare('SELECT temp_mail_address FROM users WHERE id = ?').get(Number(req.params.userId)); if (!user) return res.status(404).json({ error: 'not found' });
  const messages = await pollTempMail(user.temp_mail_address);
  const local = db.prepare("SELECT created_at, expires_at FROM otps WHERE user_id = ? AND purpose = 'dev-copy' ORDER BY id DESC LIMIT 1").get(Number(req.params.userId));
  res.json({ address: user.temp_mail_address, provider: '1secmail', messages, localPreview: local ? 'SMTP সেট না থাকায় কোডটি signup response-এ দেখানো হয়েছে' : null });
});

app.get('/api/dashboard', auth, (req, res) => {
  const stats = db.prepare(`SELECT COUNT(*) total, SUM(status='active') active, SUM(status='paused') paused, SUM(expiry_at IS NOT NULL AND expiry_at < datetime('now')) expired, COALESCE(SUM(print_count),0) prints, COALESCE(SUM(session_count),0) sessions FROM products WHERE user_id = ?`).get(req.user.id);
  const products = db.prepare('SELECT id, product_code, customer_name, product_name, category, status, print_limit, print_count, session_count, expiry_at, created_at FROM products WHERE user_id = ? ORDER BY id DESC LIMIT 8').all(req.user.id);
  res.json({ stats: { total: stats.total || 0, active: stats.active || 0, paused: stats.paused || 0, expired: stats.expired || 0, prints: stats.prints || 0, sessions: stats.sessions || 0, scans: Math.round((stats.sessions || 0) * 1.7) }, products });
});
app.get('/api/products', auth, (req, res) => res.json({ products: db.prepare('SELECT * FROM products WHERE user_id = ? ORDER BY id DESC').all(req.user.id) }));
app.post('/api/products', auth, upload.single('photo'), async (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'একটি JPG, PNG অথবা WEBP ছবি দিন' });
  const code = productCode(); const expiry = req.body.expiry || new Date(Date.now() + 30 * 86400000).toISOString();
  const qrData = `${APP_URL}/p/${code}`;
  const result = db.prepare('INSERT INTO products (user_id, product_code, customer_name, product_name, category, file_name, mime_type, qr_data, print_limit, expiry_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)').run(req.user.id, code, req.body.customerName || 'নতুন কাস্টমার', req.body.productName || 'Untitled Product', req.body.category || 'সাধারণ', req.file.filename, req.file.mimetype, qrData, Number(req.body.printLimit || 5), expiry);
  const qrPath = path.join(uploadDir, `${code}.png`); await QRCode.toFile(qrPath, qrData, { errorCorrectionLevel: 'H', margin: 3, width: 512, color: { dark: '#111827', light: '#ffffff' } });
  db.prepare('INSERT INTO print_settings (product_id) VALUES (?)').run(result.lastInsertRowid);
  db.prepare('INSERT INTO product_activity (product_id, action, details) VALUES (?, ?, ?)').run(result.lastInsertRowid, 'PRODUCT_CREATED', 'Photo uploaded and QR generated');
  const product = db.prepare('SELECT * FROM products WHERE id = ?').get(result.lastInsertRowid);
  res.status(201).json({ product, card: { qr: `/private/qr/${code}`, printUrl: `/p/${code}` } });
});
app.get('/api/products/:id', auth, (req, res) => { const p = db.prepare('SELECT * FROM products WHERE id = ? AND user_id = ?').get(Number(req.params.id), req.user.id); if (!p) return res.status(404).json({ error: 'পণ্য পাওয়া যায়নি' }); res.json({ product: p }); });
app.patch('/api/products/:id', auth, (req, res) => { const p = db.prepare('SELECT * FROM products WHERE id = ? AND user_id = ?').get(Number(req.params.id), req.user.id); if (!p) return res.status(404).json({ error: 'পণ্য পাওয়া যায়নি' }); const status = req.body.status || p.status; const privacy = req.body.privacy || p.privacy || 'PRINT-ONLY'; if (!['PUBLIC','PRIVATE','PRINT-ONLY'].includes(privacy)) return res.status(400).json({ error: 'Privacy value অবৈধ' }); db.prepare('UPDATE products SET status = ?, print_limit = ?, customer_name = ?, product_name = ?, privacy = ?, expiry_at = ? WHERE id = ?').run(status, Number(req.body.printLimit ?? p.print_limit), req.body.customerName || p.customer_name, req.body.productName || p.product_name, privacy, req.body.expiry || p.expiry_at, p.id); res.json({ product: db.prepare('SELECT * FROM products WHERE id = ?').get(p.id) }); });
app.get('/private/qr/:code', (req, res) => { const p = db.prepare('SELECT product_code FROM products WHERE product_code = ?').get(req.params.code); if (!p) return res.sendStatus(404); res.sendFile(path.join(uploadDir, `${p.product_code}.png`)); });
app.get('/p/:code', (req, res) => res.sendFile(path.join(__dirname, 'public', 'print.html')));
app.get('/api/print/:code', async (req, res) => { const p = db.prepare('SELECT * FROM products WHERE product_code = ? AND deleted_at IS NULL').get(req.params.code); if (!p) return res.status(404).json({ error: 'পণ্য পাওয়া যায়নি' }); if (p.privacy === 'PRIVATE') return res.status(403).json({ error: 'এই পণ্যটি private করা আছে' }); if (p.status !== 'active') return res.status(403).json({ error: p.status === 'paused' ? 'Product temporarily unavailable.' : 'এই পণ্যটি আর সক্রিয় নেই' }); if (p.expiry_at && new Date(p.expiry_at) < new Date()) return res.status(403).json({ error: 'এই পণ্যের মেয়াদ শেষ' }); if (p.print_limit !== -1 && p.print_count >= p.print_limit) return res.status(403).json({ error: 'Print limit reached.' }); const sessionId = `PS-${crypto.randomBytes(3).toString('hex').toUpperCase()}`; db.prepare('INSERT INTO print_sessions VALUES (?, ?, ?, 0, ?)').run(sessionId, p.id, Date.now() + 60_000, Date.now()); db.prepare('INSERT INTO print_jobs (product_id, session_id, copies, status) VALUES (?, ?, ?, ?)').run(p.id, sessionId, 1, 'READY'); db.prepare('INSERT INTO product_activity (product_id, action, details) VALUES (?, ?, ?)').run(p.id, 'QR_SCANNED', 'Temporary print session created'); db.prepare('UPDATE products SET session_count = session_count + 1 WHERE id = ?').run(p.id); res.json({ sessionId, expiresAt: Date.now() + 60_000, product: { code: p.product_code, customerName: p.customer_name, productName: p.product_name, category: p.category, printCount: p.print_count, printLimit: p.print_limit, image: `/private/photo/${p.product_code}/${sessionId}` } }); });
app.get('/private/photo/:code/:session', (req, res) => { const row = db.prepare('SELECT p.* , s.expires_at, s.used FROM products p JOIN print_sessions s ON s.product_id = p.id WHERE p.product_code = ? AND s.id = ?').get(req.params.code, req.params.session); if (!row || row.expires_at < Date.now() || row.used) return res.sendStatus(403); res.type(row.mime_type); res.sendFile(path.join(uploadDir, row.file_name)); });
app.post('/api/print/:session/complete', (req, res) => { const s = db.prepare('SELECT * FROM print_sessions WHERE id = ?').get(req.params.session); if (!s || s.expires_at < Date.now() || s.used) return res.status(403).json({ error: 'Print session expired' }); db.prepare('UPDATE print_sessions SET used = 1 WHERE id = ?').run(s.id); db.prepare("UPDATE print_jobs SET status = 'COMPLETED', completed_at = datetime('now') WHERE session_id = ?").run(s.id); db.prepare('UPDATE products SET print_count = print_count + 1 WHERE id = ?').run(s.product_id); db.prepare('INSERT INTO product_activity (product_id, action, details) VALUES (?, ?, ?)').run(s.product_id, 'PRINT_COMPLETED', 'Print session completed'); res.json({ ok: true }); });

// Extended product lifecycle, settings, analytics and account APIs.
function ownedProduct(userId, id) { return db.prepare('SELECT * FROM products WHERE id = ? AND user_id = ? AND deleted_at IS NULL').get(Number(id), userId); }
app.get('/api/search', auth, (req, res) => { const q = `%${String(req.query.q || '').trim()}%`; const status = req.query.status; let sql = 'SELECT * FROM products WHERE user_id = ? AND deleted_at IS NULL AND (product_code LIKE ? OR customer_name LIKE ? OR product_name LIKE ? OR category LIKE ?)'; const args = [req.user.id, q, q, q, q]; if (['active','paused'].includes(status)) { sql += ' AND status = ?'; args.push(status); } if (status === 'limit') sql += ' AND print_limit != -1 AND print_count >= print_limit'; res.json({ products: db.prepare(sql + ' ORDER BY id DESC LIMIT 100').all(...args) }); });
app.get('/api/products/:id/activity', auth, (req, res) => { const p = ownedProduct(req.user.id, req.params.id); if (!p) return res.status(404).json({ error: 'পণ্য পাওয়া যায়নি' }); res.json({ activity: db.prepare('SELECT * FROM product_activity WHERE product_id = ? ORDER BY id DESC').all(p.id) }); });
app.post('/api/products/:id/action', auth, (req, res) => { const p = ownedProduct(req.user.id, req.params.id); if (!p) return res.status(404).json({ error: 'পণ্য পাওয়া যায়নি' }); const { action } = req.body; const actions = { pause: ['paused','PRODUCT_PAUSED'], resume: ['active','PRODUCT_RESUMED'] }; if (actions[action]) { db.prepare('UPDATE products SET status = ? WHERE id = ?').run(actions[action][0], p.id); db.prepare('INSERT INTO product_activity (product_id, action, details) VALUES (?, ?, ?)').run(p.id, actions[action][1], 'Status changed by owner'); } else if (action === 'delete') { db.prepare("UPDATE products SET status = 'deleted', deleted_at = datetime('now') WHERE id = ?").run(p.id); db.prepare('INSERT INTO product_activity (product_id, action, details) VALUES (?, ?, ?)').run(p.id, 'PRODUCT_TRASHED', 'Soft deleted; recoverable from trash'); } else if (action === 'renew') { const days = Math.max(1, Math.min(3650, Number(req.body.days || 30))); db.prepare("UPDATE products SET expiry_at = datetime('now', '+' || ? || ' days'), status = 'active' WHERE id = ?").run(days, p.id); db.prepare('INSERT INTO product_activity (product_id, action, details) VALUES (?, ?, ?)').run(p.id, 'PRODUCT_RENEWED', `${days} days`); } else if (action === 'reset-print') { db.prepare('UPDATE products SET print_count = 0 WHERE id = ?').run(p.id); db.prepare('INSERT INTO product_activity (product_id, action, details) VALUES (?, ?, ?)').run(p.id, 'PRINT_COUNT_RESET', 'Reset by owner'); } else return res.status(400).json({ error: 'অজানা action' }); res.json({ product: db.prepare('SELECT * FROM products WHERE id = ?').get(p.id) }); });
app.get('/api/products/:id/settings', auth, (req, res) => { const p = ownedProduct(req.user.id, req.params.id); if (!p) return res.status(404).json({ error: 'পণ্য পাওয়া যায়নি' }); let settings = db.prepare('SELECT * FROM print_settings WHERE product_id = ?').get(p.id); if (!settings) { db.prepare('INSERT OR IGNORE INTO print_settings (product_id) VALUES (?)').run(p.id); settings = db.prepare('SELECT * FROM print_settings WHERE product_id = ?').get(p.id); } res.json({ settings }); });
app.put('/api/products/:id/settings', auth, (req, res) => { const p = ownedProduct(req.user.id, req.params.id); if (!p) return res.status(404).json({ error: 'পণ্য পাওয়া যায়নি' }); const x = req.body; db.prepare(`INSERT INTO print_settings (product_id,paper,photo_size,unit,orientation,margin_top,margin_bottom,margin_left,margin_right,gap_horizontal,gap_vertical,copies,fit,dpi,border,crop_marks) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(product_id) DO UPDATE SET paper=excluded.paper,photo_size=excluded.photo_size,unit=excluded.unit,orientation=excluded.orientation,margin_top=excluded.margin_top,margin_bottom=excluded.margin_bottom,margin_left=excluded.margin_left,margin_right=excluded.margin_right,gap_horizontal=excluded.gap_horizontal,gap_vertical=excluded.gap_vertical,copies=excluded.copies,fit=excluded.fit,dpi=excluded.dpi,border=excluded.border,crop_marks=excluded.crop_marks`).run(p.id,x.paper||'A4',x.photoSize||'35x45 mm',x.unit||'mm',x.orientation||'portrait',Number(x.marginTop||5),Number(x.marginBottom||5),Number(x.marginLeft||5),Number(x.marginRight||5),Number(x.gapHorizontal||2),Number(x.gapVertical||2),Number(x.copies||1),x.fit||'fit',Number(x.dpi||300),x.border?1:0,x.cropMarks?1:0); res.json({ settings: db.prepare('SELECT * FROM print_settings WHERE product_id = ?').get(p.id) }); });
app.get('/api/print-queue', auth, (req, res) => res.json({ jobs: db.prepare('SELECT j.*, p.product_code, p.customer_name, p.product_name FROM print_jobs j JOIN products p ON p.id=j.product_id WHERE p.user_id=? ORDER BY j.id DESC LIMIT 100').all(req.user.id) }));
app.get('/api/analytics', auth, (req, res) => { const r = db.prepare(`SELECT COUNT(*) products, SUM(status='active') active, SUM(status='paused') paused, SUM(print_count) prints, SUM(session_count) sessions, SUM(expiry_at IS NOT NULL AND expiry_at < datetime('now')) expired FROM products WHERE user_id=? AND deleted_at IS NULL`).get(req.user.id); const activity = db.prepare(`SELECT substr(a.created_at,1,10) day, count(*) count FROM product_activity a JOIN products p ON p.id=a.product_id WHERE p.user_id=? GROUP BY day ORDER BY day DESC LIMIT 14`).all(req.user.id); res.json({ summary: r, activity }); });
app.get('/api/account', auth, (req, res) => { const user = userById(req.user.id); const shop = db.prepare('SELECT * FROM shops WHERE user_id=?').get(req.user.id) || {}; res.json({ user, shop }); });
app.put('/api/account', auth, (req, res) => { const x=req.body; db.prepare('UPDATE users SET full_name=?, shop_name=?, phone=? WHERE id=?').run(String(x.fullName||'').trim(),String(x.shopName||'').trim(),String(x.phone||''),req.user.id); db.prepare(`INSERT INTO shops (user_id,address,website,facebook,instagram,business_description,theme) VALUES (?,?,?,?,?,?,?) ON CONFLICT(user_id) DO UPDATE SET address=excluded.address,website=excluded.website,facebook=excluded.facebook,instagram=excluded.instagram,business_description=excluded.business_description,theme=excluded.theme`).run(req.user.id,x.address||'',x.website||'',x.facebook||'',x.instagram||'',x.businessDescription||'',x.theme||'light'); res.json({ user: userById(req.user.id) }); });
app.get('/api/card/:code.svg', async (req, res) => { const p = db.prepare('SELECT p.*, u.shop_name, u.full_name, u.phone FROM products p JOIN users u ON u.id=p.user_id WHERE p.product_code=? AND p.deleted_at IS NULL').get(req.params.code); if(!p) return res.sendStatus(404); const qr=await QRCode.toDataURL(p.qr_data,{errorCorrectionLevel:'H',margin:2,width:260}); const svg=`<svg xmlns="http://www.w3.org/2000/svg" width="1600" height="900" viewBox="0 0 1600 900"><defs><linearGradient id="g" x1="0" y1="0" x2="1" y2="1"><stop stop-color="#211d5f"/><stop offset="1" stop-color="#6d5dfc"/></linearGradient></defs><rect width="1600" height="900" rx="42" fill="url(#g)"/><circle cx="1320" cy="120" r="260" fill="#ffffff10"/><text x="100" y="130" fill="#fff" font-family="Arial" font-size="42" font-weight="700">${p.shop_name}</text><text x="100" y="310" fill="#dcd9ff" font-family="Arial" font-size="25">SECURE PRINT CARD</text><text x="100" y="390" fill="#fff" font-family="Arial" font-size="64" font-weight="700">${p.customer_name}</text><text x="100" y="455" fill="#dcd9ff" font-family="Arial" font-size="32">${p.product_name}</text><text x="100" y="760" fill="#fff" font-family="Arial" font-size="27">SCAN QR TO SECURELY PRINT YOUR PHOTO</text><text x="100" y="815" fill="#c5c1ff" font-family="Arial" font-size="22">${p.product_code} · ${p.phone||''}</text><rect x="1170" y="210" width="310" height="310" rx="24" fill="#fff"/><image href="${qr}" x="1195" y="235" width="260" height="260"/><text x="1250" y="585" fill="#fff" font-family="Arial" font-size="23">PRINT-ONLY ACCESS</text></svg>`; res.type('image/svg+xml').send(svg); });

app.use((err, req, res, next) => { console.error(err); res.status(500).json({ error: 'সার্ভারে একটি সমস্যা হয়েছে' }); });
app.listen(PORT, '0.0.0.0', () => console.log(`Secure Print Platform running at ${APP_URL}`));

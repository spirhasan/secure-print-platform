# Secure Print Platform

লোকাল-ফার্স্ট photo → product → QR → print-only platform। এটি static mockup নয়; Express backend, persistent database, private upload storage এবং real print-session workflowসহ runnable application।

## Implemented modules

- Bengali desktop-first SaaS dashboard এবং mobile bottom navigation
- Signup / login / logout
- bcrypt password hashing
- 6-digit OTP verification: 10-minute expiry, hashed code, 5 attempts, resend throttle
- Password reset OTP API
- Free temporary-mail adapter: 1secmail inbox provisioning + polling endpoint
- SMTP না থাকলে local Dev Mailbox mode
- Helmet, CORS, global rate limit এবং auth rate limit
- Private uploaded photos; direct original-file URL নেই
- প্রতিটি upload-এর জন্য unique Product ID এবং high-error-correction QR
- Product lifecycle: edit, pause, resume, renew, soft-delete, reset print count
- Product privacy: PUBLIC / PRIVATE / PRINT-ONLY; QR print route-এ server-side enforcement
- Print settings: paper, photo size, unit, orientation, margins, spacing, copies, fit, DPI, border, crop marks
- Secure QR route → server validation → 60-second temporary print session
- QR scan, print completion, product lifecycle activity log
- Persistent print queue: READY / COMPLETED status
- Analytics API এবং dashboard analytics view
- Global product search by code, customer, product name, category
- Account / shop profile editing এবং theme preference storage
- Automatic 16:9 SVG QR product card generation: `/api/card/:productCode.svg`
- No download button in customer print-only environment
- Health endpoint: `/api/health`
- Render Docker deployment files: `Dockerfile`, `render.yaml`
- PostgreSQL production schema reference: `schema.sql`

## Local run

```bash
cp .env.example .env
npm install
npm run dev
```

Open: `http://localhost:3000`

লোকাল OTP testing-এর জন্য SMTP প্রয়োজন নেই। Signup করলে UI-তে Dev Mailbox OTP দেখাবে। `TEMP_MAIL_PROVIDER=1secmail` থাকলে user-এর জন্য একটি free temporary inbox তৈরি করার চেষ্টা হবে এবং `/api/dev-mailbox/:userId` endpoint inbox poll করবে।

## SMTP

বাস্তব inbox-এ OTP পাঠাতে `.env`-এ SMTP সেট করুন:

```env
SMTP_HOST=smtp.example.com
SMTP_PORT=587
SMTP_USER=...
SMTP_PASS=...
SMTP_FROM=no-reply@example.com
```

## Production / Render

- `Dockerfile` Node 22 production image তৈরি করে
- `render.yaml` health check এবং environment variables define করে
- `schema.sql` PostgreSQL normalized schema reference হিসেবে দেওয়া আছে
- production-এ `DATABASE_URL`, `SESSION_SECRET/JWT_SECRET`, verified-domain SMTP এবং object storage adapter configure করতে হবে
- বর্তমান runnable local adapter SQLite ব্যবহার করে, যাতে আলাদা database server ছাড়াই development হয়
- production image-এ local filesystem uploads ব্যবহার না করে S3/R2-compatible private object storage adapter বসাতে হবে
- HTTPS production-এ secure cookie flag enable করতে হবে

## Important security note

Temp mail কেবল local QA/testing-এর জন্য। Production customer authentication-এর জন্য নিজের verified email domain ও SMTP ব্যবহার করুন। Screenshots বা screen-photograph কোনো web app শতভাগ আটকাতে পারে না; এই project private storage, short-lived session, server-side permission check, print limit এবং no-download UI ব্যবহার করে practical protection দেয়।

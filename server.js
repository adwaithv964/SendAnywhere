'use strict';

const express = require('express');
const helmet = require('helmet');
const compression = require('compression');
const rateLimit = require('express-rate-limit');
const multer = require('multer');
const archiver = require('archiver');
const fs = require('fs');
const fsp = require('fs/promises');
const path = require('path');
const crypto = require('crypto');

// ─── Master key validation ────────────────────────────────────────────────────
// Generate with: node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
const MASTER_KEY_HEX = process.env.SERVER_MASTER_KEY || '';
if (!/^[0-9a-fA-F]{64}$/.test(MASTER_KEY_HEX)) {
  console.error(
    '\n  ✗  SERVER_MASTER_KEY is missing or invalid.\n' +
    '     Generate a key with:\n' +
    "       node -e \"console.log(require('crypto').randomBytes(32).toString('hex'))\"\n" +
    '     Then set it as the SERVER_MASTER_KEY environment variable.\n'
  );
  process.exit(1);
}
const MASTER_KEY = Buffer.from(MASTER_KEY_HEX, 'hex');

// Derive a separate secret for download token HMAC (never used for file encryption)
const TOKEN_SECRET = crypto.createHmac('sha256', MASTER_KEY).update('download-token-v1').digest();

// ─── Configuration ─────────────────────────────────────────────────────────────
const app = express();
const PORT = Number(process.env.PORT || 3000);
const HOST = process.env.HOST || '0.0.0.0';
const MAX_FILE_SIZE = Number(process.env.MAX_FILE_SIZE || 2 * 1024 * 1024 * 1024); // 2 GB
const MAX_FILES = Number(process.env.MAX_FILES || 50);
const EXPIRY_MINUTES = Number(process.env.EXPIRY_MINUTES || 30);
const DATA_DIR = path.resolve(process.env.DATA_DIR || path.join(__dirname, 'data'));
const TRANSFER_DIR = path.join(DATA_DIR, 'transfers');
const TMP_DIR = path.join(DATA_DIR, 'tmp');

// MIME types blocked from upload (HTML/JS injection and execution risk)
const BLOCKED_MIME = new Set([
  'text/html', 'text/javascript', 'application/javascript',
  'application/x-javascript', 'text/xml', 'application/xml',
  'application/xhtml+xml', 'application/x-httpd-php', 'text/x-php'
]);

fs.mkdirSync(TRANSFER_DIR, { recursive: true });
fs.mkdirSync(TMP_DIR, { recursive: true });

// ─── Cryptographic helpers ─────────────────────────────────────────────────────

/**
 * Encrypt a small buffer (e.g. a filename) with AES-256-GCM.
 * Returns base64-encoded [12-byte IV | 16-byte auth tag | ciphertext].
 */
function encryptSmall(keyBuf, plainBuf) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', keyBuf, iv);
  const ct = Buffer.concat([cipher.update(plainBuf), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([iv, tag, ct]).toString('base64');
}

/**
 * Decrypt a base64-encoded [IV | tag | ciphertext] blob.
 * Throws if authentication fails (tampered data).
 */
function decryptSmall(keyBuf, b64) {
  const buf = Buffer.from(b64, 'base64');
  const iv = buf.subarray(0, 12);
  const tag = buf.subarray(12, 28);
  const ct = buf.subarray(28);
  const decipher = crypto.createDecipheriv('aes-256-gcm', keyBuf, iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ct), decipher.final()]);
}

/**
 * Seal a 32-byte transfer key under the server master key (AES-256-GCM).
 * Returns base64 — safe to store in manifest.json.
 */
function sealKey(transferKeyBuf) {
  return encryptSmall(MASTER_KEY, transferKeyBuf);
}

/**
 * Unseal a sealed key. Throws on any tamper or wrong master key.
 * Returns 32-byte Buffer.
 */
function unsealKey(sealedBase64) {
  return decryptSmall(MASTER_KEY, sealedBase64);
}

/**
 * Encrypt a file from inputPath → outputPath using AES-256-GCM.
 * Only ciphertext is written to disk. IV and auth tag are returned
 * for storage in the manifest (they are not secret, only the key is).
 */
async function encryptFileTo(inputPath, outputPath, keyBuf) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', keyBuf, iv);
  let authTag;

  await new Promise((resolve, reject) => {
    const rStream = fs.createReadStream(inputPath);
    const wStream = fs.createWriteStream(outputPath);
    rStream.on('error', reject);
    wStream.on('error', reject);
    cipher.on('error', reject);
    // Capture auth tag as soon as cipher is done, before wStream finishes
    cipher.on('end', () => { authTag = cipher.getAuthTag(); });
    wStream.on('finish', resolve);
    rStream.pipe(cipher).pipe(wStream);
  });

  return { iv: iv.toString('hex'), tag: authTag.toString('hex') };
}

/**
 * Create an AES-256-GCM decryption Transform stream for a stored file.
 * Authentication tag is verified when the stream ends; pipe errors bubble up.
 */
function createDecryptStream(keyBuf, ivHex, tagHex) {
  const iv = Buffer.from(ivHex, 'hex');
  const tag = Buffer.from(tagHex, 'hex');
  const decipher = crypto.createDecipheriv('aes-256-gcm', keyBuf, iv);
  decipher.setAuthTag(tag);
  return decipher;
}

// ─── One-time signed download tokens ──────────────────────────────────────────
// Tokens are HMAC-SHA256 signed, expire in 60 seconds, and are single-use.
// This prevents download-URL sharing and replay attacks.
const usedNonces = new Set();

function issueToken(transferId, fileId) {
  const nonce = crypto.randomBytes(8).toString('hex');
  const exp = Date.now() + 60_000;
  const payload = JSON.stringify({ tid: transferId, fid: fileId ?? 'all', exp, n: nonce });
  const sig = crypto.createHmac('sha256', TOKEN_SECRET).update(payload).digest('base64url');
  // Schedule nonce removal 30 s after token expiry (GC)
  setTimeout(() => usedNonces.delete(nonce), 90_000);
  return Buffer.from(JSON.stringify({ p: payload, s: sig })).toString('base64url');
}

function verifyToken(token, transferId, fileId) {
  let outer;
  try { outer = JSON.parse(Buffer.from(String(token), 'base64url').toString()); } catch {
    return { ok: false, reason: 'Malformed token.' };
  }
  const { p: payload, s: sig } = outer;
  if (typeof payload !== 'string' || typeof sig !== 'string') {
    return { ok: false, reason: 'Malformed token.' };
  }

  const expectedSig = crypto.createHmac('sha256', TOKEN_SECRET).update(payload).digest('base64url');
  try {
    // Constant-time comparison — prevents timing-based forgery
    if (!crypto.timingSafeEqual(Buffer.from(sig, 'base64url'), Buffer.from(expectedSig, 'base64url'))) {
      return { ok: false, reason: 'Invalid token.' };
    }
  } catch {
    return { ok: false, reason: 'Invalid token.' };
  }

  let claims;
  try { claims = JSON.parse(payload); } catch { return { ok: false, reason: 'Malformed token.' }; }

  if (Date.now() > claims.exp) return { ok: false, reason: 'Token expired.' };
  if (claims.tid !== transferId) return { ok: false, reason: 'Token mismatch.' };
  if (claims.fid !== (fileId ?? 'all')) return { ok: false, reason: 'Token mismatch.' };
  if (usedNonces.has(claims.n)) return { ok: false, reason: 'Token already used.' };

  usedNonces.add(claims.n); // Mark as used (single-use enforcement)
  return { ok: true };
}

// ─── Express setup ─────────────────────────────────────────────────────────────
app.disable('x-powered-by');
app.set('trust proxy', 1);

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      scriptSrcAttr: ["'none'"],   // Block inline event handlers
      styleSrc: ["'self'"],
      imgSrc: ["'self'", 'data:'],
      connectSrc: ["'self'"],
      objectSrc: ["'none'"],
      baseUri: ["'self'"],
      frameAncestors: ["'none'"],  // Clickjacking protection
      upgradeInsecureRequests: []  // Force HTTPS when behind TLS proxy
    }
  },
  crossOriginEmbedderPolicy: false,
  referrerPolicy: { policy: 'no-referrer' }
}));

// Extra headers not covered by helmet defaults
app.use((_req, res, next) => {
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  res.setHeader('X-DNS-Prefetch-Control', 'off');
  res.setHeader('Cross-Origin-Resource-Policy', 'same-origin');
  next();
});

app.use(compression());
app.use(express.json({ limit: '1mb' }));

// ─── Rate limiters ─────────────────────────────────────────────────────────────

// Baseline: all /api/ routes
const generalApiLimiter = rateLimit({
  windowMs: 60 * 1000,
  limit: 120,
  standardHeaders: 'draft-7',
  legacyHeaders: false
});

// Upload: 5 per 15 min per IP — upload is expensive, prevent abuse
const uploadLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 5,
  standardHeaders: 'draft-7',
  legacyHeaders: false,
  message: { error: 'Too many uploads. Try again in 15 minutes.' }
});

// Code lookup: 10 per 5 min per IP — prevent brute-force of 6-digit codes
const lookupLimiter = rateLimit({
  windowMs: 5 * 60 * 1000,
  limit: 10,
  standardHeaders: 'draft-7',
  legacyHeaders: false,
  message: { error: 'Too many key attempts. Try again in a few minutes.' }
});

// Token issuance: 20 per 5 min per IP
const tokenLimiter = rateLimit({
  windowMs: 5 * 60 * 1000,
  limit: 20,
  standardHeaders: 'draft-7',
  legacyHeaders: false,
  message: { error: 'Too many requests. Try again shortly.' }
});

app.use('/api/', generalApiLimiter);

// ─── Filename sanitizer ────────────────────────────────────────────────────────
function sanitizeFilename(input) {
  const base = path.basename(String(input || 'file'));
  const cleaned = base.replace(/[\u0000-\u001F\u007F]/g, '').replace(/[<>:"/\\|?*]/g, '_').trim();
  return cleaned.slice(0, 180) || 'file';
}

// ─── Transfer path helpers ─────────────────────────────────────────────────────
function transferPath(id) { return path.join(TRANSFER_DIR, id); }
function manifestPath(id) { return path.join(transferPath(id), 'manifest.json'); }
function newCode() { return String(crypto.randomInt(100000, 1000000)); }

async function readManifest(id) {
  const raw = await fsp.readFile(manifestPath(id), 'utf8');
  return JSON.parse(raw);
}

async function writeManifest(id, manifest) {
  const target = manifestPath(id);
  const tmp = `${target}.tmp`;
  await fsp.writeFile(tmp, JSON.stringify(manifest, null, 2), 'utf8');
  await fsp.rename(tmp, target);
}

function isExpired(m) { return Date.now() >= m.expiresAt; }

async function safeRemoveTransfer(id) {
  try { await fsp.rm(transferPath(id), { recursive: true, force: true }); } catch {}
}

// ─── Multer storage (uploads land in TMP_DIR before encryption) ────────────────
const storage = multer.diskStorage({
  destination: async (_req, _file, cb) => {
    try {
      const tempDir = path.join(TMP_DIR, crypto.randomUUID());
      await fsp.mkdir(tempDir, { recursive: true });
      cb(null, tempDir);
    } catch (err) { cb(err); }
  },
  filename: (_req, file, cb) => {
    cb(null, `${crypto.randomUUID()}-${sanitizeFilename(file.originalname)}`);
  }
});

const upload = multer({
  storage,
  limits: { fileSize: MAX_FILE_SIZE, files: MAX_FILES },
  fileFilter: (_req, file, cb) => {
    const mime = (file.mimetype || '').toLowerCase().split(';')[0].trim();
    if (BLOCKED_MIME.has(mime)) {
      return cb(Object.assign(new Error('File type not allowed.'), { status: 400 }));
    }
    cb(null, true);
  }
});

// ─── Upload ────────────────────────────────────────────────────────────────────
app.post('/api/transfers', uploadLimiter, upload.array('files', MAX_FILES), async (req, res) => {
  const files = req.files || [];
  if (!files.length) return res.status(400).json({ error: 'Choose at least one file.' });

  // One unique 256-bit AES key per transfer — never stored in plaintext
  const transferKey = crypto.randomBytes(32);
  const sealedKey = sealKey(transferKey);

  let code = newCode();
  for (let i = 0; i < 8; i++) {
    if (!await findTransferByCode(code)) break;
    code = newCode();
  }

  const id = crypto.randomUUID();
  const targetDir = transferPath(id);
  const filesForResponse = [];

  try {
    await fsp.mkdir(targetDir, { recursive: true });
    let totalBytes = 0;
    const manifestFiles = [];

    for (const file of files) {
      totalBytes += file.size;
      const storedName = `${crypto.randomUUID()}.enc`;
      const finalPath = path.join(targetDir, storedName);

      // Encrypt before writing to TRANSFER_DIR — plaintext never persists on disk
      const { iv, tag } = await encryptFileTo(file.path, finalPath, transferKey);

      // Encrypt the original filename — manifest won't expose plaintext names
      const safeOriginalName = sanitizeFilename(file.originalname);
      const encName = encryptSmall(transferKey, Buffer.from(safeOriginalName, 'utf8'));

      manifestFiles.push({
        id: crypto.randomUUID(),
        encName,   // AES-256-GCM encrypted filename (base64)
        size: file.size,
        type: file.mimetype || 'application/octet-stream',
        storedName,
        iv,        // AES-GCM IV (not secret)
        tag        // AES-GCM auth tag (not secret, but proves integrity)
      });
      filesForResponse.push({ name: safeOriginalName, size: file.size, type: file.mimetype || 'application/octet-stream' });
    }

    const manifest = {
      id, code, sealedKey,
      createdAt: Date.now(),
      expiresAt: Date.now() + EXPIRY_MINUTES * 60 * 1000,
      downloads: 0, maxDownloads: 20,
      totalBytes, files: manifestFiles
    };

    await writeManifest(id, manifest);

    // Clean up temp upload directories
    const tmpDirs = await fsp.readdir(TMP_DIR).catch(() => []);
    for (const dir of tmpDirs) {
      try { await fsp.rm(path.join(TMP_DIR, dir), { recursive: true, force: true }); } catch {}
    }

    res.status(201).json({ code, expiresAt: manifest.expiresAt, files: filesForResponse, totalBytes });
  } catch (err) {
    console.error('Upload error:', err);
    await safeRemoveTransfer(id);
    res.status(500).json({ error: 'Upload could not be completed.' });
  }
});

// ─── Transfer lookup helpers ───────────────────────────────────────────────────
async function findTransferByCode(code) {
  let entries;
  try { entries = await fsp.readdir(TRANSFER_DIR, { withFileTypes: true }); } catch { return null; }
  for (const entry of entries) {
    if (!entry.isDirectory()) continue;
    try {
      const m = await readManifest(entry.name);
      if (m.code === code) return m;
    } catch {}
  }
  return null;
}

async function requireTransfer(req, res, next) {
  const code = String(req.params.code || '');
  if (!/^\d{6}$/.test(code)) return res.status(400).json({ error: 'Enter a valid 6-digit key.' });
  const manifest = await findTransferByCode(code);
  if (!manifest) return res.status(404).json({ error: 'Transfer not found or expired.' });
  if (isExpired(manifest) || manifest.downloads >= manifest.maxDownloads) {
    await safeRemoveTransfer(manifest.id);
    return res.status(410).json({ error: 'This transfer is no longer available.' });
  }
  req.transfer = manifest;
  next();
}

// ─── Transfer info ─────────────────────────────────────────────────────────────
app.get('/api/transfers/:code', lookupLimiter, requireTransfer, (req, res) => {
  const m = req.transfer;
  let key;
  try { key = unsealKey(m.sealedKey); } catch {
    return res.status(500).json({ error: 'Could not read transfer.' });
  }
  const decryptedFiles = m.files.map(f => {
    let name = 'file';
    try { name = decryptSmall(key, f.encName).toString('utf8'); } catch {}
    return { id: f.id, name, size: f.size, type: f.type };
  });
  res.json({
    code: m.code,
    expiresAt: m.expiresAt,
    downloadsRemaining: Math.max(0, m.maxDownloads - m.downloads),
    totalBytes: m.totalBytes,
    files: decryptedFiles
  });
});

// ─── Issue one-time download token ────────────────────────────────────────────
// Client must call this before each download. Tokens expire in 60 s and are single-use.
app.post('/api/transfers/:code/token', tokenLimiter, requireTransfer, (req, res) => {
  const m = req.transfer;
  const { fileId } = req.body;
  if (fileId !== undefined && fileId !== null && !m.files.find(f => f.id === fileId)) {
    return res.status(404).json({ error: 'File not found.' });
  }
  res.json({ token: issueToken(m.id, fileId ?? null) });
});

// ─── Single file download ──────────────────────────────────────────────────────
app.get('/api/transfers/:code/files/:fileId', requireTransfer, async (req, res) => {
  const m = req.transfer;
  const file = m.files.find(f => f.id === req.params.fileId);
  if (!file) return res.status(404).json({ error: 'File not found.' });

  // Require a valid one-time token
  const token = req.query.t;
  if (!token) return res.status(403).json({ error: 'Download token required.' });
  const check = verifyToken(String(token), m.id, file.id);
  if (!check.ok) return res.status(403).json({ error: check.reason });

  const source = path.join(transferPath(m.id), file.storedName);
  try { await fsp.access(source, fs.constants.R_OK); } catch {
    return res.status(404).json({ error: 'File is unavailable.' });
  }

  let key, displayName = 'file';
  try {
    key = unsealKey(m.sealedKey);
    displayName = decryptSmall(key, file.encName).toString('utf8');
  } catch { return res.status(500).json({ error: 'Decryption key unavailable.' }); }

  res.setHeader('Content-Disposition', `attachment; filename*=UTF-8''${encodeURIComponent(displayName)}`);
  res.setHeader('Content-Type', file.type || 'application/octet-stream');
  res.setHeader('Content-Length', String(file.size)); // AES-GCM output == plaintext size
  res.setHeader('Cache-Control', 'no-store');

  const rStream = fs.createReadStream(source);
  const decipher = createDecryptStream(key, file.iv, file.tag);

  rStream.on('error', () => { if (!res.headersSent) res.status(500).end('Download failed.'); });
  decipher.on('error', () => { if (!res.headersSent) res.status(500).end('Decryption failed.'); });

  decipher.on('end', async () => {
    try {
      const latest = await readManifest(m.id);
      latest.downloads += 1;
      await writeManifest(m.id, latest);
      if (latest.downloads >= latest.maxDownloads || isExpired(latest)) await safeRemoveTransfer(latest.id);
    } catch {}
  });

  rStream.pipe(decipher).pipe(res);
});

// ─── Download all as ZIP ───────────────────────────────────────────────────────
app.get('/api/transfers/:code/all', requireTransfer, async (req, res) => {
  const m = req.transfer;
  if (!m.files.length) return res.status(404).json({ error: 'No files in transfer.' });

  const token = req.query.t;
  if (!token) return res.status(403).json({ error: 'Download token required.' });
  const check = verifyToken(String(token), m.id, null);
  if (!check.ok) return res.status(403).json({ error: check.reason });

  let key;
  try { key = unsealKey(m.sealedKey); } catch {
    return res.status(500).json({ error: 'Decryption key unavailable.' });
  }

  res.setHeader('Content-Disposition', `attachment; filename="send-${m.code}.zip"`);
  res.setHeader('Content-Type', 'application/zip');
  res.setHeader('Cache-Control', 'no-store');

  const archive = archiver('zip', { zlib: { level: 6 } });
  archive.on('error', () => res.destroy());
  archive.pipe(res);

  for (const file of m.files) {
    const source = path.join(transferPath(m.id), file.storedName);
    let name = 'file';
    try { name = decryptSmall(key, file.encName).toString('utf8'); } catch {}
    // Decrypt each file on-the-fly into the ZIP stream
    const decipher = createDecryptStream(key, file.iv, file.tag);
    archive.append(fs.createReadStream(source).pipe(decipher), { name });
  }

  await archive.finalize();

  try {
    const latest = await readManifest(m.id);
    latest.downloads += 1;
    await writeManifest(m.id, latest);
    if (latest.downloads >= latest.maxDownloads || isExpired(latest)) await safeRemoveTransfer(latest.id);
  } catch {}
});

// ─── Delete transfer ───────────────────────────────────────────────────────────
app.delete('/api/transfers/:code', requireTransfer, async (req, res) => {
  await safeRemoveTransfer(req.transfer.id);
  res.status(204).end();
});

// ─── Health ────────────────────────────────────────────────────────────────────
app.get('/api/health', (_req, res) => res.json({ ok: true, encrypted: true }));

// ─── Static files ──────────────────────────────────────────────────────────────
app.use(express.static(path.join(__dirname, 'public'), { extensions: ['html'], maxAge: '1h' }));
app.get('/{*splat}', (_req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

// ─── Cleanup expired transfers every 5 minutes ─────────────────────────────────
setInterval(async () => {
  try {
    const entries = await fsp.readdir(TRANSFER_DIR, { withFileTypes: true });
    for (const entry of entries) {
      if (!entry.isDirectory()) continue;
      try {
        const m = await readManifest(entry.name);
        if (isExpired(m) || m.downloads >= m.maxDownloads) await safeRemoveTransfer(m.id);
      } catch {}
    }
  } catch {}
}, 5 * 60 * 1000).unref();

// ─── Start ─────────────────────────────────────────────────────────────────────
app.listen(PORT, HOST, () => {
  console.log(`🔒 Send tool running on http://${HOST}:${PORT} (AES-256-GCM encrypted at rest)`);
});

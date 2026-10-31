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

// â”€â”€â”€ Master key validation â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// Generate with: node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
const MASTER_KEY_HEX = process.env.SERVER_MASTER_KEY || '';
if (!/^[0-9a-fA-F]{64}$/.test(MASTER_KEY_HEX)) {
  console.error(
    '\n  âœ—  SERVER_MASTER_KEY is missing or invalid.\n' +
    '     Generate a key with:\n' +
    "       node -e \"console.log(require('crypto').randomBytes(32).toString('hex'))\"\n" +
    '     Then set it as the SERVER_MASTER_KEY environment variable.\n'
  );
  process.exit(1);
}
const MASTER_KEY = Buffer.from(MASTER_KEY_HEX, 'hex');

// Derive a separate secret for download token HMAC (never used for file encryption)
const TOKEN_SECRET = crypto.createHmac('sha256', MASTER_KEY).update('download-token-v1').digest();

// â”€â”€â”€ Configuration â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
const app = express();
const PORT = Number(process.env.PORT || 3000);
const HOST = process.env.HOST || '0.0.0.0';
const MAX_FILE_SIZE = Number(process.env.MAX_FILE_SIZE || 2 * 1024 * 1024 * 1024); // 2 GB
const MAX_FILES = Number(process.env.MAX_FILES || 50);
const EXPIRY_MINUTES = Number(process.env.EXPIRY_MINUTES || 30);
const DATA_DIR = path.resolve(process.env.DATA_DIR || path.join(__dirname, 'data'));
const TRANSFER_DIR = path.join(DATA_DIR, 'transfers');
const TMP_DIR = path.join(DATA_DIR, 'tmp');
const TEXT_DIR = path.join(DATA_DIR, 'texts');
const MAX_TEXT_SIZE = 2 * 1024 * 1024; // 2 MB â€” covers 500,000 chars worst-case UTF-8

// MIME types blocked from upload (HTML/JS injection and execution risk)
const BLOCKED_MIME = new Set([
  'text/html', 'text/javascript', 'application/javascript',
  'application/x-javascript', 'text/xml', 'application/xml',
  'application/xhtml+xml', 'application/x-httpd-php', 'text/x-php'
]);

fs.mkdirSync(TRANSFER_DIR, { recursive: true });
fs.mkdirSync(TMP_DIR, { recursive: true });
fs.mkdirSync(TEXT_DIR, { recursive: true });

// â”€â”€â”€ Cryptographic helpers â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

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
 * Returns base64 â€” safe to store in manifest.json.
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
 * Encrypt a file from inputPath â†’ outputPath using AES-256-GCM.
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

// â”€â”€â”€ One-time signed download tokens â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
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
    // Constant-time comparison â€” prevents timing-based forgery
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

// â”€â”€â”€ Express setup â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
app.disable('x-powered-by');
// Trust exactly one hop (the Render/cloud reverse proxy). Never set to `true`
// which trusts all proxies â€” that's what enabled the proxy-addr IP spoof.
app.set('trust proxy', 1);

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      scriptSrcAttr: ["'none'"],   // Block inline event handlers
      styleSrc: ["'self'"],
      imgSrc: ["'self'", 'data:'],
      fontSrc: ["'none'"],         // No external fonts
      connectSrc: ["'self'"],
      objectSrc: ["'none'"],
      mediaSrc: ["'none'"],
      frameSrc: ["'none'"],
      workerSrc: ["'none'"],
      manifestSrc: ["'none'"],
      formAction: ["'self'"],      // Block form submissions to foreign origins
      baseUri: ["'none'"],         // Prevent base tag hijacking
      frameAncestors: ["'none'"],  // Clickjacking protection
      upgradeInsecureRequests: []  // Force HTTPS when behind TLS proxy
    }
  },
  crossOriginEmbedderPolicy: false,
  referrerPolicy: { policy: 'no-referrer' },
  hsts: { maxAge: 31536000, includeSubDomains: true, preload: true }
}));

// Extra headers not covered by helmet defaults
app.use((_req, res, next) => {
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=(), payment=()');
  res.setHeader('X-DNS-Prefetch-Control', 'off');
  res.setHeader('Cross-Origin-Resource-Policy', 'same-origin');
  // Prevent MIME sniffing on API responses
  res.setHeader('X-Content-Type-Options', 'nosniff');
  next();
});

// Force all /api/ responses to be treated as JSON and not cached
app.use('/api/', (_req, res, next) => {
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('Vary', 'Accept');
  next();
});

app.use(compression());
app.use(express.json({ limit: '4mb' }));

// â”€â”€â”€ Rate limiters â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

// Baseline: all /api/ routes
const generalApiLimiter = rateLimit({
  windowMs: 60 * 1000,
  limit: 120,
  standardHeaders: 'draft-7',
  legacyHeaders: false
});

// Upload: 5 per 15 min per IP â€” upload is expensive, prevent abuse
const uploadLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 5,
  standardHeaders: 'draft-7',
  legacyHeaders: false,
  message: { error: 'Too many uploads. Try again in 15 minutes.' }
});

// Code lookup: 10 per 5 min per IP â€” prevent brute-force of 6-digit codes
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

// Text send: 10 per 15 min per IP
const textSendLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  standardHeaders: 'draft-7',
  legacyHeaders: false,
  message: { error: 'Too many text sends. Try again in 15 minutes.' }
});

// Text lookup: 15 per 5 min per IP
const textLookupLimiter = rateLimit({
  windowMs: 5 * 60 * 1000,
  limit: 15,
  standardHeaders: 'draft-7',
  legacyHeaders: false,
  message: { error: 'Too many key attempts. Try again in a few minutes.' }
});

app.use('/api/', generalApiLimiter);

// â”€â”€â”€ Filename sanitizer â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
function sanitizeFilename(input) {
  const base = path.basename(String(input || 'file'));
  const cleaned = base.replace(/[\u0000-\u001F\u007F]/g, '').replace(/[<>:"/\\|?*]/g, '_').trim();
  return cleaned.slice(0, 180) || 'file';
}

// â”€â”€â”€ Transfer path helpers â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
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

// â”€â”€â”€ Multer storage (uploads land in TMP_DIR before encryption) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
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
  limits: { fileSize: MAX_FILE_SIZE, files: MAX_FILES, fields: 0, parts: MAX_FILES + 1 },
  fileFilter: (_req, file, cb) => {
    const mime = (file.mimetype || '').toLowerCase().split(';')[0].trim();
    if (BLOCKED_MIME.has(mime)) {
      return cb(Object.assign(new Error('File type not allowed.'), { status: 400 }));
    }
    cb(null, true);
  }
});

// Multer error handler â€” surfaces clean 4xx messages without stack traces
function handleMulterError(err, req, res, next) {
  if (err && err.code === 'LIMIT_FILE_SIZE') return res.status(413).json({ error: 'File too large.' });
  if (err && err.code === 'LIMIT_FILE_COUNT') return res.status(400).json({ error: `Too many files (max ${MAX_FILES}).` });
  if (err && err.code === 'LIMIT_UNEXPECTED_FILE') return res.status(400).json({ error: 'Unexpected field.' });
  if (err && err.status === 400) return res.status(400).json({ error: err.message });
  if (err) return res.status(500).json({ error: 'Upload could not be processed.' });
  next();
}

// â”€â”€â”€ Upload â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
app.post('/api/transfers', uploadLimiter, upload.array('files', MAX_FILES), handleMulterError, async (req, res) => {
  const files = req.files || [];
  if (!files.length) return res.status(400).json({ error: 'Choose at least one file.' });

  // One unique 256-bit AES key per transfer â€” never stored in plaintext
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

      // Encrypt before writing to TRANSFER_DIR â€” plaintext never persists on disk
      const { iv, tag } = await encryptFileTo(file.path, finalPath, transferKey);

      // Encrypt the original filename â€” manifest won't expose plaintext names
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

// â”€â”€â”€ Transfer lookup helpers â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
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
  // Validate manifest.id is a real UUID before using it in path operations (path traversal guard)
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(manifest.id)) {
    return res.status(500).json({ error: 'Corrupt transfer record.' });
  }
  req.transfer = manifest;
  next();
}

// â”€â”€â”€ Transfer info â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
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

// â”€â”€â”€ Issue one-time download token â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// Client must call this before each download. Tokens expire in 60 s and are single-use.
app.post('/api/transfers/:code/token', tokenLimiter, requireTransfer, (req, res) => {
  const m = req.transfer;
  const { fileId } = req.body;
  // Validate fileId is a UUID to prevent injection into token payload
  const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
  if (fileId !== undefined && fileId !== null) {
    if (typeof fileId !== 'string' || !UUID_RE.test(fileId) || !m.files.find(f => f.id === fileId)) {
      return res.status(404).json({ error: 'File not found.' });
    }
  }
  res.json({ token: issueToken(m.id, fileId ?? null) });
});

// â”€â”€â”€ Single file download â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
app.get('/api/transfers/:code/files/:fileId', requireTransfer, async (req, res) => {
  const m = req.transfer;
  // Validate fileId is a UUID to prevent path traversal via :fileId param
  const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
  if (!UUID_RE.test(req.params.fileId)) return res.status(400).json({ error: 'Invalid file ID.' });
  const file = m.files.find(f => f.id === req.params.fileId);
  if (!file) return res.status(404).json({ error: 'File not found.' });
  // Require a valid one-time token
  const token = req.query.t;
  if (!token) return res.status(403).json({ error: 'Download token required.' });
  const check = verifyToken(String(token), m.id, file.id);
  if (!check.ok) return res.status(403).json({ error: check.reason });

  const source = path.join(transferPath(m.id), file.storedName);
  // Path traversal guard: ensure resolved path stays within the transfer directory
  const expectedDir = path.resolve(transferPath(m.id));
  const resolvedSource = path.resolve(source);
  if (!resolvedSource.startsWith(expectedDir + path.sep) && resolvedSource !== expectedDir) {
    return res.status(400).json({ error: 'Invalid file path.' });
  }
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

// â”€â”€â”€ Download all as ZIP â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
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

// â”€â”€â”€ Delete transfer â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
app.delete('/api/transfers/:code', requireTransfer, async (req, res) => {
  await safeRemoveTransfer(req.transfer.id);
  res.status(204).end();
});

// â”€â”€â”€ Text transfers â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

function textManifestPath(code) { return path.join(TEXT_DIR, `${code}.json`); }

async function readTextManifest(code) {
  const raw = await fsp.readFile(textManifestPath(code), 'utf8');
  return JSON.parse(raw);
}

async function writeTextManifest(code, manifest) {
  const target = textManifestPath(code);
  const tmp = `${target}.tmp`;
  await fsp.writeFile(tmp, JSON.stringify(manifest, null, 2), 'utf8');
  await fsp.rename(tmp, target);
}

async function newTextCode() {
  for (let i = 0; i < 8; i++) {
    const code = String(crypto.randomInt(100000, 1000000));
    try { await fsp.access(textManifestPath(code)); } catch { return code; }
  }
  return String(crypto.randomInt(100000, 1000000));
}

// POST /api/texts â€” create a text transfer
app.post('/api/texts', textSendLimiter, async (req, res) => {
  const text = req.body && typeof req.body.text === 'string' ? req.body.text : '';
  if (!text.trim()) return res.status(400).json({ error: 'Text cannot be empty.' });
  if (Buffer.byteLength(text, 'utf8') > MAX_TEXT_SIZE) {
    return res.status(400).json({ error: 'Text exceeds maximum size of 500,000 characters.' });
  }

  const transferKey = crypto.randomBytes(32);
  const sealedKey = sealKey(transferKey);
  const encText = encryptSmall(transferKey, Buffer.from(text, 'utf8'));

  const code = await newTextCode();
  const manifest = {
    code, sealedKey, encText,
    charCount: text.length,
    createdAt: Date.now(),
    expiresAt: Date.now() + EXPIRY_MINUTES * 60 * 1000
  };

  try {
    await writeTextManifest(code, manifest);
    res.status(201).json({ code, expiresAt: manifest.expiresAt, charCount: manifest.charCount });
  } catch (err) {
    console.error('[TEXT_SEND_ERROR]', err.message || '');
    res.status(500).json({ error: 'Could not save text.' });
  }
});

// GET /api/texts/:code â€” retrieve a text transfer (single-use)
app.get('/api/texts/:code', textLookupLimiter, async (req, res) => {
  const code = String(req.params.code || '');
  if (!/^\d{6}$/.test(code)) return res.status(400).json({ error: 'Enter a valid 6-digit key.' });

  let manifest;
  try { manifest = await readTextManifest(code); } catch {
    return res.status(404).json({ error: 'Text not found or expired.' });
  }

  if (Date.now() >= manifest.expiresAt) {
    try { await fsp.unlink(textManifestPath(code)); } catch {}
    return res.status(410).json({ error: 'This text transfer is no longer available.' });
  }

  let key, text;
  try {
    key = unsealKey(manifest.sealedKey);
    text = decryptSmall(key, manifest.encText).toString('utf8');
  } catch {
    return res.status(500).json({ error: 'Could not decrypt text.' });
  }

  // Single-use: delete after retrieval
  try { await fsp.unlink(textManifestPath(code)); } catch {}

  res.json({ code, text, charCount: manifest.charCount, expiresAt: manifest.expiresAt });
});

// DELETE /api/texts/:code â€” cancel a text transfer (sender)
app.delete('/api/texts/:code', async (req, res) => {
  const code = String(req.params.code || '');
  if (!/^\d{6}$/.test(code)) return res.status(400).json({ error: 'Invalid key.' });
  try { await fsp.unlink(textManifestPath(code)); } catch {}
  res.status(204).end();
});

// â”€â”€â”€ Health â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
app.get('/api/health', (_req, res) => res.json({ ok: true, encrypted: true }));

// â”€â”€â”€ 404 handler for unknown API routes â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
app.use('/api/', (_req, res) => res.status(404).json({ error: 'Not found.' }));

// â”€â”€â”€ Static files â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
app.use(express.static(path.join(__dirname, 'public'), { extensions: ['html'], maxAge: '1h' }));
app.get('/{*splat}', (_req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

// â”€â”€â”€ Global error handler (OWASP A09 â€” never leak stack traces) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// eslint-disable-next-line no-unused-vars
app.use((err, _req, res, _next) => {
  console.error('[ERROR]', err.status || 500, err.code || '', err.message || '');
  const status = (typeof err.status === 'number' && err.status >= 400 && err.status < 600)
    ? err.status : 500;
  if (!res.headersSent) {
    res.status(status).json({ error: status < 500 ? (err.message || 'Bad request.') : 'Internal server error.' });
  }
});

// â”€â”€â”€ Cleanup expired transfers every 5 minutes â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
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

  // Also clean up expired text transfers
  try {
    const textFiles = await fsp.readdir(TEXT_DIR);
    for (const file of textFiles) {
      if (!file.endsWith('.json')) continue;
      try {
        const raw = await fsp.readFile(path.join(TEXT_DIR, file), 'utf8');
        const m = JSON.parse(raw);
        if (Date.now() >= m.expiresAt) await fsp.unlink(path.join(TEXT_DIR, file));
      } catch {}
    }
  } catch {}
}, 5 * 60 * 1000).unref();

// â”€â”€â”€ Process-level error guards â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
process.on('uncaughtException', (err) => {
  console.error('[UNCAUGHT]', err.message || err);
  process.exit(1);
});
process.on('unhandledRejection', (reason) => {
  console.error('[UNHANDLED_REJECTION]', reason instanceof Error ? reason.message : reason);
});

// â”€â”€â”€ Start â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
app.listen(PORT, HOST, () => {
  console.log(`ðŸ”’ Send tool running on http://${HOST}:${PORT} (AES-256-GCM encrypted at rest)`);
});

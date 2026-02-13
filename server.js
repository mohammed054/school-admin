const express = require('express');
const session = require('express-session');
const { default: MongoStore } = require('connect-mongo');
const cookieParser = require('cookie-parser');
const cors = require('cors');
const helmet = require('helmet');
const mongoose = require('mongoose');
const crypto = require('crypto');
const cloudinary = require('cloudinary').v2;
const streamifier = require('streamifier');
const multer = require('multer');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3001;
const IS_TEST = process.env.NODE_ENV === 'test';

const TOKEN_SECRET = process.env.TOKEN_SECRET || crypto.randomBytes(32).toString('hex');
const SESSION_SECRET = process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex');
const ADMIN_USERNAME = process.env.ADMIN_USERNAME || 'admin';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'Hikmah2026!';
const MAX_IMAGE_SIZE_BYTES = 5 * 1024 * 1024;
const MAX_CONTENT_VALUE_BYTES = 200 * 1024;
const IDENTIFIER_PATTERN = /^[a-zA-Z0-9_-]{1,80}$/;
const LOGIN_WINDOW_MS = 15 * 60 * 1000;
const LOGIN_MAX_ATTEMPTS = 10;
const loginAttempts = new Map();
const API_RATE_WINDOW_MS = 5 * 60 * 1000;
const API_RATE_MAX_REQUESTS = 300;
const MUTATION_RATE_WINDOW_MS = 15 * 60 * 1000;
const MUTATION_RATE_MAX_REQUESTS = 120;
const apiRequestBuckets = new Map();
const mutationRequestBuckets = new Map();

const ALLOWED_IMAGE_MIME_TYPES = new Set([
  'image/jpeg',
  'image/png',
  'image/webp',
  'image/gif',
  'image/svg+xml'
]);

if (!process.env.MONGODB_URI && !IS_TEST) {
  console.error('ERROR: MONGODB_URI environment variable is not set.');
  process.exit(1);
}

if (!process.env.SESSION_SECRET) {
  console.warn('WARN: SESSION_SECRET is not set. A temporary secret is being used for this process.');
}

if (!process.env.ADMIN_PASSWORD) {
  console.warn('WARN: ADMIN_PASSWORD is not set. Using fallback password.');
}

function generateToken(sessionID) {
  return crypto.createHmac('sha256', TOKEN_SECRET).update(sessionID).digest('hex');
}

function deepEqual(a, b) {
  return JSON.stringify(a) === JSON.stringify(b);
}

function parseBool(value) {
  return value === '1' || value === 'true' || value === true;
}

function isValidIdentifier(value) {
  return typeof value === 'string' && IDENTIFIER_PATTERN.test(value);
}

function getSerializedSizeBytes(value) {
  try {
    return Buffer.byteLength(JSON.stringify(value ?? ''), 'utf8');
  } catch {
    return Number.POSITIVE_INFINITY;
  }
}

function getLoginKey(req) {
  const forwarded = req.headers['x-forwarded-for'];
  if (typeof forwarded === 'string' && forwarded.length > 0) {
    return forwarded.split(',')[0].trim();
  }
  return req.ip || req.connection?.remoteAddress || 'unknown';
}

function isLoginRateLimited(key) {
  const now = Date.now();
  const record = loginAttempts.get(key);
  if (!record) {
    return { limited: false, retryAfterSeconds: 0 };
  }

  if (now - record.windowStart > LOGIN_WINDOW_MS) {
    loginAttempts.delete(key);
    return { limited: false, retryAfterSeconds: 0 };
  }

  if (record.count < LOGIN_MAX_ATTEMPTS) {
    return { limited: false, retryAfterSeconds: 0 };
  }

  const retryAfterSeconds = Math.ceil((LOGIN_WINDOW_MS - (now - record.windowStart)) / 1000);
  return { limited: true, retryAfterSeconds: Math.max(retryAfterSeconds, 1) };
}

function recordLoginFailure(key) {
  const now = Date.now();
  const current = loginAttempts.get(key);
  if (!current || now - current.windowStart > LOGIN_WINDOW_MS) {
    loginAttempts.set(key, { count: 1, windowStart: now });
    return;
  }

  loginAttempts.set(key, { count: current.count + 1, windowStart: current.windowStart });
}

function clearLoginFailures(key) {
  loginAttempts.delete(key);
}

function createRateLimiter(bucket, windowMs, maxRequests, scopeLabel) {
  return (req, res, next) => {
    if (req.method === 'OPTIONS' || req.path === '/health') {
      next();
      return;
    }

    const now = Date.now();
    const key = getLoginKey(req);
    const record = bucket.get(key);

    if (!record || now - record.windowStart > windowMs) {
      bucket.set(key, { count: 1, windowStart: now });
      next();
      return;
    }

    if (record.count >= maxRequests) {
      const retryAfterSeconds = Math.ceil((windowMs - (now - record.windowStart)) / 1000);
      const waitSeconds = Math.max(retryAfterSeconds, 1);
      res.setHeader('Retry-After', String(waitSeconds));
      res.status(429).json({
        error: `Too many ${scopeLabel} requests. Try again in ${waitSeconds} seconds.`
      });
      return;
    }

    bucket.set(key, { count: record.count + 1, windowStart: record.windowStart });
    next();
  };
}

const apiRateLimiter = createRateLimiter(apiRequestBuckets, API_RATE_WINDOW_MS, API_RATE_MAX_REQUESTS, 'API');
const mutationRateLimiter = createRateLimiter(
  mutationRequestBuckets,
  MUTATION_RATE_WINDOW_MS,
  MUTATION_RATE_MAX_REQUESTS,
  'write'
);

function applyMutationRateLimit(req, res, next) {
  if (req.method === 'POST' || req.method === 'PUT' || req.method === 'PATCH' || req.method === 'DELETE') {
    mutationRateLimiter(req, res, next);
    return;
  }

  next();
}

function buildFieldMeta(item, hasDraftOverride) {
  const publishedValue = item.publishedValue !== undefined ? item.publishedValue : item.value;
  const draftValue = item.draftValue;
  const hasDraft = typeof hasDraftOverride === 'boolean'
    ? hasDraftOverride
    : (typeof item.hasDraft === 'boolean' ? item.hasDraft : (draftValue !== undefined && !deepEqual(draftValue, publishedValue)));

  return {
    isDraft: hasDraft,
    version: Number.isInteger(item.version) && item.version > 0 ? item.version : 1,
    lastModified: item.updatedAt || null,
    lastPublishedAt: item.lastPublishedAt || null,
    lastPublishedBy: item.lastPublishedBy || null,
    lastEditedAt: item.lastEditedAt || null,
    lastEditedBy: item.lastEditedBy || null
  };
}

function getReadableValue(item, includeDraft) {
  const publishedValue = item.publishedValue !== undefined ? item.publishedValue : item.value;
  const hasDraft = typeof item.hasDraft === 'boolean'
    ? item.hasDraft
    : (item.draftValue !== undefined && !deepEqual(item.draftValue, publishedValue));

  if (includeDraft && hasDraft) {
    return item.draftValue;
  }

  return publishedValue;
}

function ensureLegacyMigrationOnDocument(doc) {
  let touched = false;

  if (doc.publishedValue === undefined) {
    doc.publishedValue = doc.value !== undefined ? doc.value : '';
    touched = true;
  }

  if (!Number.isInteger(doc.version) || doc.version < 1) {
    doc.version = 1;
    touched = true;
  }

  if (!Array.isArray(doc.history)) {
    doc.history = [];
    touched = true;
  }

  if (doc.history.length === 0) {
    doc.history.push({
      version: doc.version,
      value: doc.publishedValue,
      publishedAt: doc.lastPublishedAt || doc.updatedAt || new Date(),
      publishedBy: doc.lastPublishedBy || 'system'
    });
    touched = true;
  }

  return touched;
}

function mapContentResponse(items, includeDraft, includeMeta) {
  const contentMap = {};
  const metaMap = {};

  for (const item of items) {
    if (!contentMap[item.section]) {
      contentMap[item.section] = {};
    }

    contentMap[item.section][item.field] = getReadableValue(item, includeDraft);

    if (includeMeta) {
      metaMap[`${item.section}_${item.field}`] = buildFieldMeta(item);
    }
  }

  return includeMeta ? { content: contentMap, meta: metaMap } : contentMap;
}

const allowedOrigins = [
  'http://localhost:5173',
  'http://localhost:4173',
  'http://127.0.0.1:5173',
  'http://127.0.0.1:4173',
  'https://mohammed054.github.io'
];

if (process.env.FRONTEND_URL) {
  allowedOrigins.push(process.env.FRONTEND_URL);
}

app.set('trust proxy', 1);
app.disable('x-powered-by');

app.use(cors({
  origin(origin, callback) {
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
      return;
    }
    callback(new Error('Not allowed by CORS'));
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Session-ID']
}));

app.use(helmet({
  contentSecurityPolicy: false,
  crossOriginResourcePolicy: { policy: 'cross-origin' }
}));
app.use('/api', apiRateLimiter);
app.use('/api', applyMutationRateLimit);
app.use(express.json({ limit: '2mb' }));
app.use(cookieParser());

const sessionOptions = {
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    maxAge: 24 * 60 * 60 * 1000,
    sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax',
    domain: process.env.NODE_ENV === 'production' ? '.up.railway.app' : undefined
  }
};

if (!IS_TEST) {
  sessionOptions.store = new MongoStore({
    mongoUrl: process.env.MONGODB_URI,
    collectionName: 'sessions',
    ttl: 24 * 60 * 60
  });
}

app.use(session(sessionOptions));

if (!IS_TEST && process.env.MONGODB_URI) {
  mongoose.connect(process.env.MONGODB_URI, {
    serverSelectionTimeoutMS: 30000,
    socketTimeoutMS: 45000,
    maxPoolSize: 10,
    authSource: 'admin'
  })
    .then(() => console.log('Connected to MongoDB'))
    .catch((err) => console.error('MongoDB connection error:', err));
}

const historyEntrySchema = new mongoose.Schema({
  version: { type: Number, required: true },
  value: { type: mongoose.Schema.Types.Mixed, required: true },
  publishedAt: { type: Date, default: Date.now },
  publishedBy: { type: String, default: 'system' }
}, { _id: false });

const contentSchema = new mongoose.Schema({
  section: { type: String, required: true, index: true },
  field: { type: String, required: true, index: true },
  publishedValue: { type: mongoose.Schema.Types.Mixed, default: '' },
  draftValue: { type: mongoose.Schema.Types.Mixed, default: undefined },
  hasDraft: { type: Boolean, default: false },
  version: { type: Number, default: 1 },
  history: { type: [historyEntrySchema], default: [] },
  type: { type: String, default: 'text' },
  lastEditedAt: { type: Date, default: null },
  lastEditedBy: { type: String, default: null },
  lastPublishedAt: { type: Date, default: null },
  lastPublishedBy: { type: String, default: null },
  // Legacy support for older documents
  value: { type: mongoose.Schema.Types.Mixed, required: false }
}, {
  timestamps: true,
  minimize: false
});

contentSchema.index({ section: 1, field: 1 }, { unique: true });

const Content = mongoose.model('Content', contentSchema);

const checkAdminAuth = (req) => {
  if (req.session?.isAdmin) {
    return true;
  }

  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return false;
  }

  const token = authHeader.slice(7);
  const sessionID = req.headers['x-session-id'];
  if (!sessionID || !token || token.length !== 64) {
    return false;
  }

  const expected = generateToken(sessionID);
  if (token !== expected) {
    return false;
  }

  req.session.isAdmin = true;
  req.session.username = ADMIN_USERNAME;
  return true;
};

const requireAdmin = (req, res, next) => {
  if (!checkAdminAuth(req)) {
    res.status(401).json({ error: 'Unauthorized' });
    return;
  }
  next();
};

const getActor = (req) => req.session?.username || ADMIN_USERNAME;

app.get('/api/content', async (req, res) => {
  try {
    if (mongoose.connection.readyState !== 1) {
      return res.status(503).json({ error: 'Database unavailable' });
    }

    const includeDraft = req.query.mode === 'draft' && checkAdminAuth(req);
    const includeMeta = parseBool(req.query.includeMeta) && includeDraft;
    const allContent = await Content.find({}).maxTimeMS(20000).lean();

    const payload = mapContentResponse(allContent, includeDraft, includeMeta);
    res.json(payload);
  } catch (error) {
    console.error('Error fetching content:', error);
    res.status(503).json({ error: 'Failed to fetch content' });
  }
});

app.get('/api/content/:section', async (req, res) => {
  try {
    if (mongoose.connection.readyState !== 1) {
      return res.status(503).json({ error: 'Database unavailable' });
    }

    const includeDraft = req.query.mode === 'draft' && checkAdminAuth(req);
    const includeMeta = parseBool(req.query.includeMeta) && includeDraft;
    const sectionItems = await Content.find({ section: req.params.section }).maxTimeMS(20000).lean();

    const contentMap = {};
    const metaMap = {};

    for (const item of sectionItems) {
      contentMap[item.field] = getReadableValue(item, includeDraft);
      if (includeMeta) {
        metaMap[item.field] = buildFieldMeta(item);
      }
    }

    res.json(includeMeta ? { content: contentMap, meta: metaMap } : contentMap);
  } catch (error) {
    console.error('Error fetching section content:', error);
    res.status(503).json({ error: 'Failed to fetch section content' });
  }
});

app.get('/api/content/history/:section/:field', requireAdmin, async (req, res) => {
  try {
    const { section, field } = req.params;
    if (!isValidIdentifier(section) || !isValidIdentifier(field)) {
      return res.status(400).json({ error: 'Invalid section or field identifier' });
    }

    const item = await Content.findOne({ section, field }).lean();
    if (!item) {
      return res.status(404).json({ error: 'Content field not found' });
    }

    const history = Array.isArray(item.history) ? [...item.history].sort((a, b) => b.version - a.version) : [];
    res.json({
      section,
      field,
      version: Number.isInteger(item.version) ? item.version : 1,
      history
    });
  } catch (error) {
    console.error('Error fetching content history:', error);
    res.status(500).json({ error: 'Failed to fetch content history' });
  }
});

app.put('/api/content/:section/:field', requireAdmin, async (req, res) => {
  try {
    const { section, field } = req.params;
    const { value } = req.body;
    if (!isValidIdentifier(section) || !isValidIdentifier(field)) {
      return res.status(400).json({ error: 'Invalid section or field identifier' });
    }

    if (value === undefined) {
      return res.status(400).json({ error: 'value is required' });
    }
    if (getSerializedSizeBytes(value) > MAX_CONTENT_VALUE_BYTES) {
      return res.status(413).json({ error: 'Content value is too large' });
    }

    let item = await Content.findOne({ section, field });
    if (!item) {
      item = new Content({
        section,
        field,
        publishedValue: '',
        version: 1,
        history: []
      });
    }

    ensureLegacyMigrationOnDocument(item);

    item.draftValue = value;
    item.hasDraft = !deepEqual(value, item.publishedValue);
    if (!item.hasDraft) {
      item.draftValue = undefined;
    }

    item.lastEditedAt = new Date();
    item.lastEditedBy = getActor(req);

    await item.save();

    res.json({
      success: true,
      content: {
        section,
        field,
        value: getReadableValue(item.toObject(), true)
      },
      meta: buildFieldMeta(item.toObject())
    });
  } catch (error) {
    console.error('Error updating content draft:', error);
    res.status(500).json({ error: 'Failed to update content' });
  }
});

app.post('/api/content/:section/:field/publish', requireAdmin, async (req, res) => {
  try {
    const { section, field } = req.params;
    if (!isValidIdentifier(section) || !isValidIdentifier(field)) {
      return res.status(400).json({ error: 'Invalid section or field identifier' });
    }

    const item = await Content.findOne({ section, field });

    if (!item) {
      return res.status(404).json({ error: 'Content field not found' });
    }

    ensureLegacyMigrationOnDocument(item);

    if (!item.hasDraft) {
      return res.json({
        success: true,
        alreadyPublished: true,
        content: {
          section,
          field,
          value: item.publishedValue
        },
        meta: buildFieldMeta(item.toObject(), false)
      });
    }

    const actor = getActor(req);
    const publishedAt = new Date();
    const nextVersion = (item.version || 1) + 1;

    item.publishedValue = item.draftValue;
    item.draftValue = undefined;
    item.hasDraft = false;
    item.version = nextVersion;
    item.lastPublishedAt = publishedAt;
    item.lastPublishedBy = actor;

    item.history.push({
      version: nextVersion,
      value: item.publishedValue,
      publishedAt,
      publishedBy: actor
    });

    if (item.history.length > 50) {
      item.history = item.history.slice(item.history.length - 50);
    }

    await item.save();

    res.json({
      success: true,
      content: {
        section,
        field,
        value: item.publishedValue
      },
      meta: buildFieldMeta(item.toObject(), false)
    });
  } catch (error) {
    console.error('Error publishing content field:', error);
    res.status(500).json({ error: 'Failed to publish content' });
  }
});

app.post('/api/content/:section/:field/restore', requireAdmin, async (req, res) => {
  try {
    const { section, field } = req.params;
    if (!isValidIdentifier(section) || !isValidIdentifier(field)) {
      return res.status(400).json({ error: 'Invalid section or field identifier' });
    }

    const { version } = req.body || {};
    if (!Number.isInteger(version) || version < 1) {
      return res.status(400).json({ error: 'A valid version number is required' });
    }

    const item = await Content.findOne({ section, field });
    if (!item) {
      return res.status(404).json({ error: 'Content field not found' });
    }

    ensureLegacyMigrationOnDocument(item);
    const entry = item.history.find((historyItem) => historyItem.version === version);
    if (!entry) {
      return res.status(404).json({ error: 'Version not found' });
    }

    item.draftValue = entry.value;
    item.hasDraft = !deepEqual(entry.value, item.publishedValue);
    if (!item.hasDraft) {
      item.draftValue = undefined;
    }

    item.lastEditedAt = new Date();
    item.lastEditedBy = getActor(req);
    await item.save();

    res.json({
      success: true,
      content: {
        section,
        field,
        value: getReadableValue(item.toObject(), true)
      },
      meta: buildFieldMeta(item.toObject())
    });
  } catch (error) {
    console.error('Error restoring content version:', error);
    res.status(500).json({ error: 'Failed to restore content version' });
  }
});

app.post('/api/content/publish-all', requireAdmin, async (req, res) => {
  try {
    const actor = getActor(req);
    const items = await Content.find({ hasDraft: true });

    if (!items.length) {
      return res.json({ success: true, publishedCount: 0, publishedContent: {}, meta: {} });
    }

    const publishedContent = {};
    const meta = {};

    for (const item of items) {
      ensureLegacyMigrationOnDocument(item);

      const publishedAt = new Date();
      const nextVersion = (item.version || 1) + 1;

      item.publishedValue = item.draftValue;
      item.draftValue = undefined;
      item.hasDraft = false;
      item.version = nextVersion;
      item.lastPublishedAt = publishedAt;
      item.lastPublishedBy = actor;

      item.history.push({
        version: nextVersion,
        value: item.publishedValue,
        publishedAt,
        publishedBy: actor
      });

      if (item.history.length > 50) {
        item.history = item.history.slice(item.history.length - 50);
      }

      await item.save();

      if (!publishedContent[item.section]) {
        publishedContent[item.section] = {};
      }

      publishedContent[item.section][item.field] = item.publishedValue;
      meta[`${item.section}_${item.field}`] = buildFieldMeta(item.toObject(), false);
    }

    res.json({
      success: true,
      publishedCount: items.length,
      publishedContent,
      meta
    });
  } catch (error) {
    console.error('Error publishing all drafts:', error);
    res.status(500).json({ error: 'Failed to publish all drafts' });
  }
});

app.post('/api/content/bulk', requireAdmin, async (req, res) => {
  try {
    const { content } = req.body;
    if (!Array.isArray(content) || content.length === 0 || content.length > 100) {
      return res.status(400).json({ error: 'content must be a non-empty array with up to 100 items' });
    }

    const actor = getActor(req);

    for (const itemInput of content) {
      if (!itemInput?.section || !itemInput?.field) {
        continue;
      }
      if (!isValidIdentifier(itemInput.section) || !isValidIdentifier(itemInput.field)) {
        return res.status(400).json({ error: `Invalid section or field: ${itemInput.section || ''}/${itemInput.field || ''}` });
      }
      if (getSerializedSizeBytes(itemInput.value) > MAX_CONTENT_VALUE_BYTES) {
        return res.status(413).json({ error: `Content value is too large for ${itemInput.section}/${itemInput.field}` });
      }

      let item = await Content.findOne({ section: itemInput.section, field: itemInput.field });
      if (!item) {
        item = new Content({ section: itemInput.section, field: itemInput.field, version: 1, history: [] });
      }

      ensureLegacyMigrationOnDocument(item);

      const nextValue = itemInput.value;
      const changed = !deepEqual(nextValue, item.publishedValue);

      if (changed) {
        item.version = (item.version || 1) + 1;
        item.history.push({
          version: item.version,
          value: nextValue,
          publishedAt: new Date(),
          publishedBy: actor
        });
      }

      item.publishedValue = nextValue;
      item.draftValue = undefined;
      item.hasDraft = false;
      item.type = itemInput.type || item.type || 'text';
      item.lastEditedAt = new Date();
      item.lastEditedBy = actor;
      item.lastPublishedAt = new Date();
      item.lastPublishedBy = actor;

      if (item.history.length > 50) {
        item.history = item.history.slice(item.history.length - 50);
      }

      await item.save();
    }

    res.json({ success: true });
  } catch (error) {
    console.error('Error in bulk content upsert:', error);
    res.status(500).json({ error: 'Failed to bulk upsert content' });
  }
});

cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET
});

const upload = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: MAX_IMAGE_SIZE_BYTES
  },
  fileFilter: (req, file, cb) => {
    if (!ALLOWED_IMAGE_MIME_TYPES.has(file.mimetype)) {
      cb(new Error('INVALID_FILE_TYPE'));
      return;
    }
    cb(null, true);
  }
});

app.post('/api/upload', requireAdmin, (req, res) => {
  upload.single('image')(req, res, async (error) => {
    if (error) {
      if (error instanceof multer.MulterError && error.code === 'LIMIT_FILE_SIZE') {
        return res.status(400).json({ error: 'Image is too large. Max allowed size is 5MB.' });
      }
      if (error.message === 'INVALID_FILE_TYPE') {
        return res.status(400).json({ error: 'Unsupported file type. Allowed: JPG, PNG, WEBP, GIF, SVG.' });
      }
      return res.status(400).json({ error: 'Upload failed validation.' });
    }

    try {
      if (!req.file) {
        return res.status(400).json({ error: 'No file uploaded' });
      }

      const result = await new Promise((resolve, reject) => {
        const uploadStream = cloudinary.uploader.upload_stream(
          {
            folder: 'school-web',
            resource_type: 'image'
          },
          (streamError, streamResult) => {
            if (streamResult) {
              resolve(streamResult);
            } else {
              reject(streamError);
            }
          }
        );
        streamifier.createReadStream(req.file.buffer).pipe(uploadStream);
      });

      res.json({ url: result.secure_url, publicId: result.public_id });
    } catch (uploadError) {
      console.error('Upload error:', uploadError);
      res.status(500).json({ error: 'Failed to upload image' });
    }
  });
});

app.delete('/api/image/:publicId', requireAdmin, async (req, res) => {
  try {
    await cloudinary.uploader.destroy(req.params.publicId);
    res.json({ success: true });
  } catch (error) {
    console.error('Delete image error:', error);
    res.status(500).json({ error: 'Failed to delete image' });
  }
});

app.post('/api/login', (req, res) => {
  const { username, password } = req.body || {};
  if (typeof username !== 'string' || typeof password !== 'string') {
    return res.status(400).json({ success: false, message: 'Username and password are required.' });
  }
  if (username.length > 120 || password.length > 200) {
    return res.status(400).json({ success: false, message: 'Invalid credentials format.' });
  }

  const loginKey = getLoginKey(req);
  const limiter = isLoginRateLimited(loginKey);
  if (limiter.limited) {
    return res.status(429).json({
      success: false,
      message: `Too many login attempts. Try again in ${limiter.retryAfterSeconds} seconds.`
    });
  }

  if (username === ADMIN_USERNAME && password === ADMIN_PASSWORD) {
    req.session.isAdmin = true;
    req.session.username = username;
    clearLoginFailures(loginKey);
    const token = generateToken(req.sessionID);
    res.json({ success: true, message: 'Login successful', token, sessionID: req.sessionID });
    return;
  }

  recordLoginFailure(loginKey);
  res.status(401).json({ success: false, message: 'Invalid credentials' });
});

app.post('/api/logout', (req, res) => {
  req.session.destroy((error) => {
    if (error) {
      return res.status(500).json({ success: false, message: 'Logout failed' });
    }

    res.clearCookie('connect.sid');
    res.json({ success: true, message: 'Logout successful' });
  });
});

app.get('/api/check-auth', (req, res) => {
  if (checkAdminAuth(req)) {
    res.json({ isAuthenticated: true, username: req.session.username || ADMIN_USERNAME });
    return;
  }

  res.json({ isAuthenticated: false });
});

app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

if (require.main === module) {
  app.listen(PORT, () => {
    console.log(`School Admin Server running on port ${PORT}`);
  });
}

module.exports = app;

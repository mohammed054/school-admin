const express = require('express');
const session = require('express-session');
const cookieParser = require('cookie-parser');
const cors = require('cors');
const mongoose = require('mongoose');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3001;
const ADMIN_USERNAME = 'admin';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'Hikmah2026!';

if (!process.env.MONGODB_URI) {
  console.error('ERROR: MONGODB_URI environment variable is not set!');
  console.error('Please add MONGODB_URI to Railway variables');
  process.exit(1);
}

console.log('MongoDB URI configured:', process.env.MONGODB_URI.replace(/:([^:@]+)@/, ':****@'));

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

app.use(cors({
  origin: function(origin, callback) {
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

app.use(express.json({ limit: '50mb' }));
app.use(cookieParser());

app.use(session({
  secret: process.env.SESSION_SECRET || 'HikmahAdminSecret2026!',
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    maxAge: 24 * 60 * 60 * 1000,
    sameSite: 'none',
    domain: process.env.NODE_ENV === 'production' ? undefined : undefined
  }
}));

app.use((req, res, next) => {
  console.log(`${req.method} ${req.url} - Session ID: ${req.sessionID}, isAdmin: ${req.session ? req.session.isAdmin : 'N/A'}`);
  next();
});

mongoose.connect(process.env.MONGODB_URI, {
  serverSelectionTimeoutMS: 30000,
  socketTimeoutMS: 45000,
  maxPoolSize: 10,
  authSource: 'admin'
})
  .then(() => console.log('Connected to MongoDB'))
  .catch(err => console.error('MongoDB connection error:', err));

const contentSchema = new mongoose.Schema({
  section: { type: String, required: true, index: true },
  field: { type: String, required: true, index: true },
  value: { type: String, required: true },
  type: { type: String, default: 'text' },
  updatedAt: { type: Date, default: Date.now }
});

contentSchema.index({ section: 1, field: 1 }, { unique: true });

const Content = mongoose.model('Content', contentSchema);

app.get('/api/content', async (req, res) => {
  try {
    if (mongoose.connection.readyState !== 1) {
      return res.status(503).json({ error: 'Database unavailable' });
    }
    const allContent = await Content.find({}).maxTimeMS(20000).lean();
    const contentMap = {};
    allContent.forEach(item => {
      if (!contentMap[item.section]) contentMap[item.section] = {};
      contentMap[item.section][item.field] = item.value;
    });
    res.json(contentMap);
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
    const sectionContent = await Content.find({ section: req.params.section }).maxTimeMS(20000).lean();
    const contentMap = {};
    sectionContent.forEach(item => {
      contentMap[item.field] = item.value;
    });
    res.json(contentMap);
  } catch (error) {
    console.error('Error fetching content:', error);
    res.status(503).json({ error: 'Failed to fetch content' });
  }
});

const checkAdminAuth = (req) => {
  console.log('Auth check - Session:', req.session.isAdmin, 'Auth header:', req.headers.authorization ? 'present' : 'missing');
  if (req.session.isAdmin) return true;
  
  const authHeader = req.headers.authorization;
  if (authHeader && authHeader.startsWith('Bearer ')) {
    if (authHeader === 'Bearer logged_in') {
      req.session.isAdmin = true;
      req.session.username = 'admin';
      return true;
    }
  }
  return false;
};

app.put('/api/content/:section/:field', async (req, res) => {
  console.log('PUT request received:', req.params);
  if (!checkAdminAuth(req)) {
    console.log('Authentication failed');
    return res.status(401).json({ error: 'Unauthorized' });
  }
  try {
    const { section, field } = req.params;
    const { value } = req.body;
    
    if (mongoose.connection.readyState !== 1) {
      return res.status(503).json({ error: 'Database unavailable' });
    }
    
    const updated = await Content.findOneAndUpdate(
      { section, field },
      { section, field, value, updatedAt: new Date() },
      { upsert: true, new: true }
    );
    
    res.json({ success: true, content: updated });
  } catch (error) {
    console.error('Error updating content:', error);
    res.status(500).json({ error: 'Failed to update content' });
  }
});

app.post('/api/content/bulk', async (req, res) => {
  if (!checkAdminAuth(req)) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  try {
    if (mongoose.connection.readyState !== 1) {
      return res.status(503).json({ error: 'Database unavailable' });
    }
    const { content } = req.body;
    const bulkOps = content.map(item => ({
      updateOne: {
        filter: { section: item.section, field: item.field },
        update: { $set: { ...item, updatedAt: new Date() } },
        upsert: true
      }
    }));
    
    await Content.bulkWrite(bulkOps);
    res.json({ success: true });
  } catch (error) {
    console.error('Error bulk inserting content:', error);
    res.status(500).json({ error: 'Failed to bulk insert content' });
  }
});

const cloudinary = require('cloudinary').v2;
const streamifier = require('streamifier');
const multer = require('multer');

cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET
});

const upload = multer({ storage: multer.memoryStorage() });

app.post('/api/upload', upload.single('image'), async (req, res) => {
  if (!checkAdminAuth(req)) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'No file uploaded' });
    }

    const uploadFromBuffer = (req) => {
      return new Promise((resolve, reject) => {
        let cld_upload_stream = cloudinary.uploader.upload_stream(
          { folder: 'school-web', resource_type: 'auto' },
          (error, result) => {
            if (result) resolve(result);
            else reject(error);
          }
        );
        streamifier.createReadStream(req.file.buffer).pipe(cld_upload_stream);
      });
    };

    const result = await uploadFromBuffer(req);
    res.json({ url: result.secure_url, publicId: result.public_id });
  } catch (error) {
    console.error('Upload error:', error);
    res.status(500).json({ error: 'Failed to upload image' });
  }
});

app.delete('/api/image/:publicId', async (req, res) => {
  if (!checkAdminAuth(req)) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  
  try {
    await cloudinary.uploader.destroy(req.params.publicId);
    res.json({ success: true });
  } catch (error) {
    console.error('Delete error:', error);
    res.status(500).json({ error: 'Failed to delete image' });
  }
});

app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  console.log('Login attempt:', username, 'Session ID:', req.sessionID);
  
  if (username === ADMIN_USERNAME && password === ADMIN_PASSWORD) {
    req.session.isAdmin = true;
    req.session.username = username;
    console.log('Login successful, session saved');
    res.json({ success: true, message: 'Login successful' });
  } else {
    console.log('Login failed: invalid credentials');
    res.status(401).json({ success: false, message: 'Invalid credentials' });
  }
});

app.post('/api/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      return res.status(500).json({ success: false, message: 'Logout failed' });
    }
    res.clearCookie('connect.sid');
    res.json({ success: true, message: 'Logout successful' });
  });
});

app.get('/api/check-auth', (req, res) => {
  if (req.session.isAdmin) {
    res.json({ isAuthenticated: true, username: req.session.username });
  } else {
    const authHeader = req.headers.authorization;
    if (authHeader && authHeader.startsWith('Bearer ')) {
      if (authHeader === 'Bearer logged_in') {
        req.session.isAdmin = true;
        req.session.username = 'admin';
        res.json({ isAuthenticated: true, username: 'admin' });
      } else {
        res.json({ isAuthenticated: false });
      }
    } else {
      res.json({ isAuthenticated: false });
    }
  }
});

app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

app.listen(PORT, () => {
  console.log(`School Admin Server running on port ${PORT}`);
});

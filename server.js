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
      callback(null, true);
    }
  },
  credentials: true
}));
app.use(express.json({ limit: '50mb' }));
app.use(cookieParser());

app.use(session({
  secret: process.env.SESSION_SECRET || 'HikmahAdminSecret2026!',
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure: false,
    maxAge: null,
    sameSite: 'lax'
  }
}));

mongoose.connect(process.env.MONGODB_URI)
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
    const allContent = await Content.find({});
    const contentMap = {};
    allContent.forEach(item => {
      if (!contentMap[item.section]) contentMap[item.section] = {};
      contentMap[item.section][item.field] = item.value;
    });
    res.json(contentMap);
  } catch (error) {
    console.error('Error fetching content:', error);
    res.status(500).json({ error: 'Failed to fetch content' });
  }
});

app.get('/api/content/:section', async (req, res) => {
  try {
    const sectionContent = await Content.find({ section: req.params.section });
    const contentMap = {};
    sectionContent.forEach(item => {
      contentMap[item.field] = item.value;
    });
    res.json(contentMap);
  } catch (error) {
    console.error('Error fetching content:', error);
    res.status(500).json({ error: 'Failed to fetch content' });
  }
});

app.put('/api/content/:section/:field', async (req, res) => {
  if (!req.session.isAdmin) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  try {
    const { section, field } = req.params;
    const { value } = req.body;
    
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
  if (!req.session.isAdmin) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  try {
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

const { Cloudinary } = require('cloudinary');
const streamifier = require('streamifier');
const multer = require('multer');

const cloudinary = new Cloudinary({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET
});

const upload = multer({ storage: multer.memoryStorage() });

app.post('/api/upload', upload.single('image'), async (req, res) => {
  if (!req.session.isAdmin) {
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
  if (!req.session.isAdmin) {
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
  
  if (username === ADMIN_USERNAME && password === ADMIN_PASSWORD) {
    req.session.isAdmin = true;
    req.session.username = username;
    res.json({ success: true, message: 'Login successful' });
  } else {
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
    res.json({ isAuthenticated: false });
  }
});

app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

app.listen(PORT, () => {
  console.log(`School Admin Server running on http://localhost:${PORT}`);
});

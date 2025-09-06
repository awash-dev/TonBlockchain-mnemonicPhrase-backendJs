const serverless = require('serverless-http');
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const cloudinary = require('cloudinary').v2;
const multer = require('multer');
const { mnemonicNew, mnemonicToWalletKey, mnemonicValidate } = require('@ton/crypto');

const User = require('../models/user');
const PhraseLog = require('../models/phraseLog');
const ImageUpload = require('../models/imageUpload');

const app = express();
app.use(cors());
app.use(express.json({ limit: '2mb' }));

// Multer for image uploads
const storage = multer.memoryStorage();
const upload = multer({ storage });

// Cloudinary config
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});

// MongoDB connection
mongoose.connect(process.env.MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true
}).then(() => console.log('✅ Connected to MongoDB'))
  .catch(err => console.error(err));

// Auth middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Token required' });
  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Invalid token' });
    req.user = user;
    next();
  });
};

// Helpers
const normalizeMnemonic = (phrase) => phrase.trim().toLowerCase().split(/\s+/).join(' ');

const generateNewWallet = async (wordCount = 24) => {
  const words = await mnemonicNew(wordCount);
  if (!(await mnemonicValidate(words))) throw new Error('Invalid generated mnemonic');
  const keyPair = await mnemonicToWalletKey(words);
  return {
    mnemonic: words.join(' '),
    publicKey: keyPair.publicKey.toString('hex'),
    wordCount: words.length
  };
};

// ======== ROUTES ======== //

// Register
app.post('/api/register-auth-phrasecode', async (req, res) => {
  try {
    const { username, password, phraseCode } = req.body;
    if (!username || !password || !phraseCode) return res.status(400).json({ error: 'All fields required' });
    if (await User.findOne({ username })) return res.status(409).json({ error: 'Username taken' });

    const wallet = await generateNewWallet(Number(phraseCode));

    const newUser = new User({
      username,
      password,
      phraseCode,
      mnemonicPhrase: normalizeMnemonic(wallet.mnemonic),
      publicKey: wallet.publicKey
    });
    await newUser.save();

    const token = jwt.sign({ userId: newUser._id, username: newUser.username }, process.env.JWT_SECRET, { expiresIn: '3d' });

    res.status(201).json({
      success: true,
      message: 'User registered successfully',
      data: { token, user: { id: newUser._id, username, phraseCode, publicKey: newUser.publicKey }, mnemonic: wallet.mnemonic }
    });
  } catch (err) {
    console.error('Register error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Login by phrase
app.post('/api/login-phrase', async (req, res) => {
  try {
    const { mnemonicPhrase } = req.body;
    if (!mnemonicPhrase) return res.status(400).json({ error: 'Mnemonic phrase required' });

    const normalized = normalizeMnemonic(mnemonicPhrase);
    const words = normalized.split(' ');
    if (![12, 24].includes(words.length)) return res.status(400).json({ error: 'Phrase must be 12 or 24 words' });
    if (!(await mnemonicValidate(words))) return res.status(400).json({ error: 'Invalid mnemonic phrase' });

    const user = await User.findOne({ mnemonicPhrase: normalized });
    if (!user) return res.status(404).json({ error: 'User not found' });

    const token = jwt.sign({ userId: user._id, username: user.username }, process.env.JWT_SECRET, { expiresIn: '3d' });

    res.json({ success: true, message: 'Login successful', data: { token, user: { id: user._id, username: user.username, phraseCode: user.phraseCode, publicKey: user.publicKey } } });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get profile
app.get('/api/profile', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId).select('username phraseCode publicKey createdAt');
    const uploads = await ImageUpload.find({ userId: user._id }).select('imageUrl createdAt').sort({ createdAt: -1 });
    res.json({ success: true, data: { user, uploads } });
  } catch (err) {
    console.error('Profile error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Generate random phrase
app.post('/api/generate-random-phrase', async (req, res) => {
  try {
    const { code } = req.body;
    if (!['12', '24'].includes(code)) return res.status(400).json({ error: 'Invalid code' });

    const wallet = await generateNewWallet(Number(code));
    await new PhraseLog({ generatedCode: code, mnemonicPhrase: normalizeMnemonic(wallet.mnemonic), wordCount: wallet.wordCount, publicKey: wallet.publicKey, type: 'random_generated' }).save();

    res.json({ success: true, message: `Random ${wallet.wordCount}-word phrase generated`, data: wallet });
  } catch (err) {
    console.error('Generate phrase error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Upload image
app.post('/api/upload-image', authenticateToken, upload.single('image'), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: 'No image provided' });

    const result = await new Promise((resolve, reject) => {
      const stream = cloudinary.uploader.upload_stream({ folder: 'mnemonic_uploads' }, (err, uploaded) => {
        if (err) reject(err);
        else resolve(uploaded);
      });
      stream.end(req.file.buffer);
    });

    const newUpload = new ImageUpload({ userId: req.user.userId, imageUrl: result.secure_url, publicId: result.public_id });
    await newUpload.save();
    res.json({ success: true, data: newUpload });
  } catch (err) {
    console.error('Image upload error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

module.exports.handler = serverless(app);

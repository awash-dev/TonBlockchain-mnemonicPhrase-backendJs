require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const multer = require('multer');
const cloudinary = require('cloudinary').v2;
const { mnemonicNew, mnemonicToWalletKey, mnemonicValidate } = require('@ton/crypto');

const User = require('./models/user');
const PhraseLog = require('./models/phraseLog');
const ImageUpload = require('./models/imageUpload');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key';

app.use(cors());
app.use(express.json({ limit: '2mb' }));

// Multer
const storage = multer.memoryStorage();
const upload = multer({ storage });

// Cloudinary config
cloudinary.config({
    cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
    api_key: process.env.CLOUDINARY_API_KEY,
    api_secret: process.env.CLOUDINARY_API_SECRET
});

// MongoDB
mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/tonapp', {
    useNewUrlParser: true,
    useUnifiedTopology: true
}).then(() => console.log('✅ Connected to MongoDB'))
    .catch(err => console.error('MongoDB error:', err));

// Auth middleware
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'Token required' });
    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ error: 'Invalid token' });
        req.user = user;
        next();
    });
};

// Helpers
function normalizeMnemonic(phrase) {
    return phrase.trim().toLowerCase().split(/\s+/).join(' ');
}

async function generateNewWallet(wordCount = 24) {
    const words = await mnemonicNew(wordCount);
    const isValid = await mnemonicValidate(words);
    if (!isValid) throw new Error('Invalid mnemonic generated');
    const keyPair = await mnemonicToWalletKey(words);
    return { mnemonic: words.join(' '), publicKey: keyPair.publicKey.toString('hex'), wordCount: words.length };
}

// ================= ROUTES ================= //

// 1️⃣ Register
app.post('/api/register', async (req, res) => {
    const { username, password, phraseCode } = req.body;
    if (!username || !password || !phraseCode) return res.status(400).json({ error: 'All fields required' });
    if (!['12', '24'].includes(phraseCode)) return res.status(400).json({ error: 'Phrase code must be 12 or 24' });

    try {
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
        await new PhraseLog({
            generatedCode: phraseCode,
            mnemonicPhrase: normalizeMnemonic(wallet.mnemonic),
            wordCount: wallet.wordCount,
            publicKey: wallet.publicKey,
            type: 'registered'
        }).save();

        const token = jwt.sign({ userId: newUser._id, username: newUser.username }, JWT_SECRET, { expiresIn: '3d' });

        res.status(201).json({
            success: true,
            message: 'User registered',
            data: { token, user: { id: newUser._id, username: newUser.username, phraseCode: newUser.phraseCode, publicKey: newUser.publicKey }, mnemonic: wallet.mnemonic }
        });
    } catch (err) {
        console.error('Register error:', err);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// 2️⃣ Login by mnemonic
app.post('/api/login-phrase', async (req, res) => {
    const { mnemonicPhrase } = req.body;
    if (!mnemonicPhrase) return res.status(400).json({ error: 'Mnemonic phrase required' });
    try {
        const normalized = normalizeMnemonic(mnemonicPhrase);
        const words = normalized.split(' ');
        if (![12, 24].includes(words.length)) return res.status(400).json({ error: 'Phrase must be 12 or 24 words' });
        if (!(await mnemonicValidate(words))) return res.status(400).json({ error: 'Invalid mnemonic phrase' });

        const user = await User.findOne({ mnemonicPhrase: normalized });
        if (!user) return res.status(404).json({ error: 'User not found' });

        const token = jwt.sign({ userId: user._id, username: user.username }, JWT_SECRET, { expiresIn: '3d' });
        res.json({ success: true, message: 'Login successful', data: { token, user: { id: user._id, username: user.username, phraseCode: user.phraseCode, publicKey: user.publicKey } } });
    } catch (err) {
        console.error('Login error:', err);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// 3️⃣ Login by username/password
app.post('/api/login-username', async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'Username and password required' });
    try {
        const user = await User.findOne({ username });
        if (!user) return res.status(404).json({ error: 'User not found' });
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) return res.status(401).json({ error: 'Invalid password' });

        const token = jwt.sign({ userId: user._id, username: user.username }, JWT_SECRET, { expiresIn: '3d' });
        res.json({ success: true, message: 'Login successful', data: { token, user: { id: user._id, username: user.username, phraseCode: user.phraseCode, publicKey: user.publicKey } } });
    } catch (err) {
        console.error('Username login error:', err);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// 4️⃣ Profile
app.get('/api/profile', authenticateToken, async (req, res) => {
    try {
        const user = await User.findById(req.user.userId).select('username phraseCode publicKey createdAt');
        if (!user) return res.status(404).json({ error: 'User not found' });

        const uploads = await ImageUpload.find({ userId: user._id }).select('imageUrl publicId createdAt').sort({ createdAt: -1 });

        res.json({ success: true, data: { user, uploads } });
    } catch (err) {
        console.error('Profile error:', err);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// 5️⃣ Upload / Update image (new entry)
app.post('/api/upload-image', authenticateToken, upload.single('image'), async (req, res) => {
    try {
        if (!req.file) return res.status(400).json({ error: 'No image provided' });

        const uploaded = await new Promise((resolve, reject) => {
            const stream = cloudinary.uploader.upload_stream({ folder: 'mnemonic_uploads' }, (err, result) => {
                if (err) reject(err); else resolve(result);
            });
            stream.end(req.file.buffer);
        });

        const newImage = new ImageUpload({
            userId: req.user.userId,
            imageUrl: uploaded.secure_url,
            publicId: uploaded.public_id
        });
        await newImage.save();
        res.json({ success: true, data: newImage });
    } catch (err) {
        console.error('Image upload error:', err);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// 6️⃣ Generate random phrase (12/24 words)
app.post('/api/generate-random-phrase', async (req, res) => {
    const { code } = req.body;
    if (!['12', '24'].includes(code)) return res.status(400).json({ error: 'Provide 12 or 24' });
    try {
        const wallet = await generateNewWallet(Number(code));
        await new PhraseLog({
            generatedCode: code,
            mnemonicPhrase: normalizeMnemonic(wallet.mnemonic),
            wordCount: wallet.wordCount,
            publicKey: wallet.publicKey,
            type: 'random_generated'
        }).save();

        res.json({ success: true, message: `Random ${wallet.wordCount}-word phrase generated`, data: wallet });
    } catch (err) {
        console.error('Generate phrase error:', err);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// 7️⃣ Check phrase validity
app.post('/api/check-phrase', async (req, res) => {
    const { mnemonicPhrase } = req.body;
    if (!mnemonicPhrase) return res.status(400).json({ error: 'Phrase required' });
    try {
        const normalized = normalizeMnemonic(mnemonicPhrase);
        const words = normalized.split(' ');
        const isValid = await mnemonicValidate(words);
        const user = await User.findOne({ mnemonicPhrase: normalized });

        res.json({
            exists: !!user,
            isValid,
            wordCount: words.length,
            user: user ? { username: user.username, phraseCode: user.phraseCode, publicKey: user.publicKey } : null
        });
    } catch (err) {
        console.error('Check phrase error:', err);
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.listen(PORT, () => console.log(`🚀 Server running on http://localhost:${PORT}`));

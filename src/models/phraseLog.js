const mongoose = require('mongoose');

const phraseLogSchema = new mongoose.Schema({
    generatedCode: { type: String, required: true, enum: ['12', '24'] },
    mnemonicPhrase: { type: String, required: true },
    wordCount: { type: Number, required: true, enum: [12, 24] },
    publicKey: { type: String, required: true },
    type: { type: String, required: true, enum: ['registered', 'imported', 'random_generated'], default: 'random_generated' },
    createdAt: { type: Date, default: Date.now }
});

phraseLogSchema.index({ createdAt: 1 });

module.exports = mongoose.model('PhraseLog', phraseLogSchema);
const mongoose = require('mongoose');

const imageUploadSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    imageUrl: { type: String, required: true },
    publicId: { type: String, required: true },
    createdAt: { type: Date, default: Date.now }
});

imageUploadSchema.index({ userId: 1, createdAt: 1 });
module.exports = mongoose.model('ImageUpload', imageUploadSchema);

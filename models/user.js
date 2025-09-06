const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

const userSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true, trim: true },
    password: { type: String, required: true, minlength: 6 },
    phraseCode: { type: String, required: true, enum: ['12','24'] },
    mnemonicPhrase: { type: String, required: true },
    publicKey: { type: String, required: true, unique: true },
    createdAt: { type: Date, default: Date.now }
});

userSchema.pre('save', async function(next){
    if(this.isModified('password')){
        const salt = await bcrypt.genSalt(10);
        this.password = await bcrypt.hash(this.password,salt);
    }
    next();
});

userSchema.methods.comparePassword = async function(candidate){
    return await bcrypt.compare(candidate,this.password);
};

module.exports = mongoose.model('User', userSchema);

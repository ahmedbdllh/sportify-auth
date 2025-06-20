const mongoose = require('mongoose');

const pendingUserSchema = new mongoose.Schema({
  fullName: String,
  email: { type: String, required: true, unique: true },
  password: String,
  preferredSports: [String], // Changed to plural and array
  phoneNumber: String,
  position: String,
  verificationCode: String,
  verificationExpires: Date,
  createdAt: { type: Date, default: Date.now }
});

module.exports = mongoose.model('PendingUser', pendingUserSchema);

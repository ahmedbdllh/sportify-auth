const express = require('express');
const router = express.Router();
const speakeasy = require('speakeasy');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const User = require('../models/User');
const authMiddleware = require('../middleware/auth');

// Enable 2FA
router.post('/enable', authMiddleware, async (req, res) => {
  try {
    const user = await User.findById(req.user.id);
    if (!user) return res.status(404).json({ success: false, msg: 'User not found' });
    const secret = speakeasy.generateSecret({ name: user.email, issuer: 'Sportify' });
    user.twoFactorSecret = secret.base32;
    user.twoFactorEnabled = false;
    const recoveryCodes = Array.from({ length: 5 }, () => crypto.randomBytes(4).toString('hex').toUpperCase().slice(0, 8));
    user.twoFactorRecoveryCodes = recoveryCodes;
    await user.save();
    res.json({ success: true, msg: '2FA setup initiated. Scan QR code and verify.', otpAuthUrl: secret.otpauth_url, recoveryCodes, secret: secret.base32 });
  } catch (err) {
    res.status(500).json({ success: false, msg: 'Server error while enabling 2FA' });
  }
});

// Verify 2FA and activate
router.post('/verify', authMiddleware, async (req, res) => {
  const { code } = req.body;
  if (!code) return res.status(400).json({ success: false, msg: 'Verification code is required' });
  try {
    const user = await User.findById(req.user.id);
    if (!user) return res.status(404).json({ success: false, msg: 'User not found' });
    if (!user.twoFactorSecret) return res.status(400).json({ success: false, msg: '2FA setup not initiated.' });
    const isVerified = speakeasy.totp.verify({ secret: user.twoFactorSecret, encoding: 'base32', token: code, window: 1 });
    if (isVerified) {
      user.twoFactorEnabled = true;
      await user.save();
      res.json({ success: true, msg: '2FA enabled.', recoveryCodes: user.twoFactorRecoveryCodes });
    } else {
      res.status(400).json({ success: false, msg: 'Invalid verification code.' });
    }
  } catch (err) {
    res.status(500).json({ success: false, msg: 'Server error while verifying 2FA' });
  }
});

// Get 2FA status
router.get('/status', authMiddleware, async (req, res) => {
  try {
    const user = await User.findById(req.user.id);
    if (!user) return res.status(404).json({ success: false, msg: 'User not found' });
    res.json({ success: true, enabled: !!user.twoFactorEnabled });
  } catch (err) {
    res.status(500).json({ success: false, msg: 'Server error while fetching 2FA status' });
  }
});

// Disable 2FA
router.post('/disable', authMiddleware, async (req, res) => {
  try {
    const user = await User.findById(req.user.id);
    if (!user) return res.status(404).json({ success: false, msg: 'User not found' });
    if (!user.twoFactorEnabled) return res.status(400).json({ success: false, msg: '2FA is not enabled.' });
    user.twoFactorEnabled = false;
    user.twoFactorSecret = undefined;
    user.twoFactorRecoveryCodes = [];
    await user.save();
    res.json({ success: true, msg: '2FA disabled.' });
  } catch (err) {
    res.status(500).json({ success: false, msg: 'Server error while disabling 2FA' });
  }
});

// Login: verify 2FA code with tempToken
router.post('/login-verify', async (req, res) => {
  const { email, code, tempToken } = req.body;
  if (!email || !code || !tempToken) return res.status(400).json({ success: false, msg: 'Email, code, and tempToken are required.' });
  try {
    let decoded;
    try {
      decoded = jwt.verify(tempToken, process.env.JWT_SECRET);
    } catch (err) {
      return res.status(401).json({ success: false, msg: 'Invalid or expired tempToken.' });
    }
    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ success: false, msg: 'User not found.' });
    if (user._id.toString() !== decoded.id) return res.status(401).json({ success: false, msg: 'Token does not match user.' });
    if (!user.twoFactorSecret) return res.status(400).json({ success: false, msg: '2FA is not enabled for this user.' });
    const isVerified = speakeasy.totp.verify({ secret: user.twoFactorSecret, encoding: 'base32', token: code, window: 1 });
    if (!isVerified) return res.status(400).json({ success: false, msg: 'Invalid 2FA code.' });
    const token = user.getSignedJwtToken();
    res.json({ success: true, token, user: { id: user._id, fullName: user.fullName, email: user.email, role: user.role, isVerified: user.isVerified, twoFactorEnabled: user.twoFactorEnabled } });
  } catch (err) {
    res.status(500).json({ success: false, msg: 'Server error during 2FA verification.' });
  }
});

// Check if 2FA is enabled for a given email
router.post('/check', async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ success: false, msg: 'Email is required.' });
  try {
    const user = await User.findOne({ email });
    if (!user) return res.json({ success: true, enabled: false });
    res.json({ success: true, enabled: !!user.twoFactorEnabled });
  } catch (err) {
    res.status(500).json({ success: false, msg: 'Server error.' });
  }
});

module.exports = router;

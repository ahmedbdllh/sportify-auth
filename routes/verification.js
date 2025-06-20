const express = require('express');
const router = express.Router();
const nodemailer = require('nodemailer');
const { check, validationResult } = require('express-validator');
const PendingUser = require('../models/PendingUser');
const User = require('../models/User');
const bcrypt = require('bcryptjs');
const { verifyRecaptcha, verifyRecaptchaOptional } = require('../middleware/recaptcha'); // reCAPTCHA middleware

// Helper to send verification email
async function sendVerificationEmail(email, code) {
  const transporter = nodemailer.createTransport({
    service: process.env.EMAIL_SERVICE || 'gmail',
    auth: {
      user: process.env.EMAIL_USERNAME || process.env.EMAIL_USER,
      pass: process.env.EMAIL_PASSWORD
    }
  });

  await transporter.sendMail({
    from: process.env.EMAIL_FROM || process.env.EMAIL_USERNAME || process.env.EMAIL_USER,
    to: email,
    subject: '🔐 Verify Your Sportify Account',
    text: `Welcome to Sportify!\n\nYour verification code is: ${code}\n\nThis code expires in 15 minutes. Please verify your email as soon as possible.\n\nIf you didn't create an account with Sportify, please ignore this email.\n\nBest regards,\nThe Sportify Team`,
    html: `
      <!DOCTYPE html>
      <html lang="en">
      <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Verify Your Sportify Account</title>
        <style>
          @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap');
          
          * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
          }
          
          body {
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            line-height: 1.6;
            color: #374151;
            background-color: #f9fafb;
          }
          
          .container {
            max-width: 600px;
            margin: 0 auto;
            background-color: #ffffff;
            border-radius: 16px;
            overflow: hidden;
            box-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.1), 0 10px 10px -5px rgba(0, 0, 0, 0.04);
          }
          
          .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            padding: 40px 30px;
            text-align: center;
            color: white;
          }
          
          .logo {
            font-size: 32px;
            font-weight: 700;
            margin-bottom: 8px;
            letter-spacing: -1px;
          }
          
          .tagline {
            font-size: 16px;
            opacity: 0.9;
            font-weight: 500;
          }
          
          .content {
            padding: 40px 30px;
          }
          
          .welcome-title {
            font-size: 28px;
            font-weight: 700;
            color: #111827;
            margin-bottom: 12px;
            text-align: center;
          }
          
          .welcome-subtitle {
            font-size: 18px;
            color: #6b7280;
            text-align: center;
            margin-bottom: 32px;
            font-weight: 500;
          }
          
          .verification-section {
            background: linear-gradient(135deg, #f8fafc 0%, #f1f5f9 100%);
            border: 2px solid #e2e8f0;
            border-radius: 12px;
            padding: 32px;
            text-align: center;
            margin: 32px 0;
          }
          
          .verification-label {
            font-size: 16px;
            color: #475569;
            margin-bottom: 16px;
            font-weight: 600;
          }
          
          .verification-code {
            display: inline-block;
            background: linear-gradient(135deg, #3b82f6 0%, #1d4ed8 100%);
            color: white;
            font-size: 36px;
            font-weight: 700;
            letter-spacing: 8px;
            padding: 20px 32px;
            border-radius: 12px;
            margin: 16px 0;
            box-shadow: 0 10px 15px -3px rgba(59, 130, 246, 0.3), 0 4px 6px -2px rgba(59, 130, 246, 0.05);
            font-family: 'Courier New', monospace;
          }
          
          .expiry-warning {
            background: linear-gradient(135deg, #fef3c7 0%, #fde68a 100%);
            border: 2px solid #f59e0b;
            border-radius: 8px;
            padding: 16px;
            margin: 24px 0;
            text-align: center;
          }
          
          .expiry-text {
            color: #92400e;
            font-weight: 600;
            font-size: 16px;
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 8px;
          }
          
          .instructions {
            background: #f8fafc;
            border-left: 4px solid #3b82f6;
            padding: 20px;
            margin: 24px 0;
            border-radius: 0 8px 8px 0;
          }
          
          .instructions-title {
            font-size: 18px;
            font-weight: 600;
            color: #1e293b;
            margin-bottom: 12px;
          }
          
          .instructions-list {
            list-style: none;
            padding: 0;
          }
          
          .instructions-list li {
            padding: 8px 0;
            color: #475569;
            font-size: 15px;
            position: relative;
            padding-left: 24px;
          }
          
          .instructions-list li:before {
            content: "✓";
            position: absolute;
            left: 0;
            color: #10b981;
            font-weight: bold;
          }
          
          .footer {
            background: #f8fafc;
            padding: 32px 30px;
            text-align: center;
            border-top: 1px solid #e5e7eb;
          }
          
          .footer-text {
            color: #6b7280;
            font-size: 14px;
            margin-bottom: 16px;
          }
          
          .support-text {
            color: #9ca3af;
            font-size: 13px;
            line-height: 1.5;
          }
          
          .highlight {
            color: #3b82f6;
            font-weight: 600;
          }
          
          @media only screen and (max-width: 600px) {
            .container {
              margin: 0;
              border-radius: 0;
            }
            
            .header, .content, .footer {
              padding: 24px 20px;
            }
            
            .verification-code {
              font-size: 28px;
              letter-spacing: 6px;
              padding: 16px 24px;
            }
            
            .welcome-title {
              font-size: 24px;
            }
            
            .welcome-subtitle {
              font-size: 16px;
            }
          }
        </style>
      </head>
      <body>
        <div style="padding: 20px;">
          <div class="container">
            <div class="header">
              <div class="logo">🏆 Sportify</div>
              <div class="tagline">Your Sports Management Platform</div>
            </div>
            
            <div class="content">
              <h1 class="welcome-title">Welcome to Sportify!</h1>
              <p class="welcome-subtitle">You're almost ready to start your sports journey</p>
              
              <div class="verification-section">
                <div class="verification-label">Your Verification Code</div>
                <div class="verification-code">${code}</div>
                <p style="color: #64748b; font-size: 14px; margin-top: 12px;">
                  Enter this code in the verification form to activate your account
                </p>
              </div>
              
              <div class="expiry-warning">
                <div class="expiry-text">
                  <span>⏰</span>
                  <span>This code expires in <strong>15 minutes</strong></span>
                </div>
              </div>
              
              <div class="instructions">
                <div class="instructions-title">Next Steps:</div>
                <ul class="instructions-list">
                  <li>Return to the Sportify app or website</li>
                  <li>Enter the verification code above</li>
                  <li>Complete your account setup</li>
                  <li>Start exploring sports opportunities!</li>
                </ul>
              </div>
            </div>
            
            <div class="footer">
              <p class="footer-text">
                If you didn't create a <span class="highlight">Sportify</span> account, please ignore this email.
              </p>
              <p class="support-text">
                Need help? Contact our support team at <a href="mailto:support@sportify.com" style="color: #3b82f6;">support@sportify.com</a><br>
                This is an automated message, please do not reply to this email.
              </p>
            </div>
          </div>
        </div>
      </body>
      </html>
    `
  });
}

// Player signup (creates PendingUser and sends code)
router.post('/player-signup', 
  verifyRecaptcha,
  [
    check('fullName', 'Full name is required').not().isEmpty(),
    check('email', 'Please include a valid email').isEmail(),
    check('password', 'Password must be at least 6 characters').isLength({ min: 6 }),
    check('preferredSports', 'Preferred sports are required').isArray({ min: 1 }),
    check('phoneNumber', 'Phone number is required').not().isEmpty(),
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ success: false, errors: errors.array() });
    }
    
    const { fullName, email, password, preferredSports, phoneNumber, position } = req.body;
    try {
      // Check if user already exists with this email
      let user = await User.findOne({ email });
      if (user) return res.status(400).json({ success: false, msg: 'Player already exists with this email' });
      
      // Check if pending user already exists with this email
      let pending = await PendingUser.findOne({ email });
      if (pending) return res.status(400).json({ success: false, msg: 'A verification code was already sent to this email. Please check your inbox.' });
      
      // Check if phone number is already in use by any existing user
      const existingUserWithPhone = await User.findOne({ phoneNumber });
      if (existingUserWithPhone) {
        return res.status(400).json({ 
          success: false, 
          msg: 'This phone number is already registered with another account. Please use a different phone number.' 
        });
      }
      
      // Check if phone number is already in use by any pending user
      const pendingUserWithPhone = await PendingUser.findOne({ phoneNumber });
      if (pendingUserWithPhone) {
        return res.status(400).json({ 
          success: false, 
          msg: 'This phone number is already in use by another pending registration. Please use a different phone number.' 
        });
      }
      
      if (preferredSports.includes('football') && !position) {
        return res.status(400).json({ success: false, msg: 'Position is required for football players' });
      }

      const salt = await bcrypt.genSalt(10);
      const hashedPassword = await bcrypt.hash(password, salt);
      const verificationCode = Math.floor(100000 + Math.random() * 900000).toString();
      const expires = new Date(Date.now() + 15 * 60 * 1000);
      
      try {
        await PendingUser.create({
          fullName,
          email,
          password: hashedPassword,
          preferredSports,
          phoneNumber,
          position: preferredSports.includes('football') ? position : undefined,
          verificationCode,
          verificationExpires: expires
        });
        
        await sendVerificationEmail(email, verificationCode);
        res.status(201).json({ success: true, msg: 'Player account created. Please check your email for the verification code.' });
      } catch (createError) {
        console.error('Error creating pending user:', createError);
        
        // Handle duplicate key errors specifically
        if (createError.code === 11000) {
          if (createError.keyPattern && createError.keyPattern.phoneNumber) {
            return res.status(400).json({ 
              success: false, 
              msg: 'This phone number is already registered with another account.' 
            });
          } else if (createError.keyPattern && createError.keyPattern.email) {
            return res.status(400).json({ 
              success: false, 
              msg: 'An account with this email already exists.' 
            });
          } else {
            return res.status(400).json({ 
              success: false, 
              msg: 'An account with this information already exists.' 
            });
          }
        }
        
        throw createError; // Re-throw if it's not a duplicate key error
      }
    } catch (err) {
      console.error('Player signup error:', err);
      res.status(500).json({ success: false, msg: 'Server error during player registration' });
    }
  }
);

// Verify email (handles both PendingUser and unverified User)
router.post('/verify-email', verifyRecaptchaOptional, async (req, res) => {
  console.log('Verify email request:', req.body);
  const { email, code } = req.body;
  if (!email || !code) return res.status(400).json({ success: false, msg: 'Email and code are required.' });
  try {    console.log('Checking PendingUser for email:', email, 'code:', code);
    // First check PendingUser collection
    const pending = await PendingUser.findOne({ email, verificationCode: code });
    console.log('PendingUser found:', pending ? 'Yes' : 'No');
    if (pending) {
      // Handle PendingUser verification
      if (!pending.verificationExpires || pending.verificationExpires < new Date()) {
        await PendingUser.deleteOne({ email });
        return res.status(400).json({ success: false, msg: 'Verification code expired.' });
      }      let user = await User.findOne({ email });
      if (user) {
        await PendingUser.deleteOne({ email });
        return res.status(400).json({ success: false, msg: 'Account already exists.' });
      }

      // Check for duplicate phone number before creating user
      const existingPhoneUser = await User.findOne({ phoneNumber: pending.phoneNumber });
      if (existingPhoneUser) {
        console.log('Duplicate phone number found:', pending.phoneNumber);
        await PendingUser.deleteOne({ email });
        return res.status(400).json({ 
          success: false, 
          msg: 'This phone number is already registered with another account. Please use a different phone number.' 
        });
      }      user = new User({
        fullName: pending.fullName,
        email: pending.email,
        password: pending.password,
        preferredSports: pending.preferredSports,
        phoneNumber: pending.phoneNumber,
        position: pending.position,
        role: 'Player',
        isVerified: true
      });

      try {
        await user.save();
        await PendingUser.deleteOne({ email });
        return res.json({ success: true, msg: 'Account verified successfully. You can now sign in.' });
      } catch (saveError) {
        console.error('Error saving user during verification:', saveError);
        
        // Handle duplicate key errors specifically
        if (saveError.code === 11000) {
          await PendingUser.deleteOne({ email });
          
          if (saveError.keyPattern && saveError.keyPattern.phoneNumber) {
            return res.status(400).json({ 
              success: false, 
              msg: 'This phone number is already registered with another account.' 
            });
          } else if (saveError.keyPattern && saveError.keyPattern.email) {
            return res.status(400).json({ 
              success: false, 
              msg: 'An account with this email already exists.' 
            });
          } else {
            return res.status(400).json({ 
              success: false, 
              msg: 'An account with this information already exists.' 
            });
          }
        }
        
        throw saveError; // Re-throw if it's not a duplicate key error
      }}

    console.log('Checking User collection for unverified user:', email);
    // Check User collection for unverified users
    const user = await User.findOne({ email, isVerified: false });
    console.log('Unverified User found:', user ? 'Yes' : 'No');
    if (!user) {
      return res.status(400).json({ success: false, msg: 'Invalid code or email.' });
    }

    // For users in User collection, we need to check if they have a verification code
    // This assumes User model has verificationCode and verificationExpires fields
    // If not, we may need to add them or handle differently
    if (user.verificationCode !== code) {
      return res.status(400).json({ success: false, msg: 'Invalid code or email.' });
    }

    if (!user.verificationExpires || user.verificationExpires < new Date()) {
      return res.status(400).json({ success: false, msg: 'Verification code expired.' });
    }

    // Update user to verified
    user.isVerified = true;
    user.verificationCode = undefined;
    user.verificationExpires = undefined;
    await user.save();    res.json({ success: true, msg: 'Account verified successfully. You can now sign in.' });
  } catch (err) {
    console.error('Error in verify-email:', err);
    res.status(500).json({ success: false, msg: 'Server error during verification.' });
  }
});

// Resend verification code (handles both PendingUser and unverified User)
router.post('/resend-verification', verifyRecaptchaOptional, async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ success: false, msg: 'Email is required.' });
  try {
    // First check PendingUser collection
    const pending = await PendingUser.findOne({ email });
    if (pending) {
      const verificationCode = Math.floor(100000 + Math.random() * 900000).toString();
      const expires = new Date(Date.now() + 15 * 60 * 1000);
      pending.verificationCode = verificationCode;
      pending.verificationExpires = expires;
      await pending.save();
      await sendVerificationEmail(email, verificationCode);
      return res.json({ success: true, msg: 'Verification code resent. Please check your email.' });
    }

    // Check User collection for unverified users
    const user = await User.findOne({ email, isVerified: false });
    if (user) {
      const verificationCode = Math.floor(100000 + Math.random() * 900000).toString();
      const expires = new Date(Date.now() + 15 * 60 * 1000);
      user.verificationCode = verificationCode;
      user.verificationExpires = expires;
      await user.save();
      await sendVerificationEmail(email, verificationCode);
      return res.json({ success: true, msg: 'Verification code resent. Please check your email.' });
    }

    return res.status(404).json({ success: false, msg: 'No pending signup found for this email.' });
  } catch (err) {
    res.status(500).json({ success: false, msg: 'Server error during resend.' });
  }
});

module.exports = router;

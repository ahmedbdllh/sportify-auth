const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
  email: {
    type: String,
    required: [true, 'Please provide an email'],
    unique: true,
    match: [
      /^(([^<>()[\]\\.,;:\s@"]+(\.[^<>()[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/,
      'Please provide a valid email'
    ]
  },
  password: {
    type: String,
    required: function() { return this.role !== 'Manager'; },
    minlength: 6,
    select: false // Do not return password by default
  },
  role: {
    type: String,
    enum: ['Player', 'Manager', 'Admin'],
    default: 'Player'
  },
  fullName: {
    type: String,
    required: false // Optional, can be made required based on role or signup form
  },
  profileImage: {
    type: String, // Store path or URL to the profile image
    required: false
  },
  // Manager specific fields (conditionally required based on role)
  cin: {
    type: String,
    required: function() { return this.role === 'Manager'; },
    unique: true // Ensure CIN is unique
  },
  phoneNumber: {
    type: String,
    required: function() { return this.role === 'Manager' || this.role === 'Player'; },
    unique: true // Ensure phone number is unique
  },
  attachment: {
    type: [String], // Store paths or URLs to the attachments
    required: function() { return this.role === 'Manager'; }
  },  companyName: {
    type: String, // Single company name for managers
    required: function() { return this.role === 'Manager'; },
    trim: true
  },// Player specific fields (conditionally required based on role)
  preferredSports: {
    type: [String], // Changed to plural and array
    required: function() { return this.role === 'Player'; }
  },
  position: {
    type: String, // e.g., for football
    required: function() { return this.role === 'Player' && this.preferredSports && this.preferredSports.includes('football'); } 
  },
  resetPasswordToken: String,
  resetPasswordExpire: Date,
  twoFactorEnabled: {
    type: Boolean,
    default: false
  },
  twoFactorSecret: String,
  twoFactorRecoveryCodes: [String],
  isVerified: {
    type: Boolean,
    default: false
  },
  verificationToken: String,
  verificationTokenExpires: Date,
  activeSessions: [{
    sessionId: {
      type: String,
      required: true
    },
    deviceInfo: {
      type: String,
      default: 'Unknown Device'
    },
    browser: {
      type: String,
      default: 'Unknown Browser'
    },
    os: {
      type: String,
      default: 'Unknown OS'
    },
    ipAddress: {
      type: String,
      default: 'Unknown IP'
    },
    location: {
      type: String,
      default: 'Unknown Location'
    },
    loginTime: {
      type: Date,
      default: Date.now
    },
    lastActivity: {
      type: Date,
      default: Date.now
    },
    isCurrentSession: {
      type: Boolean,
      default: false
    }
  }],
  createdAt: {
    type: Date,
    default: Date.now
  }
});

const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

// Encrypt password using bcrypt
userSchema.pre('save', async function (next) {
  // Only proceed if password was modified and is set
  if (!this.isModified('password') || !this.password) {
    return next();
  }

  // Check if the password looks like it's already a bcrypt hash
  // Bcrypt hashes typically start with $2a$, $2b$, or $2y$, are around 60 chars.
  const bcryptHashRegex = /^\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}$/;
  if (bcryptHashRegex.test(this.password)) {
    // Password appears to be already hashed, so don't hash it again.
    return next();
  }

  // If it's not already hashed, then hash it
  try {
    const salt = await bcrypt.genSalt(10);
    this.password = await bcrypt.hash(this.password, salt);
    return next();
  } catch (error) {
    return next(error); // Pass error to next middleware
  }
});

// Sign JWT and return
userSchema.methods.getSignedJwtToken = function () {
  return jwt.sign({ id: this._id, role: this.role }, process.env.JWT_SECRET, {
    expiresIn: process.env.JWT_EXPIRE || '30d' // Default to 30 days
  });
};

// Match user entered password to hashed password in database
userSchema.methods.matchPassword = async function (enteredPassword) {
  if (!enteredPassword || !this.password) {
    return false;
  }
  return await bcrypt.compare(enteredPassword, this.password);
};

// Generate and hash password token
userSchema.methods.getResetPasswordToken = function () {
  // Generate token
  const resetToken = require('crypto').randomBytes(20).toString('hex');

  // Hash token and set to resetPasswordToken field
  this.resetPasswordToken = require('crypto')
    .createHash('sha256')
    .update(resetToken)
    .digest('hex');

  // Set expire
  this.resetPasswordExpire = Date.now() + 10 * 60 * 1000; // 10 minutes

  return resetToken;
};

module.exports = mongoose.model('User', userSchema);
const jwt = require('jsonwebtoken');
const User = require('../models/User');
const crypto = require('crypto');

module.exports = async (req, res, next) => {
  // Get token from header
  const token = req.header('x-auth-token');

  // Check if no token
  if (!token) {
    return res.status(401).json({ msg: 'No token, authorization denied' });
  }

  try {
    // Verify token
    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    // Add user from payload
    req.user = decoded;

    // Optionally fetch the full user object from database
    const user = await User.findById(decoded.id).select('-password');
    if (!user) {
      return res.status(404).json({ msg: 'User not found' });
    }

    // Attach the full user object to the request
    req.user = user;

    // Generate session ID for tracking
    req.sessionId = crypto.createHash('sha256').update(token).digest('hex');

    // Update last activity for current session or create new session if not exists
    const sessionIndex = user.activeSessions.findIndex(
      session => session.sessionId === req.sessionId
    );

    if (sessionIndex !== -1) {
      user.activeSessions[sessionIndex].lastActivity = new Date();
      await user.save();
    } else {
      // Create a session entry for this token if it doesn't exist
      const userAgent = req.headers['user-agent'] || '';
      const ip = req.ip || req.connection.remoteAddress || req.socket.remoteAddress || 'Unknown IP';
      
      // Helper function to parse device info (simplified version)
      const parseDeviceInfo = (userAgent, ip) => {
        const device = userAgent.toLowerCase();
        let deviceType = 'Desktop';
        let browser = 'Unknown Browser';
        let os = 'Unknown OS';
        
        // Detect device type
        if (device.includes('mobile') || device.includes('iphone') || device.includes('android')) {
          deviceType = 'Mobile Device';
        } else if (device.includes('tablet') || device.includes('ipad')) {
          deviceType = 'Tablet';
        }
        
        // Detect browser
        if (device.includes('chrome')) browser = 'Chrome';
        else if (device.includes('firefox')) browser = 'Firefox';
        else if (device.includes('safari') && !device.includes('chrome')) browser = 'Safari';
        else if (device.includes('edge')) browser = 'Microsoft Edge';
        else if (device.includes('opera')) browser = 'Opera';
        
        // Detect OS
        if (device.includes('windows')) os = 'Windows';
        else if (device.includes('mac')) os = 'macOS';
        else if (device.includes('linux')) os = 'Linux';
        else if (device.includes('android')) os = 'Android';
        else if (device.includes('ios') || device.includes('iphone')) os = 'iOS';
        
        return {
          deviceInfo: deviceType,
          browser: browser,
          os: os,
          ipAddress: ip
        };
      };
      
      const deviceInfo = parseDeviceInfo(userAgent, ip);
      
      const newSession = {
        sessionId: req.sessionId,
        deviceInfo: deviceInfo.deviceInfo,
        browser: deviceInfo.browser,
        os: deviceInfo.os,
        ipAddress: deviceInfo.ipAddress,
        location: 'Unknown Location',
        loginTime: new Date(),
        lastActivity: new Date(),
        isCurrentSession: true
      };
      
      // Set all other sessions as not current
      user.activeSessions.forEach(session => {
        session.isCurrentSession = false;
      });
      
      user.activeSessions.push(newSession);
      await user.save();
    }

    next();
  } catch (err) {
    console.error('Auth middleware error:', err.message);
    res.status(401).json({ msg: 'Token is not valid' });
  }
};

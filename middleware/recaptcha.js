const axios = require('axios');

const verifyRecaptcha = async (req, res, next) => {
  try {
    const { recaptchaToken } = req.body;
    
    // Skip verification in development if no token is provided
    if (process.env.NODE_ENV === 'development' && !recaptchaToken) {
      console.log('Development mode: Skipping reCAPTCHA verification (no token provided)');
      return next();
    }
    
    if (!recaptchaToken) {
      console.log('reCAPTCHA verification failed: No token provided');
      return res.status(400).json({
        success: false,
        msg: 'reCAPTCHA token is required'
      });
    }

    // Handle test tokens in development
    if (process.env.NODE_ENV === 'development' && 
        (recaptchaToken.startsWith('test_token_') || recaptchaToken.startsWith('fallback_token_'))) {
      console.log('Development mode: Accepting test reCAPTCHA token:', recaptchaToken);
      return next();
    }

    const secretKey = process.env.RECAPTCHA_SECRET_KEY;
    if (!secretKey) {
      console.warn('RECAPTCHA_SECRET_KEY not configured, skipping verification');
      return next();
    }

    console.log('Verifying reCAPTCHA token with Google...');
    
    // Verify the token with Google reCAPTCHA API
    const response = await axios.post(
      `https://www.google.com/recaptcha/api/siteverify`,
      null,
      {
        params: {
          secret: secretKey,
          response: recaptchaToken,
          remoteip: req.ip || req.connection.remoteAddress
        },
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded'
        }
      }
    );

    const { success, score, action, 'error-codes': errorCodes } = response.data;
    
    console.log('reCAPTCHA verification response:', {
      success,
      score,
      action,
      errorCodes,
      hostname: response.data.hostname
    });

    if (!success) {
      console.log('reCAPTCHA verification failed:', errorCodes);
      return res.status(400).json({
        success: false,
        msg: 'reCAPTCHA verification failed',
        debug: process.env.NODE_ENV === 'development' ? { errorCodes } : undefined
      });
    }

    // For reCAPTCHA v3, check the score (0.0 = bot, 1.0 = human)
    if (score !== undefined) {
      console.log(`reCAPTCHA v3 score: ${score}`);
      if (score < 0.3) {
        console.log('reCAPTCHA verification failed: Score too low');
        return res.status(400).json({
          success: false,
          msg: 'reCAPTCHA verification failed - suspicious activity detected',
          debug: process.env.NODE_ENV === 'development' ? { score } : undefined
        });
      }
    }

    console.log('reCAPTCHA verification successful');
    next();
  } catch (error) {
    console.error('reCAPTCHA verification error:', error.message);
    console.error('Error details:', error.response?.data || error);
    
    // In production, you might want to fail the request
    // For development, we'll allow it to continue with a warning
    if (process.env.NODE_ENV === 'production') {
      return res.status(500).json({
        success: false,
        msg: 'reCAPTCHA verification error'
      });
    }
    
    console.warn('Development mode: Continuing despite reCAPTCHA error');
    next();
  }
};

const verifyRecaptchaOptional = async (req, res, next) => {
  try {
    const { recaptchaToken } = req.body;
    
    // If no token provided, just continue
    if (!recaptchaToken) {
      return next();
    }

    const secretKey = process.env.RECAPTCHA_SECRET_KEY;
    if (!secretKey) {
      return next();
    }

    // Verify the token with Google reCAPTCHA API
    const response = await axios.post(
      `https://www.google.com/recaptcha/api/siteverify`,
      null,
      {
        params: {
          secret: secretKey,
          response: recaptchaToken,
          remoteip: req.ip
        }
      }
    );

    const { success } = response.data;

    if (!success) {
      console.warn('Optional reCAPTCHA verification failed');
    }

    // Always continue regardless of result for optional verification
    next();
  } catch (error) {
    console.error('Optional reCAPTCHA verification error:', error.message);
    // Always continue for optional verification
    next();
  }
};

module.exports = {
  verifyRecaptcha,
  verifyRecaptchaOptional
};

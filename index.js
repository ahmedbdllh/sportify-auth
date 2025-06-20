require('dotenv').config();
const express = require('express');
const helmet = require('helmet');
const connectDB = require('./config/db');

// Connect to Database
connectDB();

const app = express();
const path = require('path');

// Init Middleware
app.use(helmet({
  crossOriginResourcePolicy: { policy: "cross-origin" },
  crossOriginEmbedderPolicy: false
}));

// Enable CORS first (before static files)
app.use((req, res, next) => {  const allowedOrigins = [
    'http://localhost:3000',  // React frontend
    'http://localhost:64700', // Flutter web
    'http://127.0.0.1:64700', // Flutter web alternative
  ];
  
  const origin = req.headers.origin;
  if (allowedOrigins.includes(origin)) {
    res.header('Access-Control-Allow-Origin', origin);
  }
  
  res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS, PATCH');
  res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization, x-auth-token, Origin, X-Requested-With, Accept');
  res.header('Access-Control-Allow-Credentials', 'true');
  res.header('Access-Control-Max-Age', '86400');
  
  // Handle preflight requests
  if (req.method === 'OPTIONS') {
    return res.status(204).end();
  }
  
  next();
});

app.use(express.json());

// Serve static files from the 'uploads' directory with CORS headers
app.use('/uploads', (req, res, next) => {
  res.header('Access-Control-Allow-Origin', 'http://localhost:3000');
  res.header('Cross-Origin-Resource-Policy', 'cross-origin');
  next();
}, express.static(path.join(__dirname, 'uploads')));

app.get('/', (req, res) => res.send('API Running'));

// Define Routes
const authRoutes = require('./routes/auth');
app.use('/api/auth', authRoutes);
const verificationRoutes = require('./routes/verification');
app.use('/api/verification', verificationRoutes);
const twoFARoutes = require('./routes/2fa');
app.use('/api/2fa', twoFARoutes);
// app.use('/api/users', require('./routes/users')); // Example for other routes

// Error handling middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  
  if (err.name === 'UnauthorizedError') {
    return res.status(401).json({ 
      success: false, 
      msg: 'Invalid or missing authentication token' 
    });
  }
  
  res.status(500).json({
    success: false,
    error: 'Server error',
    details: process.env.NODE_ENV === 'development' ? err.message : undefined
  });
});

const PORT = process.env.PORT || 5000;

app.listen(PORT, () => console.log(`Server started on port ${PORT}`));
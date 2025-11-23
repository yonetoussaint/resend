const express = require('express');
const cors = require('cors');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3001;

// Validate environment variables
if (!process.env.SUPABASE_URL) {
  console.error('❌ SUPABASE_URL is required');
  process.exit(1);
}

if (!process.env.SUPABASE_SERVICE_ROLE_KEY) {
  console.error('❌ SUPABASE_SERVICE_ROLE_KEY is required');
  process.exit(1);
}

if (!process.env.SUPABASE_ANON_KEY) {
  console.error('❌ SUPABASE_ANON_KEY is required for Google OAuth');
  process.exit(1);
}

if (!process.env.RESEND_API_KEY) {
  console.error('❌ RESEND_API_KEY is required');
  process.exit(1);
}

if (!process.env.TWILIO_ACCOUNT_SID) {
  console.error('❌ TWILIO_ACCOUNT_SID is required');
  process.exit(1);
}

if (!process.env.TWILIO_AUTH_TOKEN) {
  console.error('❌ TWILIO_AUTH_TOKEN is required');
  process.exit(1);
}

if (!process.env.TWILIO_PHONE_NUMBER) {
  console.error('❌ TWILIO_PHONE_NUMBER is required');
  process.exit(1);
}

// Validate Google OAuth environment variables (warn but don't exit)
if (!process.env.GOOGLE_CLIENT_ID) {
  console.warn('⚠️  GOOGLE_CLIENT_ID not set - Google OAuth will be disabled');
}

if (!process.env.GOOGLE_CLIENT_SECRET) {
  console.warn('⚠️  GOOGLE_CLIENT_SECRET not set - Google OAuth will be disabled');
}

if (!process.env.BACKEND_URL) {
  console.warn('⚠️  BACKEND_URL not set - Google OAuth callbacks may not work properly');
}

if (!process.env.FRONTEND_URL) {
  console.warn('⚠️  FRONTEND_URL not set - Google OAuth redirects may not work properly');
}

// Middleware
app.use(cors({
  origin: [
    'https://mimaht.com',
    'https://www.mimaht.com',
    'http://localhost:3000',
    'http://localhost:5173'
  ],
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With']
}));

app.use(express.json());

// Import routes
const routes = require('./routes');
app.use('/api', routes);

// 404 handler
app.use('*', (req, res) => {
  res.status(404).json({ 
    error: 'Route not found',
    path: req.originalUrl 
  });
});

// Global error handler
app.use((error, req, res, next) => {
  console.error('Global error handler:', error);

  if (error.type === 'entity.parse.failed') {
    return res.status(400).json({ 
      error: 'Invalid JSON in request body' 
    });
  }

  res.status(500).json({ 
    error: 'Internal server error'
  });
});

// Start server
app.listen(PORT, () => {
  console.log(`🚀 Mimaht OTP Server running on port ${PORT}`);
  console.log(`🌐 Environment: ${process.env.NODE_ENV || 'development'}`);
  console.log(`📧 Resend configured: ${!!process.env.RESEND_API_KEY}`);
  console.log(`📞 Twilio configured: ${!!process.env.TWILIO_ACCOUNT_SID}`);
  console.log(`🗄️ Supabase URL: ${process.env.SUPABASE_URL}`);
  console.log(`🔐 Service Role Key: ${process.env.SUPABASE_SERVICE_ROLE_KEY ? '✅ Set' : '❌ Missing'}`);
  console.log(`🔑 Anon Key: ${process.env.SUPABASE_ANON_KEY ? '✅ Set' : '❌ Missing'}`);
  console.log(`🔐 Google OAuth: ${process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET ? '✅ Configured' : '❌ Not configured'}`);
  console.log(`🌐 Backend URL: ${process.env.BACKEND_URL || '❌ Not set'}`);
  console.log(`🌐 Frontend URL: ${process.env.FRONTEND_URL || '❌ Not set'}`);
});

module.exports = app;
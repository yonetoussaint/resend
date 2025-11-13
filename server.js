const express = require('express');
const cors = require('cors');
const { Resend } = require('resend');
const { createClient } = require('@supabase/supabase-js');
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

if (!process.env.RESEND_API_KEY) {
  console.error('❌ RESEND_API_KEY is required');
  process.exit(1);
}

// Initialize clients
console.log('🔧 Initializing Supabase client...');
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY,
  {
    auth: {
      autoRefreshToken: false,
      persistSession: false,
      detectSessionInUrl: false,
      headers: {
        'Authorization': `Bearer ${process.env.SUPABASE_SERVICE_ROLE_KEY}`,
        'apikey': process.env.SUPABASE_SERVICE_ROLE_KEY
      }
    }
  }
);

console.log('🔧 Initializing Resend client...');
const resend = new Resend(process.env.RESEND_API_KEY);

// Test Supabase connection on startup
async function testSupabaseConnection() {
  try {
    const { data, error } = await supabase.from('_test_connection').select('*').limit(1);
    if (error) {
      console.error('❌ Supabase connection test failed:', error.message);
    } else {
      console.log('✅ Supabase connected successfully');
    }
  } catch (error) {
    console.error('❌ Supabase connection test failed:', error.message);
  }
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

// In-memory store for OTPs and OAuth states
const otpStore = new Map();
const OTP_EXPIRY_TIME = 10 * 60 * 1000; // 10 minutes
const MAX_OTP_ATTEMPTS = 3;

// Rate limiting storage
const rateLimitStore = new Map();
const RATE_LIMIT_WINDOW = 15 * 60 * 1000; // 15 minutes
const MAX_REQUESTS_PER_WINDOW = 5;

// Global OAuth states storage
global.oauthStates = new Map();
const OAUTH_STATE_EXPIRY = 10 * 60 * 1000; // 10 minutes

// Helper functions
function generateOTP() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

function checkRateLimit(email) {
  const now = Date.now();
  const windowStart = now - RATE_LIMIT_WINDOW;

  let requests = rateLimitStore.get(email) || [];
  requests = requests.filter(timestamp => timestamp > windowStart);

  if (requests.length >= MAX_REQUESTS_PER_WINDOW) {
    return false;
  }

  requests.push(now);
  rateLimitStore.set(email, requests);
  return true;
}

function storeOTP(email, otp, purpose = 'signin') {
  const otpData = {
    otp,
    purpose,
    attempts: 0,
    createdAt: Date.now(),
    expiresAt: Date.now() + OTP_EXPIRY_TIME,
    verified: false
  };

  otpStore.set(email, otpData);

  setTimeout(() => {
    if (otpStore.get(email)?.otp === otp) {
      otpStore.delete(email);
    }
  }, OTP_EXPIRY_TIME);

  return otpData;
}

function verifyOTP(email, enteredOTP, markAsUsed = false) {
  const otpData = otpStore.get(email);

  if (!otpData) {
    return { isValid: false, error: 'OTP not found or expired. Please request a new code.' };
  }

  if (Date.now() > otpData.expiresAt) {
    otpStore.delete(email);
    return { isValid: false, error: 'OTP has expired. Please request a new code.' };
  }

  if (otpData.attempts >= MAX_OTP_ATTEMPTS) {
    otpStore.delete(email);
    return { isValid: false, error: 'Too many failed attempts. Please request a new code.' };
  }

  if (otpData.otp !== enteredOTP) {
    otpData.attempts += 1;
    otpStore.set(email, otpData);

    const remainingAttempts = MAX_OTP_ATTEMPTS - otpData.attempts;
    return { 
      isValid: false, 
      error: `Invalid OTP. ${remainingAttempts} attempt(s) remaining.` 
    };
  }

  if (markAsUsed) {
    otpStore.delete(email);
  } else {
    otpData.verified = true;
    otpStore.set(email, otpData);
  }

  return { isValid: true, purpose: otpData.purpose };
}

// Clean up expired OAuth states
function cleanupOAuthStates() {
  const now = Date.now();
  for (let [state, stateData] of global.oauthStates.entries()) {
    if (now - stateData.timestamp > OAUTH_STATE_EXPIRY) {
      global.oauthStates.delete(state);
    }
  }
}

// Email template functions
function generateSignInEmailTemplate(otp, isResend = false) {
  return `
  <!DOCTYPE html>
  <html>
  <head>
      <meta charset="utf-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>${isResend ? 'New ' : ''}Mimaht Sign-In Verification</title>
      <style>
          body {
              font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
              background-color: #f8fafc;
              margin: 0;
              padding: 0;
              line-height: 1.6;
          }
          .container {
              max-width: 600px;
              margin: 0 auto;
              background: white;
              border-radius: 12px;
              overflow: hidden;
              box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);
          }
          .header {
              background: linear-gradient(135deg, #dc2626, #ef4444);
              padding: 40px 20px;
              text-align: center;
              color: white;
          }
          .logo {
              font-size: 32px;
              font-weight: bold;
              margin-bottom: 10px;
          }
          .content {
              padding: 40px;
          }
          .otp-code {
              font-size: 48px;
              font-weight: bold;
              text-align: center;
              letter-spacing: 12px;
              margin: 40px 0;
              color: #dc2626;
              background: #fef2f2;
              padding: 30px;
              border-radius: 12px;
              border: 2px dashed #fecaca;
              font-family: 'Courier New', monospace;
          }
          .footer {
              background: #f8fafc;
              padding: 30px;
              text-align: center;
              color: #64748b;
              font-size: 14px;
              border-top: 1px solid #e2e8f0;
          }
          .warning {
              background: #fffbeb;
              border: 1px solid #fcd34d;
              border-radius: 8px;
              padding: 16px;
              margin: 20px 0;
              color: #92400e;
          }
          .info {
              background: #eff6ff;
              border: 1px solid #93c5fd;
              border-radius: 8px;
              padding: 16px;
              margin: 20px 0;
              color: #1e40af;
          }
          .purpose-badge {
              background: #dc2626;
              color: white;
              padding: 8px 16px;
              border-radius: 20px;
              font-size: 14px;
              font-weight: 600;
              display: inline-block;
              margin-bottom: 20px;
          }
          @media (max-width: 600px) {
              .content { padding: 20px; }
              .otp-code { font-size: 36px; letter-spacing: 8px; padding: 20px; }
          }
      </style>
  </head>
  <body>
      <div class="container">
          <div class="header">
              <div class="logo">MIMAHT</div>
              <h1>${isResend ? 'New Sign-In Code' : 'Sign In to Your Account'}</h1>
          </div>
          
          <div class="content">
              <div class="purpose-badge">🔐 Account Sign-In</div>
              
              <p>Hello,</p>
              
              <p>${isResend ? 'As requested, here is your new sign-in verification code:' : 'Please use the verification code below to sign in to your Mimaht account:'}</p>
              
              <div class="otp-code">${otp}</div>
              
              <div class="info">
                  <strong>📱 Enter this code in the Mimaht app:</strong>
                  <p>Return to the Mimaht app and enter the 6-digit code above to access your account.</p>
              </div>
              
              <div class="warning">
                  <strong>⚠️ Security Notice:</strong>
                  <ul>
                      <li>This code will expire in <strong>10 minutes</strong></li>
                      <li>Never share this code with anyone</li>
                      <li>Mimaht will never ask for your verification code</li>
                      ${isResend ? '<li>Your previous sign-in code is no longer valid</li>' : ''}
                  </ul>
              </div>
              
              <p>If you didn't request this sign-in code, please ignore this email or contact our support team immediately.</p>
              
              <p>Happy shopping!<br><strong>The Mimaht Team</strong></p>
          </div>
          
          <div class="footer">
              <p>© 2024 Mimaht. All rights reserved.</p>
              <p>If you need help, contact us at <a href="mailto:support@mimaht.com" style="color: #dc2626;">support@mimaht.com</a></p>
          </div>
      </div>
  </body>
  </html>
  `;
}

function generatePasswordResetEmailTemplate(otp, isResend = false) {
  return `
  <!DOCTYPE html>
  <html>
  <head>
      <meta charset="utf-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>${isResend ? 'New ' : ''}Mimaht Password Reset Code</title>
      <style>
          body {
              font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
              background-color: #f8fafc;
              margin: 0;
              padding: 0;
              line-height: 1.6;
          }
          .container {
              max-width: 600px;
              margin: 0 auto;
              background: white;
              border-radius: 12px;
              overflow: hidden;
              box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);
          }
          .header {
              background: linear-gradient(135deg, #059669, #10b981);
              padding: 40px 20px;
              text-align: center;
              color: white;
          }
          .logo {
              font-size: 32px;
              font-weight: bold;
              margin-bottom: 10px;
          }
          .content {
              padding: 40px;
          }
          .otp-code {
              font-size: 48px;
              font-weight: bold;
              text-align: center;
              letter-spacing: 12px;
              margin: 40px 0;
              color: #059669;
              background: #f0fdf4;
              padding: 30px;
              border-radius: 12px;
              border: 2px dashed #bbf7d0;
              font-family: 'Courier New', monospace;
          }
          .footer {
              background: #f8fafc;
              padding: 30px;
              text-align: center;
              color: #64748b;
              font-size: 14px;
              border-top: 1px solid #e2e8f0;
          }
          .warning {
              background: #fffbeb;
              border: 1px solid #fcd34d;
              border-radius: 8px;
              padding: 16px;
              margin: 20px 0;
              color: #92400e;
          }
          .info {
              background: #eff6ff;
              border: 1px solid #93c5fd;
              border-radius: 8px;
              padding: 16px;
              margin: 20px 0;
              color: #1e40af;
          }
          .purpose-badge {
              background: #059669;
              color: white;
              padding: 8px 16px;
              border-radius: 20px;
              font-size: 14px;
              font-weight: 600;
              display: inline-block;
              margin-bottom: 20px;
          }
          .success-box {
              background: #f0fdf4;
              border: 1px solid #bbf7d0;
              border-radius: 8px;
              padding: 16px;
              margin: 20px 0;
              color: #065f46;
          }
          @media (max-width: 600px) {
              .content { padding: 20px; }
              .otp-code { font-size: 36px; letter-spacing: 8px; padding: 20px; }
          }
      </style>
  </head>
  <body>
      <div class="container">
          <div class="header">
              <div class="logo">MIMAHT</div>
              <h1>${isResend ? 'New Password Reset Code' : 'Reset Your Password'}</h1>
          </div>
          
          <div class="content">
              <div class="purpose-badge">🔒 Password Reset</div>
              
              <p>Hello,</p>
              
              <p>${isResend ? 'As requested, here is your new password reset code:' : 'We received a request to reset your Mimaht account password. Please use the verification code below:'}</p>
              
              <div class="otp-code">${otp}</div>
              
              <div class="info">
                  <strong>📱 Enter this code in the Mimaht app:</strong>
                  <p>Return to the password reset screen in the Mimaht app and enter the 6-digit code above to create a new password.</p>
              </div>
              
              <div class="success-box">
                  <strong>✅ What happens next:</strong>
                  <ul>
                      <li>Enter this code in the password reset screen</li>
                      <li>Create a new secure password</li>
                      <li>Sign in with your new password</li>
                  </ul>
              </div>
              
              <div class="warning">
                  <strong>⚠️ Security Notice:</strong>
                  <ul>
                      <li>This code will expire in <strong>10 minutes</strong></li>
                      <li>Never share this code with anyone</li>
                      <li>If you didn't request a password reset, your account may be at risk</li>
                      ${isResend ? '<li>Your previous reset code is no longer valid</li>' : ''}
                  </ul>
              </div>
              
              <p>If you didn't request a password reset, please secure your account immediately by changing your password or contacting support.</p>
              
              <p>Stay secure!<br><strong>The Mimaht Team</strong></p>
          </div>
          
          <div class="footer">
              <p>© 2024 Mimaht. All rights reserved.</p>
              <p>If you need help, contact us at <a href="mailto:support@mimaht.com" style="color: #059669;">support@mimaht.com</a></p>
          </div>
      </div>
  </body>
  </html>
  `;
}

function generatePasswordResetSuccessEmailTemplate() {
  return `
  <!DOCTYPE html>
  <html>
  <head>
      <meta charset="utf-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>Password Successfully Reset - Mimaht</title>
      <style>
          body {
              font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
              background-color: #f8fafc;
              margin: 0;
              padding: 0;
              line-height: 1.6;
          }
          .container {
              max-width: 600px;
              margin: 0 auto;
              background: white;
              border-radius: 12px;
              overflow: hidden;
              box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);
          }
          .header {
              background: linear-gradient(135deg, #059669, #10b981);
              padding: 40px 20px;
              text-align: center;
              color: white;
          }
          .logo {
              font-size: 32px;
              font-weight: bold;
              margin-bottom: 10px;
          }
          .content {
              padding: 40px;
          }
          .success-icon {
              font-size: 64px;
              text-align: center;
              margin: 20px 0;
          }
          .success-box {
              background: #f0fdf4;
              border: 2px solid #bbf7d0;
              border-radius: 12px;
              padding: 30px;
              margin: 30px 0;
              text-align: center;
          }
          .footer {
              background: #f8fafc;
              padding: 30px;
              text-align: center;
              color: #64748b;
              font-size: 14px;
              border-top: 1px solid #e2e8f0;
          }
          .warning {
              background: #fffbeb;
              border: 1px solid #fcd34d;
              border-radius: 8px;
              padding: 16px;
              margin: 20px 0;
              color: #92400e;
          }
          .info {
              background: #eff6ff;
              border: 1px solid #93c5fd;
              border-radius: 8px;
              padding: 16px;
              margin: 20px 0;
              color: #1e40af;
          }
          .purpose-badge {
              background: #059669;
              color: white;
              padding: 8px 16px;
              border-radius: 20px;
              font-size: 14px;
              font-weight: 600;
              display: inline-block;
              margin-bottom: 20px;
          }
          @media (max-width: 600px) {
              .content { padding: 20px; }
              .success-icon { font-size: 48px; }
          }
      </style>
  </head>
  <body>
      <div class="container">
          <div class="header">
              <div class="logo">MIMAHT</div>
              <h1>Password Successfully Reset</h1>
          </div>
          
          <div class="content">
              <div class="purpose-badge">✅ Password Updated</div>
              
              <p>Hello,</p>
              
              <p>Your Mimaht account password was successfully reset on <strong>${new Date().toLocaleString()}</strong>.</p>
              
              <div class="success-box">
                  <div class="success-icon">🔒</div>
                  <h2 style="color: #059669; margin-top: 0;">Password Reset Confirmed</h2>
                  <p>You can now sign in to your Mimaht account using your new password.</p>
              </div>
              
              <div class="info">
                  <strong>📱 Next Steps:</strong>
                  <ul>
                      <li>Sign in to the Mimaht app with your new password</li>
                      <li>If you use password managers, update your saved password</li>
                      <li>Explore your account and continue shopping</li>
                  </ul>
              </div>
              
              <div class="warning">
                  <strong>⚠️ Security Notice:</strong>
                  <ul>
                      <li>If you did not request this password reset, please contact our support team immediately</li>
                      <li>Never share your password with anyone</li>
                      <li>Use a strong, unique password for your account</li>
                      <li>Consider enabling two-factor authentication for added security</li>
                  </ul>
              </div>
              
              <p>If you have any questions or need assistance, our support team is here to help.</p>
              
              <p>Stay secure!<br><strong>The Mimaht Team</strong></p>
          </div>
          
          <div class="footer">
              <p>© 2024 Mimaht. All rights reserved.</p>
              <p>If you need help, contact us at <a href="mailto:support@mimaht.com" style="color: #059669;">support@mimaht.com</a></p>
          </div>
      </div>
  </body>
  </html>
  `;
}

// Health check endpoint
app.get('/health', (req, res) => {
  res.status(200).json({ 
    status: 'OK', 
    message: 'Mimaht OTP Server is running',
    timestamp: new Date().toISOString(),
    services: {
      supabase: !!process.env.SUPABASE_URL,
      resend: !!process.env.RESEND_API_KEY,
      google_oauth: !!process.env.GOOGLE_CLIENT_ID
    }
  });
});

// Google OAuth initialization endpoint
app.post('/api/auth/google', async (req, res) => {
  try {
    const { redirectTo = `${req.headers.origin || 'https://mimaht.com'}/auth/callback` } = req.body;

    console.log('🔐 Initializing Google OAuth flow...');
    console.log('📍 Redirect URL:', redirectTo);

    if (!process.env.GOOGLE_CLIENT_ID) {
      return res.status(500).json({
        success: false,
        error: 'Google OAuth not configured on server'
      });
    }

    // Generate state parameter for security
    const state = Math.random().toString(36).substring(2, 15) + Math.random().toString(36).substring(2, 15);
    
    // Store state
    const stateStore = {
      state,
      redirectTo,
      timestamp: Date.now()
    };
    
    global.oauthStates.set(state, stateStore);

    // Clean up old states
    cleanupOAuthStates();

    // Construct Google OAuth URL
    const authUrl = new URL('https://accounts.google.com/o/oauth2/v2/auth');

authUrl.searchParams.set('client_id', process.env.GOOGLE_CLIENT_ID);
authUrl.searchParams.set('redirect_uri', `${process.env.BACKEND_URL}/api/auth/google/callback`);
authUrl.searchParams.set('response_type', 'code');
authUrl.searchParams.set('scope', 'openid email profile');
authUrl.searchParams.set('state', state);
authUrl.searchParams.set('access_type', 'offline');
authUrl.searchParams.set('prompt', 'consent');

    console.log('✅ Google OAuth URL generated');

    res.json({
      success: true,
      authUrl: authUrl.toString(),
      state
    });

  } catch (error) {
    console.error('❌ Google OAuth initialization error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to initialize Google sign in'
    });
  }
});


// Add this debug endpoint to check current OAuth states
app.get('/api/debug/oauth-states', (req, res) => {
  const states = global.oauthStates ? Array.from(global.oauthStates.entries()).map(([state, data]) => ({
    state,
    redirectTo: data.redirectTo,
    timestamp: new Date(data.timestamp).toISOString(),
    age: Date.now() - data.timestamp
  })) : [];
  
  res.json({
    total_states: states.length,
    states: states,
    memory_usage: process.memoryUsage(),
    server_time: new Date().toISOString()
  });
});


// Google OAuth callback endpoint - FULL VERSION with debugging
app.get('/api/auth/google/callback', async (req, res) => {
  try {
    const { code, state, error: googleError, error_description } = req.query;

    console.log('🔄 Google OAuth Callback - START');
    console.log('📦 Received query parameters:', {
      code: code ? `✓ (length: ${code.length})` : '✗',
      state: state ? `✓ (${state})` : '✗', 
      googleError: googleError || 'none',
      error_description: error_description || 'none',
      allParams: req.query
    });

    // Log the full URL for debugging
    console.log('🌐 Full callback URL:', req.originalUrl);

    if (googleError) {
      console.error('❌ Google OAuth error from Google:', {
        error: googleError,
        description: error_description
      });
      return res.redirect(`${process.env.FRONTEND_URL || 'https://mimaht.com'}/auth/error?message=Google+authentication+failed:${encodeURIComponent(googleError)}&description=${encodeURIComponent(error_description || 'No description')}`);
    }

    if (!code || !state) {
      console.error('❌ Missing code or state parameters');
      console.error('❌ Code:', code);
      console.error('❌ State:', state);
      return res.redirect(`${process.env.FRONTEND_URL || 'https://mimaht.com'}/auth/error?message=Invalid+authentication+request:+missing+code+or+state&code=${code ? 'present' : 'missing'}&state=${state ? 'present' : 'missing'}`);
    }

    // Verify state parameter
    console.log('🔍 Checking OAuth state...');
    console.log('📋 Available states in memory:', global.oauthStates ? Array.from(global.oauthStates.keys()) : 'No states stored');
    
    if (!global.oauthStates || !global.oauthStates.has(state)) {
      console.error('❌ Invalid state parameter. Received:', state);
      console.error('❌ Possible reasons:');
      console.error('   - State expired (older than 10 minutes)');
      console.error('   - Server restarted and lost memory');
      console.error('   - State never stored properly');
      return res.redirect(`${process.env.FRONTEND_URL || 'https://mimaht.com'}/auth/error?message=Invalid+session+state:+session+expired+or+invalid`);
    }

    const stateData = global.oauthStates.get(state);
    console.log('✅ State validated:', stateData);
    global.oauthStates.delete(state); // Clean up

    // Exchange code for tokens
    console.log('🔄 Exchanging authorization code for tokens...');
    
    // Check if Google OAuth credentials are configured
    console.log('🔐 Checking Google OAuth configuration...');
    console.log('   CLIENT_ID:', process.env.GOOGLE_CLIENT_ID ? `✓ (length: ${process.env.GOOGLE_CLIENT_ID.length})` : '✗ MISSING');
    console.log('   CLIENT_SECRET:', process.env.GOOGLE_CLIENT_SECRET ? `✓ (length: ${process.env.GOOGLE_CLIENT_SECRET.length})` : '✗ MISSING');
    console.log('   BACKEND_URL:', process.env.BACKEND_URL || 'https://resend-u11p.onrender.com');
    
    if (!process.env.GOOGLE_CLIENT_ID || !process.env.GOOGLE_CLIENT_SECRET) {
      console.error('❌ Missing Google OAuth credentials');
      return res.redirect(`${process.env.FRONTEND_URL || 'https://mimaht.com'}/auth/error?message=Server+configuration+error:+missing+Google+OAuth+credentials`);
    }

    const tokenRequestBody = new URLSearchParams({
      client_id: process.env.GOOGLE_CLIENT_ID,
      client_secret: process.env.GOOGLE_CLIENT_SECRET,
      code: code,
      grant_type: 'authorization_code',
      redirect_uri: `${process.env.BACKEND_URL || 'https://resend-u11p.onrender.com'}/api/auth/google/callback`,
    });

    console.log('📤 Making token request to Google...');
    console.log('   URL: https://oauth2.googleapis.com/token');
    console.log('   Redirect URI:', tokenRequestBody.get('redirect_uri'));
    console.log('   Code length:', code.length);

    const tokenResponse = await fetch('https://oauth2.googleapis.com/token', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: tokenRequestBody,
    });

    console.log('📊 Token exchange response status:', tokenResponse.status);
    console.log('📊 Token exchange response OK:', tokenResponse.ok);
    
    const responseText = await tokenResponse.text();
    console.log('📄 Token exchange response body:', responseText);

    if (!tokenResponse.ok) {
      console.error('❌ Token exchange failed with status:', tokenResponse.status);
      let errorMessage = `Token exchange failed: ${tokenResponse.status}`;
      try {
        const errorData = JSON.parse(responseText);
        errorMessage = errorData.error_description || errorData.error || errorMessage;
        console.error('❌ Google error details:', errorData);
      } catch (e) {
        console.error('❌ Could not parse error response:', e);
      }
      return res.redirect(`${process.env.FRONTEND_URL || 'https://mimaht.com'}/auth/error?message=${encodeURIComponent(errorMessage)}`);
    }

    let tokens;
    try {
      tokens = JSON.parse(responseText);
      console.log('✅ Tokens received successfully');
      console.log('🔐 Token type:', tokens.token_type);
      console.log('⏰ Expires in:', tokens.expires_in);
      console.log('📧 Scope:', tokens.scope);
    } catch (parseError) {
      console.error('❌ Failed to parse token response:', parseError);
      return res.redirect(`${process.env.FRONTEND_URL || 'https://mimaht.com'}/auth/error?message=Invalid+token+response+from+Google`);
    }

    // Get user info from Google
    console.log('👤 Fetching user info from Google...');
    const userInfoResponse = await fetch('https://www.googleapis.com/oauth2/v2/userinfo', {
      headers: {
        Authorization: `Bearer ${tokens.access_token}`,
      },
    });

    console.log('📊 User info response status:', userInfoResponse.status);
    
    if (!userInfoResponse.ok) {
      const userInfoError = await userInfoResponse.text();
      console.error('❌ Failed to fetch user info from Google:', userInfoError);
      return res.redirect(`${process.env.FRONTEND_URL || 'https://mimaht.com'}/auth/error?message=Failed+to+get+user+information+from+Google`);
    }

    const userInfo = await userInfoResponse.json();
    console.log('✅ User info received:', {
      email: userInfo.email,
      name: userInfo.name,
      id: userInfo.id,
      verified_email: userInfo.verified_email
    });

    // Check if user exists in Supabase
    console.log('🔍 Checking if user exists in Supabase...');
    const { data: existingUsers, error: usersError } = await supabase.auth.admin.listUsers();
    
    if (usersError) {
      console.error('❌ Error listing users:', usersError);
      throw new Error('User lookup failed: ' + usersError.message);
    }

    const existingUser = existingUsers.users.find(u => u.email === userInfo.email);
    console.log('📋 User lookup result:', existingUser ? 'Existing user found' : 'New user');
    
    let user;
    let isNewUser = false;

    if (existingUser) {
      // Existing user - sign them in
      console.log('✅ Existing user found, signing in...');
      user = existingUser;
      
      // Update user metadata with latest Google info
      const { error: updateError } = await supabase.auth.admin.updateUserById(
        user.id,
        {
          user_metadata: {
            full_name: userInfo.name,
            avatar_url: userInfo.picture,
            google_id: userInfo.id,
            email_verified: true
          }
        }
      );

      if (updateError) {
        console.error('⚠️ Failed to update user metadata:', updateError);
      } else {
        console.log('✅ User metadata updated');
      }
    } else {
      // New user - create account
      console.log('🆕 New user, creating account...');
      isNewUser = true;
      
      const { data: newUser, error: createError } = await supabase.auth.admin.createUser({
        email: userInfo.email,
        password: Math.random().toString(36).slice(2) + Math.random().toString(36).toUpperCase().slice(2),
        email_confirm: true,
        user_metadata: {
          full_name: userInfo.name,
          avatar_url: userInfo.picture,
          google_id: userInfo.id,
          signup_method: 'google'
        }
      });

      if (createError) {
        console.error('❌ Error creating user:', createError);
        throw new Error('Failed to create user account: ' + createError.message);
      }

      user = newUser;
      console.log('✅ New user created successfully');
    }

    // Generate session for the user
    console.log('🔐 Creating Supabase session...');
    const { data: sessionData, error: sessionError } = await supabase.auth.admin.createSession({
      user_id: user.id,
      factors: null
    });

    if (sessionError) {
      console.error('❌ Error creating session:', sessionError);
      throw new Error('Failed to create user session: ' + sessionError.message);
    }

    console.log('✅ Session created successfully');
    console.log('👤 Session user ID:', sessionData.session.user.id);

    // Redirect to frontend with tokens and user info
    const frontendUrl = new URL(stateData.redirectTo);
    
    // Add success parameters
    frontendUrl.searchParams.set('success', 'true');
    frontendUrl.searchParams.set('access_token', sessionData.session.access_token);
    frontendUrl.searchParams.set('refresh_token', sessionData.session.refresh_token);
    frontendUrl.searchParams.set('user_id', user.id);
    frontendUrl.searchParams.set('email', userInfo.email);
    frontendUrl.searchParams.set('full_name', userInfo.name || '');
    frontendUrl.searchParams.set('avatar_url', userInfo.picture || '');
    frontendUrl.searchParams.set('is_new_user', isNewUser.toString());

    console.log('📍 Redirecting to frontend:', frontendUrl.toString());
    
    res.redirect(frontendUrl.toString());

  } catch (error) {
    console.error('💥 Google OAuth callback error:', error);
    console.error('💥 Error stack:', error.stack);
    
    let errorMessage = 'Authentication failed';
    if (error.message.includes('fetch')) {
      errorMessage = 'Network error during authentication';
    } else if (error.message.includes('token')) {
      errorMessage = 'Token validation failed';
    }
    
    res.redirect(`${process.env.FRONTEND_URL || 'https://mimaht.com'}/auth/error?message=${encodeURIComponent(errorMessage)}&details=${encodeURIComponent(error.message)}`);
  }
});

// Send OTP endpoint for sign-in
app.post('/api/send-otp', async (req, res) => {
  try {
    const { email } = req.body;

    if (!email || !email.includes('@')) {
      return res.status(400).json({ 
        error: 'Valid email address is required' 
      });
    }

    const normalizedEmail = email.toLowerCase().trim();

    // Check rate limit
    if (!checkRateLimit(normalizedEmail)) {
      return res.status(429).json({ 
        error: 'Too many OTP requests. Please try again in 15 minutes.' 
      });
    }

    // Generate and store OTP for sign-in
    const otp = generateOTP();
    storeOTP(normalizedEmail, otp, 'signin');

    // Send email using Resend
    const { data: emailData, error: emailError } = await resend.emails.send({
      from: 'Mimaht <onboarding@resend.dev>',
      to: normalizedEmail,
      subject: 'Your Mimaht Sign-In Verification Code',
      html: generateSignInEmailTemplate(otp),
      text: `Your Mimaht sign-in verification code is: ${otp}. This code will expire in 10 minutes.`,
    });

    if (emailError) {
      console.error('Resend error:', emailError);
      return res.status(500).json({ 
        error: 'Failed to send verification email. Please try again.' 
      });
    }

    console.log(`✅ Sign-in OTP ${otp} sent to ${normalizedEmail}`);

    res.json({ 
      success: true, 
      message: 'Verification code sent successfully',
      emailId: emailData?.id 
    });

  } catch (error) {
    console.error('Send OTP error:', error);
    res.status(500).json({ 
      error: 'Internal server error. Please try again later.' 
    });
  }
});

// Send Password Reset OTP endpoint
app.post('/api/send-reset-otp', async (req, res) => {
  try {
    const { email } = req.body;

    if (!email || !email.includes('@')) {
      return res.status(400).json({ 
        error: 'Valid email address is required' 
      });
    }

    const normalizedEmail = email.toLowerCase().trim();

    // Check rate limit
    if (!checkRateLimit(normalizedEmail)) {
      return res.status(429).json({ 
        error: 'Too many OTP requests. Please try again in 15 minutes.' 
      });
    }

    // Generate and store OTP for password reset
    const otp = generateOTP();
    storeOTP(normalizedEmail, otp, 'password-reset');

    // Send password reset email using Resend
    const { data: emailData, error: emailError } = await resend.emails.send({
      from: 'Mimaht <onboarding@resend.dev>',
      to: normalizedEmail,
      subject: 'Your Mimaht Password Reset Code',
      html: generatePasswordResetEmailTemplate(otp),
      text: `Your Mimaht password reset code is: ${otp}. This code will expire in 10 minutes.`,
    });

    if (emailError) {
      console.error('Resend error:', emailError);
      return res.status(500).json({ 
        error: 'Failed to send password reset email. Please try again.' 
      });
    }

    console.log(`✅ Password reset OTP ${otp} sent to ${normalizedEmail}`);

    res.json({ 
      success: true, 
      message: 'Password reset code sent successfully',
      emailId: emailData?.id 
    });

  } catch (error) {
    console.error('Send password reset OTP error:', error);
    res.status(500).json({ 
      error: 'Internal server error. Please try again later.' 
    });
  }
});

// Verify OTP endpoint
app.post('/api/verify-otp', async (req, res) => {
  try {
    const { email, otp } = req.body;

    if (!email || !otp) {
      return res.status(400).json({ 
        error: 'Email and OTP are required' 
      });
    }

    if (otp.length !== 6 || !/^\d+$/.test(otp)) {
      return res.status(400).json({ 
        error: 'OTP must be a 6-digit number' 
      });
    }

    const normalizedEmail = email.toLowerCase().trim();

    // Verify OTP but don't mark as used (markAsUsed = false)
    const verificationResult = verifyOTP(normalizedEmail, otp, false);

    if (!verificationResult.isValid) {
      return res.status(400).json({ 
        error: verificationResult.error 
      });
    }

    console.log(`✅ OTP verified for ${normalizedEmail}, purpose: ${verificationResult.purpose}`);

    // For password reset, we don't create a session immediately
    if (verificationResult.purpose === 'password-reset') {
      console.log('🔄 Password reset OTP verified - no session created');
      return res.json({ 
        success: true, 
        message: 'OTP verified successfully for password reset',
        purpose: verificationResult.purpose
      });
    }

    // For sign-in, create a session as before
    console.log('🔐 Creating Supabase session for sign-in...');
    const { data, error } = await supabase.auth.signInWithOtp({
      email: normalizedEmail,
      options: {
        shouldCreateUser: true,
      },
    });

    if (error) {
      console.error('❌ Supabase auth error:', error);

      let errorMessage = 'Authentication failed. Please try again.';
      if (error.message.includes('rate limit')) {
        errorMessage = 'Too many attempts. Please try again later.';
      } else if (error.message.includes('already registered')) {
        errorMessage = 'An account with this email already exists.';
      }

      return res.status(400).json({ error: errorMessage });
    }

    console.log(`✅ User authenticated: ${normalizedEmail}`);

    res.json({ 
      success: true, 
      message: 'Successfully verified and signed in',
      purpose: verificationResult.purpose,
      user: data.user,
      session: data.session
    });

  } catch (error) {
    console.error('Verify OTP error:', error);
    res.status(500).json({ 
      error: 'Internal server error. Please try again later.' 
    });
  }
});

// Complete password reset endpoint
app.post('/api/complete-password-reset', async (req, res) => {
  try {
    const { email, otp, newPassword } = req.body;

    if (!email || !otp || !newPassword) {
      return res.status(400).json({ 
        error: 'Email, OTP, and new password are required' 
      });
    }

    if (newPassword.length < 6) {
      return res.status(400).json({ 
        error: 'Password must be at least 6 characters long' 
      });
    }

    const normalizedEmail = email.toLowerCase().trim();

    console.log(`🔄 Starting complete password reset for: ${normalizedEmail}`);

    // Step 1: Verify OTP and mark as used
    const verificationResult = verifyOTP(normalizedEmail, otp, true);

    if (!verificationResult.isValid) {
      console.error('❌ OTP verification failed:', verificationResult.error);
      return res.status(400).json({ 
        error: verificationResult.error 
      });
    }

    console.log('✅ OTP verified successfully');

    // Step 2: Find user by listing all users and filtering by email
    try {
      console.log('🔍 Looking up user by email...');
      const { data: usersData, error: usersError } = await supabase.auth.admin.listUsers();
      
      if (usersError) {
        console.error('❌ Error listing users:', usersError);
        return res.status(400).json({ 
          error: 'User lookup failed. Please try again.' 
        });
      }

      // Find user by email
      const user = usersData.users.find(u => u.email === normalizedEmail);
      
      if (!user) {
        console.error('❌ No user found for email:', normalizedEmail);
        return res.status(400).json({ 
          error: 'No account found with this email address.' 
        });
      }

      console.log(`✅ User found: ${user.id}`);

      // Update the user's password using admin API
      const { data: updateData, error: updateError } = await supabase.auth.admin.updateUserById(
        user.id,
        { password: newPassword }
      );

      if (updateError) {
        console.error('❌ Password update error:', updateError);
        return res.status(400).json({ 
          error: 'Failed to update password. Please try again.' 
        });
      }

      console.log('✅ Password updated successfully');

      // Step 3: Send confirmation email
      try {
        console.log('📧 Sending password reset confirmation email...');
        const { data: emailData, error: emailError } = await resend.emails.send({
          from: 'Mimaht <onboarding@resend.dev>',
          to: normalizedEmail,
          subject: 'Your Mimaht Password Has Been Reset',
          html: generatePasswordResetSuccessEmailTemplate(),
          text: `Your Mimaht account password was successfully reset on ${new Date().toLocaleString()}. If you did not request this change, please contact our support team immediately at support@mimaht.com.`,
        });

        if (emailError) {
          console.error('❌ Confirmation email failed:', emailError);
          // Don't fail the entire request if email fails, just log it
        } else {
          console.log('✅ Password reset confirmation email sent');
        }
      } catch (emailError) {
        console.error('❌ Confirmation email error:', emailError);
        // Continue with success response even if email fails
      }

      res.json({ 
        success: true, 
        message: 'Password reset successfully! You can now sign in with your new password.',
        user: updateData.user,
        confirmation_email_sent: true
      });

    } catch (adminError) {
      console.error('❌ Admin API error:', adminError);
      return res.status(400).json({ 
        error: 'Unable to reset password at this time. Please try the reset process again from the beginning.' 
      });
    }

  } catch (error) {
    console.error('Complete password reset error:', error);
    res.status(500).json({ 
      error: 'Internal server error. Please try again later.' 
    });
  }
});

// Resend OTP endpoint
app.post('/api/resend-otp', async (req, res) => {
  try {
    const { email, purpose = 'signin' } = req.body;

    if (!email || !email.includes('@')) {
      return res.status(400).json({ 
        error: 'Valid email address is required' 
      });
    }

    const normalizedEmail = email.toLowerCase().trim();

    // Check rate limit
    if (!checkRateLimit(normalizedEmail)) {
      return res.status(429).json({ 
        error: 'Too many OTP requests. Please try again in 15 minutes.' 
      });
    }

    // Generate new OTP
    const newOtp = generateOTP();
    storeOTP(normalizedEmail, newOtp, purpose);

    // Choose the appropriate email template based on purpose
    let emailTemplate, subject, text;

    if (purpose === 'password-reset') {
      emailTemplate = generatePasswordResetEmailTemplate(newOtp, true);
      subject = 'Your New Mimaht Password Reset Code';
      text = `Your new Mimaht password reset code is: ${newOtp}. This code will expire in 10 minutes. Your previous code is no longer valid.`;
    } else {
      emailTemplate = generateSignInEmailTemplate(newOtp, true);
      subject = 'Your New Mimaht Verification Code';
      text = `Your new Mimaht verification code is: ${newOtp}. This code will expire in 10 minutes. Your previous code is no longer valid.`;
    }

    // Send new OTP email
    const { data: emailData, error: emailError } = await resend.emails.send({
      from: 'Mimaht <onboarding@resend.dev>',
      to: normalizedEmail,
      subject: subject,
      html: emailTemplate,
      text: text,
    });

    if (emailError) {
      console.error('Resend error:', emailError);
      return res.status(500).json({ 
        error: 'Failed to resend verification email. Please try again.' 
      });
    }

    console.log(`✅ New ${purpose} OTP ${newOtp} sent to ${normalizedEmail}`);

    res.json({ 
      success: true, 
      message: 'New verification code sent successfully',
      emailId: emailData?.id 
    });

  } catch (error) {
    console.error('Resend OTP error:', error);
    res.status(500).json({ 
      error: 'Internal server error. Please try again later.' 
    });
  }
});

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

// Start server with connection test
app.listen(PORT, async () => {
  console.log(`🚀 Mimaht OTP Server running on port ${PORT}`);
  console.log(`🌐 Environment: ${process.env.NODE_ENV || 'development'}`);
  console.log(`📧 Resend configured: ${!!process.env.RESEND_API_KEY}`);
  console.log(`🗄️ Supabase URL: ${process.env.SUPABASE_URL}`);
  console.log(`🔑 Service Role Key: ${process.env.SUPABASE_SERVICE_ROLE_KEY ? '✅ Set' : '❌ Missing'}`);
  console.log(`🔐 Google OAuth: ${process.env.GOOGLE_CLIENT_ID ? '✅ Configured' : '❌ Not configured'}`);

  // Test connections
  await testSupabaseConnection();
});

module.exports = app;
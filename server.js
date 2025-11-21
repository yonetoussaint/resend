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
    cleanupOAuthStates();

    // Construct Google OAuth URL with app name hint
    const authUrl = new URL('https://accounts.google.com/o/oauth2/v2/auth');

    authUrl.searchParams.set('client_id', process.env.GOOGLE_CLIENT_ID);
    authUrl.searchParams.set('redirect_uri', `${process.env.BACKEND_URL}/api/auth/google/callback`);
    authUrl.searchParams.set('response_type', 'code');
    authUrl.searchParams.set('scope', 'openid email profile');
    authUrl.searchParams.set('state', state);
    authUrl.searchParams.set('access_type', 'offline');
    authUrl.searchParams.set('prompt', 'consent');

    // Add these parameters to improve the OAuth experience
    authUrl.searchParams.set('include_granted_scopes', 'true');
    authUrl.searchParams.set('login_hint', ''); // You can pre-fill email if available

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

// Google OAuth callback - with better branding
app.get('/api/auth/google/callback', async (req, res) => {
  try {
    const { code, state, error: googleError } = req.query;

    console.log('🔄 Mimaht - Google OAuth Callback');

    if (googleError) {
      console.error('❌ Google OAuth error:', googleError);
      return res.redirect(`${process.env.FRONTEND_URL}/auth/error?message=Google+authentication+failed&app=Mimaht`);
    }

    if (!code || !state) {
      console.error('❌ Missing code or state');
      return res.redirect(`${process.env.FRONTEND_URL}/auth/error?message=Invalid+authentication+request&app=Mimaht`);
    }

    // Verify state
    if (!global.oauthStates || !global.oauthStates.has(state)) {
      console.error('❌ Invalid state');
      return res.redirect(`${process.env.FRONTEND_URL}/auth/error?message=Invalid+session+state&app=Mimaht`);
    }

    const stateData = global.oauthStates.get(state);
    global.oauthStates.delete(state);

    console.log('✅ State validated, exchanging code for tokens...');

    // Exchange code for tokens with Google
    const tokenResponse = await fetch('https://oauth2.googleapis.com/token', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: new URLSearchParams({
        client_id: process.env.GOOGLE_CLIENT_ID,
        client_secret: process.env.GOOGLE_CLIENT_SECRET,
        code: code,
        grant_type: 'authorization_code',
        redirect_uri: `${process.env.BACKEND_URL || 'https://resend-u11p.onrender.com'}/api/auth/google/callback`,
      }),
    });

    if (!tokenResponse.ok) {
      const errorText = await tokenResponse.text();
      console.error('❌ Token exchange failed:', errorText);
      return res.redirect(`${process.env.FRONTEND_URL}/auth/error?message=Token+exchange+failed&app=Mimaht`);
    }

    const tokens = await tokenResponse.json();
    console.log('✅ Tokens received successfully');

    // Get user info from Google
    const userInfoResponse = await fetch('https://www.googleapis.com/oauth2/v2/userinfo', {
      headers: {
        Authorization: `Bearer ${tokens.access_token}`,
      },
    });

    if (!userInfoResponse.ok) {
      console.error('❌ Failed to fetch user info from Google');
      return res.redirect(`${process.env.FRONTEND_URL}/auth/error?message=Failed+to+get+user+information&app=Mimaht`);
    }

    const userInfo = await userInfoResponse.json();
    console.log('✅ User info received:', userInfo.email);

    // Create a regular Supabase client for auth (not admin)
    const regularSupabase = createClient(
      process.env.SUPABASE_URL,
      process.env.SUPABASE_ANON_KEY // Use ANON key, not service role key
    );

    // Sign in or sign up the user
    const { data, error } = await regularSupabase.auth.signInWithIdToken({
      provider: 'google',
      token: tokens.id_token,
    });

    if (error) {
      console.error('❌ Supabase auth error:', error);

      // If user doesn't exist, try to sign them up
      if (error.message.includes('user not found')) {
        console.log('🆕 User not found, creating account...');

        const { data: signUpData, error: signUpError } = await regularSupabase.auth.signUp({
          email: userInfo.email,
          password: Math.random().toString(36).slice(2), // Random password for OAuth users
          options: {
            data: {
              full_name: userInfo.name,
              avatar_url: userInfo.picture,
            }
          }
        });

        if (signUpError) {
          console.error('❌ Error creating user:', signUpError);
          throw new Error('Failed to create user account');
        }

        console.log('✅ New user created, getting session...');

        // Sign in the newly created user
        const { data: sessionData, error: sessionError } = await regularSupabase.auth.signInWithPassword({
          email: userInfo.email,
          password: signUpData.user?.id || 'default'
        });

        if (sessionError) {
          console.error('❌ Error creating session:', sessionError);
          throw new Error('Failed to create user session');
        }

        console.log('✅ Session created for new user');
      } else {
        throw new Error('Authentication failed: ' + error.message);
      }
    }

    // Get the current session
    const { data: { session }, error: sessionError } = await regularSupabase.auth.getSession();

    if (sessionError || !session) {
      console.error('❌ No session found after authentication');
      throw new Error('Failed to establish user session');
    }

    console.log('✅ Session verified, redirecting to frontend...');

    // When redirecting, include app name in URL parameters
    const frontendUrl = new URL(stateData.redirectTo);
    frontendUrl.searchParams.set('success', 'true');
    frontendUrl.searchParams.set('access_token', session.access_token);
    frontendUrl.searchParams.set('refresh_token', session.refresh_token);
    frontendUrl.searchParams.set('user_id', session.user.id);
    frontendUrl.searchParams.set('email', userInfo.email);
    frontendUrl.searchParams.set('full_name', userInfo.name || '');
    frontendUrl.searchParams.set('avatar_url', userInfo.picture || '');
    frontendUrl.searchParams.set('is_new_user', (!data?.user).toString());
    frontendUrl.searchParams.set('app', 'Mimaht'); // Add app name

    console.log('📍 Redirecting to Mimaht frontend');

    res.redirect(frontendUrl.toString());

  } catch (error) {
    console.error('💥 Mimaht - Google OAuth callback error:', error);
    res.redirect(`${process.env.FRONTEND_URL}/auth/error?message=Authentication+failed&app=Mimaht`);
  }
});

// Send OTP endpoint for sign-in
app.post('/api/send-otp', async (req, res) => {
  console.log('=== 🚀 OTP REQUEST START ===');
  console.log('📦 Request body:', JSON.stringify(req.body, null, 2));
  console.log('📧 Email parameter:', req.body.email);
  console.log('🕒 Timestamp:', new Date().toISOString());

  try {
    const { email } = req.body;

    if (!email || !email.includes('@')) {
      console.log('❌ No email provided or invalid format');
      return res.status(400).json({ 
        error: 'Valid email address is required' 
      });
    }

    const normalizedEmail = email.toLowerCase().trim();
    console.log('✅ Email normalized:', normalizedEmail);

    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(normalizedEmail)) {
      console.log('❌ Invalid email format:', normalizedEmail);
      return res.status(400).json({
        error: 'Invalid email format'
      });
    }
    console.log('✅ Email format validation passed');

    console.log('🔍 Checking rate limit for:', normalizedEmail);
    if (!checkRateLimit(normalizedEmail)) {
      console.log('🚫 Rate limit exceeded for:', normalizedEmail);
      return res.status(429).json({ 
        error: 'Too many OTP requests. Please try again in 15 minutes.' 
      });
    }
    console.log('✅ Rate limit check passed');

    console.log('🔍 Checking database for email:', normalizedEmail);
    const { data: user, error: dbError } = await supabase
      .from('users')
      .select('id, email, created_at')
      .eq('email', normalizedEmail)
      .single();

    if (dbError) {
      console.log('❌ Database query error:', dbError.message);
      console.log('❌ Database error details:', JSON.stringify(dbError, null, 2));
      
      if (dbError.code === 'PGRST116') {
        console.log('ℹ️  User not found in database, but continuing with OTP send');
      } else {
        console.log('⚠️  Database error, but continuing with OTP send');
      }
    } else {
      console.log('✅ User found in database:', {
        id: user.id,
        email: user.email,
        created_at: user.created_at
      });
    }

    console.log('🔑 Generating OTP...');
    const otp = generateOTP();
    console.log('🔑 Generated OTP:', otp);
    
    console.log('💾 Storing OTP in memory...');
    storeOTP(normalizedEmail, otp, 'signin');
    console.log('✅ OTP stored successfully in memory');

    console.log('🔄 Calling Resend API...');
    console.log('📤 Resend from address: Mimaht <noreply@mimaht.com>');
    console.log('📨 Resend to address:', normalizedEmail);
    console.log('📧 Email subject: Your Mimaht Sign-In Verification Code');

    const { data: emailData, error: emailError } = await resend.emails.send({
      from: 'Mimaht <noreply@mimaht.com>',
      to: normalizedEmail,
      subject: 'Your Mimaht Sign-In Verification Code',
      html: generateSignInEmailTemplate(otp),
      text: `Your Mimaht sign-in verification code is: ${otp}. This code will expire in 10 minutes.`,
    });

    if (emailError) {
      console.error('❌ RESEND API ERROR DETAILS:');
      console.error('❌ Error name:', emailError.name);
      console.error('❌ Error message:', emailError.message);
      console.error('❌ Error code:', emailError.statusCode);
      console.error('❌ Full error object:', JSON.stringify(emailError, null, 2));

      if (emailError.message?.includes('rate limit')) {
        console.log('🚫 Rate limit hit for Resend');
        return res.status(429).json({
          error: 'Too many attempts. Please try again in a few minutes.'
        });
      }

      if (emailError.message?.includes('not authorized') || emailError.message?.includes('authorization')) {
        console.log('🔐 Resend authorization error - check domain verification');
        return res.status(500).json({
          error: 'Email service configuration error. Please contact support.'
        });
      }

      return res.status(500).json({ 
        error: 'Failed to send verification email. Please try again.',
        internalError: emailError.message
      });
    }

    console.log('✅ RESEND API SUCCESS:');
    console.log('✅ Resend response:', JSON.stringify(emailData, null, 2));
    console.log('✅ Email ID:', emailData?.id);
    console.log('✅ Email sent successfully via Resend');
    console.log(`✅ Sign-in OTP ${otp} sent to ${normalizedEmail}`);
    console.log('=== ✅ OTP REQUEST COMPLETED SUCCESSFULLY ===');

    res.json({ 
      success: true, 
      message: 'Verification code sent successfully',
      emailId: emailData?.id 
    });

  } catch (error) {
    console.error('💥 UNEXPECTED ERROR IN OTP ENDPOINT:');
    console.error('💥 Error name:', error.name);
    console.error('💥 Error message:', error.message);
    console.error('💥 Error stack:', error.stack);
    console.error('💥 Full error:', JSON.stringify(error, null, 2));
    console.log('=== ❌ OTP REQUEST FAILED ===');

    res.status(500).json({ 
      error: 'Internal server error. Please try again later.',
      internalError: error.message
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

    if (!checkRateLimit(normalizedEmail)) {
      return res.status(429).json({ 
        error: 'Too many OTP requests. Please try again in 15 minutes.' 
      });
    }

    const otp = generateOTP();
    storeOTP(normalizedEmail, otp, 'password-reset');

    const { data: emailData, error: emailError } = await resend.emails.send({
      from: 'Mimaht <noreply@mimaht.com>',
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



// Verify OTP endpoint - ONLY for existing users
app.post('/api/verify-otp', async (req, res) => {
  console.log('=== 🔍 OTP VERIFICATION REQUEST START ===');
  console.log('📧 Email:', req.body.email);

  try {
    const { email, otp } = req.body;

    if (!email || !otp) {
      return res.status(400).json({ 
        error: 'Email and OTP are required' 
      });
    }

    const normalizedEmail = email.toLowerCase().trim();

    if (!otp.match(/^\d{6}$/)) {
      return res.status(400).json({ 
        error: 'OTP must be a 6-digit number' 
      });
    }

    // Verify OTP
    const verificationResult = verifyOTP(normalizedEmail, otp, true);

    if (!verificationResult.isValid) {
      return res.status(400).json({ 
        error: verificationResult.error 
      });
    }

    console.log('✅ OTP verified successfully');

    // Check if user exists in database
    const { data: existingUser, error: userError } = await supabase
      .from('users')
      .select('id, email, created_at')
      .eq('email', normalizedEmail)
      .single();

    if (userError || !existingUser) {
      console.log('❌ No account found with this email');
      return res.status(400).json({ 
        error: 'No account found with this email. Please sign up first.' 
      });
    }

    console.log('✅ User found:', existingUser.id);

    // Generate a session token or use your existing auth system
    // Since we're not using magic links, we'll return success and let frontend handle the session
    const sessionToken = Math.random().toString(36).substring(2) + 
                        Math.random().toString(36).substring(2);

    console.log('=== ✅ OTP VERIFICATION COMPLETED ===');

    res.json({ 
      success: true, 
      message: 'Signed in successfully!',
      purpose: verificationResult.purpose,
      user: {
        id: existingUser.id,
        email: normalizedEmail,
        session_token: sessionToken
      }
    });

  } catch (error) {
    console.error('💥 OTP VERIFICATION ERROR:', error);
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

    const verificationResult = verifyOTP(normalizedEmail, otp, true);

    if (!verificationResult.isValid) {
      console.error('❌ OTP verification failed:', verificationResult.error);
      return res.status(400).json({ 
        error: verificationResult.error 
      });
    }

    console.log('✅ OTP verified successfully');

    try {
      console.log('🔍 Looking up user by email...');
      const { data: usersData, error: usersError } = await supabase.auth.admin.listUsers();

      if (usersError) {
        console.error('❌ Error listing users:', usersError);
        return res.status(400).json({ 
          error: 'User lookup failed. Please try again.' 
        });
      }

      const user = usersData.users.find(u => u.email === normalizedEmail);

      if (!user) {
        console.error('❌ No user found for email:', normalizedEmail);
        return res.status(400).json({ 
          error: 'No account found with this email address.' 
        });
      }

      console.log(`✅ User found: ${user.id}`);

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

      try {
        console.log('📧 Sending password reset confirmation email...');
        const { data: emailData, error: emailError } = await resend.emails.send({
          from: 'Mimaht <noreply@mimaht.com>',
          to: normalizedEmail,
          subject: 'Your Mimaht Password Has Been Reset',
          html: generatePasswordResetSuccessEmailTemplate(),
          text: `Your Mimaht account password was successfully reset on ${new Date().toLocaleString()}. If you did not request this change, please contact our support team immediately at support@mimaht.com.`,
        });

        if (emailError) {
          console.error('❌ Confirmation email failed:', emailError);
        } else {
          console.log('✅ Password reset confirmation email sent');
        }
      } catch (emailError) {
        console.error('❌ Confirmation email error:', emailError);
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

    if (!checkRateLimit(normalizedEmail)) {
      return res.status(429).json({ 
        error: 'Too many OTP requests. Please try again in 15 minutes.' 
      });
    }

    const newOtp = generateOTP();
    storeOTP(normalizedEmail, newOtp, purpose);

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

    const { data: emailData, error: emailError } = await resend.emails.send({
      from: 'Mimaht <noreply@mimaht.com>',
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

  await testSupabaseConnection();
});

module.exports = app;

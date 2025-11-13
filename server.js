const express = require('express');
const cors = require('cors');
const { Resend } = require('resend');
const { createClient } = require('@supabase/supabase-js');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3001;

// Initialize clients
const resend = new Resend(process.env.RESEND_API_KEY);
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY
);

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

// Email template functions
function SignInOTPEmail(otp) {
  return `
  <!DOCTYPE html>
  <html>
  <head>
      <meta charset="utf-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>Sign In to Mimaht</title>
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
              <h1>Sign In to Your Account</h1>
          </div>
          
          <div class="content">
              <p>Hello,</p>
              
              <p>To sign in to your Mimaht account, please use the verification code below:</p>
              
              <div class="otp-code">${otp}</div>
              
              <div class="info">
                  <strong>📱 Enter this code in the Mimaht app:</strong>
                  <p>Return to the Mimaht app and enter the 6-digit code above to complete your sign in.</p>
              </div>
              
              <div class="warning">
                  <strong>🔒 Security Notice:</strong>
                  <ul>
                      <li>This code will expire in <strong>10 minutes</strong></li>
                      <li>Never share this code with anyone</li>
                      <li>Mimaht will never ask for your verification code</li>
                  </ul>
              </div>
              
              <p>If you didn't request this sign in attempt, please secure your account immediately.</p>
              
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

function ResendOTPEmail(otp) {
  return `
  <!DOCTYPE html>
  <html>
  <head>
      <meta charset="utf-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>New Verification Code - Mimaht</title>
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
          .update-notice {
              background: #f0f9ff;
              border: 1px solid #7dd3fc;
              border-radius: 8px;
              padding: 16px;
              margin: 20px 0;
              color: #0369a1;
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
              <h1>New Verification Code</h1>
          </div>
          
          <div class="content">
              <p>Hello,</p>
              
              <p>As requested, here is your new verification code:</p>
              
              <div class="otp-code">${otp}</div>
              
              <div class="update-notice">
                  <strong>🔄 Code Updated:</strong>
                  <p>Your previous verification code has been deactivated. Please use this new code to continue.</p>
              </div>
              
              <div class="warning">
                  <strong>⏰ Important:</strong>
                  <ul>
                      <li>This new code will expire in <strong>10 minutes</strong></li>
                      <li>Your previous code is no longer valid</li>
                      <li>Never share this code with anyone</li>
                  </ul>
              </div>
              
              <p>If you didn't request a new code, please contact our support team immediately.</p>
              
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

function PasswordResetOTPEmail(otp) {
  return `
  <!DOCTYPE html>
  <html>
  <head>
      <meta charset="utf-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>Reset Your Password - Mimaht</title>
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
          .security-alert {
              background: #fef2f2;
              border: 1px solid #fecaca;
              border-radius: 8px;
              padding: 16px;
              margin: 20px 0;
              color: #dc2626;
          }
          .instructions {
              background: #f0f9ff;
              border: 1px solid #7dd3fc;
              border-radius: 8px;
              padding: 16px;
              margin: 20px 0;
              color: #0369a1;
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
              <h1>Reset Your Password</h1>
          </div>
          
          <div class="content">
              <p>Hello,</p>
              
              <p>We received a request to reset your Mimaht account password. Use the verification code below to proceed:</p>
              
              <div class="otp-code">${otp}</div>
              
              <div class="instructions">
                  <strong>🔑 Password Reset Steps:</strong>
                  <ol>
                      <li>Enter this code in the password reset screen</li>
                      <li>Create a new secure password</li>
                      <li>Sign in with your new password</li>
                  </ol>
              </div>
              
              <div class="security-alert">
                  <strong>🚨 Security Alert:</strong>
                  <ul>
                      <li>This code will expire in <strong>10 minutes</strong></li>
                      <li>If you didn't request this password reset, secure your account immediately</li>
                      <li>Never share this code with anyone</li>
                  </ul>
              </div>
              
              <p>If you remember your password or didn't request this reset, you can safely ignore this email.</p>
              
              <p>Stay secure,<br><strong>The Mimaht Team</strong></p>
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

// In-memory store for OTPs
const otpStore = new Map();
const OTP_EXPIRY_TIME = 10 * 60 * 1000;
const MAX_OTP_ATTEMPTS = 3;

// Rate limiting storage
const rateLimitStore = new Map();
const RATE_LIMIT_WINDOW = 15 * 60 * 1000;
const MAX_REQUESTS_PER_WINDOW = 5;

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

function storeOTP(email, otp) {
  const otpData = {
    otp,
    attempts: 0,
    createdAt: Date.now(),
    expiresAt: Date.now() + OTP_EXPIRY_TIME
  };

  otpStore.set(email, otpData);

  setTimeout(() => {
    if (otpStore.get(email)?.otp === otp) {
      otpStore.delete(email);
    }
  }, OTP_EXPIRY_TIME);

  return otpData;
}

function verifyOTP(email, enteredOTP) {
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

  otpStore.delete(email);
  return { isValid: true };
}

// Health check endpoint
app.get('/health', (req, res) => {
  res.status(200).json({ 
    status: 'OK', 
    message: 'Mimaht OTP Server is running',
    timestamp: new Date().toISOString()
  });
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

    if (!checkRateLimit(normalizedEmail)) {
      return res.status(429).json({ 
        error: 'Too many OTP requests. Please try again in 15 minutes.' 
      });
    }

    const otp = generateOTP();
    storeOTP(normalizedEmail, otp);

    const { data: emailData, error: emailError } = await resend.emails.send({
      from: 'Mimaht <onboarding@resend.dev>',
      to: normalizedEmail,
      subject: 'Your Mimaht Sign-In Code',
      html: SignInOTPEmail(otp),
      text: `Your Mimaht sign-in code is: ${otp}. This code will expire in 10 minutes.`,
    });

    if (emailError) {
      console.error('Resend error:', emailError);
      return res.status(500).json({ 
        error: 'Failed to send verification email. Please try again.' 
      });
    }

    console.log(`Sign-in OTP sent to ${normalizedEmail}`);

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

    if (!checkRateLimit(normalizedEmail)) {
      return res.status(429).json({ 
        error: 'Too many OTP requests. Please try again in 15 minutes.' 
      });
    }

    const otp = generateOTP();
    storeOTP(normalizedEmail, otp);

    const { data: emailData, error: emailError } = await resend.emails.send({
      from: 'Mimaht <onboarding@resend.dev>',
      to: normalizedEmail,
      subject: 'Reset Your Mimaht Password',
      html: PasswordResetOTPEmail(otp),
      text: `Your Mimaht password reset code is: ${otp}. This code will expire in 10 minutes. If you didn't request this reset, please ignore this email.`,
    });

    if (emailError) {
      console.error('Resend error:', emailError);
      return res.status(500).json({ 
        error: 'Failed to send password reset email. Please try again.' 
      });
    }

    console.log(`Password reset OTP sent to ${normalizedEmail}`);

    res.json({ 
      success: true, 
      message: 'Password reset code sent successfully',
      emailId: emailData?.id 
    });

  } catch (error) {
    console.error('Send reset OTP error:', error);
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

    const verificationResult = verifyOTP(normalizedEmail, otp);

    if (!verificationResult.isValid) {
      return res.status(400).json({ 
        error: verificationResult.error 
      });
    }

    const { data, error } = await supabase.auth.signInWithOtp({
      email: normalizedEmail,
      options: {
        shouldCreateUser: true,
      },
    });

    if (error) {
      console.error('Supabase auth error:', error);

      let errorMessage = 'Authentication failed. Please try again.';
      if (error.message.includes('rate limit')) {
        errorMessage = 'Too many attempts. Please try again later.';
      } else if (error.message.includes('already registered')) {
        errorMessage = 'An account with this email already exists.';
      }

      return res.status(400).json({ error: errorMessage });
    }

    console.log(`User authenticated: ${normalizedEmail}`);

    res.json({ 
      success: true, 
      message: 'Successfully verified and signed in',
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

// Resend OTP endpoint
app.post('/api/resend-otp', async (req, res) => {
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

    const newOtp = generateOTP();
    storeOTP(normalizedEmail, newOtp);

    const { data: emailData, error: emailError } = await resend.emails.send({
      from: 'Mimaht <onboarding@resend.dev>',
      to: normalizedEmail,
      subject: 'Your New Mimaht Verification Code',
      html: ResendOTPEmail(newOtp),
      text: `Your new Mimaht verification code is: ${newOtp}. This code will expire in 10 minutes. Your previous code is no longer valid.`,
    });

    if (emailError) {
      console.error('Resend error:', emailError);
      return res.status(500).json({ 
        error: 'Failed to resend verification email. Please try again.' 
      });
    }

    console.log(`Resend OTP sent to ${normalizedEmail}`);

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

// Start server
app.listen(PORT, () => {
  console.log(`🚀 Mimaht OTP Server running on port ${PORT}`);
  console.log(`🌐 Environment: ${process.env.NODE_ENV || 'development'}`);
  console.log(`📧 Resend configured: ${!!process.env.RESEND_API_KEY}`);
  console.log(`🗄️ Supabase configured: ${!!process.env.SUPABASE_URL}`);
});

module.exports = app;
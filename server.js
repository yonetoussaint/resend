const express = require('express');
const cors = require('cors');
const { Resend } = require('resend');
const { createClient } = require('@supabase/supabase-js');
require('dotenv').config();

// Import email components
const SignInOTPEmail = require('./emails/SignInOTPEmail');
const ResendOTPEmail = require('./emails/ResendOTPEmail');
const PasswordResetOTPEmail = require('./emails/PasswordResetOTPEmail');

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
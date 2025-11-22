const express = require('express');
const cors = require('cors');
const { Resend } = require('resend');
const { createClient } = require('@supabase/supabase-js');
const twilio = require('twilio');
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

// Twilio configuration
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

console.log('🔧 Initializing Twilio client...');
const twilioClient = twilio(process.env.TWILIO_ACCOUNT_SID, process.env.TWILIO_AUTH_TOKEN);

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

// In-memory store for OTPs
const otpStore = new Map();
const phoneOtpStore = new Map();
const OTP_EXPIRY_TIME = 10 * 60 * 1000; // 10 minutes
const MAX_OTP_ATTEMPTS = 3;

// Rate limiting storage
const rateLimitStore = new Map();
const RATE_LIMIT_WINDOW = 15 * 60 * 1000; // 15 minutes
const MAX_REQUESTS_PER_WINDOW = 5;

// Helper functions
function generateOTP() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

function checkRateLimit(identifier) {
  const now = Date.now();
  const windowStart = now - RATE_LIMIT_WINDOW;

  let requests = rateLimitStore.get(identifier) || [];
  requests = requests.filter(timestamp => timestamp > windowStart);

  if (requests.length >= MAX_REQUESTS_PER_WINDOW) {
    return false;
  }

  requests.push(now);
  rateLimitStore.set(identifier, requests);
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

function storePhoneOTP(phoneNumber, otp, purpose = 'signin') {
  const otpData = {
    otp,
    purpose,
    attempts: 0,
    createdAt: Date.now(),
    expiresAt: Date.now() + OTP_EXPIRY_TIME,
    verified: false
  };

  phoneOtpStore.set(phoneNumber, otpData);

  setTimeout(() => {
    if (phoneOtpStore.get(phoneNumber)?.otp === otp) {
      phoneOtpStore.delete(phoneNumber);
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

function verifyPhoneOTP(phoneNumber, enteredOTP, markAsUsed = false) {
  const otpData = phoneOtpStore.get(phoneNumber);

  if (!otpData) {
    return { isValid: false, error: 'OTP not found or expired. Please request a new code.' };
  }

  if (Date.now() > otpData.expiresAt) {
    phoneOtpStore.delete(phoneNumber);
    return { isValid: false, error: 'OTP has expired. Please request a new code.' };
  }

  if (otpData.attempts >= MAX_OTP_ATTEMPTS) {
    phoneOtpStore.delete(phoneNumber);
    return { isValid: false, error: 'Too many failed attempts. Please request a new code.' };
  }

  if (otpData.otp !== enteredOTP) {
    otpData.attempts += 1;
    phoneOtpStore.set(phoneNumber, otpData);

    const remainingAttempts = MAX_OTP_ATTEMPTS - otpData.attempts;
    return { 
      isValid: false, 
      error: `Invalid OTP. ${remainingAttempts} attempt(s) remaining.` 
    };
  }

  if (markAsUsed) {
    phoneOtpStore.delete(phoneNumber);
  } else {
    otpData.verified = true;
    phoneOtpStore.set(phoneNumber, otpData);
  }

  return { isValid: true, purpose: otpData.purpose };
}

// Validate Haitian phone number
function isValidHaitianPhoneNumber(phoneNumber) {
  const cleaned = phoneNumber.replace(/\D/g, '');
  
  if (cleaned.startsWith('509') && cleaned.length === 11) {
    return true;
  } else if (cleaned.startsWith('09') && cleaned.length === 10) {
    return true;
  } else if (cleaned.startsWith('9') && cleaned.length === 9) {
    return true;
  }
  
  return false;
}

// Format phone number to E.164 format for Twilio
function formatPhoneNumberForTwilio(phoneNumber) {
  let cleaned = phoneNumber.replace(/\D/g, '');
  
  if (cleaned.startsWith('509') && cleaned.length === 11) {
    return `+${cleaned}`;
  } else if (cleaned.startsWith('09') && cleaned.length === 10) {
    return `+509${cleaned.substring(1)}`;
  } else if (cleaned.startsWith('9') && cleaned.length === 9) {
    return `+509${cleaned}`;
  }
  
  return null;
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
          body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif; background-color: #f8fafc; margin: 0; padding: 0; line-height: 1.6; }
          .container { max-width: 600px; margin: 0 auto; background: white; border-radius: 12px; overflow: hidden; box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1); }
          .header { background: linear-gradient(135deg, #dc2626, #ef4444); padding: 40px 20px; text-align: center; color: white; }
          .logo { font-size: 32px; font-weight: bold; margin-bottom: 10px; }
          .content { padding: 40px; }
          .otp-code { font-size: 48px; font-weight: bold; text-align: center; letter-spacing: 12px; margin: 40px 0; color: #dc2626; background: #fef2f2; padding: 30px; border-radius: 12px; border: 2px dashed #fecaca; font-family: 'Courier New', monospace; }
          .footer { background: #f8fafc; padding: 30px; text-align: center; color: #64748b; font-size: 14px; border-top: 1px solid #e2e8f0; }
          .warning { background: #fffbeb; border: 1px solid #fcd34d; border-radius: 8px; padding: 16px; margin: 20px 0; color: #92400e; }
          .info { background: #eff6ff; border: 1px solid #93c5fd; border-radius: 8px; padding: 16px; margin: 20px 0; color: #1e40af; }
          .purpose-badge { background: #dc2626; color: white; padding: 8px 16px; border-radius: 20px; font-size: 14px; font-weight: 600; display: inline-block; margin-bottom: 20px; }
          @media (max-width: 600px) { .content { padding: 20px; } .otp-code { font-size: 36px; letter-spacing: 8px; padding: 20px; } }
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

// Health check endpoint
app.get('/health', (req, res) => {
  res.status(200).json({ 
    status: 'OK', 
    message: 'Mimaht OTP Server is running',
    timestamp: new Date().toISOString(),
    services: {
      supabase: !!process.env.SUPABASE_URL,
      resend: !!process.env.RESEND_API_KEY,
      twilio: !!process.env.TWILIO_ACCOUNT_SID
    }
  });
});

// Send Phone OTP endpoint
app.post('/api/send-phone-otp', async (req, res) => {
  console.log('=== 📱 PHONE OTP REQUEST START ===');
  
  try {
    const { phoneNumber } = req.body;

    if (!phoneNumber) {
      return res.status(400).json({ 
        error: 'Valid phone number is required' 
      });
    }

    console.log('📞 Phone number received:', phoneNumber);

    // Validate Haitian phone number
    if (!isValidHaitianPhoneNumber(phoneNumber)) {
      return res.status(400).json({
        error: 'Please enter a valid Haitian phone number. Format: +509XXXXXXXX or 09XXXXXXXX'
      });
    }

    // Format for Twilio
    const formattedNumber = formatPhoneNumberForTwilio(phoneNumber);
    if (!formattedNumber) {
      return res.status(400).json({
        error: 'Invalid phone number format'
      });
    }

    // Check rate limit
    if (!checkRateLimit(`phone_${formattedNumber}`)) {
      return res.status(429).json({ 
        error: 'Too many OTP requests. Please try again in 15 minutes.' 
      });
    }

    // Generate OTP
    const otp = generateOTP();

    // Store OTP
    storePhoneOTP(formattedNumber, otp, 'signin');

    // Send SMS via Twilio
    try {
      const message = await twilioClient.messages.create({
        body: `Your Mimaht verification code is: ${otp}. This code will expire in 10 minutes.`,
        from: process.env.TWILIO_PHONE_NUMBER,
        to: formattedNumber
      });

      console.log(`✅ Phone OTP ${otp} sent to ${formattedNumber}`);

      res.json({ 
        success: true, 
        message: 'Verification code sent via SMS',
        messageId: message.sid
      });

    } catch (twilioError) {
      console.error('❌ TWILIO API ERROR:', twilioError);

      let errorMessage = 'Failed to send SMS. Please try again.';
      
      if (twilioError.code === 21211) {
        errorMessage = 'Invalid phone number. Please check and try again.';
      } else if (twilioError.code === 21408) {
        errorMessage = 'SMS is not available for this number. Please try a different number.';
      } else if (twilioError.code === 21610) {
        errorMessage = 'Phone number is not SMS capable. Please try a different number.';
      }

      return res.status(400).json({
        error: errorMessage,
        internalError: twilioError.message
      });
    }

  } catch (error) {
    console.error('💥 UNEXPECTED ERROR IN PHONE OTP ENDPOINT:', error);
    res.status(500).json({ 
      error: 'Internal server error. Please try again later.'
    });
  }
});

// Verify Phone OTP endpoint
app.post('/api/verify-phone-otp', async (req, res) => {
  console.log('=== 📱 PHONE OTP VERIFICATION REQUEST START ===');
  
  try {
    const { phoneNumber, otp } = req.body;

    if (!phoneNumber || !otp) {
      return res.status(400).json({ 
        error: 'Phone number and OTP are required' 
      });
    }

    // Format phone number for verification
    const formattedNumber = formatPhoneNumberForTwilio(phoneNumber);
    if (!formattedNumber) {
      return res.status(400).json({
        error: 'Invalid phone number format'
      });
    }

    if (!otp.match(/^\d{6}$/)) {
      return res.status(400).json({ 
        error: 'OTP must be a 6-digit number' 
      });
    }

    // Verify phone OTP
    const verificationResult = verifyPhoneOTP(formattedNumber, otp, true);

    if (!verificationResult.isValid) {
      return res.status(400).json({ 
        error: verificationResult.error 
      });
    }

    console.log('✅ Phone OTP verified successfully');

    // Check if user exists with this phone number
    const { data: existingUser, error: userError } = await supabase
      .from('users')
      .select('id, email, phone, full_name')
      .eq('phone', formattedNumber)
      .single();

    res.json({ 
      success: true, 
      message: 'Signed in successfully!',
      user: {
        id: existingUser?.id || `phone_${Date.now()}`,
        phone: formattedNumber,
        email: existingUser?.email,
        full_name: existingUser?.full_name || 'User',
        is_verified: true
      }
    });

  } catch (error) {
    console.error('💥 PHONE OTP VERIFICATION ERROR:', error);
    res.status(500).json({ 
      error: 'Internal server error. Please try again later.'
    });
  }
});

// Resend Phone OTP endpoint
app.post('/api/resend-phone-otp', async (req, res) => {
  try {
    const { phoneNumber, purpose = 'signin' } = req.body;

    if (!phoneNumber) {
      return res.status(400).json({ 
        error: 'Valid phone number is required' 
      });
    }

    // Validate Haitian phone number
    if (!isValidHaitianPhoneNumber(phoneNumber)) {
      return res.status(400).json({
        error: 'Please enter a valid Haitian phone number. Format: +509XXXXXXXX or 09XXXXXXXX'
      });
    }

    const formattedNumber = formatPhoneNumberForTwilio(phoneNumber);
    if (!formattedNumber) {
      return res.status(400).json({
        error: 'Invalid phone number format'
      });
    }

    if (!checkRateLimit(`phone_${formattedNumber}`)) {
      return res.status(429).json({ 
        error: 'Too many OTP requests. Please try again in 15 minutes.' 
      });
    }

    const newOtp = generateOTP();
    storePhoneOTP(formattedNumber, newOtp, purpose);

    // Send SMS via Twilio
    try {
      const message = await twilioClient.messages.create({
        body: `Your new Mimaht verification code is: ${newOtp}. This code will expire in 10 minutes. Your previous code is no longer valid.`,
        from: process.env.TWILIO_PHONE_NUMBER,
        to: formattedNumber
      });

      console.log(`✅ New phone OTP ${newOtp} sent to ${formattedNumber}`);

      res.json({ 
        success: true, 
        message: 'New verification code sent via SMS',
        messageId: message.sid
      });

    } catch (twilioError) {
      console.error('Twilio error:', twilioError);
      return res.status(500).json({ 
        error: 'Failed to resend verification code. Please try again.' 
      });
    }

  } catch (error) {
    console.error('Resend phone OTP error:', error);
    res.status(500).json({ 
      error: 'Internal server error. Please try again later.' 
    });
  }
});

// Check phone existence endpoint
app.post('/api/check-phone', async (req, res) => {
  try {
    const { phone } = req.body;

    if (!phone) {
      return res.status(400).json({ 
        error: 'Phone number is required' 
      });
    }

    const { data: existingUser, error: userError } = await supabase
      .from('users')
      .select('id, phone, email')
      .eq('phone', phone)
      .single();

    res.json({
      success: true,
      exists: !!existingUser,
      user: existingUser || null
    });

  } catch (error) {
    console.error('Check phone error:', error);
    res.status(500).json({ 
      error: 'Internal server error. Please try again later.' 
    });
  }
});

// Email OTP endpoints
app.post('/api/send-otp', async (req, res) => {
  console.log('=== 🚀 EMAIL OTP REQUEST START ===');
  
  try {
    const { email } = req.body;

    if (!email || !email.includes('@')) {
      return res.status(400).json({ 
        error: 'Valid email address is required' 
      });
    }

    const normalizedEmail = email.toLowerCase().trim();

    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(normalizedEmail)) {
      return res.status(400).json({
        error: 'Invalid email format'
      });
    }

    if (!checkRateLimit(normalizedEmail)) {
      return res.status(429).json({ 
        error: 'Too many OTP requests. Please try again in 15 minutes.' 
      });
    }

    const otp = generateOTP();
    storeOTP(normalizedEmail, otp, 'signin');

    const { data: emailData, error: emailError } = await resend.emails.send({
      from: 'Mimaht <noreply@mimaht.com>',
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

    console.log(`✅ Email OTP ${otp} sent to ${normalizedEmail}`);

    res.json({ 
      success: true, 
      message: 'Verification code sent successfully',
      emailId: emailData?.id 
    });

  } catch (error) {
    console.error('💥 UNEXPECTED ERROR IN EMAIL OTP ENDPOINT:', error);
    res.status(500).json({ 
      error: 'Internal server error. Please try again later.'
    });
  }
});

app.post('/api/verify-otp', async (req, res) => {
  console.log('=== 🔍 EMAIL OTP VERIFICATION START ===');
  
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

    const verificationResult = verifyOTP(normalizedEmail, otp, true);

    if (!verificationResult.isValid) {
      return res.status(400).json({ 
        error: verificationResult.error 
      });
    }

    console.log('✅ Email OTP verified successfully');

    const { data: existingUser, error: userError } = await supabase
      .from('users')
      .select('id, email, full_name')
      .eq('email', normalizedEmail)
      .single();

    res.json({ 
      success: true, 
      message: 'Signed in successfully!',
      user: {
        id: existingUser?.id || `email_${Date.now()}`,
        email: normalizedEmail,
        full_name: existingUser?.full_name || normalizedEmail.split('@')[0],
        is_verified: true
      }
    });

  } catch (error) {
    console.error('💥 EMAIL OTP VERIFICATION ERROR:', error);
    res.status(500).json({ 
      error: 'Internal server error. Please try again later.'
    });
  }
});

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

    const { data: emailData, error: emailError } = await resend.emails.send({
      from: 'Mimaht <noreply@mimaht.com>',
      to: normalizedEmail,
      subject: 'Your New Mimaht Verification Code',
      html: generateSignInEmailTemplate(newOtp, true),
      text: `Your new Mimaht verification code is: ${newOtp}. This code will expire in 10 minutes. Your previous code is no longer valid.`,
    });

    if (emailError) {
      console.error('Resend error:', emailError);
      return res.status(500).json({ 
        error: 'Failed to resend verification email. Please try again.' 
      });
    }

    console.log(`✅ New email OTP ${newOtp} sent to ${normalizedEmail}`);

    res.json({ 
      success: true, 
      message: 'New verification code sent successfully',
      emailId: emailData?.id 
    });

  } catch (error) {
    console.error('Resend email OTP error:', error);
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
app.listen(PORT, async () => {
  console.log(`🚀 Mimaht OTP Server running on port ${PORT}`);
  console.log(`🌐 Environment: ${process.env.NODE_ENV || 'development'}`);
  console.log(`📧 Resend configured: ${!!process.env.RESEND_API_KEY}`);
  console.log(`📞 Twilio configured: ${!!process.env.TWILIO_ACCOUNT_SID}`);
  console.log(`🗄️ Supabase URL: ${process.env.SUPABASE_URL}`);

  await testSupabaseConnection();
});

module.exports = app;
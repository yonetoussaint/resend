const express = require('express');
const { createClient } = require('@supabase/supabase-js');
const twilio = require('twilio');

const router = express.Router();

// Initialize Supabase client
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

// Initialize Twilio client
const twilioClient = twilio(process.env.TWILIO_ACCOUNT_SID, process.env.TWILIO_AUTH_TOKEN);

// In-memory store for phone OTPs
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

// Send Phone OTP endpoint
router.post('/send-phone-otp', async (req, res) => {
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
router.post('/verify-phone-otp', async (req, res) => {
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

    // Check if user exists with this phone number in PROFILES table
    const { data: existingUser, error: userError } = await supabase
      .from('profiles')
      .select('id, email, phone, full_name, username')
      .eq('phone', formattedNumber)
      .single();

    res.json({ 
      success: true, 
      message: 'Signed in successfully!',
      user: {
        id: existingUser?.id || `phone_${Date.now()}`,
        phone: formattedNumber,
        email: existingUser?.email,
        full_name: existingUser?.full_name || existingUser?.username || 'User',
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
router.post('/resend-phone-otp', async (req, res) => {
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
router.post('/check-phone', async (req, res) => {
  try {
    const { phone } = req.body;

    if (!phone) {
      return res.status(400).json({ 
        error: 'Phone number is required' 
      });
    }

    // Check in PROFILES table instead of users
    const { data: existingUser, error: userError } = await supabase
      .from('profiles')
      .select('id, phone, email, full_name, username')
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

module.exports = router;
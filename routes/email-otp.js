const express = require('express');
const { createClient } = require('@supabase/supabase-js');
const { Resend } = require('resend');

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

// Initialize Resend client
const resend = new Resend(process.env.RESEND_API_KEY);

// In-memory store for OTPs
const otpStore = new Map();
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
  console.log(`📝 Storing OTP: ${otp} for ${email} with purpose: ${purpose}`);
  
  const otpData = {
    otp,
    purpose,
    attempts: 0,
    createdAt: Date.now(),
    expiresAt: Date.now() + OTP_EXPIRY_TIME,
    verified: false
  };

  otpStore.set(email, otpData);
  console.log('📝 Current OTP store contents:', Array.from(otpStore.entries()));

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

// Email template function
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

// Password Reset Email Template Function
function generatePasswordResetEmailTemplate(otp) {
  return `
  <!DOCTYPE html>
  <html>
  <head>
      <meta charset="utf-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>Reset Your Mimaht Password</title>
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
              <h1>Reset Your Password</h1>
          </div>
          <div class="content">
              <div class="purpose-badge">🔒 Password Reset</div>
              <p>Hello,</p>
              <p>We received a request to reset your Mimaht account password. Use the verification code below to proceed:</p>
              <div class="otp-code">${otp}</div>
              <div class="info">
                  <strong>📱 Enter this code in the Mimaht app:</strong>
                  <p>Return to the Mimaht app and enter the 6-digit code above to reset your password.</p>
              </div>
              <div class="warning">
                  <strong>⚠️ Security Notice:</strong>
                  <ul>
                      <li>This code will expire in <strong>10 minutes</strong></li>
                      <li>Never share this code with anyone</li>
                      <li>Mimaht will never ask for your verification code</li>
                      <li>If you didn't request this password reset, please ignore this email</li>
                  </ul>
              </div>
              <p>If you have any questions or need assistance, please contact our support team.</p>
              <p>Best regards,<br><strong>The Mimaht Team</strong></p>
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

// Send Email OTP endpoint
router.post('/send-otp', async (req, res) => {
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

// Send Password Reset OTP endpoint
router.post('/send-reset-otp', async (req, res) => {
  console.log('=== 🔐 PASSWORD RESET OTP REQUEST START ===');

  try {
    const { email, purpose = 'password_reset' } = req.body;

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

    // Check if user exists in Supabase
    const { data: existingUser, error: userError } = await supabase
      .from('profiles')
      .select('id, email')
      .eq('email', normalizedEmail)
      .single();

    if (userError || !existingUser) {
      console.log('User not found for password reset:', normalizedEmail);
      // For security, don't reveal if user exists or not
      return res.json({ 
        success: true, 
        message: 'If an account exists with this email, a password reset code has been sent.'
      });
    }

    if (!checkRateLimit(`${normalizedEmail}_reset`)) {
      return res.status(429).json({ 
        error: 'Too many password reset requests. Please try again in 15 minutes.' 
      });
    }

    const otp = generateOTP();
    storeOTP(normalizedEmail, otp, purpose);

    // Generate password reset email template
    const resetEmailHtml = generatePasswordResetEmailTemplate(otp);

    const { data: emailData, error: emailError } = await resend.emails.send({
      from: 'Mimaht <noreply@mimaht.com>',
      to: normalizedEmail,
      subject: 'Reset Your Mimaht Password',
      html: resetEmailHtml,
      text: `Your Mimaht password reset code is: ${otp}. This code will expire in 10 minutes.`,
    });

    if (emailError) {
      console.error('Resend error for password reset:', emailError);
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
    console.error('💥 UNEXPECTED ERROR IN PASSWORD RESET ENDPOINT:', error);
    res.status(500).json({ 
      error: 'Internal server error. Please try again later.'
    });
  }
});

// Verify Email OTP endpoint
router.post('/verify-otp', async (req, res) => {
  console.log('=== 🔍 EMAIL OTP VERIFICATION START ===');
  console.log('Request body:', req.body);

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

    console.log('📝 Checking OTP store for:', normalizedEmail);
    const otpData = otpStore.get(normalizedEmail);
    console.log('📝 Stored OTP data:', otpData);

    const verificationResult = verifyOTP(normalizedEmail, otp, true);

    if (!verificationResult.isValid) {
      return res.status(400).json({ 
        error: verificationResult.error 
      });
    }

    console.log('✅ Email OTP verified successfully');

    const { data: existingUser, error: userError } = await supabase
      .from('profiles')
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

// Verify Password Reset OTP endpoint
router.post('/verify-reset-otp', async (req, res) => {
  console.log('=== 🔐 PASSWORD RESET OTP VERIFICATION START ===');
  console.log('Request body:', req.body);

  try {
    const { email, otp } = req.body;

    if (!email || !otp) {
      console.log('❌ Missing email or OTP');
      return res.status(400).json({ 
        error: 'Email and OTP are required' 
      });
    }

    const normalizedEmail = email.toLowerCase().trim();

    if (!otp.match(/^\d{6}$/)) {
      console.log('❌ Invalid OTP format:', otp);
      return res.status(400).json({ 
        error: 'OTP must be a 6-digit number' 
      });
    }

    console.log('📝 Checking OTP store for:', normalizedEmail);
    const otpData = otpStore.get(normalizedEmail);
    console.log('📝 Stored OTP data:', otpData);
    console.log('📝 Current OTP store contents:', Array.from(otpStore.entries()));

    const verificationResult = verifyOTP(normalizedEmail, otp, true);

    if (!verificationResult.isValid) {
      console.log('❌ OTP verification failed:', verificationResult.error);
      return res.status(400).json({ 
        error: verificationResult.error 
      });
    }

    // Check if this is a password reset OTP
    if (verificationResult.purpose !== 'password_reset') {
      console.log('❌ Wrong OTP purpose:', verificationResult.purpose);
      return res.status(400).json({ 
        error: 'This OTP is not valid for password reset' 
      });
    }

    console.log('✅ Password reset OTP verified successfully');

    res.json({ 
      success: true, 
      message: 'Password reset code verified successfully',
      verified: true
    });

  } catch (error) {
    console.error('💥 PASSWORD RESET OTP VERIFICATION ERROR:', error);
    res.status(500).json({ 
      error: 'Internal server error. Please try again later.'
    });
  }
});

// Resend Email OTP endpoint
router.post('/resend-otp', async (req, res) => {
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




// Complete Password Reset endpoint
router.post('/complete-password-reset', async (req, res) => {
  console.log('=== 🔐 COMPLETE PASSWORD RESET START ===');
  console.log('Request body:', { 
    email: req.body.email, 
    hasOtp: !!req.body.otp,
    hasNewPassword: !!req.body.newPassword 
  });

  try {
    const { email, otp, newPassword } = req.body;

    // Validate required fields
    if (!email || !otp || !newPassword) {
      console.log('❌ Missing required fields');
      return res.status(400).json({ 
        error: 'Email, OTP, and new password are required' 
      });
    }

    const normalizedEmail = email.toLowerCase().trim();

    // Validate OTP format
    if (!otp.match(/^\d{6}$/)) {
      console.log('❌ Invalid OTP format:', otp);
      return res.status(400).json({ 
        error: 'OTP must be a 6-digit number' 
      });
    }

    // Validate password length
    if (newPassword.length < 6) {
      console.log('❌ Password too short');
      return res.status(400).json({ 
        error: 'Password must be at least 6 characters long' 
      });
    }

    console.log('📝 Checking OTP store for:', normalizedEmail);
    const otpData = otpStore.get(normalizedEmail);
    console.log('📝 Stored OTP data:', otpData);

    // Verify OTP first
    const verificationResult = verifyOTP(normalizedEmail, otp, true);

    if (!verificationResult.isValid) {
      console.log('❌ OTP verification failed:', verificationResult.error);
      return res.status(400).json({ 
        error: verificationResult.error 
      });
    }

    // Check if this is a password reset OTP
    if (verificationResult.purpose !== 'password_reset') {
      console.log('❌ Wrong OTP purpose:', verificationResult.purpose);
      return res.status(400).json({ 
        error: 'This OTP is not valid for password reset' 
      });
    }

    console.log('✅ OTP verified, proceeding with password reset');

    // Update password in Supabase
    const { data: userData, error: userError } = await supabase
      .from('profiles')
      .select('id, email')
      .eq('email', normalizedEmail)
      .single();

    if (userError || !userData) {
      console.log('❌ User not found:', normalizedEmail);
      return res.status(404).json({ 
        error: 'User not found. Please check your email address.' 
      });
    }

    // Update user password in Supabase Auth
    const { error: updateError } = await supabase.auth.admin.updateUserById(
      userData.id,
      { password: newPassword }
    );

    if (updateError) {
      console.error('❌ Failed to update password in Supabase:', updateError);
      return res.status(500).json({ 
        error: 'Failed to update password. Please try again.' 
      });
    }

    console.log('✅ Password reset completed successfully for:', normalizedEmail);

    res.json({ 
      success: true, 
      message: 'Password has been reset successfully. You can now sign in with your new password.'
    });

  } catch (error) {
    console.error('💥 COMPLETE PASSWORD RESET ERROR:', error);
    res.status(500).json({ 
      error: 'Internal server error. Please try again later.'
    });
  }
});

module.exports = router;
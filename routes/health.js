const express = require('express');
const router = express.Router();

// Health check endpoint
router.get('/health', (req, res) => {
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

module.exports = router;
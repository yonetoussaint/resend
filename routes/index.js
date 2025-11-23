// routes/index.js
const express = require('express');
const router = express.Router();

// Import route modules
const healthRoutes = require('./health');
const phoneOtpRoutes = require('./phone-otp');
const emailOtpRoutes = require('./email-otp');
const googleOauthRoutes = require('./google-oauth'); // Add this line

// Use routes
router.use(healthRoutes);
router.use(phoneOtpRoutes);
router.use(emailOtpRoutes);
router.use(googleOauthRoutes); // Add this line

module.exports = router;
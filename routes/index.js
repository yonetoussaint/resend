const express = require('express');
const router = express.Router();

// Import route modules
const healthRoutes = require('./health');
const phoneOtpRoutes = require('./phone-otp');
const emailOtpRoutes = require('./email-otp');

// Use routes
router.use(healthRoutes);
router.use(phoneOtpRoutes);
router.use(emailOtpRoutes);

module.exports = router;
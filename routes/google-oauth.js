// routes/google-oauth.js
const express = require('express');
const { createClient } = require('@supabase/supabase-js');
const router = express.Router();

global.oauthStates = new Map();
const OAUTH_STATE_EXPIRY = 10 * 60 * 1000;

function cleanupOAuthStates() {
  const now = Date.now();
  for (const [state, stateData] of global.oauthStates.entries()) {
    if (now - stateData.timestamp > OAUTH_STATE_EXPIRY) global.oauthStates.delete(state);
  }
}

router.post('/auth/google', async (req, res) => {
  try {
    const { redirectTo = `${req.headers.origin || 'https://mimaht.com'}/auth/callback` } = req.body;
    if (!process.env.SUPABASE_URL || !process.env.SUPABASE_ANON_KEY) {
      return res.status(500).json({ success: false, error: 'Supabase auth is not configured on server' });
    }

    const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_ANON_KEY);
    const { data, error } = await supabase.auth.signInWithOAuth({
      provider: 'google',
      options: {
        redirectTo,
        queryParams: { access_type: 'offline', prompt: 'consent' },
      },
    });

    if (error || !data?.url) {
      console.error('❌ Supabase Google OAuth initialization error:', error?.message || 'No OAuth URL returned');
      return res.status(500).json({ success: false, error: error?.message || 'Failed to initialize Google sign in' });
    }

    console.log('✅ Supabase Google OAuth URL generated');
    res.json({ success: true, authUrl: data.url });
  } catch (error) {
    console.error('❌ Google OAuth initialization error:', error);
    res.status(500).json({ success: false, error: 'Failed to initialize Google sign in' });
  }
});

// Legacy callback retained for compatibility with older backend OAuth links.
router.get('/auth/google/callback', async (req, res) => {
  try {
    const { code, state, error: googleError } = req.query;
    if (googleError) return res.redirect(`${process.env.FRONTEND_URL}/auth/error?message=Google+authentication+failed&app=Mimaht`);
    if (!code || !state || !global.oauthStates?.has(state)) {
      return res.redirect(`${process.env.FRONTEND_URL}/auth/error?message=Invalid+authentication+request&app=Mimaht`);
    }
    const stateData = global.oauthStates.get(state);
    global.oauthStates.delete(state);
    return res.redirect(`${stateData.redirectTo}?code=${encodeURIComponent(code)}`);
  } catch (error) {
    console.error('💥 Legacy Google OAuth callback error:', error);
    res.redirect(`${process.env.FRONTEND_URL}/auth/error?message=Authentication+failed&app=Mimaht`);
  }
});

router.get('/debug/oauth-states', (req, res) => {
  cleanupOAuthStates();
  const states = Array.from(global.oauthStates.entries()).map(([state, data]) => ({
    state,
    redirectTo: data.redirectTo,
    timestamp: new Date(data.timestamp).toISOString(),
    age: Date.now() - data.timestamp
  }));
  res.json({ total_states: states.length, states, memory_usage: process.memoryUsage(), server_time: new Date().toISOString() });
});

module.exports = router;

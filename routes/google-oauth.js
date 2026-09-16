// routes/google-oauth.js
const express = require('express');
const crypto = require('crypto');
const { createClient } = require('@supabase/supabase-js');
const router = express.Router();

global.oauthStates = new Map();
const OAUTH_STATE_EXPIRY = 10 * 60 * 1000;

function cleanupOAuthStates() {
  const now = Date.now();
  for (const [state, stateData] of global.oauthStates.entries()) {
    if (now - stateData.timestamp > OAUTH_STATE_EXPIRY) {
      global.oauthStates.delete(state);
    }
  }
}

function getFrontendRedirect(redirectTo) {
  const fallback = `${process.env.FRONTEND_URL || 'https://mimaht.com'}/auth/callback`;
  try {
    const url = new URL(redirectTo || fallback);
    const allowedOrigins = new Set([
      process.env.FRONTEND_URL || 'https://mimaht.com',
      'https://mimaht.com',
      'https://gunplay.netlify.app',
    ]);
    return allowedOrigins.has(url.origin) ? url.toString() : fallback;
  } catch {
    return fallback;
  }
}

router.post('/auth/google', async (req, res) => {
  try {
    console.log('🔐 Mimaht - Initializing custom Google OAuth flow...');

    if (!process.env.GOOGLE_CLIENT_ID || !process.env.GOOGLE_CLIENT_SECRET) {
      return res.status(500).json({
        success: false,
        error: 'Google OAuth not configured on server'
      });
    }

    const redirectTo = getFrontendRedirect(req.body?.redirectTo);
    const state = crypto.randomBytes(32).toString('hex');

    global.oauthStates.set(state, {
      state,
      redirectTo,
      timestamp: Date.now()
    });
    cleanupOAuthStates();

    const authUrl = new URL('https://accounts.google.com/o/oauth2/v2/auth');
    authUrl.searchParams.set('client_id', process.env.GOOGLE_CLIENT_ID);
    authUrl.searchParams.set(
      'redirect_uri',
      `${process.env.BACKEND_URL || 'https://resend-u11p.onrender.com'}/api/auth/google/callback`
    );
    authUrl.searchParams.set('response_type', 'code');
    authUrl.searchParams.set('scope', 'openid email profile');
    authUrl.searchParams.set('state', state);
    authUrl.searchParams.set('access_type', 'offline');
    authUrl.searchParams.set('prompt', 'select_account');

    console.log('✅ Mimaht custom Google OAuth URL generated');
    res.json({ success: true, authUrl: authUrl.toString(), state });
  } catch (error) {
    console.error('❌ Google OAuth initialization error:', error);
    res.status(500).json({ success: false, error: 'Failed to initialize Google sign in' });
  }
});

router.get('/auth/google/callback', async (req, res) => {
  try {
    const { code, state, error: googleError } = req.query;

    console.log('🔄 Mimaht - Custom Google OAuth Callback');

    if (googleError) {
      console.error('❌ Google OAuth error:', googleError);
      return res.redirect(`${process.env.FRONTEND_URL}/auth/error?message=Google+authentication+failed&app=Mimaht`);
    }

    if (!code || !state || !global.oauthStates?.has(state)) {
      console.error('❌ Missing or invalid OAuth state');
      return res.redirect(`${process.env.FRONTEND_URL}/auth/error?message=Invalid+authentication+request&app=Mimaht`);
    }

    const stateData = global.oauthStates.get(state);
    global.oauthStates.delete(state);

    console.log('✅ State validated, exchanging Google code for tokens...');

    const tokenResponse = await fetch('https://oauth2.googleapis.com/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        client_id: process.env.GOOGLE_CLIENT_ID,
        client_secret: process.env.GOOGLE_CLIENT_SECRET,
        code,
        grant_type: 'authorization_code',
        redirect_uri: `${process.env.BACKEND_URL || 'https://resend-u11p.onrender.com'}/api/auth/google/callback`,
      }),
    });

    if (!tokenResponse.ok) {
      const errorText = await tokenResponse.text();
      console.error('❌ Google token exchange failed:', errorText);
      return res.redirect(`${process.env.FRONTEND_URL}/auth/error?message=Token+exchange+failed&app=Mimaht`);
    }

    const tokens = await tokenResponse.json();
    if (!tokens.id_token || !tokens.access_token) {
      console.error('❌ Google did not return the required tokens');
      return res.redirect(`${process.env.FRONTEND_URL}/auth/error?message=Invalid+Google+tokens&app=Mimaht`);
    }

    console.log('✅ Google tokens received successfully');

    const userInfoResponse = await fetch('https://www.googleapis.com/oauth2/v2/userinfo', {
      headers: { Authorization: `Bearer ${tokens.access_token}` },
    });

    if (!userInfoResponse.ok) {
      console.error('❌ Failed to fetch user info from Google');
      return res.redirect(`${process.env.FRONTEND_URL}/auth/error?message=Failed+to+get+user+information&app=Mimaht`);
    }

    const userInfo = await userInfoResponse.json();
    console.log('✅ Google user info received:', userInfo.email);

    const supabase = createClient(
      process.env.SUPABASE_URL,
      process.env.SUPABASE_ANON_KEY
    );

    // Google OAuth itself is handled entirely by this backend.
    // Supabase is used only to establish the application's existing auth session.
    const { data: idTokenData, error: idTokenError } = await supabase.auth.signInWithIdToken({
      provider: 'google',
      token: tokens.id_token,
    });

    if (idTokenError || !idTokenData?.session) {
      console.error('❌ Failed to establish Mimaht session:', idTokenError?.message || 'No session returned');
      return res.redirect(`${process.env.FRONTEND_URL}/auth/error?message=Failed+to+establish+Mimaht+session&app=Mimaht`);
    }

    const session = idTokenData.session;

    console.log('✅ Mimaht session established, redirecting to frontend...');

    const frontendUrl = new URL(stateData.redirectTo);
    frontendUrl.searchParams.set('success', 'true');
    frontendUrl.searchParams.set('access_token', session.access_token);
    frontendUrl.searchParams.set('refresh_token', session.refresh_token);
    frontendUrl.searchParams.set('user_id', session.user.id);
    frontendUrl.searchParams.set('email', userInfo.email || session.user.email || '');
    frontendUrl.searchParams.set('full_name', userInfo.name || '');
    frontendUrl.searchParams.set('avatar_url', userInfo.picture || '');
    frontendUrl.searchParams.set('app', 'Mimaht');

    console.log('📍 Redirecting to Mimaht frontend callback:', stateData.redirectTo);
    res.redirect(frontendUrl.toString());
  } catch (error) {
    console.error('💥 Mimaht - Google OAuth callback error:', error);
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

  res.json({
    total_states: states.length,
    states,
    memory_usage: process.memoryUsage(),
    server_time: new Date().toISOString()
  });
});

module.exports = router;

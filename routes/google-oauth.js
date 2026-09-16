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
      return res.status(500).json({ success: false, error: 'Google OAuth not configured on server' });
    }

    const redirectTo = getFrontendRedirect(req.body?.redirectTo);
    const state = crypto.randomBytes(32).toString('hex');
    global.oauthStates.set(state, { state, redirectTo, timestamp: Date.now() });
    cleanupOAuthStates();

    const authUrl = new URL('https://accounts.google.com/o/oauth2/v2/auth');
    authUrl.searchParams.set('client_id', process.env.GOOGLE_CLIENT_ID);
    authUrl.searchParams.set('redirect_uri', `${process.env.BACKEND_URL || 'https://resend-u11p.onrender.com'}/api/auth/google/callback`);
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
      return res.redirect(`${process.env.FRONTEND_URL}/auth/error?message=Google+authentication+failed&app=Mimaht`);
    }
    if (!code || !state || !global.oauthStates?.has(state)) {
      return res.redirect(`${process.env.FRONTEND_URL}/auth/error?message=Invalid+authentication+request&app=Mimaht`);
    }

    const stateData = global.oauthStates.get(state);
    global.oauthStates.delete(state);

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
      console.error('❌ Google token exchange failed:', await tokenResponse.text());
      return res.redirect(`${process.env.FRONTEND_URL}/auth/error?message=Token+exchange+failed&app=Mimaht`);
    }

    const tokens = await tokenResponse.json();
    if (!tokens.access_token || !tokens.id_token) {
      return res.redirect(`${process.env.FRONTEND_URL}/auth/error?message=Invalid+Google+tokens&app=Mimaht`);
    }

    const userInfoResponse = await fetch('https://www.googleapis.com/oauth2/v2/userinfo', {
      headers: { Authorization: `Bearer ${tokens.access_token}` },
    });
    if (!userInfoResponse.ok) {
      return res.redirect(`${process.env.FRONTEND_URL}/auth/error?message=Failed+to+get+user+information&app=Mimaht`);
    }

    const userInfo = await userInfoResponse.json();
    if (!userInfo.email) {
      return res.redirect(`${process.env.FRONTEND_URL}/auth/error?message=Google+account+has+no+email&app=Mimaht`);
    }

    // Google authentication is completely handled by this backend.
    // We deliberately do NOT call Supabase signInWithOAuth/signInWithIdToken,
    // so this flow can never redirect through another Supabase application's
    // Google provider (for example Konkouht). Supabase is only used as the
    // existing Mimaht session store.
    if (!process.env.SUPABASE_URL || !process.env.SUPABASE_SERVICE_ROLE_KEY) {
      return res.status(500).json({ success: false, error: 'Mimaht auth service is not configured on server' });
    }

    const admin = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_ROLE_KEY, {
      auth: { autoRefreshToken: false, persistSession: false },
    });

    let linkData;
    let linkError;

    // Generate a one-time Mimaht session link for the verified Google email.
    // If the email has no Mimaht account yet, create one first.
    ({ data: linkData, error: linkError } = await admin.auth.admin.generateLink({
      type: 'magiclink',
      email: userInfo.email,
      options: {
        redirectTo: stateData.redirectTo,
        data: {
          full_name: userInfo.name || '',
          avatar_url: userInfo.picture || '',
          auth_provider: 'google',
        },
      },
    }));

    if (linkError) {
      console.log('ℹ️ Mimaht user may not exist; creating account:', linkError.message);
      const { error: createError } = await admin.auth.admin.createUser({
        email: userInfo.email,
        email_confirm: true,
        user_metadata: {
          full_name: userInfo.name || '',
          avatar_url: userInfo.picture || '',
          auth_provider: 'google',
        },
      });

      if (createError && !createError.message?.toLowerCase().includes('already')) {
        console.error('❌ Failed to create Mimaht user:', createError.message);
        return res.redirect(`${process.env.FRONTEND_URL}/auth/error?message=Failed+to+create+Mimaht+account&app=Mimaht`);
      }

      ({ data: linkData, error: linkError } = await admin.auth.admin.generateLink({
        type: 'magiclink',
        email: userInfo.email,
        options: { redirectTo: stateData.redirectTo },
      }));
    }

    if (linkError || !linkData?.properties?.hashed_token) {
      console.error('❌ Failed to generate Mimaht session link:', linkError?.message || 'No token returned');
      return res.redirect(`${process.env.FRONTEND_URL}/auth/error?message=Failed+to+establish+Mimaht+session&app=Mimaht`);
    }

    const frontendUrl = new URL(stateData.redirectTo);
    frontendUrl.searchParams.set('token_hash', linkData.properties.hashed_token);
    frontendUrl.searchParams.set('type', 'magiclink');
    frontendUrl.searchParams.set('app', 'Mimaht');

    console.log('✅ Mimaht backend session link generated; redirecting to Mimaht frontend');
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
  res.json({ total_states: states.length, states, memory_usage: process.memoryUsage(), server_time: new Date().toISOString() });
});

module.exports = router;

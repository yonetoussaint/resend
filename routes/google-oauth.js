// routes/google-oauth.js
const express = require('express');
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

router.post('/auth/google', async (req, res) => {
  try {
    const { redirectTo = `${req.headers.origin || 'https://mimaht.com'}/auth/callback` } = req.body;

    console.log('🔐 Initializing Google OAuth flow...');

    if (!process.env.GOOGLE_CLIENT_ID) {
      return res.status(500).json({
        success: false,
        error: 'Google OAuth not configured on server'
      });
    }

    const state = Math.random().toString(36).substring(2, 15) + Math.random().toString(36).substring(2, 15);
    global.oauthStates.set(state, { state, redirectTo, timestamp: Date.now() });
    cleanupOAuthStates();

    const authUrl = new URL('https://accounts.google.com/o/oauth2/v2/auth');
    authUrl.searchParams.set('client_id', process.env.GOOGLE_CLIENT_ID);
    authUrl.searchParams.set('redirect_uri', `${process.env.BACKEND_URL}/api/auth/google/callback`);
    authUrl.searchParams.set('response_type', 'code');
    authUrl.searchParams.set('scope', 'openid email profile');
    authUrl.searchParams.set('state', state);
    authUrl.searchParams.set('access_type', 'offline');
    authUrl.searchParams.set('prompt', 'consent');
    authUrl.searchParams.set('include_granted_scopes', 'true');

    console.log('✅ Google OAuth URL generated');
    res.json({ success: true, authUrl: authUrl.toString(), state });
  } catch (error) {
    console.error('❌ Google OAuth initialization error:', error);
    res.status(500).json({ success: false, error: 'Failed to initialize Google sign in' });
  }
});

router.get('/auth/google/callback', async (req, res) => {
  try {
    const { code, state, error: googleError } = req.query;

    console.log('🔄 Mimaht - Google OAuth Callback');

    if (googleError) {
      console.error('❌ Google OAuth error:', googleError);
      return res.redirect(`${process.env.FRONTEND_URL}/auth/error?message=Google+authentication+failed&app=Mimaht`);
    }

    if (!code || !state) {
      console.error('❌ Missing code or state');
      return res.redirect(`${process.env.FRONTEND_URL}/auth/error?message=Invalid+authentication+request&app=Mimaht`);
    }

    if (!global.oauthStates || !global.oauthStates.has(state)) {
      console.error('❌ Invalid state');
      return res.redirect(`${process.env.FRONTEND_URL}/auth/error?message=Invalid+session+state&app=Mimaht`);
    }

    const stateData = global.oauthStates.get(state);
    global.oauthStates.delete(state);

    console.log('✅ State validated, exchanging code for tokens...');

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
      console.error('❌ Token exchange failed:', errorText);
      return res.redirect(`${process.env.FRONTEND_URL}/auth/error?message=Token+exchange+failed&app=Mimaht`);
    }

    const tokens = await tokenResponse.json();
    console.log('✅ Tokens received successfully');

    const userInfoResponse = await fetch('https://www.googleapis.com/oauth2/v2/userinfo', {
      headers: { Authorization: `Bearer ${tokens.access_token}` },
    });

    if (!userInfoResponse.ok) {
      console.error('❌ Failed to fetch user info from Google');
      return res.redirect(`${process.env.FRONTEND_URL}/auth/error?message=Failed+to+get+user+information&app=Mimaht`);
    }

    const userInfo = await userInfoResponse.json();
    console.log('✅ User info received:', userInfo.email);

    const regularSupabase = createClient(
      process.env.SUPABASE_URL,
      process.env.SUPABASE_ANON_KEY
    );

    let authData;
    let authError;

    const idTokenResult = await regularSupabase.auth.signInWithIdToken({
      provider: 'google',
      token: tokens.id_token,
    });

    authData = idTokenResult.data;
    authError = idTokenResult.error;

    if (authError) {
      console.error('❌ Supabase Google ID-token auth error:', authError.message);

      if (authError.message?.toLowerCase().includes('user not found')) {
        console.log('🆕 User not found, creating account...');

        const oauthPassword = `${require('crypto').randomBytes(32).toString('hex')}Aa1!`;
        const { data: signUpData, error: signUpError } = await regularSupabase.auth.signUp({
          email: userInfo.email,
          password: oauthPassword,
          options: {
            data: {
              full_name: userInfo.name,
              avatar_url: userInfo.picture,
            }
          }
        });

        if (signUpError) {
          console.error('❌ Error creating user:', signUpError.message);
          throw new Error('Failed to create user account');
        }

        if (signUpData.session) {
          authData = signUpData;
          console.log('✅ New user created with an active session');
        } else {
          const { data: passwordData, error: passwordError } = await regularSupabase.auth.signInWithPassword({
            email: userInfo.email,
            password: oauthPassword,
          });

          if (passwordError || !passwordData.session) {
            console.error('❌ Error creating session for new user:', passwordError?.message || 'No session returned');
            throw new Error('Failed to create user session');
          }

          authData = passwordData;
          console.log('✅ Session created for new user');
        }
      } else {
        throw new Error('Authentication failed: ' + authError.message);
      }
    }

    const { data: { session }, error: sessionError } = await regularSupabase.auth.getSession();

    if (sessionError || !session) {
      console.error('❌ No session found after authentication:', sessionError?.message || 'unknown error');
      throw new Error('Failed to establish user session');
    }

    console.log('✅ Session verified, redirecting to frontend...');

    const frontendUrl = new URL(stateData.redirectTo);
    frontendUrl.searchParams.set('success', 'true');
    frontendUrl.searchParams.set('access_token', session.access_token);
    frontendUrl.searchParams.set('refresh_token', session.refresh_token);
    frontendUrl.searchParams.set('user_id', session.user.id);
    frontendUrl.searchParams.set('email', userInfo.email);
    frontendUrl.searchParams.set('full_name', userInfo.name || '');
    frontendUrl.searchParams.set('avatar_url', userInfo.picture || '');
    frontendUrl.searchParams.set('is_new_user', (!authData?.user).toString());
    frontendUrl.searchParams.set('app', 'Mimaht');

    console.log('📍 Redirecting to Mimaht frontend');
    res.redirect(frontendUrl.toString());
  } catch (error) {
    console.error('💥 Mimaht - Google OAuth callback error:', error);
    res.redirect(`${process.env.FRONTEND_URL}/auth/error?message=Authentication+failed&app=Mimaht`);
  }
});

router.get('/debug/oauth-states', (req, res) => {
  const states = global.oauthStates ? Array.from(global.oauthStates.entries()).map(([state, data]) => ({
    state,
    redirectTo: data.redirectTo,
    timestamp: new Date(data.timestamp).toISOString(),
    age: Date.now() - data.timestamp
  })) : [];

  res.json({
    total_states: states.length,
    states,
    memory_usage: process.memoryUsage(),
    server_time: new Date().toISOString()
  });
});

module.exports = router;

// routes/google-oauth.js
const express = require('express');
const { createClient } = require('@supabase/supabase-js');
const router = express.Router();

// Global OAuth states storage
global.oauthStates = new Map();
const OAUTH_STATE_EXPIRY = 10 * 60 * 1000; // 10 minutes

// Clean up expired OAuth states
function cleanupOAuthStates() {
  const now = Date.now();
  for (let [state, stateData] of global.oauthStates.entries()) {
    if (now - stateData.timestamp > OAUTH_STATE_EXPIRY) {
      global.oauthStates.delete(state);
    }
  }
}

// Google OAuth initialization endpoint
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

    // Generate state parameter for security
    const state = Math.random().toString(36).substring(2, 15) + Math.random().toString(36).substring(2, 15);

    // Store state
    const stateStore = {
      state,
      redirectTo,
      timestamp: Date.now()
    };

    global.oauthStates.set(state, stateStore);
    cleanupOAuthStates();

    // Construct Google OAuth URL with app name hint
    const authUrl = new URL('https://accounts.google.com/o/oauth2/v2/auth');

    authUrl.searchParams.set('client_id', process.env.GOOGLE_CLIENT_ID);
    authUrl.searchParams.set('redirect_uri', `${process.env.BACKEND_URL}/api/auth/google/callback`);
    authUrl.searchParams.set('response_type', 'code');
    authUrl.searchParams.set('scope', 'openid email profile');
    authUrl.searchParams.set('state', state);
    authUrl.searchParams.set('access_type', 'offline');
    authUrl.searchParams.set('prompt', 'consent');

    // Add these parameters to improve the OAuth experience
    authUrl.searchParams.set('include_granted_scopes', 'true');
    authUrl.searchParams.set('login_hint', ''); // You can pre-fill email if available

    console.log('✅ Google OAuth URL generated');

    res.json({
      success: true,
      authUrl: authUrl.toString(),
      state
    });

  } catch (error) {
    console.error('❌ Google OAuth initialization error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to initialize Google sign in'
    });
  }
});

// Google OAuth callback - with better branding
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

    // Verify state
    if (!global.oauthStates || !global.oauthStates.has(state)) {
      console.error('❌ Invalid state');
      return res.redirect(`${process.env.FRONTEND_URL}/auth/error?message=Invalid+session+state&app=Mimaht`);
    }

    const stateData = global.oauthStates.get(state);
    global.oauthStates.delete(state);

    console.log('✅ State validated, exchanging code for tokens...');

    // Exchange code for tokens with Google
    const tokenResponse = await fetch('https://oauth2.googleapis.com/token', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: new URLSearchParams({
        client_id: process.env.GOOGLE_CLIENT_ID,
        client_secret: process.env.GOOGLE_CLIENT_SECRET,
        code: code,
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

    // Get user info from Google
    const userInfoResponse = await fetch('https://www.googleapis.com/oauth2/v2/userinfo', {
      headers: {
        Authorization: `Bearer ${tokens.access_token}`,
      },
    });

    if (!userInfoResponse.ok) {
      console.error('❌ Failed to fetch user info from Google');
      return res.redirect(`${process.env.FRONTEND_URL}/auth/error?message=Failed+to+get+user+information&app=Mimaht`);
    }

    const userInfo = await userInfoResponse.json();
    console.log('✅ User info received:', userInfo.email);

    // Create a regular Supabase client for auth (not admin)
    const regularSupabase = createClient(
      process.env.SUPABASE_URL,
      process.env.SUPABASE_ANON_KEY // Use ANON key, not service role key
    );

    // Sign in or sign up the user
    const { data, error } = await regularSupabase.auth.signInWithIdToken({
      provider: 'google',
      token: tokens.id_token,
    });

    if (error) {
      console.error('❌ Supabase auth error:', error);

      // If user doesn't exist, try to sign them up
      if (error.message.includes('user not found')) {
        console.log('🆕 User not found, creating account...');

        const { data: signUpData, error: signUpError } = await regularSupabase.auth.signUp({
          email: userInfo.email,
          password: Math.random().toString(36).slice(2), // Random password for OAuth users
          options: {
            data: {
              full_name: userInfo.name,
              avatar_url: userInfo.picture,
            }
          }
        });

        if (signUpError) {
          console.error('❌ Error creating user:', signUpError);
          throw new Error('Failed to create user account');
        }

        console.log('✅ New user created, getting session...');

        // Sign in the newly created user
        const { data: sessionData, error: sessionError } = await regularSupabase.auth.signInWithPassword({
          email: userInfo.email,
          password: signUpData.user?.id || 'default'
        });

        if (sessionError) {
          console.error('❌ Error creating session:', sessionError);
          throw new Error('Failed to create user session');
        }

        console.log('✅ Session created for new user');
      } else {
        throw new Error('Authentication failed: ' + error.message);
      }
    }

    // Get the current session
    const { data: { session }, error: sessionError } = await regularSupabase.auth.getSession();

    if (sessionError || !session) {
      console.error('❌ No session found after authentication');
      throw new Error('Failed to establish user session');
    }

    console.log('✅ Session verified, redirecting to frontend...');

    // When redirecting, include app name in URL parameters
    const frontendUrl = new URL(stateData.redirectTo);
    frontendUrl.searchParams.set('success', 'true');
    frontendUrl.searchParams.set('access_token', session.access_token);
    frontendUrl.searchParams.set('refresh_token', session.refresh_token);
    frontendUrl.searchParams.set('user_id', session.user.id);
    frontendUrl.searchParams.set('email', userInfo.email);
    frontendUrl.searchParams.set('full_name', userInfo.name || '');
    frontendUrl.searchParams.set('avatar_url', userInfo.picture || '');
    frontendUrl.searchParams.set('is_new_user', (!data?.user).toString());
    frontendUrl.searchParams.set('app', 'Mimaht'); // Add app name

    console.log('📍 Redirecting to Mimaht frontend');

    res.redirect(frontendUrl.toString());

  } catch (error) {
    console.error('💥 Mimaht - Google OAuth callback error:', error);
    res.redirect(`${process.env.FRONTEND_URL}/auth/error?message=Authentication+failed&app=Mimaht`);
  }
});

// Debug endpoint for OAuth states
router.get('/debug/oauth-states', (req, res) => {
  const states = global.oauthStates ? Array.from(global.oauthStates.entries()).map(([state, data]) => ({
    state,
    redirectTo: data.redirectTo,
    timestamp: new Date(data.timestamp).toISOString(),
    age: Date.now() - data.timestamp
  })) : [];

  res.json({
    total_states: states.length,
    states: states,
    memory_usage: process.memoryUsage(),
    server_time: new Date().toISOString()
  });
});

module.exports = router;
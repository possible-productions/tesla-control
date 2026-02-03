const express = require('express');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const app = express();
app.use(express.json());

// =============================================================================
// Configuration
// =============================================================================

const PORT = process.env.PORT || 3000;
const TESLA_CLIENT_ID = process.env.TESLA_CLIENT_ID;
const TESLA_CLIENT_SECRET = process.env.TESLA_CLIENT_SECRET;
const API_KEY = process.env.API_KEY;
const REDIRECT_URI = 'https://car.figge.com/auth/callback';
const TESLA_AUTH_URL = 'https://auth.tesla.com/oauth2/v3/authorize';
const TESLA_TOKEN_URL = 'https://auth.tesla.com/oauth2/v3/token';
const TESLA_API_BASE = 'https://fleet-api.prd.na.vn.cloud.tesla.com';
const TOKEN_FILE = path.join(__dirname, 'tokens.json');

// Scopes needed for vehicle data + commands
const SCOPES = [
  'openid',
  'offline_access',
  'vehicle_device_data',
  'vehicle_cmds',
  'vehicle_charging_cmds',
].join(' ');

// =============================================================================
// Token Storage (file-based, persists across restarts with Railway volume)
// =============================================================================

let tokens = loadTokens();

function loadTokens() {
  try {
    if (fs.existsSync(TOKEN_FILE)) {
      return JSON.parse(fs.readFileSync(TOKEN_FILE, 'utf8'));
    }
  } catch (e) {
    console.error('Failed to load tokens:', e.message);
  }
  // Fall back to env var if file doesn't exist
  if (process.env.TESLA_REFRESH_TOKEN) {
    return {
      refresh_token: process.env.TESLA_REFRESH_TOKEN,
      access_token: process.env.TESLA_ACCESS_TOKEN || null,
      expires_at: parseInt(process.env.TESLA_TOKEN_EXPIRES_AT || '0'),
    };
  }
  return { access_token: null, refresh_token: null, expires_at: 0 };
}

function saveTokens(data) {
  tokens = {
    access_token: data.access_token || tokens.access_token,
    refresh_token: data.refresh_token || tokens.refresh_token,
    expires_at: data.expires_in
      ? Date.now() + data.expires_in * 1000 - 60000 // 1min buffer
      : tokens.expires_at,
  };
  try {
    fs.writeFileSync(TOKEN_FILE, JSON.stringify(tokens, null, 2));
    console.log('Tokens saved to file');
  } catch (e) {
    console.error('Failed to save tokens to file:', e.message);
  }
}

function isAuthenticated() {
  return !!(tokens.access_token && tokens.expires_at > Date.now());
}

// =============================================================================
// Tesla API Helper
// =============================================================================

async function teslaFetch(endpoint, options = {}) {
  // Auto-refresh if token expired but we have a refresh token
  if (!isAuthenticated() && tokens.refresh_token) {
    console.log('Token expired, refreshing...');
    await refreshAccessToken();
  }

  if (!isAuthenticated()) {
    throw new Error('Not authenticated. Please complete OAuth flow at /auth/login');
  }

  const url = `${TESLA_API_BASE}${endpoint}`;
  const resp = await fetch(url, {
    ...options,
    headers: {
      Authorization: `Bearer ${tokens.access_token}`,
      'Content-Type': 'application/json',
      ...options.headers,
    },
  });

  if (resp.status === 401) {
    // Try refresh once
    if (tokens.refresh_token) {
      console.log('Got 401, attempting token refresh...');
      await refreshAccessToken();
      const retry = await fetch(url, {
        ...options,
        headers: {
          Authorization: `Bearer ${tokens.access_token}`,
          'Content-Type': 'application/json',
          ...options.headers,
        },
      });
      if (!retry.ok) {
        const body = await retry.text();
        throw new Error(`Tesla API error ${retry.status}: ${body}`);
      }
      return retry.json();
    }
    throw new Error('Authentication expired. Re-authenticate at /auth/login');
  }

  if (!resp.ok) {
    const body = await resp.text();
    throw new Error(`Tesla API error ${resp.status}: ${body}`);
  }

  return resp.json();
}

async function refreshAccessToken() {
  if (!tokens.refresh_token) throw new Error('No refresh token available');

  const resp = await fetch(TESLA_TOKEN_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'refresh_token',
      client_id: TESLA_CLIENT_ID,
      client_secret: TESLA_CLIENT_SECRET,
      refresh_token: tokens.refresh_token,
    }),
  });

  if (!resp.ok) {
    const body = await resp.text();
    throw new Error(`Token refresh failed ${resp.status}: ${body}`);
  }

  const data = await resp.json();
  saveTokens(data);
  console.log('Token refreshed successfully');
}

// =============================================================================
// Middleware
// =============================================================================

function apiKeyAuth(req, res, next) {
  if (!API_KEY) {
    return res.status(500).json({ error: 'API_KEY not configured on server' });
  }

  const key =
    req.headers['x-api-key'] ||
    req.headers['authorization']?.replace('Bearer ', '') ||
    req.query.api_key;

  if (!key || key !== API_KEY) {
    return res.status(401).json({ error: 'Invalid or missing API key' });
  }
  next();
}

// =============================================================================
// Routes: Health & Status
// =============================================================================

app.get('/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

app.get('/', (req, res) => {
  const authenticated = isAuthenticated();
  const hasRefreshToken = !!tokens.refresh_token;
  const configOk = !!(TESLA_CLIENT_ID && TESLA_CLIENT_SECRET && API_KEY);

  res.send(`<!DOCTYPE html>
<html><head><title>Tesla Control - car.figge.com</title>
<style>
  body { font-family: -apple-system, system-ui, sans-serif; max-width: 600px; margin: 40px auto; padding: 20px; background: #0a0a0a; color: #e0e0e0; }
  h1 { color: #fff; }
  .status { padding: 12px 16px; border-radius: 8px; margin: 12px 0; }
  .ok { background: #0d2818; border: 1px solid #1a5c2e; }
  .warn { background: #2d1f00; border: 1px solid #5c4a1a; }
  .err { background: #2d0a0a; border: 1px solid #5c1a1a; }
  a { color: #4a9eff; }
  code { background: #1a1a1a; padding: 2px 6px; border-radius: 4px; }
</style></head><body>
  <h1>🚗 Tesla Control</h1>
  <p>OAuth service for Tesla Fleet API</p>

  <div class="status ${configOk ? 'ok' : 'err'}">
    <strong>Config:</strong> ${configOk ? '✅ All env vars set' : '❌ Missing env vars'}
    ${!TESLA_CLIENT_ID ? '<br>• TESLA_CLIENT_ID missing' : ''}
    ${!TESLA_CLIENT_SECRET ? '<br>• TESLA_CLIENT_SECRET missing' : ''}
    ${!API_KEY ? '<br>• API_KEY missing' : ''}
  </div>

  <div class="status ${authenticated ? 'ok' : hasRefreshToken ? 'warn' : 'err'}">
    <strong>Auth:</strong> ${
      authenticated
        ? '✅ Authenticated (token valid)'
        : hasRefreshToken
        ? '⚠️ Have refresh token (will auto-refresh)'
        : '❌ Not authenticated'
    }
    ${!authenticated && configOk ? '<br><a href="/auth/login">→ Start OAuth Login</a>' : ''}
  </div>

  <div class="status ok">
    <strong>Endpoints:</strong><br>
    <code>GET /api/vehicles</code> — List vehicles<br>
    <code>GET /api/vehicle/:id/status</code> — Vehicle data<br>
    <code>GET /api/vehicle/:id/location</code> — Location<br>
    <code>POST /api/vehicle/:id/wake</code> — Wake up<br>
    <code>POST /api/vehicle/:id/climate/on</code> — HVAC on<br>
    <code>POST /api/vehicle/:id/climate/off</code> — HVAC off<br>
    <code>POST /api/vehicle/:id/climate/temp</code> — Set temp<br>
    <br>All <code>/api/*</code> require <code>X-API-Key</code> header
  </div>
</body></html>`);
});

// =============================================================================
// Routes: OAuth Flow
// =============================================================================

app.get('/auth/login', (req, res) => {
  if (!TESLA_CLIENT_ID) {
    return res.status(500).send('TESLA_CLIENT_ID not configured');
  }

  const state = crypto.randomBytes(16).toString('hex');
  // Store state in a cookie for CSRF validation
  res.cookie('oauth_state', state, { httpOnly: true, secure: true, maxAge: 600000 });

  const params = new URLSearchParams({
    response_type: 'code',
    client_id: TESLA_CLIENT_ID,
    redirect_uri: REDIRECT_URI,
    scope: SCOPES,
    state,
  });

  res.redirect(`${TESLA_AUTH_URL}?${params}`);
});

app.get('/auth/callback', async (req, res) => {
  const { code, state, error } = req.query;

  if (error) {
    return res.status(400).send(`OAuth error: ${error}`);
  }

  if (!code) {
    return res.status(400).send('Missing authorization code');
  }

  try {
    const resp = await fetch(TESLA_TOKEN_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        client_id: TESLA_CLIENT_ID,
        client_secret: TESLA_CLIENT_SECRET,
        code,
        redirect_uri: REDIRECT_URI,
        audience: TESLA_API_BASE,
      }),
    });

    if (!resp.ok) {
      const body = await resp.text();
      return res.status(resp.status).send(`Token exchange failed: ${body}`);
    }

    const data = await resp.json();
    saveTokens(data);
    console.log('OAuth complete — tokens stored');

    res.send(`<!DOCTYPE html>
<html><head><title>Tesla Auth Success</title>
<style>body{font-family:system-ui;max-width:500px;margin:80px auto;text-align:center;background:#0a0a0a;color:#e0e0e0;}
.check{font-size:64px;margin:20px;}</style></head><body>
  <div class="check">✅</div>
  <h1>Authenticated!</h1>
  <p>Tesla OAuth flow complete. Tokens are stored.</p>
  <p><a href="/" style="color:#4a9eff">← Back to status</a></p>
</body></html>`);
  } catch (err) {
    console.error('OAuth callback error:', err);
    res.status(500).send(`OAuth callback error: ${err.message}`);
  }
});

// =============================================================================
// Routes: API (all require API key)
// =============================================================================

app.use('/api', apiKeyAuth);

// List vehicles
app.get('/api/vehicles', async (req, res) => {
  try {
    const data = await teslaFetch('/api/1/vehicles');
    res.json(data);
  } catch (err) {
    res.status(err.message.includes('Not authenticated') ? 401 : 502).json({ error: err.message });
  }
});

// Vehicle status (full data dump)
app.get('/api/vehicle/:id/status', async (req, res) => {
  try {
    const data = await teslaFetch(
      `/api/1/vehicles/${req.params.id}/vehicle_data?endpoints=${encodeURIComponent(
        'location_data;charge_state;climate_state;vehicle_state;drive_state;vehicle_config'
      )}`
    );
    res.json(data);
  } catch (err) {
    res.status(502).json({ error: err.message });
  }
});

// Location
app.get('/api/vehicle/:id/location', async (req, res) => {
  try {
    const data = await teslaFetch(
      `/api/1/vehicles/${req.params.id}/vehicle_data?endpoints=${encodeURIComponent('location_data;drive_state')}`
    );
    const ds = data?.response?.drive_state;
    if (ds) {
      res.json({
        latitude: ds.latitude,
        longitude: ds.longitude,
        heading: ds.heading,
        speed: ds.speed,
        timestamp: ds.timestamp,
        gps_as_of: ds.gps_as_of,
      });
    } else {
      res.json(data);
    }
  } catch (err) {
    res.status(502).json({ error: err.message });
  }
});

// Wake up
app.post('/api/vehicle/:id/wake', async (req, res) => {
  try {
    const data = await teslaFetch(`/api/1/vehicles/${req.params.id}/wake_up`, {
      method: 'POST',
    });
    res.json(data);
  } catch (err) {
    res.status(502).json({ error: err.message });
  }
});

// Climate ON
app.post('/api/vehicle/:id/climate/on', async (req, res) => {
  try {
    const data = await teslaFetch(
      `/api/1/vehicles/${req.params.id}/command/auto_conditioning_start`,
      { method: 'POST' }
    );
    res.json(data);
  } catch (err) {
    res.status(502).json({ error: err.message });
  }
});

// Climate OFF
app.post('/api/vehicle/:id/climate/off', async (req, res) => {
  try {
    const data = await teslaFetch(
      `/api/1/vehicles/${req.params.id}/command/auto_conditioning_stop`,
      { method: 'POST' }
    );
    res.json(data);
  } catch (err) {
    res.status(502).json({ error: err.message });
  }
});

// Set temperature
app.post('/api/vehicle/:id/climate/temp', async (req, res) => {
  try {
    let tempF = req.body.temp;
    if (!tempF) {
      return res.status(400).json({ error: 'Missing temp in body (Fahrenheit)' });
    }
    // Tesla API uses Celsius
    const tempC = ((tempF - 32) * 5) / 9;
    const data = await teslaFetch(
      `/api/1/vehicles/${req.params.id}/command/set_temps`,
      {
        method: 'POST',
        body: JSON.stringify({
          driver_temp: tempC,
          passenger_temp: tempC,
        }),
      }
    );
    res.json(data);
  } catch (err) {
    res.status(502).json({ error: err.message });
  }
});

// =============================================================================
// Start
// =============================================================================

app.listen(PORT, () => {
  console.log(`Tesla Control running on port ${PORT}`);
  console.log(`Config: client_id=${TESLA_CLIENT_ID ? 'set' : 'MISSING'}, client_secret=${TESLA_CLIENT_SECRET ? 'set' : 'MISSING'}, api_key=${API_KEY ? 'set' : 'MISSING'}`);
  console.log(`Auth: ${isAuthenticated() ? 'authenticated' : tokens.refresh_token ? 'have refresh token' : 'not authenticated'}`);
});

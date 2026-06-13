/**
 * Sansun Living — Contact Form Worker
 *
 * Receives POST { name, email, message }
 * - Writes to Firestore
 * - Forwards to Naomi's email via Mailchannels (free on Cloudflare)
 *
 * Environment variables (set in Cloudflare dashboard > Workers > Settings > Variables):
 *   FIREBASE_PROJECT_ID   — e.g. "sansunliving"
 *   FIREBASE_CLIENT_EMAIL — service account email
 *   FIREBASE_PRIVATE_KEY  — service account private key (paste full PEM including \n)
 *   TO_EMAIL              — naomi@sansungroup.com
 *   FROM_EMAIL            — hello@sansunliving.com
 */

const ALLOWED_ORIGIN = 'https://sansunliving.com';

export default {
  async fetch(request, env) {
    if (request.method === 'OPTIONS') {
      return cors(new Response(null, { status: 204 }));
    }

    if (request.method !== 'POST') {
      return cors(new Response('Method not allowed', { status: 405 }));
    }

    let body;
    try {
      body = await request.json();
    } catch {
      return cors(new Response('Invalid JSON', { status: 400 }));
    }

    const { name, email, message } = body;
    if (!name || !email || !message) {
      return cors(new Response('Missing fields', { status: 400 }));
    }

    // Basic email format check
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      return cors(new Response('Invalid email', { status: 400 }));
    }

    const timestamp = new Date().toISOString();

    try {
      await Promise.all([
        writeToFirestore({ name, email, message, timestamp }, env),
        sendEmail({ name, email, message, timestamp }, env),
      ]);
    } catch (err) {
      console.error('Worker error:', err);
      return cors(new Response('Internal error', { status: 500 }));
    }

    return cors(new Response('OK', { status: 200 }));
  }
};

// ── Firestore ────────────────────────────────────────────────────────────────

async function writeToFirestore(data, env) {
  const token = await getFirebaseToken(env);
  const url = `https://firestore.googleapis.com/v1/projects/${env.FIREBASE_PROJECT_ID}/databases/(default)/documents/contact_submissions`;

  const res = await fetch(url, {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${token}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      fields: {
        name:      { stringValue: data.name },
        email:     { stringValue: data.email },
        message:   { stringValue: data.message },
        timestamp: { stringValue: data.timestamp },
      }
    }),
  });

  if (!res.ok) {
    const text = await res.text();
    throw new Error(`Firestore write failed: ${res.status} ${text}`);
  }
}

async function getFirebaseToken(env) {
  const now = Math.floor(Date.now() / 1000);
  const header = btoa(JSON.stringify({ alg: 'RS256', typ: 'JWT' }));
  const payload = btoa(JSON.stringify({
    iss: env.FIREBASE_CLIENT_EMAIL,
    sub: env.FIREBASE_CLIENT_EMAIL,
    aud: 'https://oauth2.googleapis.com/token',
    iat: now,
    exp: now + 3600,
    scope: 'https://www.googleapis.com/auth/datastore',
  }));

  const signingInput = `${header}.${payload}`;
  const privateKey = await importPrivateKey(env.FIREBASE_PRIVATE_KEY);
  const signature = await crypto.subtle.sign(
    { name: 'RSASSA-PKCS1-v1_5' },
    privateKey,
    new TextEncoder().encode(signingInput)
  );

  const jwt = `${signingInput}.${btoa(String.fromCharCode(...new Uint8Array(signature)))}`;

  const tokenRes = await fetch('https://oauth2.googleapis.com/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: `grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer&assertion=${jwt}`,
  });

  const tokenData = await tokenRes.json();
  if (!tokenData.access_token) throw new Error('Failed to get Firebase token');
  return tokenData.access_token;
}

async function importPrivateKey(pem) {
  const pemContents = pem
    .replace(/-----BEGIN PRIVATE KEY-----/, '')
    .replace(/-----END PRIVATE KEY-----/, '')
    .replace(/\n/g, '');
  const binaryDer = Uint8Array.from(atob(pemContents), c => c.charCodeAt(0));
  return crypto.subtle.importKey(
    'pkcs8',
    binaryDer,
    { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
    false,
    ['sign']
  );
}

// ── Email via MailChannels ───────────────────────────────────────────────────

async function sendEmail(data, env) {
  const res = await fetch('https://api.mailchannels.net/tx/v1/send', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      personalizations: [{
        to: [{ email: env.TO_EMAIL, name: 'Naomi Murray' }],
        reply_to: { email: data.email, name: data.name },
      }],
      from: { email: env.FROM_EMAIL, name: 'Sansun Living' },
      subject: `New consultation request from ${data.name}`,
      content: [{
        type: 'text/plain',
        value: [
          `Name: ${data.name}`,
          `Email: ${data.email}`,
          ``,
          `Message:`,
          data.message,
          ``,
          `Submitted: ${data.timestamp}`,
        ].join('\n'),
      }, {
        type: 'text/html',
        value: `
          <p style="font-family:Georgia,serif;color:#3a2e22;font-size:15px;">
            <strong>Name:</strong> ${escHtml(data.name)}<br>
            <strong>Email:</strong> <a href="mailto:${escHtml(data.email)}">${escHtml(data.email)}</a>
          </p>
          <p style="font-family:Georgia,serif;color:#3a2e22;font-size:15px;white-space:pre-wrap;">${escHtml(data.message)}</p>
          <p style="font-family:Georgia,serif;color:#7a6a58;font-size:12px;">Submitted ${data.timestamp}</p>
        `,
      }],
    }),
  });

  if (!res.ok && res.status !== 202) {
    const text = await res.text();
    throw new Error(`MailChannels failed: ${res.status} ${text}`);
  }
}

function escHtml(str) {
  return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

// ── CORS ─────────────────────────────────────────────────────────────────────

function cors(response) {
  const headers = new Headers(response.headers);
  headers.set('Access-Control-Allow-Origin', ALLOWED_ORIGIN);
  headers.set('Access-Control-Allow-Methods', 'POST, OPTIONS');
  headers.set('Access-Control-Allow-Headers', 'Content-Type');
  return new Response(response.body, { status: response.status, headers });
}

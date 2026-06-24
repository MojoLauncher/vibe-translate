const express = require('express');
const session = require('express-session');
const { Octokit } = require('@octokit/rest');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

try { require('dotenv').config({ path: path.join(__dirname, '..', '.env') }); } catch (_) {}

const app = express();

const GITHUB_CLIENT_ID = process.env.GITHUB_CLIENT_ID;
const GITHUB_CLIENT_SECRET = process.env.GITHUB_CLIENT_SECRET;
const GITHUB_BOT_TOKEN = process.env.GITHUB_BOT_TOKEN;
const GITHUB_ADMIN_LOGIN = process.env.GITHUB_ADMIN_LOGIN;
const SESSION_SECRET = process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex');
const PORT = process.env.PORT || 3000;
const NODE_ENV = process.env.NODE_ENV || 'development';
const FRONTEND_URL = process.env.FRONTEND_URL || `http://localhost:${PORT}`;

const GITHUB_REPO_OWNER = process.env.GITHUB_REPO_OWNER || 'MojoLauncher';
const GITHUB_REPO_NAME = process.env.GITHUB_REPO_NAME || 'MojoLauncher';
const GITHUB_BRANCH = process.env.GITHUB_BRANCH || 'v3_openjdk';
const RES_PATH = process.env.RES_PATH || 'app_pojavlauncher/src/main/res';

const BANNED_FILE = path.join(__dirname, '..', 'banned-users.json');

if (!GITHUB_CLIENT_ID || !GITHUB_CLIENT_SECRET) {
  console.error('ERROR: GITHUB_CLIENT_ID and GITHUB_CLIENT_SECRET must be set in .env');
  process.exit(1);
}
if (!GITHUB_BOT_TOKEN) {
  console.error('ERROR: GITHUB_BOT_TOKEN must be set in .env');
  process.exit(1);
}
if (!GITHUB_ADMIN_LOGIN) {
  console.error('ERROR: GITHUB_ADMIN_LOGIN must be set in .env');
  process.exit(1);
}

app.set('trust proxy', 1);

app.use(helmet({
  contentSecurityPolicy: false,
  crossOriginEmbedderPolicy: false,
}));

app.use(express.json({ limit: '500kb' }));

app.use(session({
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  name: 'translate.sid',
  cookie: {
    httpOnly: true,
    secure: NODE_ENV === 'production',
    sameSite: 'lax',
    maxAge: 24 * 60 * 60 * 1000,
  },
}));

const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 60,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many requests, please try again later.' },
});
app.use('/api/', apiLimiter);

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many authentication attempts, please try again later.' },
});
app.use('/auth/', authLimiter);

const submitLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 3,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many submissions (max 3 per hour). Please wait before submitting again.' },
});
app.use('/api/submit', submitLimiter);

app.use(express.static(path.join(__dirname, '..'), {
  maxAge: NODE_ENV === 'production' ? '1h' : 0,
}));

app.get('/', (req, res) => {
  res.redirect('/translator.html');
});

function generateCsrfToken() {
  return crypto.randomBytes(32).toString('hex');
}

function csrfProtection(req, res, next) {
  if (req.method === 'GET' || req.method === 'HEAD' || req.method === 'OPTIONS') {
    return next();
  }
  const token = req.headers['x-csrf-token'];
  if (!token || token.length !== 64 || !req.session.csrfToken || !crypto.timingSafeEqual(Buffer.from(token), Buffer.from(req.session.csrfToken))) {
    return res.status(403).json({ error: 'Invalid or missing CSRF token. Refresh the page and try again.' });
  }
  next();
}

// --- Ban list persistence ---

function loadBanned() {
  try {
    const raw = fs.readFileSync(BANNED_FILE, 'utf-8');
    const data = JSON.parse(raw);
    return Array.isArray(data) ? data : [];
  } catch {
    return [];
  }
}

function saveBanned(list) {
  fs.writeFileSync(BANNED_FILE, JSON.stringify(list, null, 2) + '\n', 'utf-8');
}

function isBanned(login) {
  return loadBanned().some(b => b.login.toLowerCase() === login.toLowerCase());
}

// --- Admin check middleware ---

function requireAdmin(req, res, next) {
  if (!req.session.user) {
    return res.status(401).json({ error: 'Not authenticated.' });
  }
  if (req.session.user.login.toLowerCase() !== GITHUB_ADMIN_LOGIN.toLowerCase()) {
    return res.status(403).json({ error: 'Only the administrator can perform this action.' });
  }
  next();
}

// --- CSRF token ---

app.get('/api/csrf-token', (req, res) => {
  if (!req.session.csrfToken) {
    req.session.csrfToken = generateCsrfToken();
  }
  res.json({ token: req.session.csrfToken });
});

// --- OAuth ---

app.get('/auth/github', (req, res) => {
  const state = crypto.randomBytes(16).toString('hex');
  req.session.oauthState = state;
  const returnTo = (req.query.redirect || '').trim();
  if (returnTo && returnTo.startsWith('/')) {
    req.session.oauthReturnTo = returnTo;
  }
  const redirectUri = `${FRONTEND_URL}/auth/github/callback`;
  const url = `https://github.com/login/oauth/authorize` +
    `?client_id=${encodeURIComponent(GITHUB_CLIENT_ID)}` +
    `&redirect_uri=${encodeURIComponent(redirectUri)}` +
    `&scope=${encodeURIComponent('user:email')}` +
    `&state=${state}`;
  res.redirect(url);
});

async function fetchPrimaryEmail(octokit) {
  try {
    const { data: emails } = await octokit.users.listEmailsForAuthenticatedUser();
    const primary = emails.find(e => e.primary && e.verified);
    return primary ? primary.email : null;
  } catch {
    return null;
  }
}

app.get('/auth/github/callback', async (req, res) => {
  const { code, state } = req.query;

  if (!state || !req.session.oauthState || !crypto.timingSafeEqual(Buffer.from(state), Buffer.from(req.session.oauthState))) {
    delete req.session.oauthState;
    return res.status(400).send('Invalid state parameter. Please try signing in again.');
  }
  delete req.session.oauthState;

  if (!code) {
    return res.status(400).send('No authorization code provided.');
  }

  try {
    const tokenResp = await fetch('https://github.com/login/oauth/access_token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
      body: JSON.stringify({
        client_id: GITHUB_CLIENT_ID,
        client_secret: GITHUB_CLIENT_SECRET,
        code,
        redirect_uri: `${FRONTEND_URL}/auth/github/callback`,
      }),
    });

    if (!tokenResp.ok) {
      throw new Error(`GitHub returned HTTP ${tokenResp.status}`);
    }

    const tokenData = await tokenResp.json();

    if (tokenData.error) {
      throw new Error(tokenData.error_description || tokenData.error);
    }

    const octokit = new Octokit({ auth: tokenData.access_token });
    const { data: user } = await octokit.users.getAuthenticated();
    const email = await fetchPrimaryEmail(octokit);

    if (isBanned(user.login)) {
      return res.status(403).send('Your account has been banned from submitting translations. Contact the administrator if you believe this is an error.');
    }

    req.session.user = {
      id: user.id,
      login: user.login,
      avatar_url: user.avatar_url,
      name: user.name || user.login,
      email: email || `${user.login}@users.noreply.github.com`,
    };

    req.session.csrfToken = generateCsrfToken();

    const returnTo = req.session.oauthReturnTo || FRONTEND_URL;
    delete req.session.oauthReturnTo;
    res.redirect(returnTo);
  } catch (err) {
    console.error('OAuth callback error:', err);
    res.status(500).send('Authentication failed: ' + err.message);
  }
});

app.get('/api/me', (req, res) => {
  if (!req.session.user) {
    return res.json({ authenticated: false });
  }
  res.json({
    authenticated: true,
    user: req.session.user,
    isAdmin: req.session.user.login.toLowerCase() === GITHUB_ADMIN_LOGIN.toLowerCase(),
  });
});

app.post('/api/logout', csrfProtection, (req, res) => {
  req.session.destroy(() => {
    res.json({ success: true });
  });
});

app.get('/api/config', (_req, res) => {
  res.json({
    owner: GITHUB_REPO_OWNER,
    repo: GITHUB_REPO_NAME,
    branch: GITHUB_BRANCH,
    resPath: RES_PATH,
  });
});

// --- Ban list admin API ---

app.get('/api/admin/banned', csrfProtection, requireAdmin, (_req, res) => {
  res.json({ banned: loadBanned() });
});

app.post('/api/admin/banned', csrfProtection, requireAdmin, (req, res) => {
  const { login, reason } = req.body;

  if (!login || typeof login !== 'string' || !/^[a-zA-Z0-9](?:[a-zA-Z0-9]|-(?=[a-zA-Z0-9])){0,38}$/.test(login)) {
    return res.status(400).json({ error: 'Invalid GitHub login format.' });
  }

  const banned = loadBanned();
  if (banned.some(b => b.login.toLowerCase() === login.toLowerCase())) {
    return res.status(409).json({ error: `User "${login}" is already banned.` });
  }

  banned.push({
    login,
    reason: (typeof reason === 'string' && reason.trim()) ? reason.trim() : '',
    bannedAt: new Date().toISOString(),
    bannedBy: req.session.user.login,
  });
  saveBanned(banned);

  res.json({ success: true, banned: loadBanned() });
});

app.delete('/api/admin/banned/:login', csrfProtection, requireAdmin, (req, res) => {
  const login = req.params.login;
  let banned = loadBanned();
  const before = banned.length;
  banned = banned.filter(b => b.login.toLowerCase() !== login.toLowerCase());
  if (banned.length === before) {
    return res.status(404).json({ error: `User "${login}" is not in the ban list.` });
  }
  saveBanned(banned);

  res.json({ success: true, banned: loadBanned() });
});

app.get('/api/admin/lookup-user', requireAdmin, async (req, res) => {
  const q = (req.query.q || '').trim();
  if (!q || q.length < 2) {
    return res.status(400).json({ error: 'Query must be at least 2 characters.' });
  }

  try {
    const octokit = new Octokit({ auth: GITHUB_BOT_TOKEN });
    const { data } = await octokit.rest.search.users({
      q: q + ' type:user',
      per_page: 10,
    });

    const users = data.items.map(u => ({
      login: u.login,
      avatar_url: u.avatar_url,
      name: u.name || null,
    }));

    res.json({ users });
  } catch (err) {
    console.error('User lookup error:', err);
    res.status(502).json({ error: 'Failed to search GitHub users.' });
  }
});

// --- Submit ---

const LOCALE_RE = /^[a-z]{2,3}(-r[A-Z]{2})?$/;

app.post('/api/submit', csrfProtection, async (req, res) => {
  if (!req.session.user) {
    return res.status(401).json({ error: 'Not authenticated. Please sign in with GitHub first.' });
  }

  if (isBanned(req.session.user.login)) {
    return res.status(403).json({ error: 'Your account has been banned from submitting translations.' });
  }

  const { locale, xml, commitMessage: customMessage } = req.body;

  if (!locale || typeof locale !== 'string' || !LOCALE_RE.test(locale)) {
    return res.status(400).json({ error: 'Invalid locale format. Expected format like "fr", "fr-rCA".' });
  }

  if (locale.includes('..') || locale.includes('/') || locale.includes('\\') || locale.includes('\0')) {
    return res.status(400).json({ error: 'Invalid locale.' });
  }

  if (!xml || typeof xml !== 'string' || xml.length > 500000) {
    return res.status(400).json({ error: 'Invalid or too large XML content.' });
  }

  const trimmed = xml.trim();
  if (!trimmed.startsWith('<?xml') || !trimmed.includes('<resources>') || !trimmed.includes('</resources>')) {
    return res.status(400).json({ error: 'Invalid strings.xml: must be a valid XML with <resources> root.' });
  }

  const disallowed = /<!DOCTYPE|<!ENTITY|<!\[CDATA\[|<\?xml-stylesheet|<script|<iframe|<img/gi;
  if (disallowed.test(trimmed)) {
    return res.status(400).json({ error: 'XML contains disallowed content.' });
  }

  try {
    const octokit = new Octokit({ auth: GITHUB_BOT_TOKEN });
    const filePath = `${RES_PATH}/values-${locale}/strings.xml`;

    let sha = null;
    try {
      const { data: existing } = await octokit.repos.getContent({
        owner: GITHUB_REPO_OWNER,
        repo: GITHUB_REPO_NAME,
        path: filePath,
        ref: GITHUB_BRANCH,
      });
      sha = existing.sha;

      const existingContent = Buffer.from(existing.content, 'base64').toString('utf-8').trim();
      if (existingContent === trimmed) {
        return res.status(409).json({ error: 'No changes detected — the submitted content is identical to the current file.' });
      }
    } catch (err) {
      if (err.status !== 404) {
        if (err.status === 403) {
          return res.status(403).json({ error: 'The bot does not have write access to this repository. Contact the repository owner to grant access.' });
        }
        throw err;
      }
    }

    const commitMessage = customMessage || `Add/update ${locale} translations`;
    const content = Buffer.from(trimmed, 'utf-8').toString('base64');

    const { data: commit } = await octokit.repos.createOrUpdateFileContents({
      owner: GITHUB_REPO_OWNER,
      repo: GITHUB_REPO_NAME,
      path: filePath,
      message: commitMessage,
      content,
      sha: sha || undefined,
      branch: GITHUB_BRANCH,
      author: {
        name: req.session.user.name,
        email: req.session.user.email,
      },
    });

    res.json({
      success: true,
      commit: {
        url: commit.content.html_url,
        sha: commit.commit.sha,
        message: commitMessage,
        author: req.session.user.name,
      },
    });
  } catch (err) {
    console.error('Submit error:', err);

    if (err.status === 403) {
      return res.status(403).json({ error: 'The bot does not have write access to this repository.' });
    }
    if (err.status === 409) {
      return res.status(409).json({ error: 'The file was modified since we last checked. Please try again.' });
    }
    if (err.status === 422) {
      return res.status(422).json({ error: 'GitHub rejected the commit. The branch may be protected or the repository is read-only.' });
    }
    if (err.code === 'ENOTFOUND' || err.code === 'ECONNREFUSED') {
      return res.status(502).json({ error: 'Could not connect to GitHub. Please check your network and try again.' });
    }

    res.status(500).json({ error: 'Failed to submit translation: ' + err.message });
  }
});

app.use((_req, res) => {
  res.status(404).json({ error: 'Not found' });
});

app.use((err, _req, res, _next) => {
  console.error('Unhandled error:', err);
  res.status(500).json({ error: 'Internal server error' });
});

app.listen(PORT, () => {
  console.log(`Vibe Translate backend running at http://localhost:${PORT}`);
});

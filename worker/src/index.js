const COOKIE_SESSION = 'ipxe_sess';
const COOKIE_STATE = 'ipxe_install_state';
const COOKIE_OAUTH_STATE = 'ipxe_user_oauth_state';
const COOKIE_OAUTH_USER = 'ipxe_user_oauth';
const WORKFLOW_FILE = 'build-ipxe-efi.yml';
const ARTIFACT_NAME = 'ipxe-efi';
const GITHUB_USER_AGENT = 'ipxe-builder-worker';

export default {
  async fetch(request, env) {
    try {
      return await handleRequest(request, env);
    } catch (err) {
      if (err instanceof Response) {
        return withCors(err, env, request);
      }
      return json(
        { error: err instanceof Error ? err.message : String(err) },
        { status: 500 },
        env,
        request
      );
    }
  },
};

async function handleRequest(request, env) {
  const url = new URL(request.url);

  if (request.method === 'OPTIONS') {
    return new Response(null, { headers: corsHeaders(env, request) });
  }

  if (url.pathname === '/api/health') {
    return json({ ok: true }, {}, env, request);
  }

  if (url.pathname === '/api/config' && request.method === 'GET') {
    assertFrontendOrigin(request, env);
    return json(
      {
        ...getTemplateConfig(env),
        auth_mode: 'github_app',
        github_app_slug: must(env.GITHUB_APP_SLUG, 'missing GITHUB_APP_SLUG'),
      },
      {},
      env,
      request
    );
  }

  if (url.pathname === '/api/auth/login' && request.method === 'GET') {
    return authLogin(env);
  }

  if (url.pathname === '/api/auth/callback' && request.method === 'GET') {
    return authCallback(request, env);
  }

  if (url.pathname === '/api/oauth/login' && request.method === 'GET') {
    return oauthLogin(env);
  }

  if (url.pathname === '/api/oauth/callback' && request.method === 'GET') {
    return oauthCallback(request, env);
  }

  if (url.pathname === '/api/auth/logout' && request.method === 'POST') {
    assertFrontendOrigin(request, env);
    return logout(env, request);
  }

  if (url.pathname === '/api/oauth/installations' && request.method === 'GET') {
    assertFrontendOrigin(request, env);
    const userToken = await requireOauthUserToken(request, env);
    const result = await listUserInstallations(userToken, env);
    return json(result, {}, env, request);
  }

  if (url.pathname === '/api/auth/resume' && request.method === 'POST') {
    assertFrontendOrigin(request, env);
    const payload = await parseJson(request);
    const installationId = Number(must(payload.installation_id, 'missing installation_id'));
    return authResume(installationId, env, request);
  }

  if (url.pathname === '/api/me' && request.method === 'GET') {
    assertFrontendOrigin(request, env);
    const session = await requireSession(request, env);
    return json(
      {
        login: session.account_login,
        installation_id: session.installation_id,
      },
      {},
      env,
      request
    );
  }

  if (url.pathname === '/api/fork/ensure' && request.method === 'POST') {
    assertFrontendOrigin(request, env);
    const session = await requireSession(request, env);
    const token = await getInstallationAccessToken(session.installation_id, env);
    const result = await ensureRepoAccess(token, session.account_login, env);
    return json(result, {}, env, request);
  }

  if (url.pathname === '/api/fork/status' && request.method === 'GET') {
    assertFrontendOrigin(request, env);
    const session = await requireSession(request, env);
    const token = await getInstallationAccessToken(session.installation_id, env);
    const result = await forkStatus(token, session.account_login, env);
    return json(result, {}, env, request);
  }

  if (url.pathname === '/api/build/start' && request.method === 'POST') {
    assertFrontendOrigin(request, env);
    const session = await requireSession(request, env);
    const token = await getInstallationAccessToken(session.installation_id, env);
    const payload = await parseJson(request);
    const result = await startBuild(token, session.account_login, payload, env);
    return json(result, {}, env, request);
  }

  if (url.pathname === '/api/build/latest' && request.method === 'GET') {
    assertFrontendOrigin(request, env);
    const session = await requireSession(request, env);
    const token = await getInstallationAccessToken(session.installation_id, env);
    const result = await latestRun(token, session.account_login, env);
    return json(result, {}, env, request);
  }

  if (url.pathname === '/api/build/probe' && request.method === 'GET') {
    assertFrontendOrigin(request, env);
    const session = await requireSession(request, env);
    const token = await getInstallationAccessToken(session.installation_id, env);
    const result = await probeWorkflow(token, session.account_login, env);
    return json(result, {}, env, request);
  }

  if (url.pathname === '/api/build/logs' && request.method === 'GET') {
    assertFrontendOrigin(request, env);
    const session = await requireSession(request, env);
    const token = await getInstallationAccessToken(session.installation_id, env);
    const runId = Number(must(url.searchParams.get('run_id'), 'missing run_id'));
    const result = await buildLogs(token, session.account_login, runId, env);
    return json(result, {}, env, request);
  }

  if (url.pathname === '/api/build/cleanup' && request.method === 'POST') {
    assertFrontendOrigin(request, env);
    const session = await requireSession(request, env);
    const token = await getInstallationAccessToken(session.installation_id, env);
    const payload = await parseJson(request);
    const runId = Number(must(payload.run_id, 'missing run_id'));
    const result = await cleanupArtifact(token, session.account_login, runId, env);
    return json(result, {}, env, request);
  }

  if (url.pathname === '/api/build/download' && request.method === 'GET') {
    const cleanup = url.searchParams.get('cleanup') === '1';
    if (cleanup) {
      assertFrontendOrigin(request, env);
    } else {
      assertFrontendOriginOrRefererOrNone(request, env);
    }

    const session = await requireSession(request, env);
    const token = await getInstallationAccessToken(session.installation_id, env);
    const runId = Number(must(url.searchParams.get('run_id'), 'missing run_id'));
    return downloadArtifact(token, session.account_login, runId, cleanup, env, request);
  }

  return json({ error: 'Not found' }, { status: 404 }, env, request);
}

function assertFrontendOrigin(request, env) {
  const origin = request.headers.get('Origin');
  if (!origin || origin !== env.FRONTEND_ORIGIN) {
    throw new Error('Origin not allowed');
  }
}

function assertFrontendOriginOrRefererOrNone(request, env) {
  const origin = request.headers.get('Origin');
  if (origin === env.FRONTEND_ORIGIN) return;

  const referer = request.headers.get('Referer') || '';
  if (!origin && referer.startsWith(env.FRONTEND_ORIGIN)) return;

  if (!origin && !referer) return;

  throw new Error('Origin not allowed');
}

function corsHeaders(env, request) {
  const origin = request.headers.get('Origin') || '';
  const allowOrigin = origin === env.FRONTEND_ORIGIN ? origin : env.FRONTEND_ORIGIN;
  return {
    'Access-Control-Allow-Origin': allowOrigin,
    'Access-Control-Allow-Credentials': 'true',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Access-Control-Allow-Methods': 'GET,POST,OPTIONS',
  };
}

function json(data, init = {}, env, request) {
  const headers = new Headers(init.headers || {});
  headers.set('Content-Type', 'application/json; charset=utf-8');
  if (env && request) {
    const ch = corsHeaders(env, request);
    Object.entries(ch).forEach(([k, v]) => headers.set(k, v));
  }
  return new Response(JSON.stringify(data), { ...init, headers });
}

function withCors(response, env, request) {
  const headers = new Headers(response.headers);
  const ch = corsHeaders(env, request);
  Object.entries(ch).forEach(([k, v]) => headers.set(k, v));
  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers,
  });
}

function must(value, msg) {
  if (!value) throw new Error(msg);
  return value;
}

function getTemplateConfig(env) {
  return {
    templateOwner: must(env.TEMPLATE_OWNER, 'missing TEMPLATE_OWNER'),
    templateRepo: must(env.TEMPLATE_REPO, 'missing TEMPLATE_REPO'),
    branch: env.TEMPLATE_BRANCH || 'main',
  };
}

async function parseJson(request) {
  const data = await request.json();
  if (!data || typeof data !== 'object') {
    throw new Error('invalid json body');
  }
  return data;
}

function getCookieMap(request) {
  const cookie = request.headers.get('Cookie') || '';
  const map = new Map();
  for (const entry of cookie.split(';')) {
    const [k, ...rest] = entry.trim().split('=');
    if (!k) continue;
    map.set(k, rest.join('='));
  }
  return map;
}

function randomHex(len = 16) {
  const bytes = crypto.getRandomValues(new Uint8Array(len));
  return [...bytes].map((b) => b.toString(16).padStart(2, '0')).join('');
}

function utf8(str) {
  return new TextEncoder().encode(str);
}

function bytesToBase64(bytes) {
  let bin = '';
  bytes.forEach((b) => {
    bin += String.fromCharCode(b);
  });
  return btoa(bin);
}

function base64ToBytes(base64) {
  const bin = atob(base64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i += 1) out[i] = bin.charCodeAt(i);
  return out;
}

function base64urlEncodeBytes(bytes) {
  return bytesToBase64(bytes).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

function base64urlEncodeText(str) {
  return base64urlEncodeBytes(utf8(str));
}

function base64urlToBytes(input) {
  const b64 = input.replace(/-/g, '+').replace(/_/g, '/');
  const pad = '='.repeat((4 - (b64.length % 4)) % 4);
  return base64ToBytes(b64 + pad);
}

async function hmacSign(secret, payload) {
  const key = await crypto.subtle.importKey(
    'raw',
    utf8(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  const sig = await crypto.subtle.sign('HMAC', key, utf8(payload));
  return base64urlEncodeBytes(new Uint8Array(sig));
}

async function createSignedValue(secret, payloadObj) {
  const payload = base64urlEncodeText(JSON.stringify(payloadObj));
  const sig = await hmacSign(secret, payload);
  return `${payload}.${sig}`;
}

async function verifySignedValue(secret, value) {
  if (!value || !value.includes('.')) return null;
  const [payload, sig] = value.split('.');
  const expected = await hmacSign(secret, payload);
  if (sig !== expected) return null;
  const decoded = new TextDecoder().decode(base64urlToBytes(payload));
  return JSON.parse(decoded);
}

function makeCookie(name, value, maxAgeSec) {
  return `${name}=${value}; Path=/; HttpOnly; Secure; SameSite=None; Max-Age=${maxAgeSec}`;
}

function clearCookie(name) {
  return `${name}=; Path=/; HttpOnly; Secure; SameSite=None; Max-Age=0`;
}

async function authLogin(env) {
  const state = randomHex(20);
  const appSlug = must(env.GITHUB_APP_SLUG, 'missing GITHUB_APP_SLUG');
  const installUrl = new URL(`https://github.com/apps/${appSlug}/installations/new`);
  installUrl.searchParams.set('state', state);

  const signedState = await createSignedValue(env.SESSION_SECRET, {
    state,
    exp: Date.now() + 10 * 60 * 1000,
  });

  const headers = new Headers();
  headers.set('Location', installUrl.toString());
  headers.append('Set-Cookie', makeCookie(COOKIE_STATE, signedState, 600));
  return new Response(null, { status: 302, headers });
}

async function authCallback(request, env) {
  const url = new URL(request.url);
  const installationId = Number(must(url.searchParams.get('installation_id'), 'missing installation_id'));
  const state = must(url.searchParams.get('state'), 'missing install state');

  const cookies = getCookieMap(request);
  const rawState = cookies.get(COOKIE_STATE);
  const stateObj = await verifySignedValue(env.SESSION_SECRET, rawState);
  if (!stateObj || stateObj.state !== state || Number(stateObj.exp) < Date.now()) {
    throw new Error('invalid install state');
  }

  const installation = await getInstallation(installationId, env);
  const accountLogin = must(installation?.account?.login, 'missing installation account login');
  return createSessionRedirectResponse(accountLogin, installationId, `${env.FRONTEND_ORIGIN}?post_install=1`, env, true);
}

function getOauthRedirectUri(env) {
  const appBase = must(env.APP_BASE_URL, 'missing APP_BASE_URL');
  return `${appBase.replace(/\/$/, '')}/api/oauth/callback`;
}

async function oauthLogin(env) {
  const state = randomHex(20);
  const clientId = must(env.GITHUB_OAUTH_CLIENT_ID, 'missing GITHUB_OAUTH_CLIENT_ID');
  const oauthUrl = new URL('https://github.com/login/oauth/authorize');
  oauthUrl.searchParams.set('client_id', clientId);
  oauthUrl.searchParams.set('redirect_uri', getOauthRedirectUri(env));
  oauthUrl.searchParams.set('scope', 'read:user read:org');
  oauthUrl.searchParams.set('state', state);

  const signedState = await createSignedValue(env.SESSION_SECRET, {
    state,
    exp: Date.now() + 10 * 60 * 1000,
  });

  const headers = new Headers();
  headers.set('Location', oauthUrl.toString());
  headers.append('Set-Cookie', makeCookie(COOKIE_OAUTH_STATE, signedState, 600));
  return new Response(null, { status: 302, headers });
}

async function oauthCallback(request, env) {
  const url = new URL(request.url);
  const code = must(url.searchParams.get('code'), 'missing oauth code');
  const state = must(url.searchParams.get('state'), 'missing oauth state');

  const cookies = getCookieMap(request);
  const rawState = cookies.get(COOKIE_OAUTH_STATE);
  const stateObj = await verifySignedValue(env.SESSION_SECRET, rawState);
  if (!stateObj || stateObj.state !== state || Number(stateObj.exp) < Date.now()) {
    throw new Error('invalid oauth state');
  }

  const token = await exchangeOauthToken(code, env);
  const me = await githubRequest('https://api.github.com/user', token);
  const oauthSigned = await createSignedValue(env.SESSION_SECRET, {
    token,
    login: me.login,
    exp: Date.now() + 7 * 24 * 60 * 60 * 1000,
  });

  const headers = new Headers();
  headers.set('Location', `${env.FRONTEND_ORIGIN}?oauth_done=1`);
  headers.append('Set-Cookie', clearCookie(COOKIE_OAUTH_STATE));
  headers.append('Set-Cookie', makeCookie(COOKIE_OAUTH_USER, oauthSigned, 7 * 24 * 60 * 60));
  return new Response(null, { status: 302, headers });
}

async function exchangeOauthToken(code, env) {
  const clientId = must(env.GITHUB_OAUTH_CLIENT_ID, 'missing GITHUB_OAUTH_CLIENT_ID');
  const clientSecret = must(env.GITHUB_OAUTH_CLIENT_SECRET, 'missing GITHUB_OAUTH_CLIENT_SECRET');
  const body = new URLSearchParams({
    client_id: clientId,
    client_secret: clientSecret,
    code,
    redirect_uri: getOauthRedirectUri(env),
  });

  const res = await fetch('https://github.com/login/oauth/access_token', {
    method: 'POST',
    headers: {
      Accept: 'application/json',
      'Content-Type': 'application/x-www-form-urlencoded',
      'User-Agent': GITHUB_USER_AGENT,
    },
    body: body.toString(),
  });

  if (!res.ok) {
    const text = await res.text();
    throw new Error(`GitHub OAuth token exchange ${res.status}: ${text}`);
  }

  const jsonBody = await res.json();
  if (jsonBody.error) {
    throw new Error(`GitHub OAuth error: ${jsonBody.error_description || jsonBody.error}`);
  }
  return must(jsonBody.access_token, 'missing oauth access token');
}

async function authResume(installationId, env, request) {
  if (!Number.isFinite(installationId) || installationId <= 0) {
    throw new Error('invalid installation_id');
  }
  const installation = await getInstallation(installationId, env);
  const accountLogin = must(installation?.account?.login, 'missing installation account login');
  const session = await createSignedValue(env.SESSION_SECRET, {
    installation_id: installationId,
    account_login: accountLogin,
    exp: Date.now() + 7 * 24 * 60 * 60 * 1000,
  });

  const headers = new Headers(corsHeaders(env, request));
  headers.set('Content-Type', 'application/json; charset=utf-8');
  headers.append('Set-Cookie', makeCookie(COOKIE_SESSION, session, 7 * 24 * 60 * 60));
  return new Response(JSON.stringify({ ok: true, login: accountLogin, installation_id: installationId }), {
    status: 200,
    headers,
  });
}

async function createSessionRedirectResponse(accountLogin, installationId, location, env, clearStateCookie = false) {
  const session = await createSignedValue(env.SESSION_SECRET, {
    installation_id: installationId,
    account_login: accountLogin,
    exp: Date.now() + 7 * 24 * 60 * 60 * 1000,
  });
  const headers = new Headers();
  headers.set('Location', location);
  if (clearStateCookie) headers.append('Set-Cookie', clearCookie(COOKIE_STATE));
  headers.append('Set-Cookie', makeCookie(COOKIE_SESSION, session, 7 * 24 * 60 * 60));
  return new Response(null, { status: 302, headers });
}

function logout(env, request) {
  const headers = new Headers(corsHeaders(env, request));
  headers.set('Content-Type', 'application/json; charset=utf-8');
  headers.append('Set-Cookie', clearCookie(COOKIE_SESSION));
  headers.append('Set-Cookie', clearCookie(COOKIE_STATE));
  headers.append('Set-Cookie', clearCookie(COOKIE_OAUTH_STATE));
  headers.append('Set-Cookie', clearCookie(COOKIE_OAUTH_USER));
  return new Response(JSON.stringify({ ok: true }), { status: 200, headers });
}

async function requireSession(request, env) {
  const cookies = getCookieMap(request);
  const raw = cookies.get(COOKIE_SESSION);
  const session = await verifySignedValue(env.SESSION_SECRET, raw);
  if (!session || !session.installation_id || !session.account_login || Number(session.exp) < Date.now()) {
    throw new Response('Unauthorized', { status: 401 });
  }
  return session;
}

async function requireOauthUserToken(request, env) {
  const cookies = getCookieMap(request);
  const raw = cookies.get(COOKIE_OAUTH_USER);
  const oauth = await verifySignedValue(env.SESSION_SECRET, raw);
  if (!oauth || !oauth.token || Number(oauth.exp) < Date.now()) {
    throw new Response('OAuth Unauthorized', { status: 401 });
  }
  return oauth.token;
}

async function githubRequest(url, token, init = {}) {
  const res = await fetch(url, {
    ...init,
    headers: {
      Accept: 'application/vnd.github+json',
      Authorization: `Bearer ${token}`,
      'X-GitHub-Api-Version': '2022-11-28',
      'User-Agent': GITHUB_USER_AGENT,
      ...(init.headers || {}),
    },
  });

  if (!res.ok) {
    const text = await res.text();
    throw new Error(`GitHub API ${res.status}: ${text}`);
  }

  if (res.status === 204) return null;

  const ctype = res.headers.get('content-type') || '';
  if (ctype.includes('application/json')) return res.json();
  return res;
}

function pemToArrayBuffer(pem) {
  const clean = String(pem || '')
    .replace(/-----BEGIN [A-Z ]*PRIVATE KEY-----/g, '')
    .replace(/-----END [A-Z ]*PRIVATE KEY-----/g, '')
    .replace(/[^A-Za-z0-9+/=]/g, '');
  return base64ToBytes(clean).buffer;
}

function normalizePrivateKey(input) {
  return String(input || '').replace(/\\n/g, '\n').trim();
}

async function createAppJwt(env) {
  const appId = must(env.GITHUB_APP_ID, 'missing GITHUB_APP_ID');
  const privateKeyPem = normalizePrivateKey(must(env.GITHUB_APP_PRIVATE_KEY, 'missing GITHUB_APP_PRIVATE_KEY'));

  const now = Math.floor(Date.now() / 1000);
  const header = base64urlEncodeText(JSON.stringify({ alg: 'RS256', typ: 'JWT' }));
  const payload = base64urlEncodeText(
    JSON.stringify({
      iat: now - 30,
      exp: now + 540,
      iss: String(appId),
    })
  );

  const toSign = `${header}.${payload}`;
  const key = await crypto.subtle.importKey(
    'pkcs8',
    pemToArrayBuffer(privateKeyPem),
    { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
    false,
    ['sign']
  );
  const signature = await crypto.subtle.sign('RSASSA-PKCS1-v1_5', key, utf8(toSign));
  const sig = base64urlEncodeBytes(new Uint8Array(signature));

  return `${toSign}.${sig}`;
}

async function appRequest(url, env, init = {}) {
  const appJwt = await createAppJwt(env);
  return githubRequest(url, appJwt, init);
}

async function getInstallation(installationId, env) {
  return appRequest(`https://api.github.com/app/installations/${installationId}`, env);
}

async function listUserInstallations(userToken, env) {
  const cfg = getTemplateConfig(env);
  const repoName = cfg.templateRepo;
  const me = await githubRequest('https://api.github.com/user', userToken);
  const userLogin = must(me?.login, 'missing oauth user login');
  const forkCheck = await fetch(`https://api.github.com/repos/${userLogin}/${repoName}`, {
    headers: {
      Accept: 'application/vnd.github+json',
      'X-GitHub-Api-Version': '2022-11-28',
      'User-Agent': GITHUB_USER_AGENT,
    },
  });
  const forkExists = forkCheck.status === 200;

  const list = await githubRequest('https://api.github.com/user/installations?per_page=100', userToken);
  const installations = list?.installations || [];

  const out = [];
  for (const inst of installations) {
    const item = {
      installation_id: inst.id,
      account_login: inst.account?.login || '',
      account_type: inst.account?.type || '',
      repository_selection: inst.repository_selection || 'unknown',
      html_url: `https://github.com/settings/installations/${inst.id}`,
      template_repo_selected: null,
    };

    if (item.repository_selection === 'all') {
      item.template_repo_selected = true;
      out.push(item);
      continue;
    }

    try {
      const repos = await githubRequest(
        `https://api.github.com/user/installations/${inst.id}/repositories?per_page=100`,
        userToken
      );
      const hasRepo = (repos?.repositories || []).some((r) => r?.name === repoName);
      item.template_repo_selected = hasRepo;
    } catch {
      item.template_repo_selected = null;
    }

    out.push(item);
  }

  return { user_login: userLogin, fork_exists: forkExists, installations: out };
}

async function getInstallationAccessToken(installationId, env) {
  const appJwt = await createAppJwt(env);
  const res = await fetch(`https://api.github.com/app/installations/${installationId}/access_tokens`, {
    method: 'POST',
    headers: {
      Accept: 'application/vnd.github+json',
      Authorization: `Bearer ${appJwt}`,
      'X-GitHub-Api-Version': '2022-11-28',
      'User-Agent': GITHUB_USER_AGENT,
    },
  });

  if (!res.ok) {
    const text = await res.text();
    throw new Error(`GitHub App token exchange ${res.status}: ${text}`);
  }

  const jsonBody = await res.json();
  return must(jsonBody.token, 'missing installation token');
}

async function ensureRepoAccess(token, owner, env) {
  const cfg = getTemplateConfig(env);
  const repo = cfg.templateRepo;
  const repoUrl = `https://api.github.com/repos/${owner}/${repo}`;

  const check = await fetch(repoUrl, {
    headers: {
      Accept: 'application/vnd.github+json',
      Authorization: `Bearer ${token}`,
      'X-GitHub-Api-Version': '2022-11-28',
      'User-Agent': GITHUB_USER_AGENT,
    },
  });

  if (check.ok) {
    return { owner, repo, created: false, note: 'repo accessible via GitHub App installation' };
  }

  const text = await check.text();
  throw new Error(
    `repo not accessible for GitHub App installation (${check.status}). ` +
      `Please fork ${cfg.templateOwner}/${cfg.templateRepo} to ${owner}/${repo} and install the GitHub App on that repo. ${text}`
  );
}

async function forkStatus(token, owner, env) {
  const cfg = getTemplateConfig(env);
  const repo = cfg.templateRepo;
  const repoApiUrl = `https://api.github.com/repos/${owner}/${repo}`;

  const existsRes = await fetch(repoApiUrl, {
    headers: {
      Accept: 'application/vnd.github+json',
      'X-GitHub-Api-Version': '2022-11-28',
      'User-Agent': GITHUB_USER_AGENT,
    },
  });
  const exists = existsRes.status === 200;

  const accessRes = await fetch(repoApiUrl, {
    headers: {
      Accept: 'application/vnd.github+json',
      Authorization: `Bearer ${token}`,
      'X-GitHub-Api-Version': '2022-11-28',
      'User-Agent': GITHUB_USER_AGENT,
    },
  });
  const accessible = accessRes.status === 200;

  return {
    owner,
    repo,
    exists,
    accessible,
    fork_url: `https://github.com/${cfg.templateOwner}/${cfg.templateRepo}/fork`,
    actions_url: `https://github.com/${owner}/${repo}/actions`,
  };
}

function toBase64Unicode(input) {
  return bytesToBase64(utf8(input));
}

async function startBuild(token, owner, payload, env) {
  const cfg = getTemplateConfig(env);
  const branch = cfg.branch;
  const repo = cfg.templateRepo;
  const script = must(payload.script, 'missing script');
  const rootCertPem = typeof payload.root_cert_pem === 'string' ? payload.root_cert_pem.trim() : '';
  if (rootCertPem.length > 300000) {
    throw new Error('root certificate payload too large');
  }

  await ensureRepoAccess(token, owner, env);

  const inputs = { script_b64: toBase64Unicode(script) };
  if (rootCertPem) {
    inputs.ca_cert_b64 = toBase64Unicode(`${rootCertPem}\n`);
  }

  const dispatchUrl = `https://api.github.com/repos/${owner}/${repo}/actions/workflows/${WORKFLOW_FILE}/dispatches`;
  const dispatchBody = JSON.stringify({ ref: branch, inputs });

  for (let i = 0; i < 3; i += 1) {
    try {
      await githubRequest(dispatchUrl, token, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: dispatchBody,
      });
      break;
    } catch (err) {
      if (i === 2) throw err;
      await new Promise((r) => setTimeout(r, 3000));
    }
  }

  return { owner, repo, branch };
}

async function latestRun(token, owner, env) {
  const cfg = getTemplateConfig(env);
  const repo = cfg.templateRepo;
  const branch = cfg.branch;

  const runs = await githubRequest(
    `https://api.github.com/repos/${owner}/${repo}/actions/workflows/${WORKFLOW_FILE}/runs?branch=${encodeURIComponent(branch)}&event=workflow_dispatch&per_page=1`,
    token
  );

  const run = runs?.workflow_runs?.[0];
  if (!run) throw new Error('no workflow run found');

  let artifact = null;
  if (run.status === 'completed' && run.conclusion === 'success') {
    const artifacts = await githubRequest(
      `https://api.github.com/repos/${owner}/${repo}/actions/runs/${run.id}/artifacts`,
      token
    );
    artifact = artifacts?.artifacts?.find((a) => a.name === ARTIFACT_NAME) || null;
  }

  return {
    owner,
    repo,
    run: {
      id: run.id,
      run_number: run.run_number,
      status: run.status,
      conclusion: run.conclusion,
      html_url: run.html_url,
    },
    artifact: artifact
      ? {
          id: artifact.id,
          name: artifact.name,
          expired: artifact.expired,
        }
      : null,
  };
}

async function probeWorkflow(token, owner, env) {
  const cfg = getTemplateConfig(env);
  const repo = cfg.templateRepo;
  const workflowUrl = `https://api.github.com/repos/${owner}/${repo}/actions/workflows/${WORKFLOW_FILE}`;
  const actionsUrl = `https://github.com/${owner}/${repo}/actions`;

  const res = await fetch(workflowUrl, {
    headers: {
      Accept: 'application/vnd.github+json',
      Authorization: `Bearer ${token}`,
      'X-GitHub-Api-Version': '2022-11-28',
      'User-Agent': GITHUB_USER_AGENT,
    },
  });

  if (res.ok) {
    return { ok: true, actions_url: actionsUrl };
  }

  if (res.status === 404) {
    return {
      ok: false,
      reason: 'workflow_not_accessible',
      actions_url: actionsUrl,
    };
  }

  const text = await res.text();
  throw new Error(`GitHub API ${res.status}: ${text}`);
}

function tailLines(text, maxLines = 120, maxChars = 12000) {
  const normalized = String(text || '').replace(/\r\n/g, '\n');
  const lines = normalized.split('\n');
  const tail = lines.slice(-maxLines).join('\n');
  if (tail.length <= maxChars) return tail;
  return tail.slice(tail.length - maxChars);
}

async function fetchJobLogTail(logsUrl, token) {
  const ghRes = await fetch(logsUrl, {
    method: 'GET',
    redirect: 'manual',
    headers: {
      Accept: 'application/vnd.github+json',
      Authorization: `Bearer ${token}`,
      'X-GitHub-Api-Version': '2022-11-28',
      'User-Agent': GITHUB_USER_AGENT,
    },
  });

  let rawRes = ghRes;
  if ([301, 302, 307, 308].includes(ghRes.status)) {
    const location = ghRes.headers.get('location');
    if (!location) throw new Error('job logs redirect missing location header');
    rawRes = await fetch(location, { method: 'GET' });
  }

  if (!rawRes.ok) {
    const text = await rawRes.text();
    throw new Error(`job logs download failed ${rawRes.status}: ${text}`);
  }

  const text = await rawRes.text();
  return tailLines(text);
}

async function buildLogs(token, owner, runId, env) {
  const cfg = getTemplateConfig(env);
  const repo = cfg.templateRepo;
  const jobs = await githubRequest(
    `https://api.github.com/repos/${owner}/${repo}/actions/runs/${runId}/jobs?per_page=100`,
    token
  );

  const nonSuccess = new Set(['failure', 'cancelled', 'timed_out', 'action_required', 'startup_failure']);
  const failedJobs = (jobs?.jobs || []).filter((j) => nonSuccess.has(String(j.conclusion || '').toLowerCase()));
  const targetJobs = failedJobs.length > 0 ? failedJobs : (jobs?.jobs || []).slice(-1);

  const logs = [];
  for (const job of targetJobs.slice(0, 2)) {
    let logTail = '';
    try {
      logTail = await fetchJobLogTail(job.logs_url, token);
    } catch (err) {
      logTail = `Unable to fetch job log: ${err instanceof Error ? err.message : String(err)}`;
    }

    logs.push({
      job_id: job.id,
      name: job.name,
      conclusion: job.conclusion,
      html_url: job.html_url,
      log_tail: logTail,
    });
  }

  return { run_id: runId, owner, repo, logs };
}

async function downloadArtifact(token, owner, runId, cleanup, env, request) {
  const cfg = getTemplateConfig(env);
  const repo = cfg.templateRepo;
  const artifacts = await githubRequest(
    `https://api.github.com/repos/${owner}/${repo}/actions/runs/${runId}/artifacts`,
    token
  );

  const artifact = artifacts?.artifacts?.find((a) => a.name === ARTIFACT_NAME);
  if (!artifact) {
    throw new Error('artifact not found');
  }

  const ghZipRes = await fetch(artifact.archive_download_url, {
    method: 'GET',
    redirect: 'manual',
    headers: {
      Accept: 'application/vnd.github+json',
      Authorization: `Bearer ${token}`,
      'X-GitHub-Api-Version': '2022-11-28',
      'User-Agent': GITHUB_USER_AGENT,
    },
  });

  let zipRes = ghZipRes;
  if ([301, 302, 307, 308].includes(ghZipRes.status)) {
    const location = ghZipRes.headers.get('location');
    if (!location) {
      throw new Error('artifact redirect missing location header');
    }
    zipRes = await fetch(location, { method: 'GET' });
  }

  if (!zipRes.ok) {
    const text = await zipRes.text();
    throw new Error(`artifact download failed ${zipRes.status}: ${text}`);
  }

  const headers = new Headers(corsHeaders(env, request));
  headers.set('Content-Type', 'application/zip');
  headers.set('Content-Disposition', `attachment; filename="ipxe-efi-run-${runId}.zip"`);

  if (cleanup) {
    await githubRequest(
      `https://api.github.com/repos/${owner}/${repo}/actions/artifacts/${artifact.id}`,
      token,
      { method: 'DELETE' }
    );
  }

  return new Response(zipRes.body, { status: 200, headers });
}

async function cleanupArtifact(token, owner, runId, env) {
  const cfg = getTemplateConfig(env);
  const repo = cfg.templateRepo;

  const artifacts = await githubRequest(
    `https://api.github.com/repos/${owner}/${repo}/actions/runs/${runId}/artifacts`,
    token
  );
  const artifact = artifacts?.artifacts?.find((a) => a.name === ARTIFACT_NAME);
  if (!artifact) {
    return { deleted: false };
  }

  await githubRequest(
    `https://api.github.com/repos/${owner}/${repo}/actions/artifacts/${artifact.id}`,
    token,
    { method: 'DELETE' }
  );
  return { deleted: true };
}

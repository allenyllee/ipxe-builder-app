const COOKIE_SESSION = 'ipxe_sess';
const COOKIE_STATE = 'ipxe_oauth_state';
const WORKFLOW_FILE = 'build-ipxe-efi.yml';
const ARTIFACT_NAME = 'ipxe-efi';

export default {
  async fetch(request, env, ctx) {
    try {
      return await handleRequest(request, env, ctx);
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
    return json(getTemplateConfig(env), {}, env, request);
  }

  if (url.pathname === '/api/auth/login' && request.method === 'GET') {
    return authLogin(env);
  }

  if (url.pathname === '/api/auth/callback' && request.method === 'GET') {
    return authCallback(request, env);
  }

  if (url.pathname === '/api/auth/logout' && request.method === 'POST') {
    assertFrontendOrigin(request, env);
    return logout(env, request);
  }

  if (url.pathname === '/api/me' && request.method === 'GET') {
    assertFrontendOrigin(request, env);
    const token = await requireTokenFromSession(request, env);
    const user = await githubRequest('https://api.github.com/user', token);
    return json({ login: user.login, id: user.id }, {}, env, request);
  }

  if (url.pathname === '/api/fork/ensure' && request.method === 'POST') {
    assertFrontendOrigin(request, env);
    const token = await requireTokenFromSession(request, env);
    const result = await ensureFork(token, env);
    return json(result, {}, env, request);
  }

  if (url.pathname === '/api/build/start' && request.method === 'POST') {
    assertFrontendOrigin(request, env);
    const token = await requireTokenFromSession(request, env);
    const payload = await parseJson(request);
    const result = await startBuild(token, payload, env);
    return json(result, {}, env, request);
  }

  if (url.pathname === '/api/build/latest' && request.method === 'GET') {
    assertFrontendOrigin(request, env);
    const token = await requireTokenFromSession(request, env);
    const result = await latestRun(token, env);
    return json(result, {}, env, request);
  }

  if (url.pathname === '/api/build/download' && request.method === 'GET') {
    assertFrontendOrigin(request, env);
    const token = await requireTokenFromSession(request, env);
    const runId = Number(must(url.searchParams.get('run_id'), 'missing run_id'));
    const cleanup = url.searchParams.get('cleanup') === '1';
    return downloadArtifact(token, runId, cleanup, env, request);
  }

  return json({ error: 'Not found' }, { status: 404 }, env, request);
}

function assertFrontendOrigin(request, env) {
  const origin = request.headers.get('Origin');
  if (!origin || origin !== env.FRONTEND_ORIGIN) {
    throw new Error('Origin not allowed');
  }
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
  const redirectUri = `${env.APP_BASE_URL}/api/auth/callback`;
  const authUrl = new URL('https://github.com/login/oauth/authorize');
  authUrl.searchParams.set('client_id', env.GITHUB_CLIENT_ID);
  authUrl.searchParams.set('redirect_uri', redirectUri);
  authUrl.searchParams.set('state', state);
  authUrl.searchParams.set('scope', 'repo workflow read:user');

  const signedState = await createSignedValue(env.SESSION_SECRET, {
    state,
    exp: Date.now() + 10 * 60 * 1000,
  });

  const headers = new Headers();
  headers.set('Location', authUrl.toString());
  headers.append('Set-Cookie', makeCookie(COOKIE_STATE, signedState, 600));
  return new Response(null, { status: 302, headers });
}

async function authCallback(request, env) {
  const url = new URL(request.url);
  const code = must(url.searchParams.get('code'), 'missing oauth code');
  const state = must(url.searchParams.get('state'), 'missing oauth state');

  const cookies = getCookieMap(request);
  const rawState = cookies.get(COOKIE_STATE);
  const stateObj = await verifySignedValue(env.SESSION_SECRET, rawState);
  if (!stateObj || stateObj.state !== state || Number(stateObj.exp) < Date.now()) {
    throw new Error('invalid oauth state');
  }

  const tokenRes = await fetch('https://github.com/login/oauth/access_token', {
    method: 'POST',
    headers: {
      Accept: 'application/json',
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      client_id: env.GITHUB_CLIENT_ID,
      client_secret: env.GITHUB_CLIENT_SECRET,
      code,
      redirect_uri: `${env.APP_BASE_URL}/api/auth/callback`,
      state,
    }),
  });

  if (!tokenRes.ok) {
    throw new Error(`oauth exchange failed: ${tokenRes.status}`);
  }

  const tokenJson = await tokenRes.json();
  const accessToken = must(tokenJson.access_token, 'failed to get access token');

  const session = await createSignedValue(env.SESSION_SECRET, {
    token: accessToken,
    exp: Date.now() + 7 * 24 * 60 * 60 * 1000,
  });

  const headers = new Headers();
  headers.set('Location', env.FRONTEND_ORIGIN);
  headers.append('Set-Cookie', clearCookie(COOKIE_STATE));
  headers.append('Set-Cookie', makeCookie(COOKIE_SESSION, session, 7 * 24 * 60 * 60));
  return new Response(null, { status: 302, headers });
}

function logout(env, request) {
  const headers = new Headers(corsHeaders(env, request));
  headers.set('Content-Type', 'application/json; charset=utf-8');
  headers.append('Set-Cookie', clearCookie(COOKIE_SESSION));
  headers.append('Set-Cookie', clearCookie(COOKIE_STATE));
  return new Response(JSON.stringify({ ok: true }), { status: 200, headers });
}

async function requireTokenFromSession(request, env) {
  const cookies = getCookieMap(request);
  const raw = cookies.get(COOKIE_SESSION);
  const session = await verifySignedValue(env.SESSION_SECRET, raw);
  if (!session || !session.token || Number(session.exp) < Date.now()) {
    throw new Response('Unauthorized', { status: 401 });
  }
  return session.token;
}

async function githubRequest(url, token, init = {}) {
  const res = await fetch(url, {
    ...init,
    headers: {
      Accept: 'application/vnd.github+json',
      Authorization: `Bearer ${token}`,
      'X-GitHub-Api-Version': '2022-11-28',
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

async function getViewer(token) {
  return githubRequest('https://api.github.com/user', token);
}

async function ensureFork(token, env) {
  const cfg = getTemplateConfig(env);
  const templateOwner = cfg.templateOwner;
  const templateRepo = cfg.templateRepo;

  const viewer = await getViewer(token);
  const repoUrl = `https://api.github.com/repos/${viewer.login}/${templateRepo}`;
  const repoCheck = await fetch(repoUrl, {
    headers: {
      Accept: 'application/vnd.github+json',
      Authorization: `Bearer ${token}`,
      'X-GitHub-Api-Version': '2022-11-28',
    },
  });
  if (repoCheck.ok) {
    return { owner: viewer.login, repo: templateRepo, created: false };
  }
  if (repoCheck.status === 404) {
    await githubRequest(`https://api.github.com/repos/${templateOwner}/${templateRepo}/forks`, token, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ default_branch_only: true }),
    });
    return { owner: viewer.login, repo: templateRepo, created: true };
  }
  const text = await repoCheck.text();
  throw new Error(`failed to check fork repo: ${repoCheck.status} ${text}`);
}

function toBase64Unicode(input) {
  return bytesToBase64(utf8(input));
}

async function startBuild(token, payload, env) {
  const cfg = getTemplateConfig(env);
  const branch = cfg.branch;
  const script = must(payload.script, 'missing script');

  const ensured = await ensureFork(token, env);
  const dispatchUrl = `https://api.github.com/repos/${ensured.owner}/${ensured.repo}/actions/workflows/${WORKFLOW_FILE}/dispatches`;
  const dispatchBody = JSON.stringify({
    ref: branch,
    inputs: {
      script_b64: toBase64Unicode(script),
    },
  });
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

  return { owner: ensured.owner, repo: ensured.repo, branch };
}

async function latestRun(token, env) {
  const cfg = getTemplateConfig(env);
  const templateRepo = cfg.templateRepo;
  const branch = cfg.branch;
  const viewer = await getViewer(token);

  const runs = await githubRequest(
    `https://api.github.com/repos/${viewer.login}/${templateRepo}/actions/workflows/${WORKFLOW_FILE}/runs?branch=${encodeURIComponent(branch)}&event=workflow_dispatch&per_page=1`,
    token
  );

  const run = runs?.workflow_runs?.[0];
  if (!run) throw new Error('no workflow run found');

  let artifact = null;
  if (run.status === 'completed' && run.conclusion === 'success') {
    const artifacts = await githubRequest(
      `https://api.github.com/repos/${viewer.login}/${templateRepo}/actions/runs/${run.id}/artifacts`,
      token
    );
    artifact = artifacts?.artifacts?.find((a) => a.name === ARTIFACT_NAME) || null;
  }

  return {
    owner: viewer.login,
    repo: templateRepo,
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

async function downloadArtifact(token, runId, cleanup, env, request) {
  const cfg = getTemplateConfig(env);
  const templateRepo = cfg.templateRepo;
  const viewer = await getViewer(token);
  const artifacts = await githubRequest(
    `https://api.github.com/repos/${viewer.login}/${templateRepo}/actions/runs/${runId}/artifacts`,
    token
  );

  const artifact = artifacts?.artifacts?.find((a) => a.name === ARTIFACT_NAME);
  if (!artifact) {
    throw new Error('artifact not found');
  }

  const zipRes = await githubRequest(artifact.archive_download_url, token);
  const headers = new Headers(corsHeaders(env, request));
  headers.set('Content-Type', 'application/zip');
  headers.set('Content-Disposition', `attachment; filename="ipxe-efi-run-${runId}.zip"`);

  if (cleanup) {
    await githubRequest(
      `https://api.github.com/repos/${viewer.login}/${templateRepo}/actions/artifacts/${artifact.id}`,
      token,
      { method: 'DELETE' }
    );
  }

  return new Response(zipRes.body, { status: 200, headers });
}

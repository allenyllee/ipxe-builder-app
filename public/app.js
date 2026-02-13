const el = {
  apiBase: document.getElementById('apiBase'),
  loginBtn: document.getElementById('loginBtn'),
  logoutBtn: document.getElementById('logoutBtn'),
  userInfo: document.getElementById('userInfo'),
  templateInfo: document.getElementById('templateInfo'),
  script: document.getElementById('script'),
  forkBtn: document.getElementById('forkBtn'),
  buildBtn: document.getElementById('buildBtn'),
  checkBtn: document.getElementById('checkBtn'),
  log: document.getElementById('log'),
};

const STORAGE_KEY = 'ipxe-builder-config-v3';

function appendLog(msg) {
  const ts = new Date().toISOString().replace('T', ' ').replace('Z', '');
  el.log.textContent = `[${ts}] ${msg}\n${el.log.textContent}`;
}

function apiBase() {
  return el.apiBase.value.trim().replace(/\/$/, '');
}

function readConfig() {
  return {
    apiBase: apiBase(),
    script: el.script.value,
  };
}

function saveConfig(cfg) {
  localStorage.setItem(
    STORAGE_KEY,
    JSON.stringify({
      apiBase: cfg.apiBase,
    })
  );
}

function restoreConfig() {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return;
    const cfg = JSON.parse(raw);
    if (cfg.apiBase) el.apiBase.value = cfg.apiBase;
  } catch {
    // ignore invalid localStorage content
  }
}

function requireFields(cfg, needsScript = true) {
  if (!cfg.apiBase) {
    throw new Error('請先填入 Worker API Base URL。');
  }
  if (needsScript && !cfg.script.trim()) {
    throw new Error('請填入 iPXE script。');
  }
}

async function apiRequest(path, init = {}) {
  const base = apiBase();
  if (!base) throw new Error('Worker API Base URL 尚未設定。');

  const res = await fetch(`${base}${path}`, {
    ...init,
    credentials: 'include',
    headers: {
      'Content-Type': 'application/json',
      ...(init.headers || {}),
    },
  });

  if (res.status === 401) {
    throw new Error('尚未登入 GitHub，請先點 GitHub Login。');
  }

  if (!res.ok) {
    const text = await res.text();
    throw new Error(`API error ${res.status}: ${text}`);
  }

  const ctype = res.headers.get('content-type') || '';
  if (ctype.includes('application/json')) {
    return res.json();
  }

  return res;
}

async function refreshTemplateInfo() {
  try {
    const cfg = await apiRequest('/api/config');
    el.templateInfo.textContent = `Template: ${cfg.templateOwner}/${cfg.templateRepo} @ ${cfg.branch} (固定)`;
  } catch (err) {
    el.templateInfo.textContent = 'Template: 載入失敗';
    appendLog(err instanceof Error ? err.message : String(err));
  }
}

async function refreshUser() {
  try {
    const me = await apiRequest('/api/me');
    el.userInfo.textContent = `已登入：${me.login}`;
  } catch {
    el.userInfo.textContent = '尚未登入。';
  }
}

async function ensureFork() {
  const cfg = readConfig();
  requireFields({ ...cfg, script: '#!ipxe' }, false);
  saveConfig(cfg);

  appendLog('確認使用者 fork repo...');
  const result = await apiRequest('/api/fork/ensure', {
    method: 'POST',
    body: JSON.stringify({}),
  });

  appendLog(`Fork ready: ${result.owner}/${result.repo} (created=${result.created})`);
}

async function dispatchBuild() {
  const cfg = readConfig();
  requireFields(cfg, true);
  saveConfig(cfg);

  appendLog('觸發 build workflow...');
  const result = await apiRequest('/api/build/start', {
    method: 'POST',
    body: JSON.stringify({
      script: cfg.script,
    }),
  });

  appendLog(`Workflow dispatched to ${result.owner}/${result.repo}@${result.branch}`);
  appendLog('等待約 20-60 秒，系統會自動輪詢並嘗試下載。');
}

async function checkLatestRun() {
  const cfg = readConfig();
  requireFields({ ...cfg, script: '#!ipxe' }, false);

  appendLog('查詢最新 workflow run...');
  const data = await apiRequest('/api/build/latest');
  const run = data.run;
  appendLog(`Run #${run.run_number}: status=${run.status}, conclusion=${run.conclusion || 'N/A'}`);
  appendLog(`Run URL: ${run.html_url}`);

  if (run.status === 'completed' && run.conclusion === 'success' && data.artifact?.id) {
    appendLog('偵測到成功 artifact，開始自動下載...');
    await downloadArtifact(run.id, true);
  }
}

async function downloadArtifact(runId, cleanup = true) {
  const q = new URLSearchParams({
    run_id: String(runId),
    cleanup: cleanup ? '1' : '0',
  });

  const res = await apiRequest(`/api/build/download?${q.toString()}`, {
    method: 'GET',
    headers: {},
  });

  const blob = await res.blob();
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;

  const disposition = res.headers.get('content-disposition') || '';
  const m = disposition.match(/filename="([^"]+)"/);
  a.download = m ? m[1] : 'ipxe-efi.zip';

  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);

  appendLog('下載已觸發。artifact 已由後端清除。');
}

async function pollUntilDone(maxAttempts = 15, intervalMs = 5000) {
  for (let i = 1; i <= maxAttempts; i += 1) {
    await new Promise((r) => setTimeout(r, intervalMs));
    appendLog(`輪詢進度 ${i}/${maxAttempts}...`);

    try {
      const data = await apiRequest('/api/build/latest');
      const run = data.run;
      appendLog(`Run #${run.run_number}: status=${run.status}, conclusion=${run.conclusion || 'N/A'}`);

      if (run.status === 'completed') {
        if (run.conclusion === 'success' && data.artifact?.id) {
          await downloadArtifact(run.id, true);
        } else {
          appendLog('Run 已完成但非 success，請開 Run URL 查看詳細錯誤。');
        }
        return;
      }
    } catch (err) {
      appendLog(err instanceof Error ? err.message : String(err));
    }
  }

  appendLog('輪詢超時，請稍後按 Check Latest Run。');
}

el.loginBtn.addEventListener('click', () => {
  const base = apiBase();
  if (!base) {
    appendLog('請先填 Worker API Base URL。');
    return;
  }
  const cfg = readConfig();
  saveConfig(cfg);
  window.location.href = `${base}/api/auth/login`;
});

el.logoutBtn.addEventListener('click', async () => {
  try {
    await apiRequest('/api/auth/logout', { method: 'POST' });
    appendLog('已登出。');
    await refreshUser();
  } catch (err) {
    appendLog(err instanceof Error ? err.message : String(err));
  }
});

el.forkBtn.addEventListener('click', async () => {
  el.forkBtn.disabled = true;
  try {
    await ensureFork();
  } catch (err) {
    appendLog(err instanceof Error ? err.message : String(err));
  } finally {
    el.forkBtn.disabled = false;
  }
});

el.buildBtn.addEventListener('click', async () => {
  el.buildBtn.disabled = true;
  try {
    await dispatchBuild();
    await pollUntilDone();
  } catch (err) {
    appendLog(err instanceof Error ? err.message : String(err));
  } finally {
    el.buildBtn.disabled = false;
  }
});

el.checkBtn.addEventListener('click', async () => {
  el.checkBtn.disabled = true;
  try {
    await checkLatestRun();
  } catch (err) {
    appendLog(err instanceof Error ? err.message : String(err));
  } finally {
    el.checkBtn.disabled = false;
  }
});

restoreConfig();
refreshTemplateInfo();
refreshUser();

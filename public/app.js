const el = {
  apiBase: document.getElementById('apiBase'),
  loginBtn: document.getElementById('loginBtn'),
  switchInstallBtn: document.getElementById('switchInstallBtn'),
  logoutBtn: document.getElementById('logoutBtn'),
  clearCacheBtn: document.getElementById('clearCacheBtn'),
  userInfo: document.getElementById('userInfo'),
  templateInfo: document.getElementById('templateInfo'),
  setupTips: document.getElementById('setupTips'),
  script: document.getElementById('script'),
  rootCertFile: document.getElementById('rootCertFile'),
  rootCertInfo: document.getElementById('rootCertInfo'),
  downloadInfo: document.getElementById('downloadInfo'),
  forkBtn: document.getElementById('forkBtn'),
  buildBtn: document.getElementById('buildBtn'),
  checkBtn: document.getElementById('checkBtn'),
  cleanupBtn: document.getElementById('cleanupBtn'),
  log: document.getElementById('log'),
  setupOverlay: document.getElementById('setupOverlay'),
  setupOverlayStatus: document.getElementById('setupOverlayStatus'),
  setupOverlayActions: document.getElementById('setupOverlayActions'),
  setupOverlayClose: document.getElementById('setupOverlayClose'),
};

const STORAGE_KEY = 'ipxe-builder-config-v3';
const INSTALLATION_CACHE_KEY = 'ipxe-builder-installation-id-v1';
let rootCertPem = '';
let rootCertFileCount = 0;
let cleanupTimer = null;
let lastArtifactRunId = null;
let templateConfig = null;
let setupWizardRunning = false;
let setupWizardAbort = false;
let oauthInstallations = [];
let oauthInstallationsError = '';
let oauthAuthorized = false;
let oauthUserLogin = '';
let oauthForkExists = false;

function appendLog(msg) {
  const ts = new Date().toISOString().replace('T', ' ').replace('Z', '');
  el.log.textContent = `[${ts}] ${msg}\n${el.log.textContent}`;
}

function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

function apiBase() {
  return el.apiBase.value.trim().replace(/\/$/, '');
}

function readConfig() {
  return {
    apiBase: apiBase(),
    script: el.script.value,
    rootCertPem,
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

function cacheInstallationId(id) {
  if (!id) return;
  localStorage.setItem(INSTALLATION_CACHE_KEY, String(id));
}

function getCachedInstallationId() {
  const raw = localStorage.getItem(INSTALLATION_CACHE_KEY) || '';
  const id = Number(raw);
  if (!Number.isFinite(id) || id <= 0) return null;
  return id;
}

function clearCachedInstallationId() {
  localStorage.removeItem(INSTALLATION_CACHE_KEY);
}

function clearAllLocalCache() {
  localStorage.removeItem(STORAGE_KEY);
  clearCachedInstallationId();
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
    throw new Error('尚未登入 GitHub App，請先點 GitHub App Login/Install。');
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

async function rawApiRequest(path, init = {}) {
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
  return res;
}

async function apiRequestWithRetry(path, init = {}, attempts = 3, delayMs = 500) {
  let lastErr;
  for (let i = 1; i <= attempts; i += 1) {
    try {
      return await apiRequest(path, init);
    } catch (err) {
      lastErr = err;
      if (i === attempts) break;
      await sleep(delayMs);
    }
  }
  throw lastErr;
}

async function refreshTemplateInfo() {
  try {
    const cfg = await apiRequest('/api/config');
    templateConfig = cfg;
    const authText = cfg.auth_mode === 'github_app' ? 'Auth: GitHub App' : 'Auth: Unknown';
    el.templateInfo.textContent =
      `Template: ${cfg.templateOwner}/${cfg.templateRepo} @ ${cfg.branch} (固定) | ${authText}`;
  } catch (err) {
    el.templateInfo.textContent = 'Template: 載入失敗';
    appendLog(err instanceof Error ? err.message : String(err));
  }
}

function getForkUrl() {
  if (!templateConfig) return '';
  return `https://github.com/${templateConfig.templateOwner}/${templateConfig.templateRepo}/fork`;
}

function getInstallUrl() {
  return `${apiBase()}/api/auth/login`;
}

function getOAuthLoginUrl() {
  return `${apiBase()}/api/oauth/login`;
}

function showSetupTips(reason = '', extraLinks = []) {
  const forkUrl = getForkUrl();
  const installUrl = getInstallUrl();
  if (!forkUrl || !apiBase()) return;
  const tip = reason || '尚未完成可用 repo 授權，請先 fork，再安裝 GitHub App 到 fork repo。';
  const extra = Array.isArray(extraLinks)
    ? extraLinks
        .filter((x) => x && x.href && x.label)
        .map(
          (x) =>
            `<a class="status-link ${x.secondary ? 'secondary' : ''}" href="${x.href}" target="_blank" rel="noopener noreferrer">${x.label}</a>`
        )
        .join('')
    : '';
  el.setupTips.hidden = false;
  el.setupTips.innerHTML = `${tip}
  <div class="status-links">
    <a class="status-link secondary" href="${forkUrl}" target="_blank" rel="noopener noreferrer">1) 去 Fork Template</a>
    <a class="status-link" href="${installUrl}">2) 重新 Install App</a>
    ${extra}
  </div>`;
}

function hideSetupTips() {
  el.setupTips.hidden = true;
  el.setupTips.textContent = '';
}

function setOverlayVisible(visible) {
  el.setupOverlay.hidden = !visible;
}

function setOverlay(statusText, actions = []) {
  el.setupOverlayStatus.textContent = statusText;
  el.setupOverlayActions.innerHTML = '';
  for (const action of actions) {
    if (!action || !action.label) continue;
    if (action.type === 'button') {
      const b = document.createElement('button');
      b.className = action.secondary ? 'secondary' : '';
      b.textContent = action.label;
      b.addEventListener('click', () => {
        if (typeof action.onClick === 'function') action.onClick();
      });
      el.setupOverlayActions.appendChild(b);
      continue;
    }
    if (!action.href) continue;
    const a = document.createElement('a');
    a.className = `status-link ${action.secondary ? 'secondary' : ''}`.trim();
    a.href = action.href;
    if (!action.sameTab) {
      a.target = '_blank';
      a.rel = 'noopener noreferrer';
    }
    a.textContent = action.label;
    el.setupOverlayActions.appendChild(a);
  }
}

function clearPostInstallFlagFromUrl() {
  const params = new URLSearchParams(window.location.search);
  if (!params.has('post_install') && !params.has('oauth_done')) return;
  params.delete('post_install');
  params.delete('oauth_done');
  const nextUrl = `${window.location.pathname}${params.toString() ? `?${params.toString()}` : ''}${window.location.hash}`;
  window.history.replaceState({}, '', nextUrl);
}

function isUnauthorizedError(err) {
  const msg = err instanceof Error ? err.message : String(err);
  return msg.includes('API error 401') || msg.includes('尚未登入 GitHub App');
}

async function tryApi(path, init = {}) {
  try {
    const data = await apiRequest(path, init);
    return { ok: true, data };
  } catch (err) {
    return { ok: false, err };
  }
}

async function runSetupWizard() {
  if (setupWizardRunning) return;
  setupWizardRunning = true;
  setupWizardAbort = false;
  oauthInstallations = [];
  oauthInstallationsError = '';
  oauthAuthorized = false;
  oauthUserLogin = '';
  oauthForkExists = false;
  setOverlayVisible(true);

  const installUrl = getInstallUrl();
  const resumed = await tryResumeFromCachedInstallation();
  if (resumed) {
    appendLog('已恢復登入，繼續檢查 fork / Actions 狀態。');
  }

  try {
    while (true) {
      if (setupWizardAbort) return;
      const me = await tryApi('/api/me');
      if (me.ok) {
        await refreshUser();
        break;
      }

      await loadOauthInstallations({ silent: true });
      if (!oauthAuthorized) {
        setOverlay('Step 1/4: 先完成 OAuth 使用者登入。登入後會自動回到此頁繼續檢查。', [
          { label: 'OAuth 使用者登入', href: getOAuthLoginUrl(), sameTab: true },
        ]);
        await sleep(1500);
        continue;
      }

      if (oauthInstallations.length > 0) {
        const actions = [
          {
            type: 'button',
            label: '重新整理安裝清單',
            secondary: true,
            onClick: async () => {
              await loadOauthInstallations();
            },
          },
          { label: '前往 GitHub App Install', href: installUrl },
        ];
        for (const inst of oauthInstallations) {
          actions.push({
            type: 'button',
            label: `使用 #${inst.installation_id} (${inst.account_login})`,
            onClick: async () => {
              const ok = await resumeWithInstallationId(inst.installation_id);
              if (!ok) appendLog(`installation #${inst.installation_id} 恢復失敗。`);
            },
          });
        }
        setOverlay('Step 2/4: 已找到 installations，請選擇一個恢復登入；若都不合適可改走 App Install。', actions);
        await sleep(2000);
        continue;
      }

      if (!oauthForkExists) {
        setOverlay(`Step 2/4: ${oauthUserLogin || '你的帳號'} 尚未 fork template，請先 fork。`, [
          ...(getForkUrl() ? [{ label: '前往 Fork 頁', href: getForkUrl(), secondary: true }] : []),
          {
            type: 'button',
            label: '我已完成 Fork，重新檢查',
            onClick: async () => {
              await loadOauthInstallations();
            },
          },
        ]);
        await sleep(2000);
        continue;
      }

      setOverlay('Step 3/4: 已偵測到你有 fork，請安裝 GitHub App 到該 fork（安裝後自動回來）。', [
        ...(getForkUrl() ? [{ label: '重新 Fork 到其他組織', href: getForkUrl(), secondary: true }] : []),
        { label: '前往 GitHub App Install', href: installUrl },
        {
          type: 'button',
          label: '已安裝但沒回來？快速恢復登入',
          secondary: true,
          onClick: async () => {
            const ok = await tryResumeFromCachedInstallation();
            if (!ok) appendLog('快速恢復失敗：找不到可用安裝快取，請改用 installation 清單。');
          },
        },
      ]);
      await sleep(2000);
    }

    while (true) {
      if (setupWizardAbort) return;
      const status = await tryApi('/api/fork/status');
      if (!status.ok) {
        if (isUnauthorizedError(status.err)) {
          setOverlay('登入已失效，請重新安裝 GitHub App。', [{ label: '重新 Install', href: installUrl }]);
          await sleep(3000);
          continue;
        }
        setOverlay(`檢查 fork 狀態失敗：${status.err instanceof Error ? status.err.message : String(status.err)}`);
        await sleep(3000);
        continue;
      }

      const data = status.data;
      if (!data.exists) {
        setOverlay('正在等待 fork 完成...', [{ label: '前往 Fork 頁', href: data.fork_url, secondary: true }]);
        await sleep(3000);
        continue;
      }

      if (!data.accessible) {
        setOverlay('fork 已存在，但 GitHub App 尚未安裝到該 fork。', [{ label: '安裝 GitHub App 到 fork', href: installUrl }]);
        await sleep(3000);
        continue;
      }

      appendLog(`Repo ready: ${data.owner}/${data.repo} (fork exists + app accessible)`);
      hideSetupTips();
      break;
    }

    while (true) {
      if (setupWizardAbort) return;
      const probe = await tryApi('/api/build/probe');
      if (!probe.ok) {
        setOverlay(`檢查 Actions 狀態失敗：${probe.err instanceof Error ? probe.err.message : String(probe.err)}`);
        await sleep(3000);
        continue;
      }

      if (probe.data.ok) {
        setOverlay('Step 4/4: 檢查完成，fork / App / Actions 都已就緒。');
        appendLog('Setup 檢查完成：可以直接 Build。');
        await sleep(700);
        setOverlayVisible(false);
        clearPostInstallFlagFromUrl();
        return;
      }

      if (probe.data.reason === 'workflow_not_accessible') {
        setOverlay('請先在 fork repo 的 Actions 頁啟用 workflows（此頁會自動重試檢查）。', [
          { label: '前往 Actions 頁', href: probe.data.actions_url },
        ]);
        await sleep(3000);
        continue;
      }

      setOverlay('Actions 狀態未知，請稍後重試。');
      await sleep(3000);
    }
  } finally {
    setupWizardRunning = false;
    setupWizardAbort = false;
  }
}

async function refreshUser() {
  try {
    const me = await apiRequest('/api/me');
    el.userInfo.textContent = `已登入：${me.login}`;
    if (me.installation_id) {
      cacheInstallationId(me.installation_id);
    }
    hideSetupTips();
  } catch {
    el.userInfo.textContent = '尚未登入。';
  }
}

async function tryResumeFromCachedInstallation() {
  const installationId = getCachedInstallationId();
  if (!installationId) return false;

  const res = await tryApi('/api/auth/resume', {
    method: 'POST',
    body: JSON.stringify({ installation_id: installationId }),
  });
  if (!res.ok) {
    clearCachedInstallationId();
    return false;
  }

  appendLog(`已使用上次 installation (#${installationId}) 快速恢復登入。`);
  await refreshUser();
  return true;
}

async function resumeWithInstallationId(installationId) {
  const res = await tryApi('/api/auth/resume', {
    method: 'POST',
    body: JSON.stringify({ installation_id: installationId }),
  });
  if (!res.ok) return false;
  cacheInstallationId(installationId);
  appendLog(`已使用 installation #${installationId} 建立 session。`);
  await refreshUser();
  return true;
}

async function loadOauthInstallations({ silent = false } = {}) {
  oauthInstallationsError = '';
  if (!silent) appendLog('正在查詢 OAuth 使用者可見的 GitHub App installations...');
  try {
    const res = await rawApiRequest('/api/oauth/installations', { method: 'GET' });
    if (res.status === 401) {
      oauthAuthorized = false;
      oauthUserLogin = '';
      oauthForkExists = false;
      oauthInstallations = [];
      oauthInstallationsError = 'oauth_unauthorized';
      if (!silent) appendLog('尚未完成 OAuth 使用者登入，請先點「OAuth 使用者登入（列出安裝）」。');
      return false;
    }
    if (!res.ok) {
      const text = await res.text();
      oauthAuthorized = false;
      oauthUserLogin = '';
      oauthForkExists = false;
      oauthInstallations = [];
      oauthInstallationsError = text || `HTTP ${res.status}`;
      if (!silent) appendLog(`列出 installations 失敗：${oauthInstallationsError}`);
      return false;
    }

    const data = await res.json();
    oauthAuthorized = true;
    oauthUserLogin = data.user_login || '';
    oauthForkExists = !!data.fork_exists;
    oauthInstallations = Array.isArray(data.installations) ? data.installations : [];
    if (oauthInstallations.length === 0) {
      if (!silent) appendLog('查無可用 installations。');
      return true;
    }

    if (!silent) {
      appendLog(`找到 ${oauthInstallations.length} 個 installation：`);
      for (const inst of oauthInstallations) {
        appendLog(
          `- #${inst.installation_id} ${inst.account_login} (${inst.repository_selection}), template_repo_selected=${inst.template_repo_selected}`
        );
      }
    }
    return true;
  } catch (err) {
    oauthAuthorized = false;
    oauthUserLogin = '';
    oauthForkExists = false;
    oauthInstallations = [];
    oauthInstallationsError = err instanceof Error ? err.message : String(err);
    if (!silent) appendLog(`列出 installations 失敗：${oauthInstallationsError}`);
    return false;
  }
}

async function openSwitchInstallationOverlay() {
  if (setupWizardRunning) return;
  setOverlayVisible(true);
  setOverlay('載入 installations 清單中...');

  const loaded = await loadOauthInstallations();
  if (!loaded && oauthInstallationsError === 'oauth_unauthorized') {
    setOverlay('請先完成 OAuth 使用者登入，才能切換 installation。', [
      { label: 'OAuth 使用者登入', href: getOAuthLoginUrl(), sameTab: true },
    ]);
    return;
  }

  if (!loaded) {
    setOverlay(`載入 installations 失敗：${oauthInstallationsError || 'unknown error'}`, [
      {
        type: 'button',
        label: '重試',
        onClick: async () => {
          await openSwitchInstallationOverlay();
        },
      },
    ]);
    return;
  }

  if (oauthInstallations.length === 0) {
    setOverlay('目前查無可切換的 installations。可先安裝 App 或重新 OAuth 登入。', [
      { label: '前往 GitHub App Install', href: getInstallUrl() },
      { label: 'OAuth 使用者登入', href: getOAuthLoginUrl(), sameTab: true, secondary: true },
    ]);
    return;
  }

  const me = await tryApi('/api/me');
  const currentInstallationId = me.ok ? Number(me.data.installation_id || 0) : 0;
  const actions = [
    {
      type: 'button',
      label: '重新整理清單',
      secondary: true,
      onClick: async () => {
        await openSwitchInstallationOverlay();
      },
    },
  ];

  for (const inst of oauthInstallations) {
    const same = currentInstallationId > 0 && Number(inst.installation_id) === currentInstallationId;
    const suffix = inst.template_repo_selected === false ? ' (template repo 未授權)' : '';
    actions.push({
      type: 'button',
      label: `${same ? '目前使用中 - ' : ''}#${inst.installation_id} ${inst.account_login}${suffix}`,
      onClick: async () => {
        const ok = await resumeWithInstallationId(inst.installation_id);
        if (!ok) {
          appendLog(`切換 installation #${inst.installation_id} 失敗。`);
          return;
        }
        appendLog(`已切換至 installation #${inst.installation_id}。`);
        setOverlayVisible(false);
      },
    });
  }

  setOverlay('選擇要切換的 fork / installation：', actions);
}

async function ensureFork() {
  const cfg = readConfig();
  requireFields({ ...cfg, script: '#!ipxe' }, false);
  saveConfig(cfg);

  appendLog('檢查 fork repo 是否可被 GitHub App 存取...');
  const result = await apiRequest('/api/fork/ensure', {
    method: 'POST',
    body: JSON.stringify({}),
  });

  appendLog(`Repo ready: ${result.owner}/${result.repo} (created=${result.created})`);
  hideSetupTips();
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
      root_cert_pem: cfg.rootCertPem || '',
    }),
  });

  appendLog(`Workflow dispatched to ${result.owner}/${result.repo}@${result.branch}`);
  el.downloadInfo.textContent = '尚無下載連結。';
  if (cfg.rootCertPem) {
    appendLog('已帶入使用者上傳的 Root CA 憑證。');
  }
  appendLog('等待約 20-60 秒，系統會自動輪詢並嘗試下載。');
}

function buildManualDownloadUrl(runId) {
  const q = new URLSearchParams({
    run_id: String(runId),
    cleanup: '0',
  });
  return `${apiBase()}/api/build/download?${q.toString()}`;
}

function showDownloadLink(runId) {
  lastArtifactRunId = runId;
  const url = buildManualDownloadUrl(runId);
  el.downloadInfo.innerHTML = '';
  const a = document.createElement('a');
  a.href = url;
  a.textContent = `手動下載連結（Run #${runId}）`;
  a.target = '_blank';
  a.rel = 'noopener noreferrer';
  el.downloadInfo.appendChild(a);
}

function scheduleCleanup(runId, delayMs = 10 * 60 * 1000) {
  if (cleanupTimer) clearTimeout(cleanupTimer);
  appendLog('已排程 10 分鐘後自動清除 artifact。');
  cleanupTimer = setTimeout(async () => {
    try {
      const res = await apiRequest('/api/build/cleanup', {
        method: 'POST',
        body: JSON.stringify({ run_id: runId }),
      });
      if (res.deleted) {
        appendLog('artifact 已清除。');
      } else {
        appendLog('artifact 已不存在，略過清除。');
      }
      el.downloadInfo.textContent = '下載連結已過期（artifact 已清除）。';
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      appendLog(`artifact 清除失敗：${msg}`);
      if (msg.includes('403')) {
        appendLog('請確認 fork repo 的 Workflow permissions 為 Read and write。');
      }
    } finally {
      cleanupTimer = null;
    }
  }, delayMs);
}

async function cleanupNow() {
  if (!lastArtifactRunId) {
    appendLog('尚無可清除的 artifact。請先完成一次 build。');
    return;
  }
  try {
    const res = await apiRequest('/api/build/cleanup', {
      method: 'POST',
      body: JSON.stringify({ run_id: lastArtifactRunId }),
    });
    if (res.deleted) {
      appendLog('手動清除成功：artifact 已刪除。');
      el.downloadInfo.textContent = '下載連結已過期（artifact 已清除）。';
    } else {
      appendLog('手動清除：artifact 已不存在。');
    }
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    appendLog(`手動清除失敗：${msg}`);
    if (msg.includes('403')) {
      appendLog('請確認 fork repo 的 Workflow permissions 為 Read and write。');
    }
  }
}

function updateRootCertInfo() {
  if (!rootCertPem) {
    el.rootCertInfo.textContent = '未上傳 Root CA，將使用系統預設信任。';
    return;
  }
  const lineCount = rootCertPem.split(/\r?\n/).length;
  el.rootCertInfo.textContent = `已載入 ${rootCertFileCount} 份 Root CA（${lineCount} lines）。`;
}

async function handleRootCertUpload(files) {
  if (!files || files.length === 0) {
    rootCertPem = '';
    rootCertFileCount = 0;
    updateRootCertInfo();
    return;
  }

  const parts = [];
  for (const file of files) {
    const text = await file.text();
    const pem = text.trim();
    if (!pem) {
      throw new Error(`憑證檔案為空：${file.name}`);
    }
    if (!pem.includes('BEGIN CERTIFICATE') || !pem.includes('END CERTIFICATE')) {
      throw new Error(`請上傳 PEM 格式憑證（${file.name} 缺少 BEGIN/END CERTIFICATE）。`);
    }
    parts.push(`${pem}\n`);
  }

  const merged = parts.join('');
  if (merged.length > 300000) {
    throw new Error('憑證總內容過大，請精簡為必要的 root CA。');
  }

  rootCertPem = merged;
  rootCertFileCount = files.length;
  updateRootCertInfo();
}

async function checkLatestRun() {
  const cfg = readConfig();
  requireFields({ ...cfg, script: '#!ipxe' }, false);

  appendLog('查詢最新 workflow run...');
  const data = await apiRequestWithRetry('/api/build/latest', {}, 3, 600);
  const run = data.run;
  appendLog(`Run #${run.run_number}: status=${run.status}, conclusion=${run.conclusion || 'N/A'}`);
  appendLog(`Run URL: ${run.html_url}`);

  if (run.status === 'completed' && run.conclusion === 'success' && data.artifact?.id) {
    showDownloadLink(run.id);
    appendLog('偵測到成功 artifact，開始自動下載...');
    await downloadArtifact(run.id, false);
    scheduleCleanup(run.id);
    return;
  }

  if (run.status === 'completed' && run.conclusion === 'success' && !data.artifact?.id) {
    appendLog('Run 已成功，但找不到 artifact。可能已被清除，請重新 Build 產生新檔案。');
    return;
  }

  if (run.status === 'completed' && run.conclusion !== 'success') {
    appendLog('偵測到 build 失敗，正在抓取失敗 log...');
    await showFailedLogs(run.id);
  }
}

async function showFailedLogs(runId) {
  const q = new URLSearchParams({ run_id: String(runId) });
  const data = await apiRequestWithRetry(`/api/build/logs?${q.toString()}`, {}, 2, 500);
  const items = data.logs || [];
  if (items.length === 0) {
    appendLog('找不到可用的 job log。');
    return;
  }

  for (const item of items) {
    appendLog(`Failed Job: ${item.name} (${item.conclusion})`);
    appendLog(`Job URL: ${item.html_url}`);
    appendLog(`--- job log tail ---\n${item.log_tail}\n--- end ---`);
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

  if (cleanup) {
    appendLog('下載已觸發。artifact 已由後端清除。');
  } else {
    appendLog('下載已觸發。artifact 尚未清除（保留手動下載與延遲清理）。');
  }
}

async function pollUntilDone(maxAttempts = 15, intervalMs = 5000) {
  for (let i = 1; i <= maxAttempts; i += 1) {
    await new Promise((r) => setTimeout(r, intervalMs));
    appendLog(`輪詢進度 ${i}/${maxAttempts}...`);

    try {
      const data = await apiRequestWithRetry('/api/build/latest', {}, 3, 600);
      const run = data.run;
      appendLog(`Run #${run.run_number}: status=${run.status}, conclusion=${run.conclusion || 'N/A'}`);

      if (run.status === 'completed') {
        if (run.conclusion === 'success' && data.artifact?.id) {
          showDownloadLink(run.id);
          await downloadArtifact(run.id, false);
          scheduleCleanup(run.id);
        } else if (run.conclusion === 'success' && !data.artifact?.id) {
          appendLog('Run 已成功，但找不到 artifact。可能已被清除，請重新 Build 產生新檔案。');
        } else {
          appendLog('Run 已完成但非 success，請開 Run URL 查看詳細錯誤。');
          appendLog('正在抓取失敗 log...');
          await showFailedLogs(run.id);
        }
        return;
      }
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      if (msg.includes('internal error; reference =')) {
        appendLog(`Warning: 暫時性後端錯誤，系統會持續重試。(${msg})`);
      } else {
        appendLog(msg);
      }
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
  runSetupWizard();
});

el.switchInstallBtn.addEventListener('click', async () => {
  const base = apiBase();
  if (!base) {
    appendLog('請先填 Worker API Base URL。');
    return;
  }
  await openSwitchInstallationOverlay();
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

el.clearCacheBtn.addEventListener('click', async () => {
  el.clearCacheBtn.disabled = true;
  try {
    try {
      await apiRequest('/api/auth/logout', { method: 'POST' });
    } catch {
      // ignore logout failure; continue clearing local cache
    }
    clearAllLocalCache();
    setupWizardAbort = true;
    setOverlayVisible(false);
    hideSetupTips();
    el.userInfo.textContent = '尚未登入。';
    el.downloadInfo.textContent = '尚無下載連結。';
    appendLog('已清除本機快取與後端登入 cookie。');
    appendLog('若仍自動登入，請同時登出 GitHub 或改用無痕視窗測試。');
  } finally {
    el.clearCacheBtn.disabled = false;
  }
});

el.forkBtn.addEventListener('click', async () => {
  el.forkBtn.disabled = true;
  try {
    await ensureFork();
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    appendLog(msg);
    if (msg.includes('repo not accessible for GitHub App installation')) {
      showSetupTips('目前找不到可存取的 fork repo。');
    }
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

el.cleanupBtn.addEventListener('click', async () => {
  el.cleanupBtn.disabled = true;
  try {
    await cleanupNow();
  } finally {
    el.cleanupBtn.disabled = false;
  }
});

el.rootCertFile.addEventListener('change', async (ev) => {
  const target = ev.target;
  const files = target?.files ? Array.from(target.files) : [];
  try {
    await handleRootCertUpload(files);
    if (files.length > 0) {
      appendLog(`Root CA 載入成功: ${files.map((f) => f.name).join(', ')}`);
    } else {
      appendLog('已清除 Root CA。');
    }
  } catch (err) {
    rootCertPem = '';
    rootCertFileCount = 0;
    updateRootCertInfo();
    appendLog(err instanceof Error ? err.message : String(err));
  }
});

restoreConfig();
updateRootCertInfo();
await refreshTemplateInfo();
await refreshUser();
el.setupOverlayClose.addEventListener('click', () => {
  setupWizardAbort = true;
  setOverlayVisible(false);
  clearPostInstallFlagFromUrl();
});
const initialParams = new URLSearchParams(window.location.search);
if (initialParams.get('post_install') === '1' || initialParams.get('oauth_done') === '1') {
  appendLog('偵測到 OAuth/Install callback，啟動 setup 檢查流程...');
  await runSetupWizard();
}

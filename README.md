# iPXE Builder (Pages + Worker + GitHub App)

這個版本是最小可用架構：
- 前端：GitHub Pages（`public/`）
- API：Cloudflare Worker（`worker/`）
- 登入：GitHub App（不需要使用者手貼 Personal Access Token）
- 編譯：使用者在自己的 fork repo 跑 GitHub Actions
- 下載：前端自動下載，保留手動下載連結，並在 10 分鐘後清理 artifact

## 系統流程

1. 使用者在前端按 `Start (Fork -> Install)` 或 `GitHub App Login/Install`。
2. 前端會顯示 Setup Overlay，分步自動檢查：
   - 是否已完成 GitHub App 安裝登入
   - fork repo 是否存在
   - GitHub App 是否可存取該 fork
   - Actions workflow 是否可用
3. 若缺步驟（例如尚未 fork 或 Actions 未啟用），Overlay 會提供對應連結（新分頁）並持續自動輪詢檢查。
4. GitHub 以 `installation_id` 回呼 Worker 後，原頁會自動續跑檢查流程。
5. 全部 ready 後，Overlay 自動關閉，使用者可直接 Build。
6. 若使用者曾安裝過 App 但 logout 後無法從安裝頁回跳，可用 Overlay 的「快速恢復登入」直接以上次 installation 重新建立 session。
5. 前端可上傳多個 Root CA（PEM），按 `Build + Auto Download` 後由 Worker 觸發 workflow。
6. 前端輪詢 run；成功時會自動下載 artifact，並保留手動下載連結。
7. 前端排程 10 分鐘後呼叫 cleanup API 刪除 artifact（也可手動 `Clean Now`）。

## 必要前置

1. template repo 需包含：
   - `.github/workflows/build-ipxe-efi.yml`
2. 使用者可 fork 該 template repo。
3. 你需要建立 GitHub App（不是 OAuth App）。

## GitHub App 設定

在 GitHub `Settings -> Developer settings -> GitHub Apps -> New GitHub App`：

1. 基本欄位：
   - `GitHub App name`: 自訂
   - `Homepage URL`: 你的 Pages 網址
   - `Setup URL`: `https://<worker-domain>/api/auth/callback`
2. Webhook：
   - 可先關閉（此專案不需要 webhook）
3. Repository permissions：
   - `Actions`: Read and write
   - `Contents`: Read and write
   - `Metadata`: Read-only（通常預設）
4. 安裝範圍：
   - 建議 `Only on this account`，由使用者自行選 repo 安裝
5. 建立後記下：
   - `App ID`
   - `App slug`
6. 產生私鑰：
   - 在 App 頁面 `Private keys -> Generate a private key`
   - 下載 PEM 內容，供 Worker secret 使用

## Cloudflare Worker 設定

### 1. 設定 `worker/wrangler.toml`

修改 `worker/wrangler.toml`：
- `FRONTEND_ORIGIN`：例如 `https://<user>.github.io`
- `APP_BASE_URL`：例如 `https://ipxe-builder-api.<subdomain>.workers.dev`
- `GITHUB_APP_ID`：GitHub App ID
- `GITHUB_APP_SLUG`：GitHub App slug
- `TEMPLATE_OWNER`：模板 repo owner（例如 `allenyllee`）
- `TEMPLATE_REPO`：模板 repo name（例如 `ipxe-builder-template`）
- `TEMPLATE_BRANCH`：固定分支（預設 `main`）

### 2. 設定 Worker secrets

在 `worker/` 目錄執行：

```bash
wrangler secret put GITHUB_APP_PRIVATE_KEY
wrangler secret put SESSION_SECRET
```

`GITHUB_APP_PRIVATE_KEY` 可貼完整 PEM（含 BEGIN/END）。

### 3. 設定 Cloudflare deploy secrets（可選，用於 GitHub Actions 自動部署 Worker）

在 repo secrets 新增：
- `CLOUDFLARE_API_TOKEN`
- `CLOUDFLARE_ACCOUNT_ID`

## GitHub Pages 設定

1. `Settings -> Pages`
2. Source: `Deploy from a branch`
3. Branch: `main`
4. Folder: `/public`

## 本機開發

1. 調整 `worker/wrangler.toml`（本機）：
   - `FRONTEND_ORIGIN = "http://localhost:8080"`
   - `APP_BASE_URL = "http://127.0.0.1:8787"`
2. 複製 `worker/.dev.vars.example` 成 `worker/.dev.vars`，填入：
   - `GITHUB_APP_PRIVATE_KEY`
   - `SESSION_SECRET`
3. 啟動 Worker：

```bash
cd worker
npx wrangler@latest dev --port 8787
```

4. 啟動前端靜態頁：

```bash
cd ../public
python3 -m http.server 8080
```

5. 開 `http://localhost:8080`，將 `Worker API Base URL` 填 `http://127.0.0.1:8787`。

## 使用者操作提示

1. 第一次使用：
   - 先在 GitHub 手動 fork template repo 到自己帳號
   - 在 GitHub App 安裝頁選擇該 fork repo
2. 若 `Check Fork Access` 失敗：
   - 確認 fork repo 存在
   - 確認 GitHub App 已安裝在該 repo
3. 若 cleanup 失敗 403：
   - 到 fork repo `Settings -> Actions -> General -> Workflow permissions`
   - 設成 `Read and write permissions`

## 檔案

- `public/index.html`: 前端頁面
- `public/app.js`: 登入、檢查 repo 存取、build、輪詢、下載
- `public/styles.css`: 樣式
- `worker/src/index.js`: GitHub App session + GitHub API 邏輯
- `worker/wrangler.toml`: Worker 設定
- `worker/.dev.vars.example`: 本機開發 secret 範例
- `.github/workflows/deploy-worker.yml`: Worker 自動部署

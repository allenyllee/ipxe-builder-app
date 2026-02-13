# iPXE Builder (Pages + Worker + GitHub Login)

這個版本是最小可用架構：
- 前端：GitHub Pages（`public/`）
- API：Cloudflare Worker（`worker/`）
- 登入：GitHub OAuth（不用手貼 token）
- 編譯：使用者 fork 「固定模板 repo」後，在自己的 fork 內跑 GitHub Actions
- 下載：前端自動下載，後端可立即刪 artifact

## 系統流程

1. 使用者在前端按 `GitHub Login`。
2. Worker 完成 OAuth，建立 session cookie。
3. 前端呼叫 `Ensure Fork`，Worker 確認使用者是否已有固定模板 repo 的 fork。
4. 前端可選上傳多個 Root CA（PEM），再呼叫 `Build + Auto Download`，Worker 對使用者 fork repo 觸發 `build-ipxe-efi.yml`。
5. 前端輪詢最新 run，成功後呼叫 Worker 下載 artifact。
6. Worker 串流 zip 給前端，並刪除 artifact（`cleanup=1`）。

## 必要前置

1. 你的 template repo 需要包含：
   - `.github/workflows/build-ipxe-efi.yml`（位於 `ipxe-builder-template` repo）
2. 使用者必須有權限 fork 這個 repo。
3. 你需要建立 GitHub OAuth App：
   - Homepage URL: 你的 Pages 網址
   - Authorization callback URL: `https://<worker-domain>/api/auth/callback`

## Cloudflare Worker 設定

### 1. 設定 `worker/wrangler.toml`

把以下欄位改成你的值：
- `FRONTEND_ORIGIN`：例如 `https://<user>.github.io`
- `APP_BASE_URL`：例如 `https://ipxe-builder-api.<subdomain>.workers.dev`
- `GITHUB_CLIENT_ID`
- `TEMPLATE_OWNER`：模板 repo owner（例如 `yourname`）
- `TEMPLATE_REPO`：模板 repo name（例如 `ipxe-builder-template`）
- `TEMPLATE_BRANCH`：固定分支（預設 `main`）

### 2. 設定 Worker secrets

在 `worker/` 目錄執行：

```bash
wrangler secret put GITHUB_CLIENT_SECRET
wrangler secret put SESSION_SECRET
```

### 3. 設定 GitHub Actions secrets（自動部署 Worker）

在 repo secrets 新增：
- `CLOUDFLARE_API_TOKEN`
- `CLOUDFLARE_ACCOUNT_ID`

## GitHub Pages 設定

1. `Settings -> Pages`
2. Source: `Deploy from a branch`
3. Branch: `main`
4. Folder: `/public`

## 自動部署 Worker

此專案已提供 `.github/workflows/deploy-worker.yml`：
- push 到 `main` 且有 `worker/**` 變動時，自動 `wrangler deploy`
- 也可手動 `workflow_dispatch`

## 本機開發建議

1. 調整 `worker/wrangler.toml`（本機）：
   - `FRONTEND_ORIGIN = "http://localhost:8080"`
   - `APP_BASE_URL = "http://127.0.0.1:8787"`
2. 複製 `worker/.dev.vars.example` 成 `worker/.dev.vars`，填入：
   - `GITHUB_CLIENT_SECRET`
   - `SESSION_SECRET`
3. 啟動 Worker：
   - `cd worker`
   - `npx wrangler@latest dev --port 8787`
4. 啟動前端靜態頁：
   - `cd ../public`
   - `python3 -m http.server 8080`
5. 開 `http://localhost:8080`，`Worker API Base URL` 填 `http://127.0.0.1:8787`。
6. 在 GitHub OAuth App 補上本機 callback：
   - Homepage URL: `http://localhost:8080`
   - Callback URL: `http://127.0.0.1:8787/api/auth/callback`
7. 在瀏覽器測試 `Ensure Fork -> Build + Auto Download`。

## 檔案

- `public/index.html`: 前端頁面
- `public/app.js`: 登入、fork、build、輪詢、下載
- `public/styles.css`: 樣式
- `worker/src/index.js`: OAuth + GitHub API + 下載刪除邏輯
- `worker/wrangler.toml`: Worker 設定
- `.github/workflows/deploy-worker.yml`: Worker 自動部署

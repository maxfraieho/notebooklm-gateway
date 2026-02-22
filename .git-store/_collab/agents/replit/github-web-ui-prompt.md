# Replit Agent Task: GitHub Web UI Configuration

## Мета

Створити веб-інтерфейс для налаштування GitHub інтеграції (токен, репозиторій, гілка) на сторінці адміністратора Replit бекенда.

## Поточний стан

Бекенд вже має:
- FastAPI сервіс на `https://notebooklm-gateway-1.replit.app`
- Головну сторінку з формою NotebookLM credentials
- `/v1/health` endpoint

## Завдання

### 1. Додати HTML форму в `templates/index.html`

Після секції NotebookLM додати нову секцію:

```html
<!-- GitHub Integration Section -->
<div class="card" style="margin-top: 2rem;">
  <h2>🔗 GitHub Integration</h2>
  <p>Configure GitHub repository for auto-committing accepted proposals.</p>
  
  <form id="github-form" class="config-form">
    <div class="form-group">
      <label for="github-token">Personal Access Token (PAT)</label>
      <input type="password" id="github-token" name="github_token" 
             placeholder="ghp_xxxxxxxxxxxxxxxxxxxx" />
      <small>Fine-grained PAT with Contents:write permission. 
        <a href="https://github.com/settings/tokens?type=beta" target="_blank">Create token →</a>
      </small>
    </div>
    
    <div class="form-group">
      <label for="github-repo">Repository (owner/repo)</label>
      <input type="text" id="github-repo" name="github_repo" 
             placeholder="owner/repo" />
    </div>
    
    <div class="form-group">
      <label for="github-branch">Branch</label>
      <input type="text" id="github-branch" name="github_branch" 
             placeholder="main" value="main" />
    </div>
    
    <button type="submit" class="btn-primary">Save GitHub Settings</button>
  </form>
  
  <div id="github-status" class="status-box"></div>
  
  <details style="margin-top: 1rem;">
    <summary>Instructions for creating GitHub token</summary>
    <ol>
      <li>Go to <a href="https://github.com/settings/tokens?type=beta" target="_blank">GitHub Fine-grained tokens</a></li>
      <li>Click "Generate new token"</li>
      <li>Token name: <code>garden-proposal-bot</code></li>
      <li>Expiration: 90 days (or custom)</li>
      <li>Repository access: Only select repositories → your target repo</li>
      <li>Permissions → Repository permissions → Contents: Read and write</li>
      <li>Generate and copy token</li>
    </ol>
  </details>
</div>

<script>
// GitHub form handler
document.getElementById('github-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const statusEl = document.getElementById('github-status');
  statusEl.textContent = 'Saving...';
  statusEl.className = 'status-box pending';
  statusEl.style.display = 'block';
  
  try {
    const resp = await fetch('/api/github/config', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        token: document.getElementById('github-token').value,
        repo: document.getElementById('github-repo').value,
        branch: document.getElementById('github-branch').value || 'main',
      }),
    });
    
    const data = await resp.json();
    if (data.success) {
      statusEl.textContent = '✅ GitHub configured: ' + data.repo;
      statusEl.className = 'status-box success';
      document.getElementById('github-token').value = ''; // Clear token
    } else {
      throw new Error(data.error || 'Configuration failed');
    }
  } catch (err) {
    statusEl.textContent = '❌ ' + err.message;
    statusEl.className = 'status-box error';
  }
});

// Load current GitHub config on page load
async function loadGitHubStatus() {
  try {
    const resp = await fetch('/api/github/status');
    const data = await resp.json();
    const statusEl = document.getElementById('github-status');
    
    if (data.configured) {
      document.getElementById('github-repo').value = data.repo || '';
      document.getElementById('github-branch').value = data.branch || 'main';
      statusEl.textContent = '✅ GitHub configured: ' + data.repo;
      statusEl.className = 'status-box success';
      statusEl.style.display = 'block';
    }
  } catch (e) {
    console.error('Failed to load GitHub status:', e);
  }
}
loadGitHubStatus();
</script>
```

### 2. Додати API endpoints в `app/routes/api_v1.py`

```python
import os
import json
from pathlib import Path
import httpx

@router.post("/api/github/config")
async def save_github_config(request: Request):
    """Save GitHub configuration."""
    body = await request.json()
    token = body.get("token", "").strip()
    repo = body.get("repo", "").strip()
    branch = body.get("branch", "main").strip()
    
    if not token or not repo:
        return {"success": False, "error": "Token and repo are required"}
    
    # Validate token by making a test API call
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    async with httpx.AsyncClient() as client:
        resp = await client.get(
            f"https://api.github.com/repos/{repo}",
            headers=headers
        )
        if resp.status_code == 404:
            return {"success": False, "error": f"Repository not found: {repo}"}
        if resp.status_code == 401:
            return {"success": False, "error": "Invalid token"}
        if resp.status_code != 200:
            return {"success": False, "error": f"GitHub API error: {resp.status_code}"}
    
    # Store in environment
    os.environ["GITHUB_TOKEN"] = token
    os.environ["GITHUB_REPO"] = repo
    os.environ["GITHUB_BRANCH"] = branch
    
    # Save to config file for persistence
    config_path = Path("config/github.json")
    config_path.parent.mkdir(exist_ok=True)
    config_path.write_text(json.dumps({
        "token": token,
        "repo": repo,
        "branch": branch,
    }))
    
    return {"success": True, "repo": repo}


@router.get("/api/github/status")
async def get_github_status():
    """Check if GitHub is configured."""
    token = os.getenv("GITHUB_TOKEN", "")
    repo = os.getenv("GITHUB_REPO", "")
    branch = os.getenv("GITHUB_BRANCH", "main")
    
    return {
        "configured": bool(token and repo),
        "repo": repo if token else "",
        "branch": branch,
    }
```

### 3. Додати завантаження конфігу при старті в `app/main.py`

```python
from pathlib import Path
import json

def load_github_config():
    """Load GitHub config from file on startup."""
    config_path = Path("config/github.json")
    if config_path.exists():
        try:
            config = json.loads(config_path.read_text())
            os.environ.setdefault("GITHUB_TOKEN", config.get("token", ""))
            os.environ.setdefault("GITHUB_REPO", config.get("repo", ""))
            os.environ.setdefault("GITHUB_BRANCH", config.get("branch", "main"))
            logger.info(f"[Startup] Loaded GitHub config for {config.get('repo')}")
        except Exception as e:
            logger.warning(f"[Startup] Failed to load GitHub config: {e}")

# Викликати на старті застосунку
load_github_config()
```

### 4. Додати CSS стилі (якщо потрібно)

```css
.status-box {
  padding: 0.75rem 1rem;
  border-radius: 6px;
  margin-top: 1rem;
  display: none;
}
.status-box.pending {
  background: #fef3c7;
  color: #92400e;
  display: block;
}
.status-box.success {
  background: #d1fae5;
  color: #065f46;
  display: block;
}
.status-box.error {
  background: #fee2e2;
  color: #991b1b;
  display: block;
}
```

## Перевірка

1. Відкрий головну сторінку бекенда
2. Заповни форму GitHub:
   - Token: `ghp_...` (Fine-grained PAT)
   - Repository: `maxfraieho/project-genesis`
   - Branch: `main`
3. Натисни Save — має з'явитись ✅
4. Перезавантаж сторінку — налаштування мають зберегтись

## Залежності

Переконайся, що `httpx` встановлено:
```
pip install httpx
```

---

**Пріоритет**: Високий  
**Час**: 30 хвилин

# Task: Add GitHub Commit Integration for Accepted Proposals

## Context

When an owner accepts an edit proposal from a guest, the current flow:
1. Updates KV storage with new content ✅
2. Updates MinIO markdown files ✅  
3. Shows "Copy Content" dialog for manual paste ❌ (poor UX)

**Goal**: Automatically commit accepted changes to the GitHub repository.

## Architecture (Base URL: `https://notebooklm-gateway-1.replit.app`)

```
ProposalsInbox (Frontend)
    ↓ POST /proposals/:id/accept
Cloudflare Worker
    ↓ POST /v1/git/commit (new endpoint)
Replit Backend (FastAPI)
    ↓ GitHub REST API
maxfraieho/garden-bloom repository
```

## Implementation Plan

### Part 1: Add GitHub Service (`app/services/github_service.py`)

```python
"""
GitHub integration for committing accepted proposals.
Uses GitHub REST API with Personal Access Token (Fine-grained).
"""
import logging
import base64
from typing import Optional
import httpx

from app.config import GITHUB_TOKEN, GITHUB_REPO, GITHUB_BRANCH

logger = logging.getLogger(__name__)

GITHUB_API = "https://api.github.com"


class GitHubService:
    """Commit files to GitHub repository via REST API."""
    
    def __init__(self):
        self.token = GITHUB_TOKEN
        self.repo = GITHUB_REPO  # e.g. "maxfraieho/garden-bloom"
        self.branch = GITHUB_BRANCH or "main"
        self.headers = {
            "Authorization": f"Bearer {self.token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }
    
    @property
    def configured(self) -> bool:
        return bool(self.token and self.repo)
    
    async def get_file_sha(self, path: str) -> Optional[str]:
        """Get current file SHA (required for updates)."""
        url = f"{GITHUB_API}/repos/{self.repo}/contents/{path}"
        params = {"ref": self.branch}
        
        async with httpx.AsyncClient() as client:
            resp = await client.get(url, headers=self.headers, params=params)
            if resp.status_code == 200:
                return resp.json().get("sha")
            return None  # File doesn't exist
    
    async def commit_file(
        self,
        path: str,
        content: str,
        message: str,
        author_name: str = "Garden Bot",
        author_email: str = "bot@garden.local",
    ) -> dict:
        """
        Create or update a file in the repository.
        
        Args:
            path: File path in repo (e.g., "src/site/notes/folder/note.md")
            content: New file content
            message: Commit message
            author_name: Git author name
            author_email: Git author email
            
        Returns:
            dict with commit info or error
        """
        if not self.configured:
            return {"success": False, "error": "GitHub not configured"}
        
        url = f"{GITHUB_API}/repos/{self.repo}/contents/{path}"
        
        # Get existing SHA if file exists
        sha = await self.get_file_sha(path)
        
        # Encode content as base64
        content_b64 = base64.b64encode(content.encode("utf-8")).decode("utf-8")
        
        payload = {
            "message": message,
            "content": content_b64,
            "branch": self.branch,
            "committer": {
                "name": author_name,
                "email": author_email,
            },
        }
        
        if sha:
            payload["sha"] = sha  # Required for updates
        
        async with httpx.AsyncClient() as client:
            resp = await client.put(url, headers=self.headers, json=payload)
            
            if resp.status_code in (200, 201):
                data = resp.json()
                logger.info(f"[GitHub] Committed {path} -> {data['commit']['sha'][:7]}")
                return {
                    "success": True,
                    "sha": data["commit"]["sha"],
                    "url": data["content"]["html_url"],
                }
            else:
                error = resp.json().get("message", resp.text)
                logger.error(f"[GitHub] Commit failed: {resp.status_code} - {error}")
                return {"success": False, "error": error, "status": resp.status_code}


# Singleton
github_service = GitHubService()
```

### Part 2: Add Config Variables (`app/config.py`)

Add these to the config:

```python
# GitHub Integration
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN", "")
GITHUB_REPO = os.getenv("GITHUB_REPO", "maxfraieho/garden-bloom")
GITHUB_BRANCH = os.getenv("GITHUB_BRANCH", "main")
```

### Part 3: Add API Endpoint (`app/routes/api_v1.py`)

Add new endpoint for git commits:

```python
from app.services.github_service import github_service

@router.post("/v1/git/commit")
async def git_commit(request: Request):
    """
    Commit a file to GitHub repository.
    Called by Cloudflare Worker after accepting a proposal.
    
    Body:
    {
        "path": "src/site/notes/folder/note.md",
        "content": "# Note content...",
        "message": "Accept proposal: Update note title",
        "authorName": "Guest User",
        "proposalId": "abc123"
    }
    """
    # Verify service token (same as NotebookLM auth)
    auth_header = request.headers.get("Authorization", "")
    expected_token = os.getenv("NOTEBOOKLM_SERVICE_TOKEN", "")
    
    if not auth_header.startswith("Bearer ") or auth_header[7:] != expected_token:
        raise APIError(
            code=ErrorCode.NOT_AUTHENTICATED,
            message="Invalid service token",
            status_code=401,
        )
    
    body = await request.json()
    path = body.get("path", "").strip()
    content = body.get("content", "")
    message = body.get("message", "Update note via proposal")
    author_name = body.get("authorName", "Garden Guest")
    
    if not path or not content:
        raise APIError(
            code=ErrorCode.VALIDATION_ERROR,
            message="path and content are required",
            status_code=400,
        )
    
    if not github_service.configured:
        return {
            "success": False,
            "error": "GitHub integration not configured",
            "hint": "Set GITHUB_TOKEN and GITHUB_REPO environment variables",
        }
    
    result = await github_service.commit_file(
        path=path,
        content=content,
        message=message,
        author_name=author_name,
        author_email=f"{author_name.lower().replace(' ', '.')}@garden.guest",
    )
    
    return result
```

### Part 4: Add Health Check for GitHub

Extend `/v1/health` to report GitHub status:

```python
@router.get("/v1/health")
async def health_check_v1(request: Request):
    # ... existing auth check ...
    
    return {
        "ok": True,
        "version": "0.2.0",
        "services": {
            "notebooklm": notebooklm_ready,
            "minio": minio_ok,
            "github": github_service.configured,  # Add this
        },
    }
```

### Part 5: Update Requirements

Add to `requirements.txt`:
```
httpx==0.28.1
```

### Part 6: Add Web UI for GitHub Token Input

Similar to existing NotebookLM credentials upload, add a form for GitHub settings.

**Update `templates/index.html`** - add new section after NotebookLM form:

```html
<!-- GitHub Integration Section -->
<div class="card">
  <h2>🔗 GitHub Integration</h2>
  <p>Configure GitHub repository for auto-committing accepted proposals.</p>
  
  <form id="github-form" class="config-form">
    <div class="form-group">
      <label for="github-token">Personal Access Token (PAT)</label>
      <input type="password" id="github-token" name="github_token" 
             placeholder="ghp_xxxxxxxxxxxxxxxxxxxx" />
      <small>Fine-grained PAT with Contents:write permission</small>
    </div>
    
    <div class="form-group">
      <label for="github-repo">Repository</label>
      <input type="text" id="github-repo" name="github_repo" 
             placeholder="owner/repo" value="maxfraieho/garden-bloom" />
    </div>
    
    <div class="form-group">
      <label for="github-branch">Branch</label>
      <input type="text" id="github-branch" name="github_branch" 
             placeholder="main" value="main" />
    </div>
    
    <button type="submit" class="btn-primary">Save GitHub Settings</button>
  </form>
  
  <div id="github-status" class="status-box"></div>
</div>

<script>
document.getElementById('github-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const statusEl = document.getElementById('github-status');
  statusEl.textContent = 'Saving...';
  statusEl.className = 'status-box pending';
  
  try {
    const resp = await fetch('/api/github/config', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        token: document.getElementById('github-token').value,
        repo: document.getElementById('github-repo').value,
        branch: document.getElementById('github-branch').value,
      }),
    });
    
    const data = await resp.json();
    if (data.success) {
      statusEl.textContent = '✅ GitHub configured successfully';
      statusEl.className = 'status-box success';
      document.getElementById('github-token').value = ''; // Clear token field
    } else {
      throw new Error(data.error || 'Configuration failed');
    }
  } catch (err) {
    statusEl.textContent = '❌ ' + err.message;
    statusEl.className = 'status-box error';
  }
});

// Load current config on page load
async function loadGitHubStatus() {
  try {
    const resp = await fetch('/api/github/status');
    const data = await resp.json();
    if (data.configured) {
      document.getElementById('github-repo').value = data.repo || '';
      document.getElementById('github-branch').value = data.branch || 'main';
      document.getElementById('github-status').textContent = '✅ GitHub configured: ' + data.repo;
      document.getElementById('github-status').className = 'status-box success';
    }
  } catch (e) {
    console.error('Failed to load GitHub status:', e);
  }
}
loadGitHubStatus();
</script>
```

**Add API routes** in `app/routes/api_v1.py`:

```python
@router.post("/api/github/config")
async def save_github_config(request: Request):
    """Save GitHub configuration (token stored in env/secrets)."""
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
    }
    async with httpx.AsyncClient() as client:
        resp = await client.get(
            f"https://api.github.com/repos/{repo}",
            headers=headers
        )
        if resp.status_code != 200:
            return {"success": False, "error": f"Invalid token or repo: {resp.status_code}"}
    
    # Store in environment (Replit secrets persist)
    os.environ["GITHUB_TOKEN"] = token
    os.environ["GITHUB_REPO"] = repo
    os.environ["GITHUB_BRANCH"] = branch
    
    # Also save to a config file for persistence across restarts
    config_path = Path("config/github.json")
    config_path.parent.mkdir(exist_ok=True)
    config_path.write_text(json.dumps({
        "token": token,  # Consider encrypting in production
        "repo": repo,
        "branch": branch,
    }))
    
    return {"success": True}

@router.get("/api/github/status")
async def get_github_status():
    """Check if GitHub is configured."""
    token = os.getenv("GITHUB_TOKEN", "")
    repo = os.getenv("GITHUB_REPO", "")
    branch = os.getenv("GITHUB_BRANCH", "main")
    
    return {
        "configured": bool(token and repo),
        "repo": repo,
        "branch": branch,
    }
```

**Add startup config loader** in `app/main.py`:

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

# Call in startup
load_github_config()
```

## Creating GitHub Token (User Instructions)

Display these instructions in the UI:

1. Go to https://github.com/settings/tokens?type=beta
2. Click "Generate new token" (Fine-grained)
3. Settings:
   - Token name: `garden-proposal-bot`
   - Expiration: 90 days (or custom)
   - Repository access: Only select repositories → `maxfraieho/garden-bloom`
   - Permissions → Repository permissions:
     - Contents: Read and write
4. Generate and copy token
5. Paste into the form above

## Testing

After implementation, test with curl:

```bash
curl -X POST https://notebooklm-gateway.replit.app/v1/git/commit \
  -H "Authorization: Bearer YOUR_SERVICE_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "path": "src/site/notes/test/test-commit.md",
    "content": "# Test Note\n\nThis is a test commit from API.",
    "message": "test: API commit integration",
    "authorName": "Test User"
  }'
```

Expected response:
```json
{
  "success": true,
  "sha": "abc1234...",
  "url": "https://github.com/maxfraieho/garden-bloom/blob/main/src/site/notes/test/test-commit.md"
}
```

## Next Steps (Cloudflare Worker)

After Replit implementation, I'll update the Cloudflare Worker's `handleProposalAccept` to call `/v1/git/commit`.

## File Path Mapping

Note slugs need to be converted to file paths:

```javascript
// In worker
function noteSlugToFilePath(slug) {
  // Decode URL-encoded slug
  const decoded = decodeURIComponent(slug);
  // Ensure .md extension
  const withExt = decoded.endsWith('.md') ? decoded : `${decoded}.md`;
  // Prefix with notes directory
  return `src/site/notes/${withExt}`;
}
```

## Security Considerations

1. **Token Scope**: Use fine-grained PAT with minimal permissions (Contents:write only)
2. **Service Auth**: Require NOTEBOOKLM_SERVICE_TOKEN for all git endpoints
3. **Rate Limits**: GitHub API allows 5000 requests/hour with auth
4. **Audit Trail**: All commits show author name from proposal

---

**Status**: Ready for implementation  
**Priority**: High  
**Estimated Time**: 1-2 hours

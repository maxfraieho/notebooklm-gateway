# Task: Debug and Fix /v1/git/commit Endpoint

## Context

The Cloudflare Worker calls `/v1/git/commit` to commit accepted edit proposals to the GitHub repository `maxfraieho/project-genesis`. 

**Current Problem**: Git commits are failing silently. The endpoint returns an error but the Cloudflare Worker only sees "Git commit failed" without details.

## Current Configuration

```
GitHub repo: maxfraieho/project-genesis
Branch: main
Endpoint: POST /v1/git/commit
```

## Expected Request Format (from OpenAPI)

```json
{
  "path": "src/site/notes/exodus.pp.ua/SSH транссфер/ПРОМТ - Налаштувати SSH ключі.md",
  "content": "---\ntitle: ...\n---\n\n## Content here...",
  "message": "docs: accept edit proposal for \"Title\" by GuestName"
}
```

Required fields: `path`, `content`
Optional: `message`, `authorName`, `proposalId`

## Task

### 1. Add Detailed Logging

In the `/v1/git/commit` endpoint handler, add comprehensive logging:

```python
@app.post("/v1/git/commit")
async def git_commit(request: GitCommitRequest, authorization: str = Header(None)):
    logger.info(f"[git_commit] Received request for path: {request.path}")
    logger.info(f"[git_commit] Content length: {len(request.content)} chars")
    logger.info(f"[git_commit] Message: {request.message}")
    
    # Check GitHub config
    config = load_github_config()
    if not config:
        logger.error("[git_commit] GitHub not configured")
        return {"success": False, "error": "GitHub not configured"}
    
    logger.info(f"[git_commit] Using repo: {config['repo']}, branch: {config['branch']}")
    
    try:
        # ... existing commit logic ...
        
        # Log the GitHub API response
        logger.info(f"[git_commit] GitHub API response: {response.status_code}")
        if response.status_code != 200 and response.status_code != 201:
            logger.error(f"[git_commit] GitHub API error: {response.text}")
            return {
                "success": False, 
                "error": f"GitHub API error: {response.status_code}",
                "details": response.json() if response.text else None
            }
        
        result = response.json()
        logger.info(f"[git_commit] Commit created: {result.get('sha', 'unknown')}")
        return {"success": True, "sha": result.get("sha"), "url": result.get("html_url")}
        
    except Exception as e:
        logger.exception(f"[git_commit] Exception: {str(e)}")
        return {"success": False, "error": str(e)}
```

### 2. Verify GitHub Token Permissions

The GitHub PAT needs these permissions:
- `Contents: Read and Write` (to create/update files)
- Repository access to `maxfraieho/project-genesis`

Check if token is valid:
```python
def verify_github_token(token: str, repo: str) -> dict:
    """Test if token can access the repo"""
    headers = {"Authorization": f"token {token}"}
    response = requests.get(
        f"https://api.github.com/repos/{repo}",
        headers=headers
    )
    return {
        "valid": response.status_code == 200,
        "status": response.status_code,
        "scopes": response.headers.get("X-OAuth-Scopes", ""),
        "error": response.json().get("message") if response.status_code != 200 else None
    }
```

### 3. Add Diagnostic Endpoint

Create a new endpoint to test GitHub connectivity:

```python
@app.get("/v1/git/status")
async def git_status():
    """Check GitHub integration status"""
    config = load_github_config()
    if not config:
        return {"configured": False, "error": "No GitHub config found"}
    
    # Test token
    token_check = verify_github_token(config["token"], config["repo"])
    
    return {
        "configured": True,
        "repo": config["repo"],
        "branch": config["branch"],
        "token_valid": token_check["valid"],
        "token_scopes": token_check["scopes"],
        "error": token_check.get("error")
    }
```

### 4. Handle Cyrillic Paths

The file paths contain Cyrillic characters (Ukrainian). Ensure proper encoding:

```python
# When calling GitHub API, the path should be URL-encoded for the API call
from urllib.parse import quote

encoded_path = quote(request.path, safe='/')
```

### 5. Return Full Error Details

Always return detailed error information:

```python
return GitCommitResponse(
    success=False,
    error=f"GitHub API returned {response.status_code}: {response.json().get('message', 'Unknown error')}",
    hint="Check if the file path exists or if you have write permissions"
)
```

## Testing

After implementing, test with:

```bash
curl -X POST https://notebooklm-gateway-1.replit.app/v1/git/commit \
  -H "Content-Type: application/json" \
  -d '{
    "path": "test-commit.md",
    "content": "# Test\n\nTest commit from debugging",
    "message": "test: debugging git commit"
  }'
```

Check Replit logs for the detailed output.

## Success Criteria

- [ ] Detailed logs show exact reason for failure
- [ ] `/v1/git/status` endpoint works and shows token validity
- [ ] Error responses include actionable information
- [ ] Cyrillic paths are handled correctly
- [ ] Commits to maxfraieho/project-genesis succeed

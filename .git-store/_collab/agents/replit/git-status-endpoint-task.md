# Task: Add `/v1/git/status` Endpoint

## Context

The frontend needs to check if a note file exists in GitHub before showing it to users. When a note is created via the editor, it gets committed to GitHub, but it takes 1-2 minutes for Cloudflare Pages to rebuild and deploy. During this time, we want to show a friendly "syncing" message instead of "not found".

The Cloudflare Worker already proxies this request from the frontend. Now the Replit backend needs to implement the actual GitHub API check.

## Endpoint Specification

### Request

```
GET /v1/git/status?path=src/site/notes/folder/note-title.md
Authorization: Bearer garden-nlm-service-2026-a7f3b9c1e5d2
```

### Response (file exists)

```json
{
  "exists": true,
  "path": "src/site/notes/folder/note-title.md",
  "sha": "abc123..."
}
```

### Response (file doesn't exist)

```json
{
  "exists": false,
  "path": "src/site/notes/folder/note-title.md"
}
```

### Response (error)

```json
{
  "success": false,
  "error": "Error message here"
}
```

## Implementation

Use the same GitHub API pattern as `/v1/git/commit` and `/v1/git/delete`:

```python
@app.get("/v1/git/status")
async def git_status(request: Request, path: str):
    # 1. Verify Bearer token
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing authorization")
    
    token = auth_header[7:]
    if token != SERVICE_TOKEN:
        raise HTTPException(status_code=401, detail="Invalid token")
    
    # 2. Validate path
    if not path.startswith("src/site/notes/"):
        raise HTTPException(status_code=400, detail="Path must start with src/site/notes/")
    
    # 3. Check file existence via GitHub API
    github_token = get_github_pat()  # From your existing config
    owner = "maxfraieho"
    repo = "project-genesis"
    encoded_path = urllib.parse.quote(path, safe="")
    
    url = f"https://api.github.com/repos/{owner}/{repo}/contents/{encoded_path}"
    headers = {
        "Authorization": f"Bearer {github_token}",
        "Accept": "application/vnd.github.v3+json",
        "X-GitHub-Api-Version": "2022-11-28"
    }
    
    response = requests.get(url, headers=headers)
    
    if response.status_code == 200:
        data = response.json()
        return {
            "exists": True,
            "path": path,
            "sha": data.get("sha")
        }
    elif response.status_code == 404:
        return {
            "exists": False,
            "path": path
        }
    else:
        return JSONResponse(
            status_code=response.status_code,
            content={"success": False, "error": f"GitHub API error: {response.status_code}"}
        )
```

## Testing

```bash
# Test existing file
curl -H "Authorization: Bearer garden-nlm-service-2026-a7f3b9c1e5d2" \
  "https://notebooklm-gateway-1.replit.app/v1/git/status?path=src/site/notes/exodus.pp.ua/Опис%20UX.md"

# Test non-existing file
curl -H "Authorization: Bearer garden-nlm-service-2026-a7f3b9c1e5d2" \
  "https://notebooklm-gateway-1.replit.app/v1/git/status?path=src/site/notes/nonexistent.md"
```

## Expected Behavior

| Scenario | Response |
|----------|----------|
| File exists in repo | `{"exists": true, "path": "...", "sha": "..."}` |
| File doesn't exist | `{"exists": false, "path": "..."}` |
| Invalid path | 400 error |
| Missing/invalid auth | 401 error |
| GitHub API error | 500 error with details |

## Notes

- This endpoint is read-only and safe
- The Cloudflare Worker calls this to determine if a note is "pending sync" vs "not found"
- Use the same authentication pattern as other `/v1/git/*` endpoints

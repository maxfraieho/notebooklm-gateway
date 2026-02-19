import httpx
import base64
from config import settings

GITHUB_API = "https://api.github.com"

async def get_file_sha(path: str) -> str | None:
    """Get SHA of existing file, or None if not exists."""
    url = f"{GITHUB_API}/repos/{settings.GITHUB_REPO}/contents/{path}"
    headers = {
        "Authorization": f"Bearer {settings.GITHUB_PAT}",
        "Accept": "application/vnd.github.v3+json"
    }
    
    async with httpx.AsyncClient() as client:
        resp = await client.get(url, headers=headers, params={"ref": settings.GITHUB_BRANCH})
        if resp.status_code == 200:
            return resp.json().get("sha")
        return None

async def commit_file(path: str, content: str, message: str) -> dict:
    """Commit a file to GitHub."""
    url = f"{GITHUB_API}/repos/{settings.GITHUB_REPO}/contents/{path}"
    headers = {
        "Authorization": f"Bearer {settings.GITHUB_PAT}",
        "Accept": "application/vnd.github.v3+json"
    }
    
    sha = await get_file_sha(path)
    
    payload = {
        "message": message,
        "content": base64.b64encode(content.encode()).decode(),
        "branch": settings.GITHUB_BRANCH
    }
    
    if sha:
        payload["sha"] = sha
    
    async with httpx.AsyncClient() as client:
        resp = await client.put(url, headers=headers, json=payload)
        resp.raise_for_status()
        return resp.json()

async def delete_file(path: str, message: str) -> dict:
    """Delete a file from GitHub."""
    url = f"{GITHUB_API}/repos/{settings.GITHUB_REPO}/contents/{path}"
    headers = {
        "Authorization": f"Bearer {settings.GITHUB_PAT}",
        "Accept": "application/vnd.github.v3+json"
    }
    
    sha = await get_file_sha(path)
    if not sha:
        raise Exception(f"File not found: {path}")
    
    payload = {
        "message": message,
        "sha": sha,
        "branch": settings.GITHUB_BRANCH
    }
    
    async with httpx.AsyncClient() as client:
        resp = await client.delete(url, headers=headers, json=payload)
        resp.raise_for_status()
        return resp.json()

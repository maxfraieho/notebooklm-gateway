"""
GitHub integration for committing accepted proposals.
Uses GitHub REST API with Personal Access Token (Fine-grained).
"""
import logging
import base64
import os
from typing import Optional
import httpx

logger = logging.getLogger(__name__)

GITHUB_API = "https://api.github.com"


class GitHubService:
    """Commit files to GitHub repository via REST API."""
    
    def __init__(self):
        self._token: Optional[str] = None
        self._repo: Optional[str] = None
        self._branch: str = "main"
    
    @property
    def token(self) -> str:
        if self._token:
            return self._token
        return os.getenv("GITHUB_TOKEN", "")
    
    @property
    def repo(self) -> str:
        if self._repo:
            return self._repo
        return os.getenv("GITHUB_REPO", "maxfraieho/project-genesis")
    
    @property
    def branch(self) -> str:
        return self._branch or os.getenv("GITHUB_BRANCH", "main")
    
    def configure(self, token: str, repo: str, branch: str = "main"):
        """Update configuration at runtime."""
        self._token = token
        self._repo = repo
        self._branch = branch
        os.environ["GITHUB_TOKEN"] = token
        os.environ["GITHUB_REPO"] = repo
        os.environ["GITHUB_BRANCH"] = branch
    
    @property
    def headers(self) -> dict:
        return {
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
            return None
    
    async def validate_token(self) -> tuple[bool, str]:
        """Validate token by checking repo access."""
        if not self.token or not self.repo:
            return False, "Token or repo not configured"
        
        url = f"{GITHUB_API}/repos/{self.repo}"
        async with httpx.AsyncClient() as client:
            resp = await client.get(url, headers=self.headers)
            if resp.status_code == 200:
                return True, "Token valid"
            elif resp.status_code == 401:
                return False, "Invalid token"
            elif resp.status_code == 404:
                return False, f"Repository {self.repo} not found or no access"
            else:
                return False, f"GitHub API error: {resp.status_code}"
    
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
        
        sha = await self.get_file_sha(path)
        
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
            payload["sha"] = sha
        
        async with httpx.AsyncClient() as client:
            resp = await client.put(url, headers=self.headers, json=payload)
            
            if resp.status_code in (200, 201):
                try:
                    data = resp.json()
                    logger.info(f"[GitHub] Committed {path} -> {data['commit']['sha'][:7]}")
                    return {
                        "success": True,
                        "sha": data["commit"]["sha"],
                        "url": data["content"]["html_url"],
                    }
                except Exception as e:
                    logger.error(f"[GitHub] Failed to parse success response: {e}")
                    return {"success": True, "sha": "unknown", "url": None}
            else:
                try:
                    error = resp.json().get("message", "Unknown error")
                except Exception:
                    error = f"GitHub API error: {resp.status_code}"
                logger.error(f"[GitHub] Commit failed: {resp.status_code} - {error}")
                return {"success": False, "error": error, "status": resp.status_code}


github_service = GitHubService()

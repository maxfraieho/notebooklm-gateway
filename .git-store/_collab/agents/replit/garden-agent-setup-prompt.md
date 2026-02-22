# 🚀 Replit Agent: Garden Backend Service

**Мета**: Налаштувати FastAPI бекенд для Digital Garden на Replit.

---

## 📋 ЩО РОБИТЬ ЦЕЙ СЕРВІС

Backend для Digital Garden з такими функціями:
1. **Git Automation** — commit/delete файлів до GitHub
2. **NotebookLM Chat** — proxy до NotebookLM через Playwright
3. **DRAKON Diagrams** — CRUD для візуальних схем

---

## 🔧 ENVIRONMENT VARIABLES

Додай у Replit Secrets:

| Variable | Value | Опис |
|----------|-------|------|
| `SERVICE_TOKEN` | `garden-nlm-service-2026-a7f3b9c1e5d2` | Bearer token для авторизації |
| `GITHUB_PAT` | `ghp_...` | GitHub Classic PAT (права: `repo`, `workflow`) |
| `GITHUB_REPO` | `maxfraieho/garden-seedling` | Target repository |
| `GITHUB_BRANCH` | `main` | Target branch |
| `DATABASE_URL` | `postgresql://...` | PostgreSQL (optional) |

---

## 📁 СТРУКТУРА ПРОЄКТУ

```
garden-backend/
├── main.py                 # FastAPI entry point
├── config.py               # Pydantic Settings
├── requirements.txt
│
├── routers/
│   ├── __init__.py
│   ├── health.py           # /health endpoint
│   ├── git.py              # /v1/git/* endpoints
│   └── drakon.py           # /v1/drakon/* endpoints
│
├── services/
│   ├── __init__.py
│   ├── github_service.py   # GitHub API operations
│   └── auth.py             # Token validation
│
└── models/
    ├── __init__.py
    └── git.py              # Request/Response models
```

---

## 📝 ФАЙЛИ ДЛЯ СТВОРЕННЯ

### `requirements.txt`
```
fastapi>=0.109.0
uvicorn[standard]>=0.27.0
pydantic>=2.5.0
pydantic-settings>=2.1.0
httpx>=0.26.0
python-dotenv>=1.0.0
```

### `config.py`
```python
from pydantic_settings import BaseSettings
from functools import lru_cache

class Settings(BaseSettings):
    SERVICE_TOKEN: str = ""
    GITHUB_PAT: str = ""
    GITHUB_REPO: str = "maxfraieho/garden-seedling"
    GITHUB_BRANCH: str = "main"
    
    class Config:
        env_file = ".env"

@lru_cache
def get_settings():
    return Settings()

settings = get_settings()
```

### `main.py`
```python
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from routers import health, git, drakon

app = FastAPI(title="Garden Backend", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(health.router)
app.include_router(git.router, prefix="/v1/git")
app.include_router(drakon.router, prefix="/v1/drakon")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
```

### `services/auth.py`
```python
from fastapi import HTTPException, Header
from config import settings

def verify_token(authorization: str = Header(...)):
    if not authorization.startswith("Bearer "):
        raise HTTPException(401, "Invalid authorization header")
    
    token = authorization.replace("Bearer ", "")
    if token != settings.SERVICE_TOKEN:
        raise HTTPException(401, "Invalid token")
    
    return token
```

### `services/github_service.py`
```python
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
```

### `routers/health.py`
```python
from fastapi import APIRouter

router = APIRouter()

@router.get("/health")
async def health():
    return {"status": "ok", "version": "1.0.0"}
```

### `routers/git.py`
```python
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from services.auth import verify_token
from services.github_service import commit_file, delete_file, get_file_sha

router = APIRouter()

class CommitRequest(BaseModel):
    path: str
    content: str
    message: str

class DeleteRequest(BaseModel):
    path: str
    message: str

@router.post("/commit")
async def git_commit(req: CommitRequest, _: str = Depends(verify_token)):
    try:
        result = await commit_file(req.path, req.content, req.message)
        return {
            "success": True,
            "sha": result["commit"]["sha"],
            "url": result["content"]["html_url"]
        }
    except Exception as e:
        raise HTTPException(500, str(e))

@router.post("/delete")
async def git_delete(req: DeleteRequest, _: str = Depends(verify_token)):
    try:
        result = await delete_file(req.path, req.message)
        return {"success": True, "sha": result["commit"]["sha"]}
    except Exception as e:
        raise HTTPException(500, str(e))

@router.get("/status")
async def git_status(path: str, _: str = Depends(verify_token)):
    sha = await get_file_sha(path)
    return {"exists": sha is not None, "sha": sha}
```

### `routers/drakon.py`
```python
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from typing import Optional
import json
from services.auth import verify_token
from services.github_service import commit_file, delete_file

router = APIRouter()

class DrakonCommitRequest(BaseModel):
    folderSlug: str
    diagramId: str
    diagram: dict
    name: str
    isNew: Optional[bool] = False

@router.post("/commit")
async def drakon_commit(req: DrakonCommitRequest, _: str = Depends(verify_token)):
    path = f"src/site/notes/{req.folderSlug}/diagrams/{req.diagramId}.drakon.json"
    content = json.dumps(req.diagram, indent=2, ensure_ascii=False)
    
    action = "Create" if req.isNew else "Update"
    message = f"🔀 {action} DRAKON diagram: {req.name}"
    
    try:
        result = await commit_file(path, content, message)
        return {
            "success": True,
            "sha": result["commit"]["sha"],
            "url": result["content"]["html_url"],
            "path": path
        }
    except Exception as e:
        raise HTTPException(500, str(e))

@router.delete("/{folder_slug}/{diagram_id}")
async def drakon_delete(
    folder_slug: str, 
    diagram_id: str, 
    _: str = Depends(verify_token)
):
    path = f"src/site/notes/{folder_slug}/diagrams/{diagram_id}.drakon.json"
    message = f"🗑️ Delete DRAKON diagram: {diagram_id}"
    
    try:
        result = await delete_file(path, message)
        return {"success": True, "sha": result["commit"]["sha"], "path": path}
    except Exception as e:
        raise HTTPException(500, str(e))
```

---

## 🧪 ТЕСТУВАННЯ

Після деплою:

```bash
# Health check
curl https://YOUR-REPLIT-URL.replit.app/health

# Git status (з авторизацією)
curl -H "Authorization: Bearer garden-nlm-service-2026-a7f3b9c1e5d2" \
  "https://YOUR-REPLIT-URL.replit.app/v1/git/status?path=README.md"

# Commit test
curl -X POST \
  -H "Authorization: Bearer garden-nlm-service-2026-a7f3b9c1e5d2" \
  -H "Content-Type: application/json" \
  -d '{"path":"test.txt","content":"Hello","message":"Test commit"}' \
  https://YOUR-REPLIT-URL.replit.app/v1/git/commit
```

---

## ✅ CHECKLIST

1. [ ] Додати всі Secrets у Replit
2. [ ] Створити структуру файлів
3. [ ] Запустити `python main.py`
4. [ ] Перевірити `/health`
5. [ ] Протестувати Git commit
6. [ ] Оновити URL у Cloudflare Worker secrets

---

## 🔗 ІНТЕГРАЦІЯ З CLOUDFLARE WORKER

Після деплою оновити у Worker secrets:
- `REPLIT_BACKEND_URL` = `https://YOUR-REPLIT-URL.replit.app`
- `NOTEBOOKLM_BASE_URL` = `https://YOUR-REPLIT-URL.replit.app`

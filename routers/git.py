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

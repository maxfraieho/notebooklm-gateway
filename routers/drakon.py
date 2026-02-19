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
    message = f"\U0001f500 {action} DRAKON diagram: {req.name}"
    
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
    message = f"\U0001f5d1\ufe0f Delete DRAKON diagram: {diagram_id}"
    
    try:
        result = await delete_file(path, message)
        return {"success": True, "sha": result["commit"]["sha"], "path": path}
    except Exception as e:
        raise HTTPException(500, str(e))

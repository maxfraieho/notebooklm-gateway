from fastapi import HTTPException, Header
from config import settings

def verify_token(authorization: str = Header(...)):
    if not authorization.startswith("Bearer "):
        raise HTTPException(401, "Invalid authorization header")
    
    token = authorization.replace("Bearer ", "")
    if token != settings.SERVICE_TOKEN:
        raise HTTPException(401, "Invalid token")
    
    return token

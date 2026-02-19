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

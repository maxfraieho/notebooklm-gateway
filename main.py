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

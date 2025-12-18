from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from routers import auth, files, health

# App metadata
tags_metadata = [
    {"name": "auth", "description": "User authentication and management"},
    {"name": "files", "description": "File upload, read, and management"},
    {"name": "system", "description": "Health checks"}
]

app = FastAPI(
    title="File Storage API",
    description="Secure file upload and preview service",
    version="1.0.0",
    openapi_tags=tags_metadata,
    docs_url="/docs",
    redoc_url="/redoc"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"]
)

# Include routers
app.include_router(auth.router)
app.include_router(files.router)
app.include_router(health.router)

@app.get("/")
async def root():
    return {"message": "File Storage API - Go to /docs"}

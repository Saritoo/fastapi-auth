from fastapi import FastAPI, Depends, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import time
import uvicorn
from app.routers import auth
from app.config import PROJECT_NAME, VERSION, API_PREFIX

# Create FastAPI app instance
app = FastAPI(
    title=PROJECT_NAME,
    version=VERSION,
    description="Authentication API for user management"
)

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], 
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Request logging middleware
@app.middleware("http")
async def add_process_time_header(request: Request, call_next):
    start_time = time.time()
    response = await call_next(request)
    process_time = time.time() - start_time
    response.headers["X-Process-Time"] = str(process_time)
    return response

# Global exception handler
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    return JSONResponse(
        status_code=500,
        content={"status": "error", "message": f"Internal server error: {str(exc)}"},
    )

# Include routers
app.include_router(auth.router, prefix=API_PREFIX)

# Root endpoint
@app.get("/")
async def root():
    return {
        "status": "success",
        "message": f"Welcome to {PROJECT_NAME} API v{VERSION}",
        "docs_url": "/docs",
    }

# Health check endpoint
@app.get("/health")
async def health_check():
    return {"status": "healthy"}


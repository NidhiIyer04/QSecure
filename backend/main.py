from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from backend.api.routes_scan import router as scan_router


def create_app() -> FastAPI:
    app = FastAPI(
        title="QSecure API",
        description="Post-Quantum Cryptography Vulnerability Scanner",
        version="1.0.0",
    )

    # CORS (safe for production since frontend is served from same app)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=False,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Register API routes
    app.include_router(scan_router)

    # Health check endpoint
    @app.get("/health")
    async def health_check():
        return {"status": "ok"}

    return app


app = create_app()

# Serve frontend from same server (NO CORS ISSUES)
app.mount("/", StaticFiles(directory="frontend", html=True), name="frontend")
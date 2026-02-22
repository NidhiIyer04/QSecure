from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from backend.api.routes_scan import router as scan_router


def create_app() -> FastAPI:
    app = FastAPI(
        title="QSecure API",
        description="Post-Quantum Cryptography Vulnerability Scanner",
        version="1.0.0",
    )

    # CORS configuration (frontend on localhost:5500)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=[
            "http://localhost:5500",
            "http://127.0.0.1:5500",
        ],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Register routers
    app.include_router(scan_router)

    # Health check endpoint
    @app.get("/health")
    async def health_check():
        return {"status": "ok"}

    return app


app = create_app()
"""Email Threat Intelligence Platform API."""
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.routes import cases, health, ingest
from app.config import settings
from app.core.logging import setup_logging


def _origin(value: str) -> str:
    return value if value.startswith(("http://", "https://")) else f"https://{value}"


@asynccontextmanager
async def lifespan(app: FastAPI):
    setup_logging()
    yield


app = FastAPI(title=settings.app_name, version=settings.app_version, lifespan=lifespan)
cors_origins = [_origin(origin) for origin in [*settings.cors_origins, settings.frontend_url] if origin]
app.add_middleware(CORSMiddleware, allow_origins=cors_origins, allow_credentials=True, allow_methods=["*"], allow_headers=["*"])
app.include_router(health.router)
app.include_router(ingest.router)
app.include_router(cases.router)


@app.get("/")
def root() -> dict:
    return {"name": settings.app_name, "docs": "/docs", "status": "operational"}

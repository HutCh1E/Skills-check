"""
Skills Security Check API — Main Application Entry Point

A security analysis service for AI agent skills (plugins/extensions).
Uses three-layer analysis: static AST scanning, Qwen 3.5 Plus LLM
deep analysis, and Docker-based sandbox dynamic execution.

Startup modes:
    python -m app.main              # API + UI (default)
    python -m app.main --mode api   # API only
    python -m app.main --mode ui    # API + UI
"""

from __future__ import annotations

import argparse
import logging
import os

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

from app.api.routes import router

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-7s | %(name)s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Parse startup mode from env var (set by __main__)
# ---------------------------------------------------------------------------
STARTUP_MODE = os.environ.get("SKILLS_CHECK_MODE", "ui")  # "api" or "ui"


# ---------------------------------------------------------------------------
# Application
# ---------------------------------------------------------------------------

app = FastAPI(
    title="Skills Security Check API",
    description=(
        "AI Agent Skill 安全检测服务。\n\n"
        "对 AI Agent 的 Skill（技能/插件）源代码进行三层安全分析：\n"
        "1. **静态分析** — 基于 AST 的危险模式检测\n"
        "2. **LLM 分析** — Qwen 3.5 Plus 深度语义分析\n"
        "3. **沙箱分析** — Docker 隔离环境动态执行\n\n"
        "检测维度包括：反向 Shell、数据窃取、代码注入、文件系统滥用、"
        "加密挖矿、权限提升、混淆技术、供应链攻击等。"
    ),
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount API routes
app.include_router(router)

# ---------------------------------------------------------------------------
# UI mode: serve static files + SPA fallback
# ---------------------------------------------------------------------------
STATIC_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "static")

if STARTUP_MODE != "api" and os.path.isdir(STATIC_DIR):
    # Serve static assets (CSS, JS)
    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

    @app.get("/", include_in_schema=False)
    async def serve_ui():
        """Serve the web UI."""
        return FileResponse(os.path.join(STATIC_DIR, "index.html"))

    logger.info("🖥️  UI mode enabled — http://localhost:8000/")
else:
    @app.get("/", include_in_schema=False)
    async def root():
        return {
            "service": "Skills Security Check API",
            "version": "1.0.0",
            "docs": "/docs",
            "mode": "api-only",
        }

    logger.info("🔌 API-only mode — http://localhost:8000/docs")

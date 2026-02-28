"""
Skills Security Check API — Main Application Entry Point

A security analysis service for AI agent skills (plugins/extensions).
Uses three-layer analysis: static AST scanning, Qwen 3.5 Plus LLM
deep analysis, and Docker-based sandbox dynamic execution.
"""

from __future__ import annotations

import logging

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.routes import router

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-7s | %(name)s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)

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

# CORS — allow all origins for development
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount routes
app.include_router(router)


@app.get("/", include_in_schema=False)
async def root():
    """Root redirect to API docs."""
    return {
        "service": "Skills Security Check API",
        "version": "1.0.0",
        "docs": "/docs",
    }


if __name__ == "__main__":
    import uvicorn
    from app.core.config import settings

    uvicorn.run(
        "app.main:app",
        host=settings.api_host,
        port=settings.api_port,
        reload=True,
    )

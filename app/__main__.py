"""
Entry point for running the application:

    python -m app              # API + UI (default)
    python -m app --mode api   # API only
    python -m app --mode ui    # API + UI
    python -m app --port 9000  # Custom port
"""

import argparse
import os


def main():
    parser = argparse.ArgumentParser(
        description="Skills Security Check — AI Agent Skill 安全检测服务",
    )
    parser.add_argument(
        "--mode",
        choices=["ui", "api"],
        default="ui",
        help="启动模式: ui=Web界面+API (默认), api=仅API",
    )
    parser.add_argument(
        "--host",
        default="0.0.0.0",
        help="监听地址 (默认: 0.0.0.0)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8000,
        help="监听端口 (默认: 8000)",
    )
    parser.add_argument(
        "--reload",
        action="store_true",
        help="启用热重载 (开发模式)",
    )
    args = parser.parse_args()

    # Pass mode to the FastAPI app via env var
    os.environ["SKILLS_CHECK_MODE"] = args.mode

    import sys
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')

    mode_text = "Web UI + API" if args.mode == "ui" else "API Only"
    print(f"""
+----------------------------------------------+
|  Skills Security Check v1.0.0                |
|  AI Agent Skill Security Scanner             |
+----------------------------------------------+
|  Mode : {mode_text:<35s}|
|  URL  : http://{args.host}:{args.port:<24d}|
|  Docs : http://{args.host}:{args.port}/docs                 |
+----------------------------------------------+
""")

    import uvicorn
    uvicorn.run(
        "app.main:app",
        host=args.host,
        port=args.port,
        reload=args.reload,
    )


if __name__ == "__main__":
    main()

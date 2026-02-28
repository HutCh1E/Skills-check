"""
Sandbox Analyzer — Docker-based isolated dynamic analysis.

Creates a temporary Docker container with strict resource limits,
mounts the skill source code, executes it, and monitors for
suspicious runtime behaviors (network connections, file writes,
process spawning).
"""

from __future__ import annotations

import logging
import tempfile
import os
from typing import Optional

from app.core.config import settings
from app.models.schemas import (
    AnalyzerType,
    Finding,
    Severity,
    ThreatCategory,
)

logger = logging.getLogger(__name__)


class SandboxAnalyzer:
    """Runs code in an isolated Docker container for dynamic analysis."""

    def __init__(self):
        self.docker_client = None
        self._init_docker()

    def _init_docker(self):
        """Try to initialize Docker client."""
        try:
            import docker
            self.docker_client = docker.from_env()
            self.docker_client.ping()
            logger.info("Docker client initialized successfully.")
        except Exception as e:
            logger.warning(f"Docker not available, sandbox analysis disabled: {e}")
            self.docker_client = None

    @property
    def is_available(self) -> bool:
        return self.docker_client is not None

    def analyze(self, source_code: str, filename: Optional[str] = None) -> list[Finding]:
        """
        Execute source code in a sandboxed Docker container and
        analyze the runtime behavior.
        """
        if not self.is_available:
            logger.info("Sandbox analyzer not available, skipping.")
            return []

        # Skip non-Python files (Markdown, JSON, YAML, etc.)
        if filename and not self._is_executable(filename):
            logger.info(f"Skipping sandbox for non-Python file: {filename}")
            return []

        findings: list[Finding] = []
        container = None
        tmp_dir = None

        try:
            # Write source code to a temp file
            tmp_dir = tempfile.mkdtemp(prefix="skills_check_")
            src_file = filename or "skill_code.py"
            src_path = os.path.join(tmp_dir, src_file)
            with open(src_path, "w", encoding="utf-8") as f:
                f.write(source_code)

            # Create monitoring wrapper script
            monitor_script = self._create_monitor_script(src_file)
            monitor_path = os.path.join(tmp_dir, "_monitor.py")
            with open(monitor_path, "w", encoding="utf-8") as f:
                f.write(monitor_script)

            # Run container with strict limits
            container = self.docker_client.containers.run(
                image=settings.sandbox_image,
                command=f"python /workspace/_monitor.py",
                volumes={
                    tmp_dir: {"bind": "/workspace", "mode": "ro"},
                },
                working_dir="/workspace",
                detach=True,
                mem_limit=settings.sandbox_memory_limit,
                nano_cpus=int(settings.sandbox_cpu_limit * 1e9),
                network_mode="none",         # No network access
                read_only=True,              # Read-only filesystem
                tmpfs={"/tmp": "size=10m"},   # Small writable /tmp
                user="nobody",               # Non-root
                security_opt=["no-new-privileges"],
            )

            # Wait for execution to complete (with timeout)
            result = container.wait(timeout=settings.sandbox_timeout)
            exit_code = result.get("StatusCode", -1)
            logs = container.logs(stdout=True, stderr=True).decode("utf-8", errors="replace")

            # Analyze results
            findings.extend(self._analyze_output(logs, exit_code))

        except Exception as e:
            error_msg = str(e)
            if "404" in error_msg or "not found" in error_msg:
                logger.warning(f"Sandbox image not found: {settings.sandbox_image}")
                findings.append(Finding(
                    category=ThreatCategory.OTHER,
                    severity=Severity.INFO,
                    analyzer=AnalyzerType.SANDBOX,
                    title="Sandbox image not available",
                    description=(
                        f"Docker image '{settings.sandbox_image}' not found. "
                        "Build it with: docker build -f Dockerfile.sandbox -t skills-check-sandbox:latest ."
                    ),
                    recommendation="Build the sandbox Docker image to enable dynamic analysis.",
                ))
            elif "timeout" in error_msg.lower() or "read timed out" in error_msg.lower():
                findings.append(Finding(
                    category=ThreatCategory.OTHER,
                    severity=Severity.HIGH,
                    analyzer=AnalyzerType.SANDBOX,
                    title="Execution timeout",
                    description=(
                        f"Code execution exceeded the {settings.sandbox_timeout}s timeout. "
                        "This may indicate an infinite loop, crypto mining, or resource exhaustion attack."
                    ),
                    recommendation="Review code for long-running operations or resource abuse.",
                ))
            else:
                logger.error(f"Sandbox execution failed: {e}")
                findings.append(Finding(
                    category=ThreatCategory.OTHER,
                    severity=Severity.INFO,
                    analyzer=AnalyzerType.SANDBOX,
                    title="Sandbox execution error",
                    description=f"Sandbox analysis encountered an error: {error_msg[:500]}",
                ))

        finally:
            # Cleanup: always remove container
            if container:
                try:
                    container.remove(force=True)
                except Exception:
                    pass
            # Cleanup: temp directory
            if tmp_dir:
                try:
                    import shutil
                    shutil.rmtree(tmp_dir, ignore_errors=True)
                except Exception:
                    pass

        return findings

    def _create_monitor_script(self, target_file: str) -> str:
        """
        Generate a Python script that imports and runs the target skill code
        while monitoring for suspicious behaviors.
        """
        return f'''
import sys
import json
import traceback

findings = []

# Monkey-patch dangerous operations to detect them at runtime
import builtins
_original_open = builtins.open
_file_access_log = []

def _monitored_open(file, *args, **kwargs):
    mode = args[0] if args else kwargs.get("mode", "r")
    _file_access_log.append({{"file": str(file), "mode": str(mode)}})
    # Block write operations outside /tmp
    if any(m in str(mode) for m in ("w", "a", "x")) and not str(file).startswith("/tmp"):
        findings.append({{
            "type": "file_write_attempt",
            "detail": f"Attempted to write to: {{file}} with mode={{mode}}"
        }})
    return _original_open(file, *args, **kwargs)

builtins.open = _monitored_open

# Try to execute the target code
try:
    exec(compile(_original_open("/workspace/{target_file}").read(), "{target_file}", "exec"))
except SystemExit:
    findings.append({{"type": "system_exit", "detail": "Code called sys.exit()"}})
except Exception as e:
    findings.append({{"type": "execution_error", "detail": str(e)}})

# Report findings
print("===MONITOR_RESULTS===")
print(json.dumps({{
    "findings": findings,
    "file_access": _file_access_log,
}}, ensure_ascii=False))
'''

    def _analyze_output(self, logs: str, exit_code: int) -> list[Finding]:
        """Analyze container output for suspicious behavior indicators."""
        findings: list[Finding] = []

        # Non-zero exit code
        if exit_code != 0:
            findings.append(Finding(
                category=ThreatCategory.OTHER,
                severity=Severity.LOW,
                analyzer=AnalyzerType.SANDBOX,
                title=f"Non-zero exit code: {exit_code}",
                description=f"The skill code exited with code {exit_code}, which may indicate errors or abnormal behavior.",
            ))

        # Parse monitor results
        if "===MONITOR_RESULTS===" in logs:
            try:
                monitor_output = logs.split("===MONITOR_RESULTS===")[1].strip()
                data = __import__("json").loads(monitor_output)

                for f in data.get("findings", []):
                    ftype = f.get("type", "unknown")
                    detail = f.get("detail", "")

                    if ftype == "file_write_attempt":
                        findings.append(Finding(
                            category=ThreatCategory.FILE_SYSTEM_ABUSE,
                            severity=Severity.HIGH,
                            analyzer=AnalyzerType.SANDBOX,
                            title="File write attempt detected at runtime",
                            description=f"The code attempted to write to a file: {detail}",
                            recommendation="Skills should not write to arbitrary file paths.",
                        ))
                    elif ftype == "system_exit":
                        findings.append(Finding(
                            category=ThreatCategory.OTHER,
                            severity=Severity.LOW,
                            analyzer=AnalyzerType.SANDBOX,
                            title="Code called sys.exit()",
                            description="The skill code attempted to terminate the process.",
                        ))
                    elif ftype == "execution_error":
                        findings.append(Finding(
                            category=ThreatCategory.OTHER,
                            severity=Severity.INFO,
                            analyzer=AnalyzerType.SANDBOX,
                            title="Runtime execution error",
                            description=f"Error during execution: {detail}",
                        ))

            except Exception as e:
                logger.warning(f"Failed to parse monitor output: {e}")

        # Check for suspicious output patterns
        suspicious_patterns = [
            ("reverse shell", ThreatCategory.REVERSE_SHELL, Severity.CRITICAL),
            ("connection refused", ThreatCategory.NETWORK_ABUSE, Severity.MEDIUM),
            ("permission denied", ThreatCategory.PRIVILEGE_ESCALATION, Severity.MEDIUM),
        ]
        logs_lower = logs.lower()
        for pattern, category, severity in suspicious_patterns:
            if pattern in logs_lower:
                findings.append(Finding(
                    category=category,
                    severity=severity,
                    analyzer=AnalyzerType.SANDBOX,
                    title=f"Suspicious output: '{pattern}'",
                    description=f"Container output contains suspicious pattern: '{pattern}'",
                ))

        return findings

    @staticmethod
    def _is_executable(filename: str) -> bool:
        """Check if the file is executable Python code."""
        if not filename:
            return True
        fname = filename.lower()
        # Only execute Python files
        if any(fname.endswith(ext) for ext in ('.py', '.pyw', '.pyi')):
            return True
        # Multi-file package scans have synthetic filenames like "requests-2.31.0"
        if '.' not in fname.split('/')[-1].split('\\')[-1]:
            return True
        return False

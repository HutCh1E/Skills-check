"""
Static Analyzer — AST-based security pattern detection.

Parses Python source code into an AST and walks the tree looking for
dangerous patterns: reverse shells, data exfiltration, code injection,
file system abuse, crypto mining indicators, and privilege escalation.
"""

from __future__ import annotations

import ast
import re
from typing import Optional

from app.models.schemas import (
    AnalyzerType,
    Finding,
    Severity,
    ThreatCategory,
)

# ---------------------------------------------------------------------------
# Dangerous pattern definitions
# ---------------------------------------------------------------------------

# Functions / attributes that indicate dynamic code execution
CODE_INJECTION_NAMES = {"eval", "exec", "compile", "__import__", "execfile"}

# Modules commonly used in reverse shells
SHELL_MODULES = {"socket", "subprocess", "pty", "telnetlib", "paramiko"}

# Suspicious shell commands
SHELL_COMMANDS = re.compile(
    r"(bash\s+-i|/bin/(ba)?sh|nc\s+-|ncat\s|netcat\s|"
    r"mkfifo|/dev/tcp/|python\s+-c\s+['\"]import\s+socket|"
    r"powershell\s+-e|cmd\.exe)",
    re.IGNORECASE,
)

# Sensitive file paths
SENSITIVE_PATHS = re.compile(
    r"(/etc/passwd|/etc/shadow|~?/\.ssh/|\.aws/credentials|"
    r"\.env|\.git/config|/proc/self|/dev/shm|"
    r"id_rsa|authorized_keys|known_hosts)",
    re.IGNORECASE,
)

# Environment variable / secret keywords
SECRET_KEYWORDS = re.compile(
    r"(api[_-]?key|api[_-]?secret|password|token|secret|"
    r"credentials|private[_-]?key|access[_-]?key)",
    re.IGNORECASE,
)

# Mining pool domains & keywords
MINING_INDICATORS = re.compile(
    r"(stratum\+tcp://|pool\.|xmrig|minerd|minergate|coinhive|"
    r"cryptonight|hashrate|nonce|difficulty_target)",
    re.IGNORECASE,
)

# Network exfiltration patterns
EXFIL_FUNCTIONS = {
    "requests.post", "requests.put", "requests.patch",
    "urllib.request.urlopen", "urllib.request.Request",
    "http.client.HTTPConnection", "http.client.HTTPSConnection",
    "httpx.post", "httpx.put",
    "aiohttp.ClientSession",
}

# Privilege escalation indicators
PRIV_ESC_NAMES = {"setuid", "setgid", "seteuid", "setegid", "setreuid", "setregid"}
PRIV_ESC_MODULES = {"ctypes", "ctypes.windll"}


class StaticAnalyzer:
    """Performs AST-based static analysis on Python source code."""

    def __init__(self):
        self.findings: list[Finding] = []

    def analyze(self, source_code: str) -> list[Finding]:
        """Run all static checks and return findings."""
        self.findings = []
        self._check_string_patterns(source_code)

        try:
            tree = ast.parse(source_code)
        except SyntaxError as e:
            self.findings.append(Finding(
                category=ThreatCategory.OTHER,
                severity=Severity.INFO,
                analyzer=AnalyzerType.STATIC,
                title="Syntax error in source code",
                description=f"Could not parse source code: {e}",
                line_number=e.lineno,
            ))
            return self.findings

        self._walk_ast(tree, source_code)
        return self.findings

    # ------------------------------------------------------------------
    # String-level pattern checks (before AST parsing)
    # ------------------------------------------------------------------

    def _check_string_patterns(self, source_code: str):
        """Check raw source code for suspicious string patterns."""
        lines = source_code.splitlines()

        for lineno, line in enumerate(lines, start=1):
            stripped = line.strip()
            if stripped.startswith("#"):
                continue

            # Shell commands
            match = SHELL_COMMANDS.search(line)
            if match:
                self.findings.append(Finding(
                    category=ThreatCategory.REVERSE_SHELL,
                    severity=Severity.CRITICAL,
                    analyzer=AnalyzerType.STATIC,
                    title="Suspicious shell command detected",
                    description=f"Found potential reverse shell / shell command pattern: `{match.group()}`",
                    line_number=lineno,
                    code_snippet=stripped,
                    recommendation="Review whether this shell command is necessary. Remove if not required.",
                ))

            # Sensitive paths
            match = SENSITIVE_PATHS.search(line)
            if match:
                self.findings.append(Finding(
                    category=ThreatCategory.FILE_SYSTEM_ABUSE,
                    severity=Severity.HIGH,
                    analyzer=AnalyzerType.STATIC,
                    title="Access to sensitive file path",
                    description=f"Code references sensitive path: `{match.group()}`",
                    line_number=lineno,
                    code_snippet=stripped,
                    recommendation="Avoid accessing system sensitive files. Use secure configuration management instead.",
                ))

            # Mining indicators
            match = MINING_INDICATORS.search(line)
            if match:
                self.findings.append(Finding(
                    category=ThreatCategory.CRYPTO_MINING,
                    severity=Severity.CRITICAL,
                    analyzer=AnalyzerType.STATIC,
                    title="Crypto mining indicator detected",
                    description=f"Found crypto mining related pattern: `{match.group()}`",
                    line_number=lineno,
                    code_snippet=stripped,
                    recommendation="Crypto mining code should not appear in agent skills.",
                ))

    # ------------------------------------------------------------------
    # AST walk
    # ------------------------------------------------------------------

    def _walk_ast(self, tree: ast.AST, source_code: str):
        """Walk the AST and apply all node-level checks."""
        lines = source_code.splitlines()

        for node in ast.walk(tree):
            self._check_dangerous_calls(node, lines)
            self._check_imports(node, lines)
            self._check_attribute_access(node, lines)
            self._check_os_environ(node, lines)
            self._check_subprocess(node, lines)
            self._check_network_calls(node, lines)

    def _get_snippet(self, lines: list[str], lineno: Optional[int]) -> Optional[str]:
        if lineno and 0 < lineno <= len(lines):
            return lines[lineno - 1].strip()
        return None

    # --- Dangerous built-in calls ---

    def _check_dangerous_calls(self, node: ast.AST, lines: list[str]):
        if not isinstance(node, ast.Call):
            return

        func_name = self._resolve_call_name(node)
        if func_name in CODE_INJECTION_NAMES:
            self.findings.append(Finding(
                category=ThreatCategory.CODE_INJECTION,
                severity=Severity.CRITICAL,
                analyzer=AnalyzerType.STATIC,
                title=f"Dangerous function call: {func_name}()",
                description=(
                    f"`{func_name}()` allows arbitrary code execution. "
                    "This is one of the most common vectors for malicious skills."
                ),
                line_number=getattr(node, "lineno", None),
                code_snippet=self._get_snippet(lines, getattr(node, "lineno", None)),
                recommendation=f"Avoid using `{func_name}()`. Use safe alternatives.",
            ))

        # os.system / os.popen
        if func_name in {"os.system", "os.popen", "os.exec", "os.execvp", "os.execve"}:
            self.findings.append(Finding(
                category=ThreatCategory.REVERSE_SHELL,
                severity=Severity.HIGH,
                analyzer=AnalyzerType.STATIC,
                title=f"OS command execution: {func_name}()",
                description=f"`{func_name}()` can execute arbitrary OS commands.",
                line_number=getattr(node, "lineno", None),
                code_snippet=self._get_snippet(lines, getattr(node, "lineno", None)),
                recommendation="Use subprocess with a whitelist of allowed commands instead.",
            ))

    # --- Import checks ---

    def _check_imports(self, node: ast.AST, lines: list[str]):
        module_name = None

        if isinstance(node, ast.Import):
            for alias in node.names:
                module_name = alias.name
        elif isinstance(node, ast.ImportFrom):
            module_name = node.module or ""

        if not module_name:
            return

        top_module = module_name.split(".")[0]

        if top_module in SHELL_MODULES:
            severity = Severity.MEDIUM
            if top_module in ("socket", "pty"):
                severity = Severity.HIGH

            self.findings.append(Finding(
                category=ThreatCategory.REVERSE_SHELL,
                severity=severity,
                analyzer=AnalyzerType.STATIC,
                title=f"Suspicious module import: {module_name}",
                description=(
                    f"Module `{module_name}` is commonly used in reverse shells "
                    "and remote access tools."
                ),
                line_number=getattr(node, "lineno", None),
                code_snippet=self._get_snippet(lines, getattr(node, "lineno", None)),
                recommendation="Verify this import is genuinely needed for the skill's purpose.",
            ))

        if top_module in PRIV_ESC_MODULES:
            self.findings.append(Finding(
                category=ThreatCategory.PRIVILEGE_ESCALATION,
                severity=Severity.HIGH,
                analyzer=AnalyzerType.STATIC,
                title=f"Low-level system access module: {module_name}",
                description=f"Module `{module_name}` can be used for privilege escalation.",
                line_number=getattr(node, "lineno", None),
                code_snippet=self._get_snippet(lines, getattr(node, "lineno", None)),
                recommendation="Skills should not require low-level system access.",
            ))

    # --- Attribute access checks ---

    def _check_attribute_access(self, node: ast.AST, lines: list[str]):
        if not isinstance(node, ast.Attribute):
            return
        attr = node.attr
        if attr in PRIV_ESC_NAMES:
            self.findings.append(Finding(
                category=ThreatCategory.PRIVILEGE_ESCALATION,
                severity=Severity.CRITICAL,
                analyzer=AnalyzerType.STATIC,
                title=f"Privilege escalation attempt: {attr}()",
                description=f"Call to `{attr}` can change process privileges.",
                line_number=getattr(node, "lineno", None),
                code_snippet=self._get_snippet(lines, getattr(node, "lineno", None)),
                recommendation="Skills must not attempt to escalate privileges.",
            ))

    # --- os.environ access (potential data exfiltration prep) ---

    def _check_os_environ(self, node: ast.AST, lines: list[str]):
        if not isinstance(node, ast.Attribute):
            return
        if node.attr == "environ" and isinstance(node.value, ast.Name) and node.value.id == "os":
            self.findings.append(Finding(
                category=ThreatCategory.DATA_EXFILTRATION,
                severity=Severity.MEDIUM,
                analyzer=AnalyzerType.STATIC,
                title="Access to environment variables",
                description=(
                    "`os.environ` access may be used to steal API keys, tokens, "
                    "or other secrets from the host environment."
                ),
                line_number=getattr(node, "lineno", None),
                code_snippet=self._get_snippet(lines, getattr(node, "lineno", None)),
                recommendation="Skills should declare required config explicitly, not read arbitrary env vars.",
            ))

    # --- subprocess checks ---

    def _check_subprocess(self, node: ast.AST, lines: list[str]):
        if not isinstance(node, ast.Call):
            return
        func_name = self._resolve_call_name(node)
        if not func_name or not func_name.startswith("subprocess."):
            return

        # Check for shell=True
        for kw in node.keywords:
            if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                self.findings.append(Finding(
                    category=ThreatCategory.REVERSE_SHELL,
                    severity=Severity.CRITICAL,
                    analyzer=AnalyzerType.STATIC,
                    title="Subprocess with shell=True",
                    description=(
                        "`subprocess` called with `shell=True` enables command injection "
                        "and is a common reverse shell vector."
                    ),
                    line_number=getattr(node, "lineno", None),
                    code_snippet=self._get_snippet(lines, getattr(node, "lineno", None)),
                    recommendation="Never use `shell=True`. Pass commands as a list.",
                ))
                return

        # General subprocess usage
        self.findings.append(Finding(
            category=ThreatCategory.REVERSE_SHELL,
            severity=Severity.MEDIUM,
            analyzer=AnalyzerType.STATIC,
            title=f"Subprocess usage: {func_name}()",
            description="Subprocess calls can execute arbitrary system commands.",
            line_number=getattr(node, "lineno", None),
            code_snippet=self._get_snippet(lines, getattr(node, "lineno", None)),
            recommendation="Review subprocess usage carefully. Consider removing if not essential.",
        ))

    # --- Network / exfiltration calls ---

    def _check_network_calls(self, node: ast.AST, lines: list[str]):
        if not isinstance(node, ast.Call):
            return
        func_name = self._resolve_call_name(node)
        if func_name in EXFIL_FUNCTIONS:
            self.findings.append(Finding(
                category=ThreatCategory.DATA_EXFILTRATION,
                severity=Severity.HIGH,
                analyzer=AnalyzerType.STATIC,
                title=f"Outbound network call: {func_name}()",
                description=(
                    f"`{func_name}()` can send data to external servers. "
                    "This may be used for data exfiltration."
                ),
                line_number=getattr(node, "lineno", None),
                code_snippet=self._get_snippet(lines, getattr(node, "lineno", None)),
                recommendation=(
                    "Verify the destination is trusted. "
                    "Skills should not send data to unknown external endpoints."
                ),
            ))

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _resolve_call_name(node: ast.Call) -> Optional[str]:
        """Resolve a Call node to a dotted name string like 'os.system'."""
        func = node.func
        if isinstance(func, ast.Name):
            return func.id
        if isinstance(func, ast.Attribute):
            parts = []
            current = func
            while isinstance(current, ast.Attribute):
                parts.append(current.attr)
                current = current.value
            if isinstance(current, ast.Name):
                parts.append(current.id)
            return ".".join(reversed(parts))
        return None

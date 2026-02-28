"""
LLM Analyzer — Qwen 3.5 Plus powered deep semantic analysis.

Sends source code to Qwen 3.5 Plus via DashScope's OpenAI-compatible API,
using a security-focused system prompt. The model identifies obfuscated
threats, social engineering in comments, and logic bombs that static
analysis might miss.
"""

from __future__ import annotations

import json
import logging
from typing import Optional

from openai import OpenAI

from app.core.config import settings
from app.models.schemas import (
    AnalyzerType,
    Finding,
    Severity,
    ThreatCategory,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# System prompt for security analysis
# ---------------------------------------------------------------------------

SECURITY_SYSTEM_PROMPT = """你是一位专业的 AI Agent Skill 安全审计专家。你的任务是对提交的代码进行深度安全分析，识别潜在的安全威胁。

## 分析维度

请从以下维度分析代码：

1. **反向 Shell / 远程控制**：代码是否试图建立反向连接、远程控制通道？
2. **数据窃取**：代码是否试图读取并外传敏感数据（环境变量、密钥、凭证等）？
3. **代码注入**：代码是否使用了 eval/exec 等动态执行危险函数？是否有混淆的恶意代码？
4. **文件系统滥用**：代码是否试图访问系统敏感文件或进行未授权的文件操作？
5. **权限提升**：代码是否试图获取更高的系统权限？
6. **供应链攻击**：代码是否引入可疑的第三方依赖？是否有后门式的依赖注入？
7. **混淆与隐藏**：是否使用 base64 编码、字符串拼接、变量名混淆等方式隐藏恶意意图？
8. **逻辑炸弹**：是否有基于时间、条件触发的隐藏恶意行为？
9. **社会工程**：注释或文档中是否包含误导性描述，试图掩盖真实行为？

## 输出格式

请以 JSON 数组格式输出发现的安全问题，每个问题包含以下字段：

```json
[
  {
    "category": "threat_category",
    "severity": "critical|high|medium|low|info",
    "title": "问题简述",
    "description": "详细描述",
    "line_number": 123,
    "code_snippet": "相关代码片段",
    "recommendation": "修复建议"
  }
]
```

category 可选值：reverse_shell, data_exfiltration, file_system_abuse, code_injection, crypto_mining, privilege_escalation, network_abuse, obfuscation, supply_chain, other

如果代码没有安全问题，请返回空数组 `[]`。

## 重要提示

- 只报告真正的安全风险，不要误报正常的代码模式
- 对于混淆代码，尝试还原其真实意图
- 注意"看起来无害但实际上是恶意的"代码模式
- 关注代码的真实行为，而非表面功能描述
"""


# ---------------------------------------------------------------------------
# Mapping from LLM response category strings to our enum
# ---------------------------------------------------------------------------

CATEGORY_MAP = {
    "reverse_shell": ThreatCategory.REVERSE_SHELL,
    "data_exfiltration": ThreatCategory.DATA_EXFILTRATION,
    "file_system_abuse": ThreatCategory.FILE_SYSTEM_ABUSE,
    "code_injection": ThreatCategory.CODE_INJECTION,
    "crypto_mining": ThreatCategory.CRYPTO_MINING,
    "privilege_escalation": ThreatCategory.PRIVILEGE_ESCALATION,
    "network_abuse": ThreatCategory.NETWORK_ABUSE,
    "obfuscation": ThreatCategory.OBFUSCATION,
    "supply_chain": ThreatCategory.SUPPLY_CHAIN,
    "other": ThreatCategory.OTHER,
}

SEVERITY_MAP = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
}


class LLMAnalyzer:
    """Uses Qwen 3.5 Plus for deep semantic security analysis."""

    def __init__(self):
        self.client: Optional[OpenAI] = None
        self._init_client()

    def _init_client(self):
        """Initialize the OpenAI-compatible client for DashScope."""
        if not settings.dashscope_api_key:
            logger.warning("DASHSCOPE_API_KEY not set — LLM analysis disabled.")
            return
        self.client = OpenAI(
            api_key=settings.dashscope_api_key,
            base_url=settings.dashscope_base_url,
        )

    @property
    def is_available(self) -> bool:
        return self.client is not None

    def analyze(self, source_code: str, filename: Optional[str] = None) -> list[Finding]:
        """
        Send source code to Qwen 3.5 Plus for security analysis.
        Returns a list of Finding objects.
        """
        if not self.is_available:
            logger.info("LLM analyzer not available, skipping.")
            return []

        prompt = f"请分析以下代码的安全性：\n\n"
        if filename:
            prompt += f"文件名: {filename}\n\n"
        prompt += f"```python\n{source_code}\n```"

        try:
            response = self.client.chat.completions.create(
                model=settings.qwen_model,
                messages=[
                    {"role": "system", "content": SECURITY_SYSTEM_PROMPT},
                    {"role": "user", "content": prompt},
                ],
                temperature=0.1,
                max_tokens=4096,
                response_format={"type": "json_object"},
                extra_body={
                    "enable_thinking": False,
                },
            )

            content = response.choices[0].message.content
            return self._parse_response(content)

        except Exception as e:
            logger.error(f"LLM analysis failed: {e}")
            return [Finding(
                category=ThreatCategory.OTHER,
                severity=Severity.INFO,
                analyzer=AnalyzerType.LLM,
                title="LLM analysis error",
                description=f"LLM analysis encountered an error: {str(e)}",
                recommendation="Retry the scan or check LLM API configuration.",
            )]

    def _parse_response(self, content: str) -> list[Finding]:
        """Parse the LLM JSON response into Finding objects."""
        findings: list[Finding] = []

        try:
            data = json.loads(content)

            # Handle both direct array and {"findings": [...]} formats
            if isinstance(data, list):
                items = data
            elif isinstance(data, dict):
                items = data.get("findings", data.get("issues", data.get("results", [])))
                if not isinstance(items, list):
                    items = [data]
            else:
                return findings

            for item in items:
                if not isinstance(item, dict):
                    continue

                category = CATEGORY_MAP.get(
                    item.get("category", "other"),
                    ThreatCategory.OTHER
                )
                severity = SEVERITY_MAP.get(
                    item.get("severity", "medium"),
                    Severity.MEDIUM
                )

                findings.append(Finding(
                    category=category,
                    severity=severity,
                    analyzer=AnalyzerType.LLM,
                    title=item.get("title", "LLM detected issue"),
                    description=item.get("description", ""),
                    line_number=item.get("line_number"),
                    code_snippet=item.get("code_snippet"),
                    recommendation=item.get("recommendation"),
                ))

        except json.JSONDecodeError:
            logger.warning("Failed to parse LLM response as JSON, extracting text.")
            if content.strip():
                findings.append(Finding(
                    category=ThreatCategory.OTHER,
                    severity=Severity.MEDIUM,
                    analyzer=AnalyzerType.LLM,
                    title="LLM analysis result (unparsed)",
                    description=content[:2000],
                    recommendation="Review the LLM analysis output manually.",
                ))

        return findings

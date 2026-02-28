# Skills Security Check API

AI Agent Skill 安全检测服务 — 对 AI Agent 的技能/插件源代码进行自动化安全分析。

## ✨ 功能特性

### 三层安全分析

| 分析层 | 技术 | 说明 |
|---|---|---|
| **静态分析** | Python AST | 基于抽象语法树的危险模式匹配，零延迟 |
| **LLM 分析** | Qwen 3.5 Plus | 深度语义分析，识别混淆代码、逻辑炸弹等高级威胁 |
| **沙箱分析** | Docker 隔离环境 | 在受限容器中动态执行，监控运行时行为 |

### 检测维度

- 🔴 **反向 Shell** — `socket.connect`、`subprocess` shell=True、`bash -i` 等
- 🟠 **数据窃取** — 环境变量读取、`requests.post` 外传敏感信息
- 🔴 **代码注入** — `eval()`、`exec()`、`compile()`、`__import__()`
- 🟠 **文件系统滥用** — 访问 `~/.ssh/`、`/etc/passwd`、`.aws/credentials`
- 🔴 **加密挖矿** — 矿池域名、xmrig 等挖矿工具特征
- 🟠 **权限提升** — `os.setuid`、`ctypes` 内核调用
- 🟡 **混淆技术** — base64 编码、字符串拼接隐藏恶意意图
- 🟡 **供应链攻击** — 可疑第三方依赖注入

## 🚀 快速开始

### 1. 安装依赖

```bash
pip install -r requirements.txt
```

### 2. 配置环境变量

```bash
cp .env.example .env
# 编辑 .env 填入你的 DASHSCOPE_API_KEY
```

> 从 [阿里云 DashScope](https://dashscope.console.aliyun.com/) 获取 API Key

### 3. 启动服务

```bash
python -m uvicorn app.main:app --reload
```

访问 http://localhost:8000/docs 查看 Swagger API 文档。

### 4. (可选) 构建沙箱镜像

```bash
docker build -f Dockerfile.sandbox -t skills-check-sandbox:latest .
```

## 📡 API 接口

### `POST /api/v1/scan` — 提交代码扫描

```bash
curl -X POST http://localhost:8000/api/v1/scan \
  -H "Content-Type: application/json" \
  -d '{
    "source_code": "import socket\ns = socket.socket()",
    "enable_llm": true,
    "enable_sandbox": false
  }'
```

**响应示例：**

```json
{
  "scan_id": "a1b2c3d4...",
  "risk_score": 65,
  "risk_level": "high",
  "summary": "⚠️ HIGH RISK — Significant security issues found...",
  "findings": [
    {
      "category": "reverse_shell",
      "severity": "high",
      "title": "Suspicious module import: socket",
      "description": "Module `socket` is commonly used in reverse shells...",
      "line_number": 1,
      "recommendation": "Verify this import is genuinely needed."
    }
  ],
  "stats": {
    "total_findings": 1,
    "analyzers_used": ["static", "llm"]
  }
}
```

### `POST /api/v1/scan/file` — 上传文件扫描

```bash
curl -X POST http://localhost:8000/api/v1/scan/file \
  -F "file=@skill.py" \
  -F "enable_llm=true"
```

### `GET /api/v1/scan/{scan_id}` — 查询扫描结果

### `GET /api/v1/health` — 健康检查

## 🧪 测试

```bash
python -m pytest tests/ -v
```

## 📁 项目结构

```
skills-check/
├── app/
│   ├── api/
│   │   └── routes.py          # API 路由与请求处理
│   ├── analyzers/
│   │   ├── static_analyzer.py # AST 静态分析引擎
│   │   ├── llm_analyzer.py    # Qwen 3.5 Plus LLM 分析
│   │   └── sandbox_analyzer.py# Docker 沙箱动态分析
│   ├── core/
│   │   ├── config.py          # 配置管理
│   │   └── scoring.py         # 风险评分算法
│   ├── models/
│   │   └── schemas.py         # Pydantic 数据模型
│   └── main.py                # FastAPI 入口
├── tests/                     # 测试用例
├── Dockerfile.sandbox         # 沙箱镜像
├── docker-compose.yml         # Docker Compose 配置
├── requirements.txt           # Python 依赖
└── .env.example               # 环境变量模板
```

## ⚙️ 技术栈

- **API 框架**: FastAPI + Uvicorn
- **大模型**: Qwen 3.5 Plus (via DashScope OpenAI-compatible API)
- **沙箱隔离**: Docker (网络隔离 + 资源限制 + 只读文件系统)
- **静态分析**: Python AST + 正则模式匹配
- **数据校验**: Pydantic v2

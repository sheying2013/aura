// Modal Logic
function openModal(id) {
    const el = document.getElementById(id);
    if (el) el.classList.add('active');
    // 打开导入弹窗时初始化 ss 密码框显隐联动
    if (id === 'import-modal') toggleImportPassField();
    if (id === 'edit-modal') toggleEditEntryPassField();
}
function closeModal(id) {
    const el = document.getElementById(id);
    if (el) el.classList.remove('active');
}

// --- i18n Engine ---
const I18N_DICT = {
    "Dashboard": "仪表盘",
    "Proxy Nodes": "节点列表",
    "Batch Import": "批量导入",
    "Subscriptions": "订阅管理",
    "Domain Relay": "域名解析轮询入口",
    "Config Preview": "配置预览",
    "Export Nodes": "导出节点",
    "Traffic Stats": "流量统计",
    "System Logs": "实时系统日志",
    "Settings": "系统设置",
    "System Operational": "系统运行正常",
    "UPTIME:": "运行时间:",
    "LOGIN / AUTH": "系统访问需身份验证",
    "LOGOUT": "↪ 退出登录",
    "AUTHENTICATING...": "验证中...",
    "ACCESS GRANTED": "验证成功",
    "INITIALIZE LINK": "登 录",
    "USERNAME": "用户名",
    "PASSWORD": "密码",
    "SECURE PROXY MANAGER": "节点管理系统",
    "AURA SYSTEM": "Aura - 节点管理系统",
    "Traffic Overview": "流量概览",
    "REAL-TIME DATA STREAM MONITORING": "中转引擎实时流量感知中",
    "Node Matrix": "节点在线矩阵",
    "PROXY INFRASTRUCTURE MANAGEMENT": "节点管理系统",
    "Sync Sources": "订阅管理",
    "EXTERNAL SUBSCRIPTION MANAGEMENT": "订阅管理",
    "Domain Load Balancer Entries": "多域名解析轮询中转入口",
    "MULTI-DOMAIN LOAD BALANCER & ROUTING": "多域名解析轮询中转入口",
    "Generated Sing-Box Config": "生成完整的配置文件 (config.json)",
    "SING-BOX CONFIGURATION (CONFIG.JSON)": "生成完整的配置文件 (config.json)",
    "EXPORT FORMATTED NODE LINKS": "导出格式化节点链接",
    "Per-Node Traffic Consumption": "全节点流量监控与重置",
    "NODE TRAFFIC CONSUMPTION & RESET": "全节点流量监控与重置",
    "System Dispatch Logs": "系统运行与端口调度日志",
    "REAL-TIME ENGINE & SCHEDULER LOGS": "系统运行与端口调度日志",
    "Core Settings": "系统设置",
    "SYSTEM & RELAY PARAMETERS": "端口冲突防范与网络参数",
    "IMPORT EXTERNAL NODES & SUBSCRIPTIONS": "批量导入外部节点",
    "INBOUND PORTS:": "入站监听:",
    "TOTAL NODES:": "出站节点:",
    "PROXY POOL:": "代理池:",
    "NORMAL NODES:": "普通:", "PREMIUM NODES:": "优质:",
    "ONLINE NODES:": "在线节点:",
    "AVG LATENCY:": "平均延迟:",
    "TOTAL TRAFFIC:": "总流量:",
    "Downlink Volume": "实时下行速率 (DOWN)",
    "Realtime Downward Throughput": "实时下行速率 (DOWN)",
    "Uplink Volume": "实时上行速率 (UP)",
    "Realtime Upward Throughput": "实时上行速率 (UP)",
    "Active Conns": "活跃连接",
    "Established Outbound Sessions": "已建立的出站会话",
    "Relay Exit Status": "端口轮询出口状态",
    "Socks5 Load Balancing Engine": "Socks5 负载均衡中转",
    "Avg Speed": "平均速率",
    "Peak Speed": "峰值速率",
    "Total Throughput": "当前总速率",
    "Today Traffic": "今日消耗流量",
    "Node Status Matrix & Ratio": "节点在线矩阵",
    "ONLINE RATE": "在线率",
    "[ Realtime Ink Wave Chart Area ]": "📈 实时流量曲线",
    "ONLINE 0 / TOTAL 0": "在线 0 / 总数 0",
    "Group:": "分组筛选:",
    "ALL GROUPS": "全部分组",
    "Rename": "重命名",
    "Convert Entry": "↔ 转换入口协议",
    "Reassign Ports": "重新编排端口",
    "Export Selected": "导出选中节点",
    "Enable Selected": "启用选中",
    "Enable All": "全部启用",
    "Disable Selected": "全选停用",
    "Delete Selected": "批量删除",
    "Probe All": "批量探活",
    "Import Nodes": "导入新节点",
    "Search Node / IP / Port...": "搜索节点名称/IP/端口...",
    "Status": "状态",
    "Port": "端口",
    "Group": "分组",
    "Protocol": "协议",
    "Entry": "入口",
    "Identity (Name)": "节点备注",
    "IP Quality": "IP 质量",
    "Latency": "延迟",
    "Traffic": "流量",
    "Actions": "操作",
    "Online": "在线",
    "Offline": "离线",
    "PING": "测活",
    "EDIT": "编辑",
    "DISABLE": "停用",
    "ENABLE": "启用",
    "DROP": "删除",
    "EXPORT": "导出",
    "RESET": "重置",
    "SYNC": "刷新",
    "Subscription URL": "订阅链接（URL）",
    "Sub Name (Optional)": "订阅名称(可选)",
    "ADD SUBSCRIPTION": "添加订阅",
    "ADD SOURCE": "添加订阅",
    "Batch Import External Node URIs": "批量导入外部节点",
    "Convert Entry Protocol": "批量转换入口协议",
    "Edit Node Parameters": "编辑节点",
    "Edit Subscription Parameters": "编辑订阅",
    "+ ADD RELAY DOMAIN": "＋ 添加轮询域名",
    "COPY JSON": "复制 JSON",
    "DOWNLOAD CONFIG.JSON": "下载 config.json",
    "Filter Group": "按分组导出:",
    "COPY ALL LINKS": "复制全部导出链接",
    "RESET ALL TRAFFIC": "清空所有节点流量",
    "CLEAR LOGS": "清空日志",
    "Current Password": "当前密码",
    "New Password": "新密码（至少 6 位）",
    "Confirm New Password": "确认新密码",
    "CHANGE PASSWORD": "修改密码",
    "APPLY CHANGES": "保存修改",
    "Authentication Required": "系统访问需身份验证",
    "CANCEL": "取消",
    "LOGIN": "登 录"
};

let currentLang = localStorage.getItem('aura_lang') || 'zh';

function saveOriginalTexts(node) {
    if (node.nodeType === 3) {
        let text = node.nodeValue.trim();
        if (text.length > 0 && !node.parentElement.hasAttribute('data-orig-text')) {
            node.parentElement.setAttribute('data-orig-text', text);
        }
    } else if (node.nodeType === 1) {
        if (node.tagName !== 'SCRIPT' && node.tagName !== 'STYLE' && node.tagName !== 'CANVAS') {
            if (node.hasAttribute('placeholder') && !node.hasAttribute('data-orig-placeholder')) {
                node.setAttribute('data-orig-placeholder', node.getAttribute('placeholder'));
            }
            if (node.hasAttribute('data-text') && !node.hasAttribute('data-orig-data-text')) {
                node.setAttribute('data-orig-data-text', node.getAttribute('data-text'));
            }
            if (node.childNodes) {
                for (let i = 0; i < node.childNodes.length; i++) {
                    saveOriginalTexts(node.childNodes[i]);
                }
            }
        }
    }
}

function applyTranslation(node) {
    if (node.nodeType === 1) {
        if (node.tagName !== 'SCRIPT' && node.tagName !== 'STYLE' && node.tagName !== 'CANVAS') {
            if (node.hasAttribute('data-orig-text')) {
                let orig = node.getAttribute('data-orig-text');
                if (I18N_DICT[orig]) {
                    for (let i = 0; i < node.childNodes.length; i++) {
                        if (node.childNodes[i].nodeType === 3 && node.childNodes[i].nodeValue.trim() !== '') {
                            node.childNodes[i].nodeValue = currentLang === 'zh' ? I18N_DICT[orig] : orig;
                            break;
                        }
                    }
                }
            }
            if (node.hasAttribute('data-orig-placeholder')) {
                let orig = node.getAttribute('data-orig-placeholder');
                if (I18N_DICT[orig]) {
                    node.setAttribute('placeholder', currentLang === 'zh' ? I18N_DICT[orig] : orig);
                }
            }
            if (node.hasAttribute('data-orig-data-text')) {
                let orig = node.getAttribute('data-orig-data-text');
                if (I18N_DICT[orig]) {
                    const newText = currentLang === 'zh' ? I18N_DICT[orig] : orig;
                    node.setAttribute('data-text', newText);
                    if (node.classList.contains('scramble-text')) {
                        new TextScramble(node).setText(newText);
                    }
                }
            }
            if (node.childNodes) {
                for (let i = 0; i < node.childNodes.length; i++) {
                    applyTranslation(node.childNodes[i]);
                }
            }
        }
    }
}

function setLanguage(lang) {
    currentLang = lang;
    localStorage.setItem('aura_lang', lang);
    const langIcon = document.getElementById('lang-icon');
    if (langIcon) langIcon.innerText = lang === 'zh' ? "AURA / EN" : "AURA / 中文";
    applyTranslation(document.body);
    // 页面标题随语言切换（title 无 data-orig，直接映射）
    const titleZh = I18N_DICT['AURA SYSTEM'] || 'Aura - 节点管理系统';
    document.title = lang === 'zh' ? titleZh : 'AURA SYSTEM';
}

const btnLang = document.getElementById('btn-lang');
if (btnLang) {
    btnLang.addEventListener('click', () => {
        setLanguage(currentLang === 'en' ? 'zh' : 'en');
    });
}

// Theme Toggle Logic
const btnTheme = document.getElementById('btn-theme');
const themeIcon = document.getElementById('theme-icon');
if (btnTheme) {
    btnTheme.addEventListener('click', () => {
        document.body.classList.toggle('light-mode');
        if (themeIcon) {
            themeIcon.innerText = document.body.classList.contains('light-mode') ? '☾ DARK MODE' : '☀ LIGHT MODE';
        }
        initCanvas();
    });
}

// Canvas Topology & Status Background Animation
const canvas = document.getElementById('bg-canvas');
const ctx = canvas ? canvas.getContext('2d') : null;
let width, height;
let hubs = [], canvasNodes = [], packets = [], bgLogs = [];

function initCanvas() {
    if (!canvas || !ctx) return;
    width = canvas.width = window.innerWidth;
    height = canvas.height = window.innerHeight;
    hubs = [
        { x: width * 0.35, y: height * 0.45, radius: 4 },
        { x: width * 0.65, y: height * 0.55, radius: 4 }
    ];
    canvasNodes = [];
    const numNodes = Math.floor((width * height) / 25000);
    for (let i = 0; i < numNodes; i++) {
        let statusRoll = Math.random();
        let status = 'online';
        if (statusRoll > 0.85) status = 'warning';
        if (statusRoll > 0.95) status = 'offline';
        canvasNodes.push({
            x: Math.random() * width,
            y: Math.random() * height,
            vx: (Math.random() - 0.5) * 0.15,
            vy: (Math.random() - 0.5) * 0.15,
            status: status,
            radius: Math.random() * 1.5 + 1.0,
            hubIndex: Math.floor(Math.random() * hubs.length),
            pulse: 0
        });
    }
    packets = [];
    bgLogs = [];
}

function getThemeColors() {
    const isLight = document.body.classList.contains('light-mode');
    return {
        line: isLight ? 'rgba(0,0,0,0.04)' : 'rgba(255,255,255,0.04)',
        hub: isLight ? 'rgba(139,105,20,0.8)' : 'rgba(200,184,154,0.8)',
        online: isLight ? '#4a7541' : '#a3b89a',
        warning: isLight ? '#b8860b' : '#c8b85a',
        offline: isLight ? '#a84242' : '#c89a9a',
        text: isLight ? 'rgba(0,0,0,0.3)' : 'rgba(255,255,255,0.2)'
    };
}

function drawCanvas() {
    if (!ctx) return;
    ctx.clearRect(0, 0, width, height);
    const isLight = document.body.classList.contains('light-mode');
    if (isLight) {
        const time = Date.now() * 0.001;
        const gridSize = 50;
        const offsetX = (time * 15) % gridSize;
        const offsetY = (time * 10) % gridSize;
        ctx.strokeStyle = 'rgba(0, 0, 0, 0.03)';
        ctx.lineWidth = 1;
        ctx.beginPath();
        for (let x = offsetX; x < width; x += gridSize) {
            ctx.moveTo(x, 0); ctx.lineTo(x, height);
        }
        for (let y = offsetY; y < height; y += gridSize) {
            ctx.moveTo(0, y); ctx.lineTo(width, y);
        }
        ctx.stroke();

        canvasNodes.forEach((n, i) => {
            n.x += n.vx * 0.5;
            n.y += n.vy * 0.5;
            if (n.x < 0 || n.x > width) n.vx *= -1;
            if (n.y < 0 || n.y > height) n.vy *= -1;
            ctx.fillStyle = n.status === 'online' ? 'rgba(76, 175, 80, 0.6)' : 'rgba(0,0,0,0.1)';
            ctx.beginPath();
            ctx.arc(n.x, n.y, 2.5, 0, Math.PI * 2);
            ctx.fill();
            for (let j = i + 1; j < canvasNodes.length; j++) {
                const n2 = canvasNodes[j];
                const dx = n.x - n2.x;
                const dy = n.y - n2.y;
                const dist = Math.sqrt(dx * dx + dy * dy);
                if (dist < 150) {
                    ctx.beginPath();
                    ctx.strokeStyle = `rgba(0, 0, 0, ${0.08 * (1 - dist / 150)})`;
                    ctx.moveTo(n.x, n.y);
                    ctx.lineTo(n2.x, n2.y);
                    ctx.stroke();
                }
            }
        });
        requestAnimationFrame(drawCanvas);
        return;
    }

    const colors = getThemeColors();
    canvasNodes.forEach(n => {
        n.x += n.vx;
        n.y += n.vy;
        if (n.x < 0 || n.x > width) n.vx *= -1;
        if (n.y < 0 || n.y > height) n.vy *= -1;
        if (n.pulse > 0) n.pulse -= 0.03;
    });

    if (Math.random() < 0.15 && canvasNodes.length > 0) {
        const targetNode = canvasNodes[Math.floor(Math.random() * canvasNodes.length)];
        if (targetNode.status !== 'offline') {
            const hub = hubs[targetNode.hubIndex];
            packets.push({
                startX: hub.x, startY: hub.y,
                target: targetNode,
                progress: 0,
                speed: 0.015 + Math.random() * 0.02
            });
        }
    }

    ctx.lineWidth = 0.5;
    canvasNodes.forEach(n => {
        const hub = hubs[n.hubIndex];
        const dist = Math.hypot(n.x - hub.x, n.y - hub.y);
        if (dist < 500) {
            ctx.beginPath();
            ctx.strokeStyle = colors.line;
            ctx.moveTo(hub.x, hub.y);
            ctx.lineTo(n.x, n.y);
            ctx.stroke();
        }
    });

    hubs.forEach(h => {
        ctx.beginPath();
        ctx.arc(h.x, h.y, h.radius, 0, Math.PI * 2);
        ctx.fillStyle = colors.hub;
        ctx.fill();
        ctx.beginPath();
        ctx.arc(h.x, h.y, h.radius * 4 + Math.sin(Date.now() / 400) * 3, 0, Math.PI * 2);
        ctx.strokeStyle = colors.line;
        ctx.stroke();
    });

    canvasNodes.forEach(n => {
        ctx.beginPath();
        ctx.arc(n.x, n.y, n.radius, 0, Math.PI * 2);
        ctx.fillStyle = colors[n.status] || colors.online;
        ctx.fill();
        if (n.pulse > 0) {
            ctx.beginPath();
            ctx.arc(n.x, n.y, n.radius + n.pulse * 12, 0, Math.PI * 2);
            ctx.strokeStyle = `rgba(255,255,255,${n.pulse * 0.4})`;
            ctx.stroke();
        }
    });

    for (let i = packets.length - 1; i >= 0; i--) {
        let p = packets[i];
        p.progress += p.speed;
        if (p.progress >= 1) {
            p.target.pulse = 1;
            if (Math.random() > 0.8) {
                const latency = Math.floor(10 + Math.random() * 120);
                bgLogs.unshift(`[SYS] PROBE NODE_${Math.floor(p.target.x).toString(16).toUpperCase()} | STATUS: OK | LATENCY: ${latency}ms`);
                if (bgLogs.length > 5) bgLogs.pop();
            }
            packets.splice(i, 1);
            continue;
        }
        const curX = p.startX + (p.target.x - p.startX) * p.progress;
        const curY = p.startY + (p.target.y - p.startY) * p.progress;
        ctx.beginPath();
        ctx.arc(curX, curY, 1.5, 0, Math.PI * 2);
        ctx.fillStyle = colors.hub;
        ctx.fill();
    }

    ctx.font = '10px "JetBrains Mono", monospace';
    ctx.fillStyle = colors.text;
    bgLogs.forEach((log, idx) => {
        ctx.globalAlpha = 1 - (idx * 0.15);
        ctx.fillText(log, 40, height - 40 - idx * 18);
    });
    ctx.globalAlpha = 1;
    requestAnimationFrame(drawCanvas);
}

window.addEventListener('resize', () => { initCanvas(); });
initCanvas();
drawCanvas();

// Text Scramble Class
class TextScramble {
    constructor(el) {
        this.el = el;
        this.chars = '!<>-_\\/[]{}—=+*^?#________';
        this.update = this.update.bind(this);
        this.originalHTML = el.innerHTML;
        this.originalText = el.getAttribute('data-text') || el.innerText;
    }
    setText(newText) {
        const oldText = this.originalText || '';
        const targetText = newText || '';
        const length = Math.max(oldText.length, targetText.length);
        const promise = new Promise((resolve) => this.resolve = resolve);
        this.queue = [];
        for (let i = 0; i < length; i++) {
            const from = oldText[i] || '';
            const to = targetText[i] || '';
            const start = Math.floor(Math.random() * 20);
            const end = start + Math.floor(Math.random() * 20);
            this.queue.push({ from, to, start, end, char: '' });
        }
        cancelAnimationFrame(this.frameRequest);
        this.frame = 0;
        this.update();
        return promise;
    }
    update() {
        let output = '';
        let complete = 0;
        for (let i = 0, n = this.queue.length; i < n; i++) {
            let { from, to, start, end, char } = this.queue[i];
            if (this.frame >= end) {
                complete++;
                output += to;
            } else if (this.frame >= start) {
                if (!char || Math.random() < 0.28) {
                    char = this.randomChar();
                    this.queue[i].char = char;
                }
                output += `<span style="color:var(--rock); opacity:0.7;">${char}</span>`;
            } else {
                output += from;
            }
        }
        this.el.innerHTML = output;
        if (complete === this.queue.length) {
            this.el.innerHTML = this.originalHTML;
            if (this.resolve) this.resolve();
        } else {
            this.frameRequest = requestAnimationFrame(this.update);
            this.frame++;
        }
    }
    randomChar() { return this.chars[Math.floor(Math.random() * this.chars.length)]; }
}

function animateNumbers(container) {
    if (!container) return;
    const els = container.querySelectorAll('.count-up');
    els.forEach(el => {
        const target = parseFloat(el.getAttribute('data-val') || '0');
        const isInt = el.getAttribute('data-int') === 'true';
        const duration = 1500;
        const start = performance.now();
        const unit = isInt ? '' : ' <span>MB/s</span>';
        function update(time) {
            let progress = (time - start) / duration;
            if (progress > 1) progress = 1;
            let easeProgress = progress === 1 ? 1 : 1 - Math.pow(2, -10 * progress);
            let current = easeProgress * target;
            el.innerHTML = (isInt ? Math.floor(current) : current.toFixed(2)) + unit;
            if (progress < 1) requestAnimationFrame(update);
        }
        requestAnimationFrame(update);
    });
}

// Navigation Routing
document.querySelectorAll('.nav-item').forEach(item => {
    item.addEventListener('click', () => {
        if (item.classList.contains('active')) return;
        document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
        item.classList.add('active');

        const targetId = item.getAttribute('data-target');
        document.querySelectorAll('.page-container').forEach(p => p.classList.remove('active'));

        const targetPage = document.getElementById(targetId);
        if (targetPage) {
            targetPage.style.animation = 'none';
            targetPage.offsetHeight;
            targetPage.style.animation = null;
            targetPage.classList.add('active');

            animateNumbers(targetPage);
            targetPage.querySelectorAll('.scramble-text').forEach(el => {
                new TextScramble(el).setText(el.getAttribute('data-text'));
            });

            if (targetId === 'traffic') {
                renderTrafficChart();
            } else if (targetId === 'config') {
                loadConfig();
            }
        }
    });
});

/* ==========================================================================
   BACKEND REST API & REAL-TIME STATE ENGINE INTEGRATION
   ========================================================================== */

const AUTH_TOKEN_KEY = 'sb_auth_token';
let authToken = localStorage.getItem(AUTH_TOKEN_KEY) || '';

let nodeState = [];
let selectedNodeIds = new Set();
let subState = [];
let relayState = [];
let editingNodeId = null;
let editingSubId = null;
let sseSource = null;
let peakSpeedMbps = 0;
let uptimeSeconds = 0;
let uptimeTimer = null;

// Format Helpers
function formatBytes(bytes) {
    if (!bytes || isNaN(bytes) || bytes <= 0) return '0 B';
    const units = ['B', 'KB', 'MB', 'GB', 'TB'];
    let i = Math.floor(Math.log(bytes) / Math.log(1024));
    if (i >= units.length) i = units.length - 1;
    return (bytes / Math.pow(1024, i)).toFixed(2) + ' ' + units[i];
}

/** HTML 转义（节点名/分组/订阅 URL 等外部可控数据渲染前必须调用） */
/** 按当前语言取 I18N 文案（缺翻译时回退原文） */
function L(key) {
    const t = I18N_DICT[key];
    return (t !== undefined && t !== '') ? t : key;
}

function escapeHtml(str) {
    if (str === null || str === undefined) return '';
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

function formatRate(bps) {
    if (!bps || isNaN(bps) || bps <= 0) return '0.00 MB/s';
    const mbps = bps / (1024 * 1024);
    return mbps.toFixed(2) + ' MB/s';
}

function formatUptime(seconds) {
    const hrs = Math.floor(seconds / 3600).toString().padStart(2, '0');
    const mins = Math.floor((seconds % 3600) / 60).toString().padStart(2, '0');
    const secs = Math.floor(seconds % 60).toString().padStart(2, '0');
    return `${hrs}:${mins}:${secs}`;
}

function addLog(type, message) {
    const timestamp = new Date().toLocaleTimeString();
    const logLine = `[${timestamp}] [${type}] ${message}`;
    bgLogs.unshift(logLine);
    if (bgLogs.length > 50) bgLogs.pop();

    const terminalEl = document.getElementById('system-logs-container');
    if (terminalEl) {
        const item = document.createElement('div');
        item.style.marginBottom = '4px';
        item.style.color = type === 'ERROR' ? 'var(--danger)' : (type === 'SUCCESS' ? 'var(--success)' : 'var(--rock)');
        item.textContent = logLine;
        terminalEl.appendChild(item);
        terminalEl.scrollTop = terminalEl.scrollHeight;
    }
}

// Unified API Wrapper with Bearer Token & 401 Redirect Handler
async function api(path, options = {}) {
    const headers = Object.assign({}, options.headers || {});
    if (authToken) headers['Authorization'] = 'Bearer ' + authToken;
    if (options.body && !headers['Content-Type']) headers['Content-Type'] = 'application/json';

    try {
        const resp = await fetch(path, Object.assign({}, options, { headers }));
        if (resp.status === 401) {
            authToken = '';
            localStorage.removeItem(AUTH_TOKEN_KEY);
            showLoginScreen(true);
            throw new Error('401 Authorization Expired');
        }
        return resp;
    } catch (err) {
        if (err.message.includes('401')) {
            authToken = '';
            localStorage.removeItem(AUTH_TOKEN_KEY);
            showLoginScreen(true);
        }
        throw err;
    }
}

/** 操作后端数据后重建 sing-box 配置（节点增删改/导入/停用等必须生效） */
async function applyConfigSilent() {
    try {
        const r = await api('/api/config/apply', { method: 'POST', body: '{}' });
        if (!r.ok) addLog('WARN', `配置重建失败 (HTTP ${r.status})`);
    } catch (e) {
        addLog('WARN', '配置重建失败: ' + e.message);
    }
}

function showLoginScreen(show) {
    const loginScreen = document.getElementById('login-screen');
    if (show) {
        document.body.classList.add('locked');
        if (loginScreen) loginScreen.classList.remove('hidden');
    } else {
        document.body.classList.remove('locked');
        if (loginScreen) loginScreen.classList.add('hidden');
    }
}

async function checkAuth() {
    try {
        const r = await api('/api/auth/check');
        if (r.ok) {
            const st = await api('/api/auth/status');
            const data = await st.json();
            if (data.passwordChangeRequired) {
                showLoginScreen(false);
                const pwdOverlay = document.getElementById('pwd-modal');
                if (pwdOverlay) pwdOverlay.classList.add('active');
            } else {
                showLoginScreen(false);
                const pwdOverlay = document.getElementById('pwd-modal');
                if (pwdOverlay) pwdOverlay.classList.remove('active');
            }
            window.__backendMode = true;
            startTrafficSSE();
            loadAllData();
            startUptimeTimer();
            return true;
        }
    } catch (e) {
        authToken = '';
        localStorage.removeItem(AUTH_TOKEN_KEY);
    }
    showLoginScreen(true);
    return false;
}

async function doLogin() {
    const userEl = document.getElementById('login-username');
    const passEl = document.getElementById('login-password');
    const errEl = document.getElementById('login-error');
    const btn = document.querySelector('.btn-login');

    const username = userEl ? userEl.value.trim() : '';
    const password = passEl ? passEl.value : '';
    if (errEl) errEl.textContent = '';

    if (!username || !password) {
        if (errEl) errEl.textContent = '请输入用户名和密码';
        return;
    }
    if (btn) {
        btn.innerText = "AUTHENTICATING...";
        btn.disabled = true;
        btn.style.opacity = "0.6";
    }
    try {
        const r = await fetch('/api/auth/login', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, password })
        });
        const data = await r.json();
        if (!r.ok) {
            if (errEl) errEl.textContent = data.detail || '登录失败';
            if (btn) {
                btn.innerText = "INITIALIZE LINK";
                btn.disabled = false;
                btn.style.opacity = "1";
            }
            return;
        }
        if (btn) {
            btn.innerText = "ACCESS GRANTED";
            btn.style.background = "var(--success)";
            btn.style.color = "var(--bg)";
        }
        authToken = data.token;
        localStorage.setItem(AUTH_TOKEN_KEY, authToken);
        if (passEl) passEl.value = '';

        setTimeout(() => {
            if (data.passwordChangeRequired) {
                showLoginScreen(false);
                const pwdOverlay = document.getElementById('pwd-modal');
                if (pwdOverlay) pwdOverlay.classList.add('active');
            } else {
                showLoginScreen(false);
                addLog('SUCCESS', '身份验证通过，进入中转枢纽');
                window.__backendMode = true;
                startTrafficSSE();
                loadAllData();
                startUptimeTimer();
            }
        }, 400);
    } catch (e) {
        if (errEl) errEl.textContent = '网络请求失败: ' + e.message;
        if (btn) {
            btn.innerText = "INITIALIZE LINK";
            btn.disabled = false;
            btn.style.opacity = "1";
        }
    }
}

async function doLogout() {
    try {
        if (authToken) {
            await api('/api/auth/logout', { method: 'POST' });
        }
    } catch (e) { }
    authToken = '';
    localStorage.removeItem(AUTH_TOKEN_KEY);
    if (sseSource) { sseSource.close(); sseSource = null; }
    showLoginScreen(true);
    addLog('INFO', '已退出登录');
}

async function doChangePassword(isFirst) {
    const oldPwd = isFirst
        ? (document.getElementById('pwd-old') ? document.getElementById('pwd-old').value : '')
        : (document.getElementById('set-pwd-old') ? document.getElementById('set-pwd-old').value : '');
    const newPwd = isFirst
        ? (document.getElementById('pwd-new') ? document.getElementById('pwd-new').value : '')
        : (document.getElementById('set-pwd-new') ? document.getElementById('set-pwd-new').value : '');
    const confirmPwd = isFirst
        ? (document.getElementById('pwd-confirm') ? document.getElementById('pwd-confirm').value : '')
        : (document.getElementById('set-pwd-confirm') ? document.getElementById('set-pwd-confirm').value : '');

    const errEl = isFirst ? document.getElementById('pwd-error') : document.getElementById('set-pwd-msg');
    if (errEl) errEl.textContent = '';

    if (!oldPwd) { if (errEl) errEl.textContent = '请输入当前密码'; return; }
    if (!newPwd || newPwd.length < 6) { if (errEl) errEl.textContent = '新密码至少 6 位'; return; }
    if (newPwd !== confirmPwd) { if (errEl) errEl.textContent = '两次输入的新密码不一致'; return; }

    try {
        const r = await api('/api/auth/change-password', {
            method: 'POST',
            body: JSON.stringify({ oldPassword: oldPwd, newPassword: newPwd })
        });
        const data = await r.json();
        if (!r.ok) {
            if (errEl) errEl.textContent = data.detail || '修改密码失败';
            return;
        }
        if (data.token) {
            authToken = data.token;
            localStorage.setItem(AUTH_TOKEN_KEY, authToken);
        }
        if (isFirst) {
            const pwdOverlay = document.getElementById('pwd-modal');
            if (pwdOverlay) pwdOverlay.classList.remove('active');
            showLoginScreen(false);
            window.__backendMode = true;
            startTrafficSSE();
            loadAllData();
            startUptimeTimer();
        } else {
            if (errEl) {
                errEl.style.color = 'var(--success)';
                errEl.textContent = '密码修改成功！';
            }
        }
        addLog('SUCCESS', '系统密码已成功修改');
    } catch (e) {
        if (errEl) errEl.textContent = e.message;
    }
}

function startUptimeTimer() {
    if (uptimeTimer) clearInterval(uptimeTimer);
    uptimeTimer = setInterval(() => {
        uptimeSeconds++;
        const uptimeEl = document.getElementById('sys-uptime');
        if (uptimeEl) uptimeEl.textContent = formatUptime(uptimeSeconds);
    }, 1000);
}

// Data Loaders
async function loadAllData() {
    await loadNodes();
    await loadSubs();
    await loadSettings();
    await loadConfig();
}

async function loadNodes() {
    try {
        const r = await api('/api/nodes');
        const data = await r.json();
        nodeState = data.items || [];
        renderNodeMatrix();
        renderNodesTable();
        renderQuickStats();
        renderDashRelayStatus();
        renderTrafficChart();
        renderTrafficTable();
        drawTrafficChart(); // 初始化实时曲线（等待数据时显示提示）
        updateGroupFilterOptions();
    } catch (e) {
        console.warn('加载节点列表失败:', e);
    }
}

function updateGroupFilterOptions() {
    const groups = new Set(['ALL']);
    nodeState.forEach(n => { if (n.group) groups.add(n.group); });

    const filterGroupSelect = document.getElementById('filter-group');
    const trafficFilterSelect = document.getElementById('traffic-filter');
    const exportGroupSelect = document.getElementById('export-group-select');

    [filterGroupSelect, trafficFilterSelect, exportGroupSelect].forEach(select => {
        if (!select) return;
        const currentVal = select.value || 'ALL';
        select.innerHTML = '';
        groups.forEach(g => {
            const opt = document.createElement('option');
            opt.value = g;
            opt.textContent = g === 'ALL' ? (I18N_DICT['ALL GROUPS'] || 'ALL GROUPS') : g;
            select.appendChild(opt);
        });
        // 停用节点筛选（仅节点列表分组下拉）
        if (select === filterGroupSelect && nodeState.some(n => n.status === 'disabled')) {
            const opt = document.createElement('option');
            opt.value = '__DISABLED__';
            opt.textContent = '停用节点';
            select.appendChild(opt);
        }
        select.value = groups.has(currentVal) || currentVal === '__DISABLED__' ? currentVal : 'ALL';
    });
}

/** 仪表盘 Relay Exit Status：渲染全部轮询域名入口（域名:端口 徽标） */
function renderDashRelayStatus() {
    const el = document.getElementById('card-relay-status');
    if (!el) return;
    if (!relayState || relayState.length === 0) {
        el.innerHTML = `<span style="color: var(--dim); border: 1px solid var(--dim); padding: 2px 8px; border-radius: 4px;">暂无域名入口</span>`;
        return;
    }
    // 当前出口：settings.relayExits（后端查 clash API 附加），tag → 节点名
    const exits = (window.__relayExits || {});
    el.innerHTML = relayState.map(rd => {
        const label = `Port ${escapeHtml(rd.port)}`;
        const tip = `socks5://${escapeHtml(rd.authUser || '')}:***@${escapeHtml(rd.domain)}:${escapeHtml(rd.port)}`;
        const exit = exits[rd.id];
        const exitTxt = exit ? ` 出口: ${escapeHtml(exit.name || exit.tag)}` : '';
        return `<span title="${tip}" style="color: var(--success); border: 1px solid var(--success); padding: 2px 8px; border-radius: 4px;">${label}${exitTxt}</span>`;
    }).join('');
}

function renderQuickStats() {
    const totalNodes = nodeState.length;
    const onlineNodes = nodeState.filter(n => n.status === 'online').length;
    const ports = new Set(nodeState.map(n => n.port).filter(Boolean));

    let pingSum = 0, pingCount = 0;
    let totalUp = 0, totalDown = 0;
    nodeState.forEach(n => {
        if (n.ping > 0) { pingSum += n.ping; pingCount++; }
        totalUp += (n.upTraffic || 0);
        totalDown += (n.downTraffic || 0);
    });
    const avgPing = pingCount > 0 ? Math.round(pingSum / pingCount) : 0;
    const totalTraffic = totalUp + totalDown;

    const setVal = (id, val) => {
        const el = document.getElementById(id);
        if (el) el.innerText = val;
    };

    setVal('qs-inbound-ports', ports.size);
    setVal('qs-total-nodes', totalNodes);
    setVal('qs-online-count', onlineNodes);
    setVal('qs-avg-ping', avgPing > 0 ? `${avgPing} ms` : '-- ms');
    setVal('qs-total-traffic', formatBytes(totalTraffic));

    // 分组统计：按真实分组名聚合（非质量分类），所有分组各显示一个 pill
    const groupEl = document.getElementById('qs-group-stats');
    if (groupEl) {
        const byGroup = {};
        nodeState.forEach(n => {
            const g = (n.group || '默认分组').trim() || '默认分组';
            byGroup[g] = (byGroup[g] || 0) + 1;
        });
        const entries = Object.entries(byGroup).sort((a, b) => b[1] - a[1]);
        groupEl.innerHTML = entries.map(([g, cnt]) => {
            const label = escapeHtml(g);
            const online = nodeState.filter(n => (n.group || '默认分组') === g && n.status === 'online').length;
            return `<span class="stat-pill" title="在线 ${online}/${cnt}" style="margin: 0;">${label}: <span class="val" style="color: ${online > 0 ? 'var(--success)' : 'inherit'}">${cnt}</span></span>`;
        }).join('');
    }

    const trafficDetail = document.getElementById('card-traffic-detail');
    if (trafficDetail) {
        trafficDetail.textContent = `Total Traffic: ${formatBytes(totalTraffic)} (Up: ${formatBytes(totalUp)} | Down: ${formatBytes(totalDown)})`;
    }
}

function renderNodeMatrix() {
    const grid = document.getElementById('node-matrix-grid');
    if (!grid) return;
    grid.innerHTML = '';
    const total = nodeState.length;
    const online = nodeState.filter(n => n.status === 'online').length;

    const summaryEl = document.getElementById('matrix-status-summary');
    if (summaryEl) summaryEl.textContent = `ONLINE ${online} / TOTAL ${total}`;

    const ratioEl = document.getElementById('card-online-ratio');
    if (ratioEl) ratioEl.textContent = `${online} / ${total}`;

    const pctEl = document.getElementById('card-online-pct');
    if (pctEl) pctEl.textContent = total > 0 ? Math.round((online / total) * 100) + '%' : '0%';

    nodeState.forEach(n => {
        const dot = document.createElement('div');
        dot.className = `node-dot ${n.status || 'offline'}`;
        dot.title = `${n.name} (${n.port}) - ${n.status || 'offline'} [${n.ping || 0}ms]`;
        grid.appendChild(dot);
    });
}

function getFilteredNodes() {
    const groupSelect = document.getElementById('filter-group');
    const searchInput = document.getElementById('search-keyword');
    const selectedGroup = groupSelect ? groupSelect.value : 'ALL';
    const keyword = searchInput ? searchInput.value.trim().toLowerCase() : '';

    return nodeState.filter(node => {
        // 停用节点独立视图：__DISABLED__ 只看停用；普通列表排除 disabled
        if (selectedGroup === '__DISABLED__') return node.status === 'disabled';
        if (node.status === 'disabled') return false;
        if (selectedGroup !== 'ALL' && node.group !== selectedGroup) return false;
        if (keyword) {
            const nameMatch = (node.name || '').toLowerCase().includes(keyword);
            const ipMatch = (node.exitIp || '').toLowerCase().includes(keyword);
            const portMatch = String(node.port || '').includes(keyword);
            if (!nameMatch && !ipMatch && !portMatch) return false;
        }
        return true;
    });
}

// ---------- 出口 IP 情报渲染（旧版 renderExitIp 移植） ----------

function exitTypeLabel(type, risk) {
    const map = { residential: '住宅', hosting: '数据中心', proxy: '代理/VPN', unknown: '' };
    const label = map[type];
    if (label) return label;
    if (type === 'unknown' && risk != null) {
        if (risk <= 30) return '住宅/ISP';
        if (risk <= 70) return '数据中心';
        return '代理/VPN';
    }
    return '';
}

function exitScoreClass(score) {
    if (score == null || score === '') return '';
    return score >= 80 ? 'high' : (score >= 50 ? 'mid' : 'low');
}

function exitRiskClass(risk) {
    if (risk == null || risk === '') return '';
    return risk <= 50 ? 'low' : (risk <= 70 ? 'mid' : 'high');
}

/** 订阅来源徽标：subName 优先，空则按 subId 从订阅列表反查；stale 警示色 */
function renderSubBadge(n) {
    let sn = n.subName;
    if (!sn && n.subId && subState && subState.length) {
        const hit = subState.find(s => s.id === n.subId);
        sn = hit ? (hit.name || '') : '';
    }
    if (!sn) return '';
    const cls = n.stale ? 'sub-tag stale' : 'sub-tag';
    return `<span class="${cls}" title="来自订阅 ${escapeHtml(sn)}${n.stale ? ' · 订阅刷新失败，使用上次快照' : ''}">${escapeHtml(sn)}</span>`;
}

/** 出口 IP 完整情报：国旗/类型徽标/纯净度/风控值/归属地 tooltip（后端字段已有） */
function renderExitIp(n) {
    const esc = v => escapeHtml(v);
    const flag = esc(n.exitFlag || '');
    const typeLabel = exitTypeLabel(n.exitType, n.exitRisk);
    const score = n.exitScore;
    const hasScore = score > 0;
    const scoreBadge = hasScore ? `<span class="exit-score ${exitScoreClass(score)}">${esc(score)}</span>` : '';
    const typeBadge = typeLabel ? `<span class="exit-badge ${esc(n.exitType || 'unknown')}">${esc(typeLabel)}</span>` : '';
    const risk = n.exitRisk;
    const hasRisk = risk != null && risk !== '';
    const riskBadge = hasRisk ? `<span class="exit-risk ${exitRiskClass(risk)}" title="风控值: ${esc(risk)}/100（越低越安全）">风控${esc(risk)}</span>` : '';
    const city = esc(n.exitCity || '');
    const country = esc(n.exitCountry || '');
    const tooltip = [esc(n.exitIp), country ? `归属地: ${country}${city ? ' ' + city : ''}` : '', typeLabel ? `类型: ${typeLabel}` : '', hasScore ? `纯净度: ${esc(score)}/100` : '', hasRisk ? `风控值: ${esc(risk)}/100（越低越安全）` : ''].filter(Boolean).join('\n');
    const ip = esc(n.exitIp) || 'N/A';
    const ipTxt = ip === 'N/A' ? 'N/A' : `<span class="ipaddr" title="${tooltip}">${ip}</span>`;
    const badges = [flag ? `<span class="flag">${flag}</span>` : '', ipTxt, typeBadge, scoreBadge, riskBadge].filter(Boolean).join('');
    return badges ? `<span class="exit-ip-cell">${badges}</span>` : 'N/A';
}

function renderNodesTable() {
    const tbody = document.getElementById('nodes-tbody');
    if (!tbody) return;
    tbody.innerHTML = '';

    const nodes = getFilteredNodes();
    if (nodes.length === 0) {
        tbody.innerHTML = `<tr><td colspan="11" style="text-align: center; color: var(--rock); padding: 24px;">暂无节点数据</td></tr>`;
        return;
    }

    nodes.forEach(node => {
        const isSelected = selectedNodeIds.has(node.id);
        const totalNodeTraffic = (node.upTraffic || 0) + (node.downTraffic || 0);
        const esc = escapeHtml;
        const isDisabled = node.status === 'disabled';
        const statusTitle = isDisabled ? '已停用（连续探活失败自动）' : (node.status || 'offline');
        const tr = document.createElement('tr');
        tr.innerHTML = `
            <td><input type="checkbox" class="chk-node" data-id="${esc(node.id)}" ${isSelected ? 'checked' : ''} onchange="toggleSelectNode('${esc(node.id)}')"></td>
            <td><span class="status-indicator ${esc(node.status) || 'offline'}" title="${esc(statusTitle)}"></span></td>
            <td style="font-family: var(--font-mono);"><input type="number" class="port-input" value="${esc(node.port)}" onchange="updateNodePort('${esc(node.id)}', this.value)" style="width:72px; background:transparent; border:1px solid var(--dim); color:inherit; border-radius:4px; padding:2px 6px; font-family:var(--font-mono); font-size:11px;"></td>
            <td><span class="group-tag">${esc(node.group) || '默认分组'}</span></td>
            <td style="font-family: var(--font-mono);">${esc(node.protocol) || 'mixed'}</td>
            <td style="font-family: var(--font-mono);">${esc(node.entryProto) || 'mixed'}</td>
            <td><strong>${esc(node.name) || '未命名'}</strong>${renderSubBadge(node)}${isDisabled ? ' <span class="proto-tag" style="background:#5a5348; color:#e8e2d8;">停用</span>' : ''}</td>
            <td style="font-size:12px;">${renderExitIp(node)}</td>
            <td style="font-family: var(--font-mono); color: ${node.ping > 0 ? (node.ping < 200 ? 'var(--success)' : 'var(--rock)') : 'var(--danger)'}">${node.ping > 0 ? node.ping + ' ms' : '--'}</td>
            <td style="font-family: var(--font-mono);">${formatBytes(totalNodeTraffic)}</td>
            <td style="text-align: center;">
                <div style="display:flex; gap:3px; justify-content:center;">
                    <button class="btn-action" onclick="pingSingleNode('${esc(node.id)}')">${L('PING')}</button>
                    <button class="btn-action" onclick="openEditNodeModal('${esc(node.id)}')">${L('EDIT')}</button>
                    <button class="btn-action" onclick="exportSingleNode('${esc(node.id)}')">${L('EXPORT')}</button>
                    <button class="btn-action ${node.status === 'online' ? 'danger' : ''}" onclick="toggleNodeEnable('${esc(node.id)}')">${node.status === 'online' ? L('DISABLE') : L('ENABLE')}</button>
                    <button class="btn-action danger" onclick="deleteSingleNode('${esc(node.id)}')">${L('DROP')}</button>
                </div>
            </td>
        `;
        tbody.appendChild(tr);
    });

    const chkAll = document.getElementById('chk-all');
    if (chkAll) {
        chkAll.checked = nodes.length > 0 && nodes.every(n => selectedNodeIds.has(n.id));
    }
}

/** 行内端口编辑：PATCH 端口并重建配置；失败恢复原值 */
async function updateNodePort(id, val) {
    const port = parseInt(val, 10);
    if (!port || port < 1024 || port > 65535) { addLog('WARN', '端口无效（1024-65535）'); renderNodesTable(); return; }
    try {
        const r = await api(`/api/nodes/${id}/port`, {
            method: 'PUT',
            body: JSON.stringify({ port: port })
        });
        if (!r.ok) {
            addLog('WARN', `端口更新失败 (HTTP ${r.status})`);
            renderNodesTable();
            return;
        }
        addLog('INFO', `节点端口已改为 ${port}`);
        await applyConfigSilent();
        await loadNodes();
    } catch (e) {
        addLog('ERROR', '端口更新失败: ' + e.message);
        renderNodesTable();
    }
}

/** 单节点导出：生成文本写导出框 + 切 tab + 复制剪贴板 */
async function exportSingleNode(nodeId) {
    const node = nodeState.find(n => n.id === nodeId);
    if (!node) return;
    const protoSel = document.getElementById('export-proto-select') ? document.getElementById('export-proto-select').value : 'both';
    const exportType = document.getElementById('export-type-select') ? document.getElementById('export-type-select').value : 'converted';
    const vpsIp = window.location.hostname || '127.0.0.1';
    const uriLines = exportNodeLines(node, vpsIp, protoSel, exportType);
    if (uriLines.length === 0) {
        addLog('WARN', `节点 [${node.name}] 没有可导出的原始链接`);
        alert(`节点 [${node.name}] 没有可导出的原始链接`);
        return;
    }
    const text = `# 节点: ${node.name.replace(/[\r\n]+/g, ' ')} | 协议: ${(node.protocol || '').toUpperCase()}${exportType === 'original' ? ' | 原始链接' : ''}\n${uriLines.join('\n')}`;
    const area = document.getElementById('export-text-area');
    if (area) {
        area.value = text;
        const exportNav = document.querySelector('.nav-item[data-target="export"]');
        if (exportNav) exportNav.click();
    }
    copyToClipboard(text);
    addLog('SUCCESS', `已生成节点 [${node.name}] 的${exportType === 'original' ? '原始链接' : '中转链接'}`);
}

// Checkbox and Toolbar Handlers
function toggleSelectAll(master) {
    const nodes = getFilteredNodes();
    if (master.checked) {
        nodes.forEach(n => selectedNodeIds.add(n.id));
    } else {
        nodes.forEach(n => selectedNodeIds.delete(n.id));
    }
    renderNodesTable();
}

function toggleSelectNode(id) {
    if (selectedNodeIds.has(id)) {
        selectedNodeIds.delete(id);
    } else {
        selectedNodeIds.add(id);
    }
    renderNodesTable();
}

const filterGroupEl = document.getElementById('filter-group');
if (filterGroupEl) filterGroupEl.addEventListener('change', renderNodesTable);
const searchKeywordEl = document.getElementById('search-keyword');
if (searchKeywordEl) searchKeywordEl.addEventListener('input', renderNodesTable);

// Ping / Probe Handlers
async function triggerPingAll() {
    addLog('INFO', '开始批量探活所有节点...');
    try {
        const r = await api('/api/nodes/ping', {
            method: 'POST',
            body: JSON.stringify({ all: true, includeDisabled: true })
        });
        const results = await r.json();
        addLog('SUCCESS', `探活完成，共测试 ${results.length} 个节点`);
        await loadNodes();
    } catch (e) {
        addLog('ERROR', '探活失败: ' + e.message);
    }
}

async function pingSingleNode(id) {
    addLog('INFO', `正在探活节点 [ID: ${id}]...`);
    try {
        const r = await api('/api/nodes/ping', {
            method: 'POST',
            body: JSON.stringify({ ids: [id], all: false, includeDisabled: true })
        });
        const results = await r.json();
        if (results && results.length > 0) {
            addLog('SUCCESS', `节点探活结果: ${results[0].status} (${results[0].ping}ms)`);
        }
        await loadNodes();
    } catch (e) {
        addLog('ERROR', '节点探活失败: ' + e.message);
    }
}

// Node Edit Modal
function openEditNodeModal(id) {
    const node = nodeState.find(n => n.id === id);
    if (!node) return;
    editingNodeId = id;

    const nameEl = document.getElementById('edit-node-name');
    const groupEl = document.getElementById('edit-node-group');
    const portEl = document.getElementById('edit-node-port');
    const userEl = document.getElementById('edit-node-auth-user');
    const passEl = document.getElementById('edit-node-auth-pass');
    const entryEl = document.getElementById('edit-node-entry');
    const ssPassEl = document.getElementById('edit-node-sspass');

    if (nameEl) nameEl.value = node.name || '';
    if (groupEl) groupEl.value = node.group || '';
    if (portEl) portEl.value = node.port || '';
    if (userEl) userEl.value = node.authUser || '';
    if (passEl) passEl.value = node.authPass || '';
    if (entryEl) entryEl.value = node.entryProto || 'mixed';
    if (ssPassEl) ssPassEl.value = node.ssPass || '';
    // 协议/端口静态信息行（旧版 edit-node-sub）
    const subEl = document.getElementById('edit-node-sub');
    if (subEl) subEl.textContent = `协议: ${(node.protocol || '').toUpperCase()} | 端口: ${node.port}${node.subName ? ' | 订阅: ' + node.subName : ''}`;
    toggleEditEntryPassField();

    openModal('edit-modal');
}

// ---------- 对话框 ss 密码框显隐联动（旧版 toggle*PassField 移植） ----------

function toggleImportPassField() {
    // 按打开的表单判断：modal 打开时读 modal select，否则读页面 select
    const modalEl = document.getElementById('import-modal');
    const modalOpen = modalEl && modalEl.classList.contains('active');
    const selectId = modalOpen ? 'modal-import-entry-proto' : 'import-entry-proto';
    const groupId = modalOpen ? 'modal-import-pass-group' : 'import-pass-group';
    const sel = document.getElementById(selectId);
    const el = document.getElementById(groupId);
    if (sel && el) el.style.display = sel.value === 'ss' ? 'block' : 'none';
}

function toggleConvertPassField() {
    const dir = document.getElementById('convert-direction');
    const el = document.getElementById('convert-pass-group');
    if (dir && el) el.style.display = dir.value === 'ss' ? 'block' : 'none';
}

function toggleEditEntryPassField() {
    const proto = document.getElementById('edit-node-entry');
    const el = document.getElementById('edit-node-sspass-group');
    if (proto && el) el.style.display = proto.value === 'ss' ? 'block' : 'none';
}

/** 转换弹窗打开时动态更新 scope 提示（旧版 openConvertEntryDialog） */
function openConvertEntryModal() {
    const hint = document.getElementById('convert-scope-hint');
    if (hint) {
        hint.textContent = selectedNodeIds.size > 0
            ? `转换范围: 当前选中的 ${selectedNodeIds.size} 个节点`
            : '转换范围: 全部节点';
    }
    toggleConvertPassField();
    const errEl = document.getElementById('convert-error');
    if (errEl) errEl.textContent = '';
    openModal('convert-entry-modal');
}

async function handleSaveNodeEdit() {
    if (!editingNodeId) return;
    const name = document.getElementById('edit-node-name').value.trim();
    const group = document.getElementById('edit-node-group').value.trim();
    const port = parseInt(document.getElementById('edit-node-port').value);
    const authUser = document.getElementById('edit-node-auth-user').value.trim();
    const authPass = document.getElementById('edit-node-auth-pass').value.trim();
    const entryProto = document.getElementById('edit-node-entry').value;
    const ssPass = document.getElementById('edit-node-sspass').value.trim();

    try {
        const r = await api(`/api/nodes/${editingNodeId}`, {
            method: 'PATCH',
            body: JSON.stringify({
                name, group, port, authUser, authPass, entryProto,
                ...(ssPass ? { ssPass } : {})
            })
        });
        if (!r.ok) {
            const err = await r.json();
            const errEl = document.getElementById('edit-node-error');
            if (errEl) errEl.textContent = err.detail || '保存失败';
            return;
        }
        closeModal('edit-modal');
        addLog('SUCCESS', `修改节点 [${name}] 成功`);
        await loadNodes();
    await applyConfigSilent();
    } catch (e) {
        const errEl = document.getElementById('edit-node-error');
        if (errEl) errEl.textContent = e.message;
    }
}

async function toggleNodeEnable(id) {
    const node = nodeState.find(n => n.id === id);
    if (!node) return;
    // 停用写 disabled（后端从配置/轮询池剔除的真实语义），offline 只是探活结果态
    const isOnline = node.status === 'online';
    const newStatus = isOnline ? 'disabled' : 'online';
    try {
        await api(`/api/nodes/${id}`, {
            method: 'PATCH',
            body: JSON.stringify({ status: newStatus })
        });
        addLog('INFO', `切换节点状态: ${node.name} -> ${newStatus}`);
        await loadNodes();
    await applyConfigSilent();
    } catch (e) {
        addLog('ERROR', '更新节点状态失败: ' + e.message);
    }
}

async function enableSelectedNodes() {
    if (selectedNodeIds.size === 0) return;
    for (const id of selectedNodeIds) {
        try {
            await api(`/api/nodes/${id}`, { method: 'PATCH', body: JSON.stringify({ status: 'online' }) });
        } catch (e) { }
    }
    addLog('SUCCESS', `已启用选中的 ${selectedNodeIds.size} 个节点`);
    await loadNodes();
    await applyConfigSilent();
}

async function enableAllDisabledNodes() {
    const offlineNodes = nodeState.filter(n => n.status !== 'online');
    for (const n of offlineNodes) {
        try {
            await api(`/api/nodes/${n.id}`, { method: 'PATCH', body: JSON.stringify({ status: 'online' }) });
        } catch (e) { }
    }
    addLog('SUCCESS', `已启用所有离线节点 (${offlineNodes.length} 个)`);
    await loadNodes();
    await applyConfigSilent();
}

async function disableSelectedNodes() {
    if (selectedNodeIds.size === 0) return;
    for (const id of selectedNodeIds) {
        try {
            await api(`/api/nodes/${id}`, { method: 'PATCH', body: JSON.stringify({ status: 'disabled' }) });
        } catch (e) { }
    }
    addLog('SUCCESS', `已停用选中的 ${selectedNodeIds.size} 个节点`);
    await loadNodes();
    await applyConfigSilent();
}

async function deleteSingleNode(id) {
    if (!confirm('确定删除该节点？')) return;
    try {
        await api(`/api/nodes/${id}`, { method: 'DELETE' });
        selectedNodeIds.delete(id);
        addLog('SUCCESS', '节点删除成功');
        await loadNodes();
    await applyConfigSilent();
    } catch (e) {
        addLog('ERROR', '删除节点失败: ' + e.message);
    }
}

async function deleteSelectedNodes() {
    if (selectedNodeIds.size === 0) {
        alert('请先选择要删除的节点');
        return;
    }
    if (!confirm(`确定删除选中的 ${selectedNodeIds.size} 个节点？`)) return;
    try {
        const idsArray = Array.from(selectedNodeIds);
        await api('/api/nodes/delete-batch', {
            method: 'POST',
            body: JSON.stringify({ ids: idsArray })
        });
        selectedNodeIds.clear();
        addLog('SUCCESS', `批量删除 ${idsArray.length} 个节点成功`);
        await loadNodes();
    await applyConfigSilent();
    } catch (e) {
        addLog('ERROR', '批量删除节点失败: ' + e.message);
    }
}

async function renameGroup() {
    const oldName = prompt('请输入要重命名的原分组名:');
    if (!oldName) return;
    const newName = prompt(`将分组 [${oldName}] 重命名为:`);
    if (!newName) return;
    try {
        const r = await api('/api/groups/rename', {
            method: 'POST',
            body: JSON.stringify({ oldName, newName })
        });
        if (!r.ok) {
            const data = await r.json();
            alert(data.detail || '重命名失败');
            return;
        }
        addLog('SUCCESS', `分组重命名成功: ${oldName} -> ${newName}`);
        await loadNodes();
    await applyConfigSilent();
    } catch (e) {
        alert('分组重命名出错: ' + e.message);
    }
}

async function reassignAllPorts() {
    const startPortStr = prompt('请输入重新编排的起始端口 (默认 52001):', '52001');
    if (!startPortStr) return;
    let startPort = parseInt(startPortStr) || 52001;

    addLog('INFO', `重新编排所有节点端口，起始端口: ${startPort}...`);
    const usedPorts = new Set();
    let failed = 0;
    for (let i = 0; i < nodeState.length; i++) {
        const n = nodeState[i];
        // 冲突跳过：起始端口撞上保留段/已分配端口时向后找空闲端口（后端也会拒绝冲突）
        let port = startPort + i;
        while (usedPorts.has(port) || port < 1024) port++;
        usedPorts.add(port);
        try {
            const r = await api(`/api/nodes/${n.id}/port`, {
                method: 'PUT',
                body: JSON.stringify({ port: port })
            });
            if (!r.ok) failed++;
        } catch (e) { failed++; }
    }
    addLog(failed ? 'WARN' : 'SUCCESS', failed ? `端口编排完成，${failed} 个节点失败` : '端口编排完成');
    await loadNodes();
    await applyConfigSilent();
}

/** 按入口协议导出单个节点的链接（ss 入口 → ss://；mixed 入口 → socks5/http 按选择） */
function exportLinkLines(node, vpsIp, protoSel) {
    const lines = [];
    if ((node.entryProto || 'mixed') === 'ss') {
        const pass = node.ssPass || node.authPass || 'relaypass';
        let userinfo;
        try {
            userinfo = btoa('aes-256-gcm:' + pass).replace(/=/g, '');
        } catch (e) {
            // 密码含非 Latin1 字符时，用 encodeURIComponent 兼容
            userinfo = btoa(unescape(encodeURIComponent('aes-256-gcm:' + pass))).replace(/=/g, '');
        }
        lines.push(`ss://${userinfo}@${vpsIp}:${node.port}#${encodeURIComponent(node.name || 'ss')}`);
        return lines;
    }
    const base = `${node.authUser || 'user'}:${node.authPass || 'pass'}@${vpsIp}:${node.port}`;
    if (protoSel !== 'http') lines.push(`socks5://${base}`);
    if (protoSel !== 'socks5') lines.push(`http://${base}`);
    return lines;
}

/** 按导出类型取节点链接行：converted=本机转换后入口，original=原始链接 */
function exportNodeLines(node, vpsIp, protoSel, exportType) {
    if (exportType === 'original') {
        const uri = node.rawConfig && node.rawConfig.uri;
        if (!uri) return [];
        // 原始链接原样透出，但消毒换行符——否则节点名/URI 内嵌 \n 会截断导出行
        // （converted 走 encodeURIComponent 天然安全；original 必须显式消毒）
        return [uri.replace(/[\r\n]+/g, ' ')];
    }
    return exportLinkLines(node, vpsIp, protoSel);
}

/** 导出页：按分组/类型/协议生成全部节点导出文本 */
function generateExportText() {
    const groupSel = document.getElementById('export-group-select') ? document.getElementById('export-group-select').value : 'ALL';
    const protoSel = document.getElementById('export-proto-select') ? document.getElementById('export-proto-select').value : 'both';
    const exportType = document.getElementById('export-type-select') ? document.getElementById('export-type-select').value : 'converted';
    const vpsIp = window.location.hostname || '127.0.0.1';

    const nodesToExport = nodeState.filter(n => groupSel === 'ALL' || n.group === groupSel);

    const lines = [];
    nodesToExport.forEach(n => {
        const uriLines = exportNodeLines(n, vpsIp, protoSel, exportType);
        if (uriLines.length === 0) return;
        lines.push(`# 节点: ${n.name.replace(/[\r\n]+/g, ' ')} | 协议: ${n.protocol} | 分组: ${(n.group || '').replace(/[\r\n]+/g, ' ')}${exportType === 'original' ? ' | 原始链接' : ''}`);
        lines.push(...uriLines);
        lines.push('');
    });

    const exportArea = document.getElementById('export-text-area');
    if (exportArea) exportArea.value = lines.join('\n');
}

/** 复制导出区内容到剪贴板 */
async function copyExportText() {
    const exportArea = document.getElementById('export-text-area');
    if (!exportArea || !exportArea.value) {
        generateExportText();
    }
    if (exportArea && exportArea.value) {
        const text = exportArea.value;
        if (navigator.clipboard && navigator.clipboard.writeText) {
            navigator.clipboard.writeText(text).then(() => addLog('SUCCESS', '导出链接已复制')).catch(() => fallbackCopy(text));
        } else fallbackCopy(text);
    }
}

async function exportSelectedNodes() {
    const targetNodes = selectedNodeIds.size > 0
        ? nodeState.filter(n => selectedNodeIds.has(n.id))
        : nodeState;

    const exportArea = document.getElementById('export-text-area');
    if (!exportArea) return;

    const protoSel = document.getElementById('export-proto-select') ? document.getElementById('export-proto-select').value : 'both';
    const exportType = document.getElementById('export-type-select') ? document.getElementById('export-type-select').value : 'converted';
    const vpsIp = window.location.hostname || '127.0.0.1';

    let text = '';
    targetNodes.forEach(n => {
        const uriLines = exportNodeLines(n, vpsIp, protoSel, exportType);
        if (uriLines.length === 0) return;
        text += `# 节点: ${n.name.replace(/[\r\n]+/g, ' ')} | 协议: ${n.protocol} | 分组: ${(n.group || '').replace(/[\r\n]+/g, ' ')}${exportType === 'original' ? ' | 原始链接' : ''}\n`;
        text += uriLines.join('\n');
        text += '\n\n';
    });
    exportArea.value = text;
    const exportNav = document.querySelector('.nav-item[data-target="export"]');
    if (exportNav) exportNav.click();
}

// Batch Import & Convert Entry
async function handleBatchImport() {
    // 兼容两套表单：modal（import-modal，工具栏按钮打开）优先，回退页面内联表单。
    // 关键1：modal 元素常驻 DOM（.active 控制显隐），未打开时其输入框是上次残留/默认值，
    //   必须只在 modal 真正打开（.active）时优先取它，否则会吞掉页面内联表单的用户输入。
    // 关键2：modal 打开时只用 modal 的值（清空即空值，不混用页面残留）——空值由下游
    //   兜底（group→默认分组、entryProto→mixed、text 空→触发"请粘贴"校验），语义干净。
    const modalOpen = () => {
        const m = document.getElementById('import-modal');
        return !!m && m.classList.contains('active');
    };
    const pick = (modalId, pageId) => {
        if (modalOpen()) {
            const m = document.getElementById(modalId);
            if (m && m.value !== undefined) return m.value;
        }
        const p = document.getElementById(pageId);
        return p ? p.value : '';
    };
    const text = pick('modal-import-text', 'import-text').trim();
    const startPortVal = pick('modal-import-start-port', 'import-start-port');
    const group = pick('modal-import-group', 'import-group').trim() || '默认分组';
    const entryProto = pick('modal-import-entry-proto', 'import-entry-proto') || 'mixed';
    const ssPass = pick('modal-import-ss-pass', 'import-ss-pass').trim();
    const authUser = pick('modal-import-auth-user', 'import-auth-user').trim();
    const authPass = pick('modal-import-auth-pass', 'import-auth-pass').trim();
    const subSource = document.getElementById('sub-source') ? document.getElementById('sub-source').value : '';

    if (!text) {
        alert('请粘贴节点订阅/单链接文本');
        return;
    }

    // 导入中动画：对齐 modal 水墨黑金 UI（class 驱动）
    const showImporting = (label) => {
        let ov = document.getElementById('import-overlay');
        if (!ov) {
            ov = document.createElement('div');
            ov.id = 'import-overlay';
            ov.className = 'import-overlay';
            ov.innerHTML = `
                <div class="import-panel">
                    <div class="import-title">正在导入节点</div>
                    <div class="import-spinner"></div>
                    <div class="import-sub" id="import-overlay-text">${label}</div>
                </div>`;
            document.body.appendChild(ov);
        }
        const t = document.getElementById('import-overlay-text');
        if (t) t.textContent = label;
        requestAnimationFrame(() => ov.classList.add('active'));
    };
    const hideImporting = () => {
        const ov = document.getElementById('import-overlay');
        if (ov) ov.classList.remove('active');
    };

    // 导入结果弹层：成功/跳过/重复/失败（对齐 modal 水墨黑金 UI）
    const showImportResult = (opts) => {
        hideImporting();
        let rl = document.getElementById('import-result-overlay');
        if (!rl) {
            rl = document.createElement('div');
            rl.id = 'import-result-overlay';
            rl.className = 'import-overlay';
            rl.addEventListener('click', e => { if (e.target === rl) rl.classList.remove('active'); });
            document.body.appendChild(rl);
        }
        const rows = [
            ['成功导入', opts.created, 'var(--success)'],
            ['重复（已存在）', opts.duplicate, 'var(--fg)'],
            ['跳过（端口冲突/已删）', opts.skipped, 'var(--rock)'],
            ['失败（无法解析）', opts.failed, 'var(--danger)']
        ].filter(([, v]) => v > 0);
        rl.innerHTML = `
            <div class="import-panel">
                <div class="import-title">批量导入完成</div>
                <div class="import-rows">
                    ${rows.map(([label, v, color]) => `
                        <div class="import-row">
                            <span class="import-row-label">${label}</span>
                            <span class="import-row-val" style="color:${color};">${v}</span>
                        </div>`).join('') || '<div class="import-empty">无结果返回</div>'}
                </div>
                <button class="btn btn-primary" style="padding: 10px 28px;" onclick="document.getElementById('import-result-overlay').classList.remove('active')">知道了</button>
            </div>`;
        requestAnimationFrame(() => rl.classList.add('active'));
    };

    const lines = text.split('\n').map(l => l.trim()).filter(l => l && !l.startsWith('#'));
    let startPort = parseInt(startPortVal) || undefined;

    const preparedNodes = lines.map((line, idx) => {
        let name = `Imported-Node-${idx + 1}`;
        let proto = 'ss';
        if (line.startsWith('vmess://')) proto = 'vmess';
        else if (line.startsWith('vless://')) proto = 'vless';
        else if (line.startsWith('trojan://')) proto = 'trojan';
        else if (line.startsWith('socks5://')) proto = 'socks5';
        else if (line.startsWith('http://')) proto = 'http';

        const hashIdx = line.indexOf('#');
        if (hashIdx !== -1) {
            try { name = decodeURIComponent(line.slice(hashIdx + 1)); } catch (e) { name = line.slice(hashIdx + 1); }
        }

        return {
            name: name,
            protocol: proto,
            group: group,
            port: startPort ? startPort + idx : undefined,
            entryProto: entryProto,
            ssPass: ssPass || undefined,
            authUser: authUser || undefined,
            authPass: authPass || undefined,
            subId: subSource || undefined,
            rawConfig: { uri: line }
        };
    });

    showImporting(`正在导入 ${lines.length} 个节点…`);
    try {
        const r = await api('/api/nodes/batch', {
            method: 'POST',
            body: JSON.stringify({ nodes: preparedNodes })
        });
        if (!r.ok) {
            let detail = '';
            try { detail = (await r.json()).detail || ''; } catch (e) { }
            hideImporting();
            alert(`导入失败 (HTTP ${r.status}): ${detail}`);
            return;
        }
        const res = await r.json();
        closeModal('import-modal');
        let msg = `成功批量导入 ${res.created || 0} 个节点`;
        if (res.skipped) msg += `，跳过 ${res.skipped} 个（重复/端口冲突/已删指纹）`;
        if (res.duplicate) msg += `，重复 ${res.duplicate} 个`;
        if (res.failed) msg += `，失败 ${res.failed} 个（无法解析）`;
        addLog('SUCCESS', msg);
        await loadNodes();
    await applyConfigSilent();
        // 明确结果弹层（failed 独立计数；skipped 中减去 duplicate 即为端口冲突/已删指纹类跳过）
        showImportResult({ created: res.created || 0, duplicate: res.duplicate || 0, failed: res.failed || 0, skipped: (res.skipped || 0) - (res.duplicate || 0) });
    } catch (e) {
        hideImporting();
        alert('导入节点失败: ' + e.message);
    }
}

async function handleConvertEntry() {
    const direction = document.getElementById('convert-direction') ? document.getElementById('convert-direction').value : 'ss';
    const ssPass = document.getElementById('convert-ss-pass') ? document.getElementById('convert-ss-pass').value.trim() : '';

    const ids = selectedNodeIds.size > 0 ? Array.from(selectedNodeIds) : nodeState.map(n => n.id);

    try {
        const r = await api('/api/nodes/convert-entry', {
            method: 'POST',
            body: JSON.stringify({
                ids: ids,
                entryProto: direction,
                ssPass: ssPass || undefined
            })
        });
        const data = await r.json();
        if (!r.ok) {
            const errEl = document.getElementById('convert-error');
            if (errEl) errEl.textContent = data.detail || '转换失败';
            return;
        }
        closeModal('convert-entry-modal');
        addLog('SUCCESS', `已批量转换 ${data.converted} 个节点入口协议为 ${direction}`);
        await loadNodes();
    await applyConfigSilent();
    } catch (e) {
        const errEl = document.getElementById('convert-error');
        if (errEl) errEl.textContent = e.message;
    }
}

// Traffic Chart & SSE

// ── 仪表盘实时流量曲线（黑金风格 SVG）──
// 数据缓冲：最多 60 个采样点（60s 滚动窗口），每次 SSE 推送追加并重绘
window.__trafficSamples = [];
const TRAFFIC_CHART_MAX_POINTS = 60;
const TRAFFIC_CHART_W = 800;
const TRAFFIC_CHART_H = 180;

/** 追加一个采样点（up/down bps），超过窗口长度时丢弃最旧 */
function pushTrafficSample(up, down) {
    const arr = window.__trafficSamples;
    arr.push({ up: up || 0, down: down || 0, t: Date.now() });
    if (arr.length > TRAFFIC_CHART_MAX_POINTS) arr.shift();
}

/** 绘制实时曲线：上行=金、下行=绿，双线 + 渐变填充 + 网格 + 当前值标注 */
function drawTrafficChart() {
    const svg = document.getElementById('traffic-chart-svg');
    if (!svg) return;
    const arr = window.__trafficSamples;
    if (arr.length < 2) {
        // 数据太少：画一条平滑的基线提示（黑金呼吸动效由 CSS 控制）
        svg.innerHTML = `<text x="${TRAFFIC_CHART_W / 2}" y="${TRAFFIC_CHART_H / 2}" text-anchor="middle" fill="rgba(200,184,154,0.35)" font-size="12" letter-spacing="2">等待实时流量数据…</text>`;
        return;
    }

    // 自适应 Y 轴最大值（取上下行最大值，保证曲线不裁切）
    let max = 1;
    arr.forEach(p => { if (p.up > max) max = p.up; if (p.down > max) max = p.down; });
    const padTop = 8, padBottom = 8;
    const plotH = TRAFFIC_CHART_H - padTop - padBottom;
    const step = TRAFFIC_CHART_W / (TRAFFIC_CHART_MAX_POINTS - 1);
    const xOf = i => i * step;
    const yOf = v => padTop + plotH - (v / max) * plotH;

    // 网格线（4 条水平参考线）
    let grid = '';
    for (let g = 1; g <= 4; g++) {
        const gy = padTop + plotH * (g / 5);
        const gv = (max * (5 - g) / 5);
        grid += `<line x1="0" y1="${gy.toFixed(1)}" x2="${TRAFFIC_CHART_W}" y2="${gy.toFixed(1)}" stroke="rgba(200,184,154,0.08)" stroke-width="1"/>`;
        grid += `<text x="${TRAFFIC_CHART_W - 4}" y="${(gy - 4).toFixed(1)}" text-anchor="end" fill="rgba(200,184,154,0.4)" font-size="8">${formatRate(gv).replace(' MB/s', 'M')}</text>`;
    }

    // 折线路径
    const lineFor = key => arr.map((p, i) => `${i === 0 ? 'M' : 'L'}${xOf(i).toFixed(1)},${yOf(p[key]).toFixed(1)}`).join(' ');
    // 渐变填充路径（闭合到底部）
    const areaFor = key => {
        const pts = arr.map((p, i) => `${xOf(i).toFixed(1)},${yOf(p[key]).toFixed(1)}`).join(' ');
        return `M${pts} L${xOf(arr.length - 1).toFixed(1)},${(padTop + plotH).toFixed(1)} L0,${(padTop + plotH).toFixed(1)} Z`;
    };

    // 当前值标注（右上角最新采样）
    const last = arr[arr.length - 1];

    svg.innerHTML = `
        <defs>
            <linearGradient id="chart-fill-up" x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stop-color="rgba(200,184,154,0.35)"/>
                <stop offset="100%" stop-color="rgba(200,184,154,0.02)"/>
            </linearGradient>
            <linearGradient id="chart-fill-down" x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stop-color="rgba(163,184,154,0.30)"/>
                <stop offset="100%" stop-color="rgba(163,184,154,0.02)"/>
            </linearGradient>
        </defs>
        ${grid}
        <path d="${areaFor('down')}" fill="url(#chart-fill-down)" opacity="0.8"/>
        <path d="${lineFor('down')}" fill="none" stroke="#a3b89a" stroke-width="1.6" stroke-linejoin="round" stroke-linecap="round" opacity="0.9"/>
        <path d="${areaFor('up')}" fill="url(#chart-fill-up)" opacity="0.8"/>
        <path d="${lineFor('up')}" fill="none" stroke="#c8b89a" stroke-width="1.6" stroke-linejoin="round" stroke-linecap="round"/>
        <circle cx="${xOf(arr.length - 1).toFixed(1)}" cy="${yOf(last.up).toFixed(1)}" r="2.5" fill="#c8b89a"/>
        <circle cx="${xOf(arr.length - 1).toFixed(1)}" cy="${yOf(last.down).toFixed(1)}" r="2.5" fill="#a3b89a"/>
    `;
}

/** SSE 推送后刷新图表数据与文字 */
function updateTrafficChart(upRate, downRate) {
    pushTrafficSample(upRate, downRate);
    drawTrafficChart();
    const upEl = document.getElementById('chart-up-rate');
    const downEl = document.getElementById('chart-down-rate');
    if (upEl) upEl.textContent = formatRate(upRate);
    if (downEl) downEl.textContent = formatRate(downRate);
}

function renderTrafficChart() {
    const container = document.getElementById('traffic-chart-container');
    if (!container) return;
    container.innerHTML = '';

    const filterSelect = document.getElementById('traffic-filter');
    const selectedGroup = filterSelect ? filterSelect.value : 'ALL';

    const targetNodes = selectedGroup === 'ALL'
        ? nodeState
        : nodeState.filter(n => n.group === selectedGroup);

    if (targetNodes.length === 0) {
        container.innerHTML = `<div style="color: var(--rock); font-size: 11px; text-align: center; padding: 20px;">暂无节点流量数据</div>`;
        return;
    }

    let maxTotal = 0;
    targetNodes.forEach(node => {
        const upMB = (node.upTraffic || 0) / (1024 * 1024);
        const downMB = (node.downTraffic || 0) / (1024 * 1024);
        if (upMB + downMB > maxTotal) maxTotal = upMB + downMB;
    });
    if (maxTotal === 0) maxTotal = 1;

    targetNodes.forEach((node, idx) => {
        const upMB = (node.upTraffic || 0) / (1024 * 1024);
        const downMB = (node.downTraffic || 0) / (1024 * 1024);
        const upPct = Math.min(100, (upMB / maxTotal) * 100);
        const downPct = Math.min(100, (downMB / maxTotal) * 100);

        const row = document.createElement('div');
        row.className = 'traffic-bar-row';
        row.innerHTML = `
            <div class="tb-label">${escapeHtml(node.name || 'Port ' + node.port)}</div>
            <div class="tb-track">
                <div class="tb-fill-up" style="width: 0%; z-index: 2;" data-target="${upPct}"></div>
                <div class="tb-fill-down" style="width: 0%; z-index: 1;" data-target="${upPct + downPct}"></div>
            </div>
            <div class="tb-value">
                <span style="color: var(--rock)">↑ ${upMB.toFixed(2)} MB</span>
                <span style="color: var(--success)">↓ ${downMB.toFixed(2)} MB</span>
            </div>
        `;
        container.appendChild(row);

        setTimeout(() => {
            const upFill = row.querySelector('.tb-fill-up');
            const downFill = row.querySelector('.tb-fill-down');
            if (upFill) upFill.style.width = upFill.getAttribute('data-target') + '%';
            if (downFill) downFill.style.width = downFill.getAttribute('data-target') + '%';
        }, 80 + (idx * 60));
    });
}

function renderTrafficTable() {
    const tbody = document.getElementById('traffic-tbody');
    if (!tbody) return;
    tbody.innerHTML = '';

    const filterSelect = document.getElementById('traffic-filter');
    const selectedGroup = filterSelect ? filterSelect.value : 'ALL';
    const targetNodes = selectedGroup === 'ALL' ? nodeState : nodeState.filter(n => n.group === selectedGroup);

    if (targetNodes.length === 0) {
        tbody.innerHTML = `<tr><td colspan="7" style="text-align:center; padding: 20px; color: var(--rock);">暂无流量记录</td></tr>`;
        return;
    }

    targetNodes.forEach(node => {
        const totalBytes = (node.upTraffic || 0) + (node.downTraffic || 0);
        const tr = document.createElement('tr');
        tr.innerHTML = `
            <td style="font-family: var(--font-mono);">${escapeHtml(node.port)}</td>
            <td><strong>${escapeHtml(node.name)}</strong></td>
            <td><span class="group-tag">${escapeHtml(node.group) || '默认分组'}</span></td>
            <td>${formatBytes(node.upTraffic || 0)}</td>
            <td>${formatBytes(node.downTraffic || 0)}</td>
            <td style="color: var(--rock); font-family: var(--font-mono);">${formatBytes(totalBytes)}</td>
            <td><button class="btn-action danger" onclick="resetNodeTraffic('${escapeHtml(node.id)}')">${L('RESET')}</button></td>
        `;
        tbody.appendChild(tr);
    });
}

async function resetNodeTraffic(id) {
    try {
        await api(`/api/nodes/${id}/traffic/reset`, { method: 'POST' });
        addLog('INFO', `复位节点 [ID: ${id}] 流量统计`);
        await loadNodes();
    await applyConfigSilent();
    } catch (e) {
        addLog('ERROR', '重置节点流量失败: ' + e.message);
    }
}

async function resetAllTraffic() {
    if (!confirm('确定重置全网所有节点的累计流量？')) return;
    try {
        await api('/api/traffic/reset', { method: 'POST' });
        addLog('SUCCESS', '所有节点流量数据已清空');
        await loadNodes();
    await applyConfigSilent();
    } catch (e) {
        addLog('ERROR', '重置全网流量失败: ' + e.message);
    }
}

function startTrafficSSE() {
    // 登出/401 后（token 清空）不建连接——否则 onerror 5s 定时器窗口内登出
    // 会发出一次无 token 的 401 SSE 请求（纯浪费）
    if (!authToken) return;
    if (sseSource) { sseSource.close(); sseSource = null; }
    try {
        const url = `/api/stats/stream${authToken ? '?token=' + encodeURIComponent(authToken) : ''}`;
        sseSource = new EventSource(url);
        sseSource.onmessage = (e) => {
            try {
                const data = JSON.parse(e.data);
                if (data.type === 'traffic') {
                    const upRate = data.upRate || data.up || 0;
                    const downRate = data.downRate || data.down || 0;
                    const totalSpeed = upRate + downRate;
                    if (totalSpeed > peakSpeedMbps) peakSpeedMbps = totalSpeed;

                    const totalSpeedEl = document.getElementById('dash-stat-total-speed');
                    if (totalSpeedEl) totalSpeedEl.innerHTML = `${formatRate(totalSpeed)}`;

                    // 实时曲线：每 1s 采样一次推送
                    updateTrafficChart(upRate, downRate);

                    const peakSpeedEl = document.getElementById('dash-stat-peak-speed');
                    if (peakSpeedEl) peakSpeedEl.innerHTML = `${formatRate(peakSpeedMbps)}`;

                    // 平均速率：滚动平均（最近 10 次采样），不再用瞬时 *0.8 假数据
                    window.__speedSamples = window.__speedSamples || [];
                    window.__speedSamples.push(totalSpeed);
                    if (window.__speedSamples.length > 10) window.__speedSamples.shift();
                    const avgSpeed = window.__speedSamples.reduce((a, b) => a + b, 0) / window.__speedSamples.length;
                    const avgSpeedEl = document.getElementById('dash-stat-avg-speed');
                    if (avgSpeedEl) avgSpeedEl.innerHTML = `${formatRate(avgSpeed)}`;

                    if (data.nodes && Array.isArray(data.nodes)) {
                        data.nodes.forEach(ns => {
                            const node = nodeState.find(n => n.id === ns.id);
                            if (node) {
                                node.upTraffic = ns.upTraffic;
                                node.downTraffic = ns.downTraffic;
                                node.status = ns.status;
                                node.ping = ns.ping;
                            }
                        });
                        const activeTrafficPage = document.getElementById('traffic');
                        if (activeTrafficPage && activeTrafficPage.classList.contains('active')) {
                            renderTrafficChart();
                        }
                        // 节流刷新节点表/矩阵/统计（SSE 每 1s 一条，2s 一次全量刷新不卡顿）
                        if (!window.__sseRenderTimer) {
                            window.__sseRenderTimer = setTimeout(() => {
                                window.__sseRenderTimer = null;
                                renderQuickStats();
                                renderDashRelayStatus();
                                renderNodeMatrix();
                                renderNodesTable();
                            }, 2000);
                        }
                    }
                }
            } catch (err) { }
        };
        sseSource.onerror = () => {
            if (sseSource) sseSource.close();
            sseSource = null;
            if (!authToken) return; // 登出/401 后不再重连
            // SSE 断流可能是网络抖动（重连）或 token 失效（容器重启后内存 token 清空）。
            // EventSource onerror 拿不到状态码，用 /api/auth/check 探测：401 时 api() 会
            // 清 token + 回登录页（authToken 变空），这里 return 停止死循环重连；
            // 探测失败（网络错误）或 200 → 5s 后重连（网络抖动自愈）。
            api('/api/auth/check').then(() => {
                if (!authToken) return;
                setTimeout(startTrafficSSE, 5000);
            }).catch(() => {
                // 网络错误（fetch 失败，非 401）→ 抖动自愈重连；token 仍有效则继续
                if (!authToken) return;
                setTimeout(startTrafficSSE, 5000);
            });
        };
    } catch (err) { }
}

// Subscriptions Management
async function loadSubs() {
    try {
        const r = await api('/api/subs');
        subState = await r.json();
        renderSubsList();
    } catch (e) { }
}

function renderSubsList() {
    const listEl = document.getElementById('sub-list');
    const sourceSelect = document.getElementById('sub-source');

    if (sourceSelect) {
        sourceSelect.innerHTML = `<option value="">Do not associate</option>`;
        subState.forEach(s => {
            const opt = document.createElement('option');
            opt.value = s.id;
            opt.textContent = `${s.name} (${s.group})`;
            sourceSelect.appendChild(opt);
        });
    }

    if (!listEl) return;
    if (subState.length === 0) {
        listEl.innerHTML = `<div style="color: var(--rock); padding: 12px 0;">No subscriptions added yet.</div>`;
        return;
    }

    listEl.innerHTML = subState.map(s => `
        <div style="display:flex; justify-content:space-between; align-items:center; border-bottom: 1px dashed var(--dim); padding: 8px 0;">
            <div>
                <strong>${escapeHtml(s.name)}</strong> <span class="group-tag">${escapeHtml(s.group)}</span>
                <div style="font-size: 10px; opacity:0.6;">${escapeHtml(s.url)}</div>
            </div>
            <div style="display:flex; gap:6px;">
                <button class="btn-action" onclick="openEditSubModal('${escapeHtml(s.id)}')">${L('EDIT')}</button>
                <button class="btn-action" onclick="refreshSub('${escapeHtml(s.id)}')">${L('SYNC')}</button>
                <button class="btn-action danger" onclick="deleteSub('${escapeHtml(s.id)}')">${L('DROP')}</button>
            </div>
        </div>
    `).join('');

    // 订阅管理页表格（subs-tbody）同步填充
    const tbody = document.getElementById('subs-tbody');
    if (tbody) {
        tbody.innerHTML = subState.map(s => {
            // 状态徽标三态：失效（stale 无快照）/ 降级（有快照兜底）/ 可用
            let badge = '';
            if (s.stale) badge = `<span class="sub-badge sub-badge-fail" title="${escapeHtml(s.lastError || '刷新失败')}">失效</span>`;
            else if (s.degraded) badge = `<span class="sub-badge sub-badge-degraded" title="${escapeHtml(s.lastError || '刷新失败，使用上次快照')}">降级</span>`;
            else badge = `<span class="sub-badge sub-badge-ok">可用 · ${escapeHtml(s.nodeCount ?? s.node_count ?? 0)} 节点</span>`;
            return `
            <tr>
                <td><strong>${escapeHtml(s.name)}</strong></td>
                <td style="font-family: var(--font-mono); font-size: 11px; max-width: 260px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;" title="${escapeHtml(s.lastError || '')}">${escapeHtml(s.url)}</td>
                <td><span class="group-tag">${escapeHtml(s.group) || '默认分组'}</span></td>
                <td>${escapeHtml(s.nodeCount ?? s.node_count ?? '-')}</td>
                <td style="font-size: 11px; opacity: 0.8;">${escapeHtml(s.lastRefresh ? new Date(s.lastRefresh).toLocaleString() : '-')}</td>
                <td>${badge}</td>
                <td>
                    <div style="display:flex; gap:6px;">
                        <button class="btn-action" onclick="openEditSubModal('${escapeHtml(s.id)}')">${L('EDIT')}</button>
                        <button class="btn-action" onclick="refreshSub('${escapeHtml(s.id)}')">${L('SYNC')}</button>
                        <button class="btn-action danger" onclick="deleteSub('${escapeHtml(s.id)}')">${L('DROP')}</button>
                    </div>
                </td>
            </tr>`;
        }).join('');
    }
}

/** 订阅管理页内联表单添加订阅（空名称回退用链接本身） */
async function addSubscriptionFromSubsPage() {
    const url = document.getElementById('subs-url').value.trim();
    const name = document.getElementById('subs-name').value.trim();
    const group = document.getElementById('subs-group').value.trim() || '订阅节点';
    if (!url) { alert('请输入订阅链接'); return; }
    try {
        const r = await api('/api/subs', {
            method: 'POST',
            body: JSON.stringify({ url, name: name || url, group })
        });
        if (!r.ok) {
            const err = await r.json();
            alert(err.detail || '添加订阅失败');
            return;
        }
        addLog('SUCCESS', `成功添加订阅 [${name || url}]`);
        document.getElementById('subs-url').value = '';
        document.getElementById('subs-name').value = '';
        await loadSubs();
    } catch (e) {
        alert('添加订阅错误: ' + e.message);
    }
}

/** 每 6 小时自动刷新开关 → settings.autoRefresh（后端 scheduler 读该字段调度） */
async function saveSubAutoRefresh() {
    const chk = document.getElementById('sub-auto-refresh');
    const autoRefresh = !!(chk && chk.checked);
    try {
        const r = await api('/api/settings');
        const s = await r.json();
        const save = await api('/api/settings', { method: 'PUT', body: JSON.stringify({ ...s, autoRefresh }) });
        if (!save.ok) addLog('WARN', `保存自动刷新设置失败 (HTTP ${save.status})`);
        else addLog('INFO', `订阅自动刷新已${autoRefresh ? '开启' : '关闭'}`);
    } catch (e) {
        addLog('ERROR', '保存自动刷新设置失败: ' + e.message);
    }
}

async function addSubscription() {
    const url = document.getElementById('sub-url').value.trim();
    const name = document.getElementById('sub-name').value.trim();
    const group = document.getElementById('sub-group').value.trim() || '订阅节点';

    if (!url) { alert('请输入订阅 URL'); return; }

    try {
        const r = await api('/api/subs', {
            method: 'POST',
            body: JSON.stringify({ url, name: name || url, group })
        });
        if (!r.ok) {
            const err = await r.json();
            alert(err.detail || '添加订阅失败');
            return;
        }
        addLog('SUCCESS', `成功添加订阅 [${name || url}]`);
        document.getElementById('sub-url').value = '';
        document.getElementById('sub-name').value = '';
        await loadSubs();
    } catch (e) {
        alert('添加订阅错误: ' + e.message);
    }
}

async function refreshSub(id) {
    addLog('INFO', `正在刷新订阅 [ID: ${id}]...`);
    try {
        const r = await api('/api/subs/refresh', {
            method: 'POST',
            body: JSON.stringify({ ids: [id], all: false })
        });
        addLog('SUCCESS', '订阅刷新成功');
        await loadSubs();
        await loadNodes();
    await applyConfigSilent();
    } catch (e) {
        addLog('ERROR', '刷新订阅失败: ' + e.message);
    }
}

async function deleteSub(id) {
    if (!confirm('确定删除该订阅？')) return;
    try {
        await api(`/api/subs/${id}`, { method: 'DELETE' });
        addLog('SUCCESS', '删除订阅成功');
        await loadSubs();
    } catch (e) {
        addLog('ERROR', '删除订阅失败: ' + e.message);
    }
}


function openEditSubModal(id) {
    const sub = subState.find(s => s.id === id);
    if (!sub) return;
    editingSubId = id;
    const setName = document.getElementById('edit-sub-name');
    const setUrl = document.getElementById('edit-sub-url');
    const setGroup = document.getElementById('edit-sub-group');
    if (setName) setName.value = sub.name || '';
    if (setUrl) setUrl.value = sub.url || '';
    if (setGroup) setGroup.value = sub.group || '';
    openModal('edit-sub-modal');
}

async function handleSaveSubEdit() {
    if (!editingSubId) { closeModal('edit-sub-modal'); return; }
    const name = document.getElementById('edit-sub-name').value.trim();
    const url = document.getElementById('edit-sub-url').value.trim();
    const group = document.getElementById('edit-sub-group').value.trim();
    const errEl = document.getElementById('edit-sub-error');
    try {
        const r = await api(`/api/subs/${editingSubId}`, {
            method: 'PATCH',
            body: JSON.stringify({ name, url, group })
        });
        if (!r.ok) {
            if (errEl) errEl.textContent = (await r.json()).detail || '保存失败';
            return;
        }
        closeModal('edit-sub-modal');
        editingSubId = null;
        addLog('SUCCESS', `订阅 [${name}] 已保存`);
        await loadSubs();
    } catch (e) {
        if (errEl) errEl.textContent = e.message;
    }
}

// System Settings & Config
async function loadSettings() {
    try {
        const r = await api('/api/settings');
        if (!r.ok) return;
        const s = await r.json();
        // 轮询域名列表 → relayState + 渲染；relayExits（当前出口）供仪表盘徽标显示
        relayState = Array.isArray(s.relayDomains) ? s.relayDomains : [];
        window.__relayExits = (s.relayExits && typeof s.relayExits === 'object') ? s.relayExits : {};
        renderRelayDomains();
        renderDashRelayStatus();

        const setVal = (id, val) => {
            const el = document.getElementById(id);
            if (el && val !== undefined) el.value = val;
        };
        const setChk = (id, val) => {
            const el = document.getElementById(id);
            if (el) el.checked = !!val;
        };

        setVal('setting-inbound-port', s.inboundPort || 2080);
        setVal('setting-clash-port', s.clashPort || 9095);
        setVal('setting-probe-interval', s.probeInterval || 30);
        setVal('setting-log-level', s.logLevel || 'info');
        setVal('setting-listen-ip', s.listenIp || '0.0.0.0');
        setVal('setting-test-url', s.testUrl || 'https://www.gstatic.com/generate_204');
        setVal('setting-reserved-ports', Array.isArray(s.reservedPorts) ? s.reservedPorts.join(', ') : (s.reservedPorts || ''));

        setChk('setting-sticky-enabled', s.stickyEnabled);
        setVal('setting-sticky-timeout', s.stickyTimeout || '5m');
        setChk('setting-random-rotate-enabled', s.randomRotateEnabled);
        setVal('setting-random-rotate-interval', s.randomRotateInterval || 30);
        const autoRefreshChk = document.getElementById('sub-auto-refresh');
        if (autoRefreshChk) autoRefreshChk.checked = s.autoRefresh !== false;
    } catch (e) { }
}

async function saveSystemSettings() {
    const getVal = (id) => { const el = document.getElementById(id); return el ? el.value : ''; };
    const getChk = (id) => { const el = document.getElementById(id); return el ? el.checked : false; };

    const reservedStr = getVal('setting-reserved-ports');
    const reservedPorts = reservedStr.split(/[\n,]+/).map(p => parseInt(p.trim())).filter(p => !isNaN(p));

    const payload = {
        inboundPort: parseInt(getVal('setting-inbound-port')) || 2080,
        clashPort: parseInt(getVal('setting-clash-port')) || 9095,
        probeInterval: parseInt(getVal('setting-probe-interval')) || 30,
        logLevel: getVal('setting-log-level') || 'info',
        listenIp: getVal('setting-listen-ip') || '0.0.0.0',
        testUrl: getVal('setting-test-url') || 'https://www.gstatic.com/generate_204',
        reservedPorts: reservedPorts,
        stickyEnabled: getChk('setting-sticky-enabled'),
        stickyTimeout: getVal('setting-sticky-timeout') || '5m',
        randomRotateEnabled: getChk('setting-random-rotate-enabled'),
        randomRotateInterval: parseInt(getVal('setting-random-rotate-interval')) || 30,
        autoRefresh: getChk('sub-auto-refresh'),   // 全量 PUT 不能冲掉订阅自动刷新开关
        // 全量 PUT 不能冲掉轮询域名（否则 settings 覆盖后 relay 卡片消失、后续 upsert 清表）
        relayDomains: Array.isArray(relayState) ? relayState : []
    };

    try {
        const r = await api('/api/settings', {
            method: 'PUT',
            body: JSON.stringify(payload)
        });
        if (r.ok) {
            addLog('SUCCESS', '系统设置保存成功，配置热重载已生效');
            alert('系统设置已应用');
        }
    } catch (e) {
        addLog('ERROR', '保存系统设置失败: ' + e.message);
    }
}

async function loadConfig() {
    try {
        const r = await api('/api/config');
        const data = await r.json();
        const codeEl = document.getElementById('config-json-code');
        if (codeEl && data.config) {
            codeEl.textContent = JSON.stringify(data.config, null, 2);
        }
    } catch (e) { }
}

/** 复制配置 JSON 到剪贴板 */
function copyConfigJson() {
    const codeEl = document.getElementById('config-json-code');
    if (!codeEl || !codeEl.textContent) return;
    const text = codeEl.textContent;
    if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(text).then(() => addLog('SUCCESS', '配置 JSON 已复制')).catch(() => fallbackCopy(text));
    } else fallbackCopy(text);
}

/** 下载 config.json */
function downloadConfigFile() {
    const codeEl = document.getElementById('config-json-code');
    if (!codeEl || !codeEl.textContent) return;
    const blob = new Blob([codeEl.textContent], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'config.json';
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    addLog('SUCCESS', 'config.json 已下载');
}

function fallbackCopy(text) {
    const ta = document.createElement('textarea');
    ta.value = text;
    document.body.appendChild(ta);
    ta.select();
    try { document.execCommand('copy'); addLog('SUCCESS', '已复制到剪贴板'); }
    catch (e) { addLog('ERROR', '复制失败: ' + e.message); }
    document.body.removeChild(ta);
}

async function addRelayDomain() {
    try {
        // 读取当前 settings，直接追加一张默认卡片（字段在卡片内联编辑，无弹窗）
        const r = await api('/api/settings');
        const s = await r.json();
        const list = Array.isArray(s.relayDomains) ? s.relayDomains : [];
        const maxPort = list.length > 0 ? Math.max(...list.map(x => parseInt(x.port) || 0), 33440) : 33439;
        list.push({
            id: 'relay-' + Date.now().toString(36),
            domain: 'relay' + (list.length + 1) + '.example.com',
            port: maxPort + 1,
            authUser: 'relayuser',
            authPass: 'relaypass',
            groups: ['ALL']
        });
        const save = await api('/api/settings', { method: 'PUT', body: JSON.stringify({ ...s, relayDomains: list }) });
        if (!save.ok) { alert('保存失败 (HTTP ' + save.status + ')'); return; }
        relayState = list;
        renderDashRelayStatus();
        addLog('SUCCESS', `已添加轮询域名，请在卡片上填写域名/端口/用户/密码`);
        renderRelayDomains();
    } catch (e) {
        alert('添加轮询域名失败: ' + e.message);
    }
}

/** 渲染轮询域名卡片（域名/端口/用户/密码可编辑 + 分组勾选 + URI 显示复制） */
function renderRelayDomains() {
    const listEl = document.getElementById('relay-domain-list');
    if (!listEl) return;
    if (!relayState || relayState.length === 0) {
        listEl.innerHTML = `<div style="color: var(--rock); padding: 12px 0;">暂无轮询域名，点击上方添加。</div>`;
        return;
    }
    const groups = Array.from(new Set(nodeState.map(n => n.group || '默认分组')));
    const allGroups = ['ALL', ...groups];

    listEl.innerHTML = relayState.map((rd, idx) => {
        const uri = `socks5://${rd.authUser || ''}:${rd.authPass || ''}@${rd.domain}:${rd.port}`;
        return `<div style="border:1px solid rgba(180,165,140,.18); border-radius:8px; padding:14px 16px; background:rgba(11,15,20,.5);">
            <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:10px;">
                <span style="font-weight:600; font-size:15px;">域名 ${idx + 1}</span>
                <button class="btn-action danger" onclick="removeRelayDomain(decodeURIComponent('${encodeURIComponent(rd.id)}'))">删除</button>
            </div>
            <div style="display:grid; grid-template-columns: 1.5fr 0.7fr 0.7fr 0.7fr; gap:12px; margin-bottom:10px;">
                <div><label class="form-label" style="font-size:12px;">域名 / IP</label>
                    <input type="text" class="form-input" value="${escapeHtml(rd.domain)}" onchange="updateRelayDomainField(decodeURIComponent('${encodeURIComponent(rd.id)}'),'domain',this.value)"></div>
                <div><label class="form-label" style="font-size:12px;">端口</label>
                    <input type="number" class="form-input" value="${escapeHtml(rd.port)}" onchange="updateRelayDomainField(decodeURIComponent('${encodeURIComponent(rd.id)}'),'port',this.value)"></div>
                <div><label class="form-label" style="font-size:12px;">用户</label>
                    <input type="text" class="form-input" value="${escapeHtml(rd.authUser || '')}" onchange="updateRelayDomainField(decodeURIComponent('${encodeURIComponent(rd.id)}'),'authUser',this.value)"></div>
                <div><label class="form-label" style="font-size:12px;">密码</label>
                    <input type="text" class="form-input" value="${escapeHtml(rd.authPass || '')}" onchange="updateRelayDomainField(decodeURIComponent('${encodeURIComponent(rd.id)}'),'authPass',this.value)"></div>
            </div>
            <div style="display:flex; flex-wrap:wrap; gap:10px; align-items:center;">
                <span style="font-size:12px; opacity:0.8;">轮询分组：</span>
                ${allGroups.map(g => `
                    <label style="font-size:12px; cursor:pointer; display:flex; align-items:center; gap:4px;">
                        <input type="checkbox" ${(rd.groups || []).includes(g) ? 'checked' : ''} onchange="toggleRelayDomainGroup(decodeURIComponent('${encodeURIComponent(rd.id)}'),decodeURIComponent('${encodeURIComponent(g)}'),this.checked)"> ${escapeHtml(g)}
                    </label>`).join('')}
            </div>
            <div style="margin-top:10px; display:flex; align-items:center; gap:8px; font-family: var(--font-mono); font-size:11px; opacity:0.8;">
                <span style="word-break:break-all;">${escapeHtml(uri)}</span>
                <button class="btn-action" onclick="copyToClipboard(decodeURIComponent('${encodeURIComponent(uri)}'))">复制</button>
            </div>
        </div>`;
    }).join('');
}

/** 编辑 relay 域名字段（域名/端口/用户/密码），保存后重建配置生效 */
async function updateRelayDomainField(id, field, val) {
    try {
        const r = await api('/api/settings');
        const s = await r.json();
        const list = Array.isArray(s.relayDomains) ? s.relayDomains : [];
        const rd = list.find(x => x.id === id);
        if (!rd) return;
        if (field === 'port') {
            const p = parseInt(val, 10);
            if (!p || p < 1024 || p > 65535) { addLog('WARN', '端口无效（1024-65535），已保留原值'); renderRelayDomains(); return; }
            rd[field] = p;
        } else {
            rd[field] = val;
        }
        const save = await api('/api/settings', { method: 'PUT', body: JSON.stringify({ ...s, relayDomains: list }) });
        if (!save.ok) { addLog('WARN', `更新失败 (HTTP ${save.status})`); return; }
        relayState = list;
        renderDashRelayStatus();
        addLog('INFO', `已更新 ${field} → ${val}`);
        renderRelayDomains();
    } catch (e) {
        addLog('ERROR', '更新失败: ' + e.message);
    }
}

/** 勾选/取消 relay 域名轮询分组 */
async function toggleRelayDomainGroup(id, group, checked) {
    try {
        const r = await api('/api/settings');
        const s = await r.json();
        const list = Array.isArray(s.relayDomains) ? s.relayDomains : [];
        const rd = list.find(x => x.id === id);
        if (!rd) return;
        if (!Array.isArray(rd.groups)) rd.groups = [];
        if (checked && !rd.groups.includes(group)) rd.groups.push(group);
        if (!checked) rd.groups = rd.groups.filter(g => g !== group);
        const save = await api('/api/settings', { method: 'PUT', body: JSON.stringify({ ...s, relayDomains: list }) });
        if (!save.ok) { addLog('WARN', `分组更新失败 (HTTP ${save.status})`); return; }
        relayState = list;
        renderDashRelayStatus();
        addLog('INFO', `轮询分组 ${group} ${checked ? '加入' : '移除'}`);
        renderRelayDomains();
    } catch (e) {
        addLog('ERROR', '分组更新失败: ' + e.message);
    }
}

/** 复制文本到剪贴板（通用） */
function copyToClipboard(text) {
    if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(text).then(() => addLog('SUCCESS', '已复制到剪贴板')).catch(() => fallbackCopy(text));
    } else fallbackCopy(text);
}

async function removeRelayDomain(id) {
    if (!confirm('确定删除该轮询域名？')) return;
    try {
        const r = await api('/api/settings');
        const s = await r.json();
        const list = (Array.isArray(s.relayDomains) ? s.relayDomains : []).filter(rd => rd.id !== id);
        const save = await api('/api/settings', { method: 'PUT', body: JSON.stringify({ ...s, relayDomains: list }) });
        if (!save.ok) { alert('删除失败 (HTTP ' + save.status + ')'); return; }
        addLog('SUCCESS', `已删除轮询域名 ${id}`);
        relayState = list;
        renderDashRelayStatus();
        renderRelayDomains();
    } catch (e) {
        alert('删除失败: ' + e.message);
    }
}

function clearSystemLogs() {
    bgLogs = [];
    const terminalEl = document.getElementById('system-logs-container');
    if (terminalEl) terminalEl.innerHTML = `<div style="color: var(--rock); font-size: 11px;">[INFO] 系统运行与端口调度日志加载完成。</div>`;
    addLog('INFO', '日志控制台已清空');
}

function loadDemoNodes() {
    alert('正在重新载入节点列表...');
    loadNodes();
}

async function clearAllData() {
    if (!confirm('⚠️ 警告：确定重置所有节点流量数据？该操作不可逆！')) return;
    try {
        await resetAllTraffic();
        addLog('SUCCESS', '所有节点流量已清空');
    } catch (e) { }
}

// Initial Page Lifecycle Hook
window.addEventListener('load', async () => {
    saveOriginalTexts(document.body);
    setLanguage(currentLang);

    // Initial check for authorization status
    await checkAuth();

    document.querySelectorAll('#login-screen .scramble-text').forEach(el => {
        new TextScramble(el).setText(el.getAttribute('data-text') || el.innerText);
    });
});
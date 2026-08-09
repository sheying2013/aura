/* ============================================
 * SingBox 中转面板 - 订阅管理模块
 * 功能：订阅 URL 管理、拉取解析、6小时自动刷新
 * 支持：Base64 列表 / Clash YAML / v2ray 订阅 / sing-box JSON
 * ============================================ */

const SubscriptionManager = (() => {
  // 订阅存储 key
  const SUB_KEY = 'sb_subscriptions';
  const REFRESH_INTERVAL = 3 * 60 * 60 * 1000; // 3 小时

  let subscriptions = [];  // {id, url, name, group, lastFetch, lastRefresh, nodeCount, enabled}
  let refreshTimer = null;
  let minuteTimer = null;

  /* ---------- 基础工具 ---------- */
  function safeB64Decode(str) {
    try {
      let s = str.replace(/-/g, '+').replace(/_/g, '/');
      while (s.length % 4) s += '=';
      const bin = atob(s);
      // 尝试 UTF-8
      try { return decodeURIComponent(escape(bin)); } catch (e) { return bin; }
    } catch (e) { return null; }
  }

  function detectB64Len(str) {
    // 判断字符串是否是 base64 内容（较长、无空白、常见 b64 字符）
    return str.length > 40 && /^[A-Za-z0-9+/=_-]+$/.test(str.trim());
  }

  /* ---------- 单链接解析（支持 ss/vmess/vless/trojan/ssr/hysteria2/tuic） ---------- */
  function parseLink(line) {
    line = line.trim();
    if (!line || line.startsWith('#')) return null;
    // 优先复用主面板已有解析器（支持 ss/vmess/vless/trojan）
    if (typeof parseProxyUri === 'function') {
      const r = parseProxyUri(line);
      if (r) return r;
    }
    // 补充解析器：hysteria2 / tuic / ssr
    let name = '';
    const hi = line.indexOf('#');
    if (hi !== -1) { name = decodeURIComponent(line.slice(hi + 1)); line = line.slice(0, hi); }
    try {
      if (line.startsWith('hysteria2://')) {
        const m = line.replace(/^hysteria2:\/\//, '').match(/^([^@]*)@?([^:]+):(\d+)(.*)$/);
        if (!m) return null;
        const params = new URLSearchParams(m[4].replace(/^\?/, ''));
        return { name, protocol: 'hysteria2', rawConfig: {
          type: 'hysteria2', server: m[2], server_port: parseInt(m[3]),
          password: m[1] || params.get('auth'), sni: params.get('sni') || '',
          obfs: params.get('obfs') || '', obfs_password: params.get('obfs-password') || ''
        }};
      }
      if (line.startsWith('tuic://')) {
        const m = line.replace(/^tuic:\/\//, '').match(/^([^@]+)@([^:]+):(\d+)(.*)$/);
        if (!m) return null;
        const parts = m[1].split(':');
        const params = new URLSearchParams(m[4].replace(/^\?/, ''));
        return { name, protocol: 'tuic', rawConfig: {
          type: 'tuic', server: m[2], server_port: parseInt(m[3]),
          uuid: parts[0], password: parts[1] || '', sni: params.get('sni') || '',
          alpn: params.get('alpn') || '', congestion_controller: params.get('congestion_controller') || 'bbr'
        }};
      }
      if (line.startsWith('ssr://')) {
        const dec = safeB64Decode(line.replace(/^ssr:\/\//, ''));
        if (!dec) return null;
        // host:port:protocol:method:obfs:base64(password)/?params
        const base = dec.split('/?')[0].split(':');
        if (base.length < 6) return null;
        const pwd = safeB64Decode(base[5]);
        return { name, protocol: 'ssr', rawConfig: {
          type: 'ssr', server: base[0], server_port: parseInt(base[1]),
          protocol: base[2], method: base[3], obfs: base[4], password: pwd || base[5]
        }};
      }
    } catch (e) {}
    return null;
  }

  /* ---------- 内容类型检测 ---------- */
  function detectContentType(content) {
    const t = content.trim();
    // 1. 以 { 或 [ 开头 → JSON（v2ray 订阅 / sing-box）
    if (t.startsWith('{') || t.startsWith('[')) return 'json';
    // 2. Clash YAML（proxies: 关键字）
    if (/^proxies:\s*$/m.test(t) || /(^|\n)\s*proxies:\s*\[/.test(t)) return 'clash';
    // 3. 含多个 URL 行 → 节点列表（base64 或明文）
    if (t.includes('\n') && /(^|\n)(ss|vmess|vless|trojan|ssr):\/\//.test(t)) return 'urllist';
    // 4. 单行 base64 或单链接
    if (/^(ss|vmess|vless|trojan|ssr):\/\//.test(t)) return 'urllist';
    if (detectB64Len(t)) return 'b64';
    return 'unknown';
  }

  /* ---------- Base64 内容解析 ---------- */
  function parseB64Content(content) {
    const dec = safeB64Decode(content.trim());
    if (!dec) return [];
    return dec.split('\n').map(l => parseLink(l)).filter(Boolean);
  }

  /* ---------- Clash YAML 解析 ---------- */
  function parseClashYaml(content) {
    const nodes = [];
    try {
      // 找 proxies: 行，取其后到文件末尾或下一个顶层键（0 缩进键）
      const lines = content.split('\n');
      let start = -1;
      for (let i = 0; i < lines.length; i++) {
        if (/^\s*proxies:\s*$/.test(lines[i])) { start = i + 1; break; }
      }
      if (start === -1) return nodes;
      // 收集代理条目：每行以（可选缩进）"- " 开头开始一个新条目
      let blocks = [];
      let cur = null;
      for (let i = start; i < lines.length; i++) {
        const l = lines[i];
        // 遇到下一个顶层键（无缩进的 key:）则停止
        if (/^[a-zA-Z][\w-]*:\s*$/.test(l) && i > start) break;
        if (/^\s*-\s+/.test(l)) {
          if (cur) blocks.push(cur);
          cur = [l.replace(/^\s*-\s+/, '')];
        } else if (cur) {
          cur.push(l);
        }
      }
      if (cur) blocks.push(cur);

      blocks.forEach(block => {
        const obj = {};
        const blines = block;
        // 顶层 kv（不含 opts 子块）
        blines.forEach(l => {
          const kv = l.match(/^\s*([\w-]+):\s*(.*)$/);
          if (kv && !/^(ws-opts|grpc-opts|reality-opts|plugin-opts|ss-opts|xhttp-opts|tls-opts|http-opts)$/.test(kv[1])) {
            obj[kv[1]] = kv[2].replace(/^["']|["']$/g, '').trim();
          }
        });
        // 嵌套 opts 子块
        for (let i = 0; i < blines.length; i++) {
          const opm = blines[i].match(/^\s*([\w-]+)-opts:\s*$/);
          if (opm) {
            const sub = {};
            for (let j = i + 1; j < blines.length && /^\s+\S/.test(blines[j]); j++) {
              const kv = blines[j].match(/^\s+([\w-]+):\s*(.*)$/);
              if (kv) sub[kv[1]] = kv[2].replace(/^["']|["']$/g, '').trim();
            }
            obj[opm[1] + '-opts'] = sub;
          }
        }
        if (!obj.name || !obj.type) return;
        const protocolMap = { ss: 'ss', ssr: 'ssr', vmess: 'vmess', vless: 'vless', trojan: 'trojan', hysteria2: 'hysteria2', wireguard: 'wireguard', tuic: 'tuic' };
        const proto = protocolMap[obj.type];
        if (!proto) return;
        nodes.push({ name: obj.name, protocol: proto, rawConfig: obj });
      });
    } catch (e) { console.warn('Clash YAML 解析失败', e); }
    return nodes;
  }

  /* ---------- JSON 订阅解析（sing-box / v2rayN / Clash JSON） ---------- */
  function parseJsonContent(content) {
    const nodes = [];
    try {
      let data = JSON.parse(content);
      // sing-box: {outbounds:[...]}
      if (data.outbounds && Array.isArray(data.outbounds)) data = data.outbounds;
      // Clash JSON: {proxies:[...]}
      if (data.proxies && Array.isArray(data.proxies)) {
        data = data.proxies.map(p => ({ type: p.type, name: p.name, ...p }));
      }
      // v2rayN/Xray 多配置: [{remarks, outbounds:[...]}]
      if (Array.isArray(data)) {
        const flat = [];
        data.forEach(elem => {
          if (elem.outbounds && Array.isArray(elem.outbounds)) {
            // v2rayN 结构：每元素含 remarks + outbounds[0] 是配置
            const ob = elem.outbounds[0];
            if (ob) flat.push({ name: elem.remarks || ob.tag || '', type: ob.protocol, settings: ob.settings, streamSettings: ob.streamSettings });
          } else flat.push(elem);
        });
        data = flat;
      }
      if (!Array.isArray(data)) return nodes;
      data.forEach(o => {
        const type = o.type || o.protocol;
        const name = o.name || o.remark || o.ps || o.remarks || '';
        if (['vmess', 'vless', 'trojan', 'shadowsocks', 'ss', 'hysteria2', 'tuic', 'wireguard'].includes(type)) {
          nodes.push({
            name: name || (o.server + ':' + (o.server_port || o.port)),
            protocol: type === 'shadowsocks' ? 'ss' : type,
            rawConfig: o
          });
        }
      });
    } catch (e) { console.warn('JSON 订阅解析失败', e); }
    return nodes;
  }

  /* ---------- 内容统一解析入口 ---------- */
  function parseContent(content) {
    const type = detectContentType(content);
    switch (type) {
      case 'b64':
      case 'urllist': {
        // urllist 可能是明文多行
        if (type === 'urllist') return content.split('\n').map(l => parseLink(l)).filter(Boolean);
        return parseB64Content(content);
      }
      case 'clash': return parseClashYaml(content);
      case 'json': return parseJsonContent(content);
      default: return [];
    }
  }

  /* ---------- 订阅拉取 ---------- */
  // 后端模式：走 /api/subs/fetch（服务端 httpx 拉取，无浏览器 CORS 限制）
  // 本地模式：直接 fetch（机场订阅大多不带 CORS 头，仅本地可用）
  async function fetchSubscription(url) {
    if (window.__backendMode) {
      const token = localStorage.getItem('sb_auth_token') || '';
      const resp = await fetch('/api/subs/fetch', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', ...(token ? { Authorization: 'Bearer ' + token } : {}) },
        body: JSON.stringify({ url })
      });
      if (!resp.ok) throw new Error('HTTP ' + resp.status);
      const data = await resp.json();
      if (!data.ok) throw new Error(data.error || '拉取失败');
      return data.content || '';
    }
    const resp = await fetch(url, { mode: 'cors' });
    if (!resp.ok) throw new Error('HTTP ' + resp.status);
    return await resp.text();
  }

  /* ---------- 订阅 CRUD ---------- */
  function load() {
    try { subscriptions = JSON.parse(localStorage.getItem(SUB_KEY) || '[]'); }
    catch (e) { subscriptions = []; }
    return subscriptions;
  }

  function save() {
    localStorage.setItem(SUB_KEY, JSON.stringify(subscriptions));
  }

  function addSub({ url, name, group, authUser = '', authPass = '', enabled = true }) {
    const existing = subscriptions.find(s => s.url === url);
    if (existing) return { ok: false, msg: '订阅已存在' };
    const sub = {
      id: 'sub-' + Date.now() + '-' + Math.floor(Math.random() * 1000),
      url, name: name || url.slice(0, 40), group: group || '订阅节点',
      authUser: authUser || '', authPass: authPass || '',
      enabled, lastRefresh: null, nodeCount: 0, lastError: null
    };
    subscriptions.push(sub);
    save();
    return { ok: true, sub };
  }

  // 更新订阅（名称/分组/自定义认证），返回更新后的订阅
  function updateSub(id, patch) {
    const s = subscriptions.find(x => x.id === id);
    if (!s) return null;
    if (patch.name !== undefined) s.name = patch.name;
    if (patch.url !== undefined) s.url = patch.url;
    if (patch.group !== undefined) s.group = patch.group;
    if (patch.authUser !== undefined) s.authUser = patch.authUser;
    if (patch.authPass !== undefined) s.authPass = patch.authPass;
    save();
    return s;
  }

  function removeSub(id) {
    subscriptions = subscriptions.filter(s => s.id !== id);
    save();
  }

  function toggleSub(id, enabled) {
    const s = subscriptions.find(x => x.id === id);
    if (s) { s.enabled = enabled; save(); }
  }

  /* ---------- 刷新单个订阅（含 last-good 快照兜底） ---------- */
  async function refreshSub(sub, onNodeParsed) {
    try {
      const content = await fetchSubscription(sub.url);
      const nodes = parseContent(content);
      if (!nodes.length) throw new Error('解析 0 个节点');
      if (onNodeParsed) onNodeParsed(sub, nodes);
      sub.lastRefresh = Date.now();
      sub.nodeCount = nodes.length;
      sub.lastError = null;
      sub.stale = false;  // 刷新成功 → 清除失效标记
      // last-good 快照：成功后保存节点列表，供失败时回退
      sub.snapshot = nodes;
      save();
      return { ok: true, count: nodes.length };
    } catch (e) {
      sub.lastError = e.message;
      sub.stale = true;  // 持久化失效标记：刷新失败 → 订阅列表红色"失效"徽标
      // 兜底：失败时若有过往快照，回退到快照（标黄）
      if (sub.snapshot && sub.snapshot.length && onNodeParsed) {
        onNodeParsed(sub, sub.snapshot, { stale: true, error: e.message });
        sub.lastRefresh = sub.lastRefresh || null;
        save();
      }
      save();
      return { ok: false, error: e.message, stale: !!(sub.snapshot && sub.snapshot.length) };
    }
  }

  /* ---------- 批量刷新（带 enabled 过滤） ---------- */
  async function refreshAll(onNodeParsed, onProgress) {
    const enabled = subscriptions.filter(s => s.enabled);
    let results = [];
    for (let i = 0; i < enabled.length; i++) {
      const r = await refreshSub(enabled[i], onNodeParsed);
      results.push({ sub: enabled[i], ...r });
      if (onProgress) onProgress(i + 1, enabled.length, r);
    }
    return results;
  }

  /* ---------- 6小时自动刷新调度 ---------- */
  function startAutoRefresh(onTick) {
    stopAutoRefresh();
    const check = () => {
      const now = Date.now();
      const due = subscriptions.filter(s => s.enabled && (!s.lastRefresh || (now - s.lastRefresh) >= REFRESH_INTERVAL));
      if (due.length) {
        if (onTick) onTick(due, REFRESH_INTERVAL);
        refreshAll(null, null).then(() => {
          if (onTick) onTick(null, REFRESH_INTERVAL);
        });
      }
    };
    // 立即检查一次（页面加载时若超6小时则刷新）
    setTimeout(check, 3000);
    refreshTimer = setInterval(check, REFRESH_INTERVAL);
    // 同时每 1 分钟轻量检查（防时间漂移/兜底）
    minuteTimer = setInterval(check, 60 * 1000);
    return check;
  }

  function stopAutoRefresh() {
    if (refreshTimer) clearInterval(refreshTimer);
    refreshTimer = null;
    if (minuteTimer) {
      clearInterval(minuteTimer);
      minuteTimer = null;
    }
  }

  function getSubs() { return subscriptions; }

  /* ---------- 对外 API ---------- */
  return {
    load, save, addSub, updateSub, removeSub, toggleSub,
    refreshSub, refreshAll, startAutoRefresh, stopAutoRefresh,
    parseContent, parseLink, getSubs,
    REFRESH_INTERVAL
  };
})();

/* 供主面板调用 */
window.SubscriptionManager = SubscriptionManager;

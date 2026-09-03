const { spawn, exec, execSync } = require('child_process');
const fs = require('fs');
const path = require('path');
const net = require('net');
const http = require('http');
const https = require('https');
const dns = require('dns').promises;
const crypto = require('crypto');

process.on('uncaughtException', (err) => console.error('[Error]', err.message));
process.on('unhandledRejection', (reason) => console.error('[Error]', reason));

const PORT = parseInt(process.env.SERVER_PORT || process.env.PORT || 3000);
const INTERNAL_PORT = PORT + 1; // sing-box 只监听本机回环，由 Node 网关统一对外
const configPath = path.join(__dirname, 'config.json');
const uuidPath = path.join(__dirname, 'uuid.txt');
const CF_OPT_DOMAIN = 'cf.090227.xyz'; // 社区维护的 CF 优选域名，客户端本地解析、就近接入

// ========== 1. 动态获取当前容器真实公网 IP ==========
let IP = '';
const fetchPublicIP = () => {
  const apis = [
    'curl -sSL --max-time 3 https://api.ipify.org',
    'curl -sSL --max-time 3 https://ifconfig.me',
    'curl -sSL --max-time 3 https://icanhazip.com'
  ];
  for (const cmd of apis) {
    try {
      const ip = execSync(cmd, { encoding: 'utf8' }).trim();
      if (ip && /^(\d{1,3}\.){3}\d{1,3}$/.test(ip) && !ip.startsWith('0.') && !ip.startsWith('127.')) {
        return ip;
      }
    } catch (e) {}
  }
  return '127.0.0.1';
};
IP = fetchPublicIP();

// ========== 2. PTR 反向解析 ==========
async function getDynamicDomain(targetIp) {
  if (!targetIp || targetIp === '127.0.0.1') return null;
  try {
    const hostnames = await dns.reverse(targetIp);
    if (hostnames && hostnames.length > 0) return hostnames[0];
  } catch (e) {}
  return null;
}

// ========== 3. 清理残留进程 ==========
try {
  execSync('pkill -f web || true');
  execSync('pkill -f npm-runner || true');
} catch (e) {}

// ========== 4. UUID：随机生成 + 持久化（不再硬编码，支持环境变量覆盖） ==========
const genUUID = () => {
  if (crypto.randomUUID) return crypto.randomUUID();
  const b = crypto.randomBytes(16);
  b[6] = (b[6] & 0x0f) | 0x40;
  b[8] = (b[8] & 0x3f) | 0x80;
  const h = b.toString('hex');
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
};
const loadUUID = () => {
  if (process.env.UUID && /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(process.env.UUID)) {
    return process.env.UUID;
  }
  try {
    if (fs.existsSync(uuidPath)) {
      const u = fs.readFileSync(uuidPath, 'utf8').trim();
      if (/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(u)) return u;
    }
  } catch (e) {}
  const u = genUUID();
  try { fs.writeFileSync(uuidPath, u); } catch (e) {}
  return u;
};
const UUID = loadUUID();

// ========== 5. sing-box 配置（只绑回环，外部流量统一走 Node 网关） ==========
const certPath = path.join(__dirname, 'cert.pem');
const keyPath = path.join(__dirname, 'key.pem');
const HY2_PASS = UUID.replace(/-/g, '').slice(0, 16); // Hysteria2 密码（由 UUID 派生）

// 配置在启动前写入：证书存在才启用 Hysteria2（UDP），避免缺证书导致核心起不来
function writeConfig() {
  const inbounds = [{
    type: "vless",
    tag: "vless-in",
    listen: "127.0.0.1",
    listen_port: INTERNAL_PORT,
    users: [{ uuid: UUID }],
    transport: {
      type: "ws",
      path: "/vless-ws",
      max_early_data: 2048,
      early_data_header_name: "Sec-WebSocket-Protocol"
    }
  }];
  if (fs.existsSync(certPath) && fs.existsSync(keyPath)) {
    inbounds.push({
      type: "hysteria2",
      tag: "hy2-in",
      listen: "0.0.0.0",
      listen_port: PORT,
      users: [{ password: HY2_PASS }],
      tls: { enabled: true, certificate_path: certPath, key_path: keyPath }
    });
  }
  const finalConfig = {
    log: { level: "info" },
    inbounds,
    outbounds: [{ type: "direct", tag: "direct" }]
  };
  fs.writeFileSync(configPath, JSON.stringify(finalConfig, null, 2));
}

// ========== 6. 运行状态与节点链接生成 ==========
const state = { tunnelDomain: null, bestCF: null, ptrDomain: null };

function buildLinks() {
  const links = [];
  const t = state.tunnelDomain;
  const ed = '&ed=2048';
  if (t) {
    // 优选域名入口：客户端自行解析，就近接入 CF 边缘
    links.push(`vless://${UUID}@${CF_OPT_DOMAIN}:443?encryption=none&security=tls&sni=${t}&type=ws&host=${t}&path=%2Fvless-ws${ed}#CF-Opt-Domain`);
    // 服务器实测最快入口 IP
    if (state.bestCF) {
      links.push(`vless://${UUID}@${state.bestCF}:443?encryption=none&security=tls&sni=${t}&type=ws&host=${t}&path=%2Fvless-ws${ed}#CF-Tunnel-OptIP`);
    }
    // 默认解析入口（保底）
    links.push(`vless://${UUID}@${t}:443?encryption=none&security=tls&sni=${t}&type=ws&host=${t}&path=%2Fvless-ws${ed}#CF-Tunnel`);
  }
  links.push(`vless://${UUID}@${IP}:${PORT}?encryption=none&security=none&type=ws&host=${IP}&path=%2Fvless-ws${ed}#Native-IP-Direct`);
  if (state.ptrDomain) {
    links.push(`vless://${UUID}@${state.ptrDomain}:${PORT}?encryption=none&security=none&type=ws&host=${state.ptrDomain}&path=%2Fvless-ws${ed}#Native-Domain-Direct`);
  }
  // Hysteria2（UDP 直连，高丢包线路提速明显；平台不放行 UDP 时此节点不可用，忽略即可）
  if (fs.existsSync(certPath) && fs.existsSync(keyPath)) {
    links.push(`hysteria2://${HY2_PASS}@${IP}:${PORT}?sni=www.bing.com&insecure=1#HY2-Direct`);
  }
  return links;
}

// ========== 7. Telegram 推送（可选：配置 TG_TOKEN + TG_CHAT_ID 环境变量即启用） ==========
function tgPush(text) {
  const token = process.env.TG_TOKEN;
  const chat = process.env.TG_CHAT_ID;
  if (!token || !chat) return;
  const data = JSON.stringify({ chat_id: chat, text });
  const req = https.request({
    hostname: 'api.telegram.org',
    path: `/bot${token}/sendMessage`,
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(data) }
  }, () => {});
  req.on('error', () => {});
  req.end(data);
}

function printAndPush() {
  const t = state.tunnelDomain;
  const tlsLinks = buildLinks().filter(l => l.includes('security=tls'));
  const lines = [];
  lines.push('==================================================');
  lines.push(`[Auto-Detect] 真实外网 IP: ${IP}`);
  lines.push(`[Auto-Detect] PTR 反查解析域名: ${state.ptrDomain || '机房未绑定反向 PTR 记录'}`);
  lines.push(`[UUID Sync] 生效 UUID: ${UUID}`);
  lines.push(`[Optimize] CF 优选入口: ${state.bestCF || '测速失败，使用默认解析'}`);
  lines.push('');
  lines.push('📡【订阅链接】(一次订阅永久有效，隧道域名变更自动跟随):');
  lines.push(`http://${IP}:${PORT}/sub`);
  if (t) lines.push(`https://${t}/sub`);
  lines.push('');
  lines.push('🚀【CF 隧道加密节点链接】:');
  lines.push(...tlsLinks);
  lines.push('');
  lines.push('⚡【原生 IP 直连节点链接】:');
  lines.push(`vless://${UUID}@${IP}:${PORT}?encryption=none&security=none&type=ws&host=${IP}&path=%2Fvless-ws&ed=2048#Native-IP-Direct`);
  if (state.ptrDomain) {
    lines.push('');
    lines.push('🌐【原生域名直连节点链接】:');
    lines.push(`vless://${UUID}@${state.ptrDomain}:${PORT}?encryption=none&security=none&type=ws&host=${state.ptrDomain}&path=%2Fvless-ws&ed=2048#Native-Domain-Direct`);
  }
  const hy2 = buildLinks().filter(l => l.startsWith('hysteria2://'));
  if (hy2.length) {
    lines.push('');
    lines.push('⚡【Hysteria2 UDP 节点】(高丢包线路提速，需平台放行 UDP，连不上即平台封 UDP):');
    lines.push(...hy2);
  }
  lines.push('==================================================');
  const text = lines.join('\n');
  console.log('\n' + text + '\n');
  tgPush(text);
}

// ========== 8. HTTP/WS 网关：/sub 订阅 + 其余全部转发给 sing-box（最先启动，端口立即可用） ==========
function proxyHttp(req, res) {
  const up = http.request({
    hostname: '127.0.0.1',
    port: INTERNAL_PORT,
    path: req.url,
    method: req.method,
    headers: req.headers
  }, (r) => {
    res.writeHead(r.statusCode, r.headers);
    r.pipe(res);
  });
  up.on('error', () => {
    try { res.writeHead(502); res.end('bad gateway'); } catch (e) {}
  });
  req.pipe(up);
}

const server = http.createServer((req, res) => {
  const url = (req.url || '/').split('?')[0];
  if (url === '/sub') {
    const body = Buffer.from(buildLinks().join('\n'), 'utf8').toString('base64');
    res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8' });
    res.end(body);
    return;
  }
  if (url === '/') {
    res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8' });
    res.end('Service is running\n');
    return;
  }
  proxyHttp(req, res);
});

// WebSocket 升级请求：原样转发到 sing-box 内部端口
server.on('upgrade', (req, socket, head) => {
  const upstream = net.connect(INTERNAL_PORT, '127.0.0.1', () => {
    const raw = `${req.method} ${req.url} HTTP/1.1\r\n` +
      Object.entries(req.headers).map(([k, v]) => `${k}: ${v}`).join('\r\n') +
      '\r\n\r\n';
    upstream.write(raw);
    if (head && head.length) upstream.write(head);
    socket.pipe(upstream);
    upstream.pipe(socket);
  });
  const bail = () => { try { socket.destroy(); } catch (e) {} try { upstream.destroy(); } catch (e) {} };
  upstream.on('error', bail);
  socket.on('error', bail);
  socket.on('close', () => upstream.destroy());
  upstream.on('close', () => socket.destroy());
});

server.on('error', (e) => console.error('[Gateway]', e.message));
server.listen(PORT, '0.0.0.0', () => {
  console.log(`[Gateway] HTTP/WS 网关已启动，端口 ${PORT}（/sub 订阅端点已可用）`);
  if (!process.env.TG_TOKEN || !process.env.TG_CHAT_ID) {
    console.log('[TG] 未配置 TG_TOKEN / TG_CHAT_ID，跳过 Telegram 推送（可选功能）');
  }
});

// ========== 9. 自动拉取二进制组件 ==========
const decode = (str) => Buffer.from(str, 'base64').toString('utf-8');
const URL_CORE = decode('aHR0cHM6Ly9naXRodWIuY29tL1NhZ2VyTmV0L3NpbmctYm94L3JlbGVhc2VzL2Rvd25sb2FkL3YxLjkuMy9zaW5nLWJveC0xLjkuMy1saW51eC1hbWQ2NC50YXIuZ3o=');
const URL_TUNNEL = decode('aHR0cHM6Ly9naXRodWIuY29tL2Nsb3VkZmxhcmUvY2xvdWRmbGFyZWQvcmVsZWFzZXMvbGF0ZXN0L2Rvd25sb2FkL2Nsb3VkZmxhcmVkLWxpbnV4LWFtZDY0');

const BIN_CORE = path.join(__dirname, 'web');
const BIN_TUNNEL = path.join(__dirname, 'npm-runner');
const ua = 'npm/9.6.7 node/v18.16.0 linux x64';

// 下载与启动改为异步串行执行，不阻塞网关端口绑定
function prepareAndStart() {
  const steps = [];
  if (!fs.existsSync(BIN_CORE)) {
    steps.push(`curl -A "${ua}" -sSL "${URL_CORE}" | tar -xz -C /tmp && mv /tmp/sing-box-*/sing-box ${BIN_CORE} && chmod +x ${BIN_CORE}`);
  }
  if (!fs.existsSync(BIN_TUNNEL)) {
    steps.push(`curl -A "${ua}" -sSL -o ${BIN_TUNNEL} "${URL_TUNNEL}" && chmod +x ${BIN_TUNNEL}`);
  }
  if (!fs.existsSync(certPath) || !fs.existsSync(keyPath)) {
    steps.push(`openssl req -x509 -newkey rsa:2048 -sha256 -days 3650 -nodes -keyout ${keyPath} -out ${certPath} -subj "/CN=www.bing.com"`);
  }
  const runSteps = (i) => {
    if (i >= steps.length) { startServices(); return; }
    console.log(`[Setup] Step ${i + 1}/${steps.length}...`);
    exec(steps[i], (err) => {
      if (err) console.error(`[Setup Failed] Step ${i + 1}:`, err.message);
      runSteps(i + 1);
    });
  };
  runSteps(0);
}

// ========== 10. CF 优选 IP：对候选入口做 TCP 握手测速，选最快的一个 ==========
const CF_CANDIDATES = [
  '104.16.160.3', '104.17.147.22', '162.159.135.42',
  '172.67.68.4', '104.16.1.1', '188.114.96.1'
];
const tcpPing = (host, port, timeout = 2000) => new Promise((resolve) => {
  const start = Date.now();
  const s = net.connect({ host, port });
  const done = (ms) => { s.removeAllListeners(); s.destroy(); resolve(ms); };
  s.setTimeout(timeout, () => done(-1));
  s.once('connect', () => done(Date.now() - start));
  s.once('error', () => done(-1));
});
async function pickBestCF() {
  const results = await Promise.all(CF_CANDIDATES.map(async ip => ({ ip, ms: await tcpPing(ip, 443) })));
  const ok = results.filter(r => r.ms > 0).sort((a, b) => a.ms - b.ms);
  return ok.length ? ok[0].ip : null;
}

// ========== 11. 启动 Sing-box + 健康检查（连续 3 次无响应才重启，避免假活） ==========
let coreProc = null;
let healthFails = 0;

const runCore = () => {
  console.log(`[Core] Launching Sing-box on 127.0.0.1:${INTERNAL_PORT}...`);
  const sb = spawn(BIN_CORE, ['run', '-c', configPath]);
  coreProc = sb;
  healthFails = 0;
  sb.stdout.on('data', data => console.log(`[Sing-box] ${data.toString().trim()}`));
  sb.stderr.on('data', data => console.log(`[Sing-box] ${data.toString().trim()}`));
  sb.on('exit', () => setTimeout(runCore, 3000));
};

function healthCheck() {
  if (!coreProc) return;
  let settled = false;
  const s = net.connect({ host: '127.0.0.1', port: INTERNAL_PORT });
  const finish = (ok) => {
    if (settled) return;
    settled = true;
    s.destroy();
    if (ok) { healthFails = 0; return; }
    healthFails++;
    if (healthFails >= 3) {
      console.log('[Health] sing-box 连续 3 次无响应，执行重启...');
      healthFails = 0;
      try { coreProc.kill(); } catch (e) {}
    }
  };
  s.setTimeout(2000, () => finish(false));
  s.on('connect', () => finish(true));
  s.on('error', () => finish(false));
}
setInterval(healthCheck, 30000);

// ========== 12. 启动隧道，抓取域名后打印节点并推送 ==========
async function runTunnel() {
  console.log('[Tunnel] Starting Cloudflare Tunnel...');
  if (!state.ptrDomain) state.ptrDomain = await getDynamicDomain(IP);
  if (!state.bestCF) state.bestCF = await pickBestCF();
  const cf = spawn(BIN_TUNNEL, ['tunnel', '--url', `http://127.0.0.1:${PORT}`]);
  let printed = false;

  cf.stderr.on('data', data => {
    const match = data.toString().match(/https:\/\/[a-zA-Z0-9-]+\.trycloudflare\.com/);
    if (match && !printed) {
      printed = true;
      state.tunnelDomain = match[0].replace('https://', '');
      printAndPush();
    }
  });
  cf.on('exit', () => setTimeout(runTunnel, 5000));
}

function startServices() {
  writeConfig();
  if (fs.existsSync(BIN_CORE)) runCore();
  if (fs.existsSync(BIN_TUNNEL)) runTunnel();
}

prepareAndStart();

setInterval(() => {}, 100000);

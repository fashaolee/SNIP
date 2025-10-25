import { connect } from 'cloudflare:sockets';

// ==================== ① 基础配置 ====================
let userID = '5c4eed9c-4071-4d02-a00f-4ac58221238f'; // 请自行替换

// --- 代理配置 (proxyip 和 socks5 只能二选一，优先级: path > query > 默认) ---
let proxyIP = 'proxy.xxxxxxxx.tk:50001';  // 默认 proxyip 代理
let socks5 = '';                          // 默认 SOCKS5 代理, e.g., 'user:pass@host:port' or 'host:port'

// --- 传输优化参数 (保留所有既有优化) ---
const RACE_ENABLED = true;
const GEN_RACE_DELAY_MS = 350;
const MEDIA_RACE_DELAY_MS = 0;
const FIRST_5S_RACE_DELAY_MS = 0;
const MAX_EARLY_BUFFER_BYTES = 64 * 1024;
const VIDEO_COALESCE_MS = 6;
const VIDEO_COALESCE_MAX_BYTES = 64 * 1024;
const GENERAL_COALESCE_MS = 2;
const GENERAL_COALESCE_MAX_BYTES = 32 * 1024;
const SEND_HEADER_EARLY = true;
const CRITICAL_PKT_SIZE = 1024;
const SMALL_PKT_SIZE = 4096;

// --- 其它配置 ---
const preferredDomains = [
    'store.ubi.com', 'ip.sb', 'mfa.gov.ua', 'www.shopify.com',
    'cloudflare-dl.byoip.top', 'staticdelivery.nexusmods.com', 'bestcf.top',
    'cf.090227.xyz', 'cf.zhetengsha.eu.org', 'baipiao.cmliussss.abrdns.com', 'saas.sin.fan',
];
const TEXT_ENCODER = new TextEncoder();
const TEXT_DECODER = new TextDecoder();

// ==================== ② 代理配置与解析 (核心改动) ====================
let activeProxy = {
    type: null, // 'proxyip' or 'socks5'
    host: '',
    port: 0,
    username: '',
    password: '',
    raw: '', // Store the raw string for path generation
};

function parseProxyIP(proxyStr) {
    if (!proxyStr) return null;
    const parts = proxyStr.split(':');
    const host = parts[0].trim();
    let port = null;
    if (parts.length > 1) {
        const p = parseInt(parts[1].trim(), 10);
        if (!isNaN(p) && p > 0 && p <= 65535) port = p;
    }
    return { type: 'proxyip', host, port, username: '', password: '', raw: proxyStr };
}

function parseSocks5(socks5Str) {
    if (!socks5Str) return null;
    // Regex to handle user:pass@host:port, with optional user:pass and IPv6 brackets
    const match = socks5Str.match(/(?:([^:@]+):([^@]+)@)?(\[[^\]]+\]|[^:]+):(\d+)/);
    if (!match) return null;
    const [, username = '', password = '', host, portStr] = match;
    const port = parseInt(portStr, 10);
    if (isNaN(port) || port <= 0 || port > 65535) return null;
    return { type: 'socks5', host, port, username, password, raw: socks5Str };
}

function initializeProxyConfig(url) {
    activeProxy = { type: null, host: '', port: 0, username: '', password: '', raw: '' };

    // 1. 路径优先级最高 (Path)
    const pathSocks5Match = url.pathname.match(/^\/socks5=([^/]+)/);
    if (pathSocks5Match) {
        const parsed = parseSocks5(pathSocks5Match[1]);
        if (parsed) { activeProxy = parsed; return; }
    }
    const pathProxyIpMatch = url.pathname.match(/^\/proxyip=([^/]+)/);
    if (pathProxyIpMatch) {
        const parsed = parseProxyIP(pathProxyIpMatch[1]);
        if (parsed) { activeProxy = parsed; return; }
    }

    // 2. 查询参数优先级次之 (Query)
    const querySocks5 = url.searchParams.get('socks5');
    if (querySocks5) {
        const parsed = parseSocks5(querySocks5);
        if (parsed) { activeProxy = parsed; return; }
    }
    const queryProxyIp = url.searchParams.get('proxyip');
    if (queryProxyIp) {
        const parsed = parseProxyIP(queryProxyIp);
        if (parsed) { activeProxy = parsed; return; }
    }

    // 3. 默认配置优先级最低 (Default)
    if (socks5) {
        const parsed = parseSocks5(socks5);
        if (parsed) { activeProxy = parsed; return; }
    }
    if (proxyIP) {
        const parsed = parseProxyIP(proxyIP);
        if (parsed) { activeProxy = parsed; return; }
    }
}

// ==================== ③ 工具函数（域名、流等） ====================
function isTelegramHost(h) { return h && (/(^|\.)t\.me$/.test(h) || /(^|\.)telegra\.ph$/.test(h) || h.endsWith('.telegram.org') || h.includes('telegram-cdn') || h.includes('cdn-telegram')); }
function isVideoHost(h) { return h && (h.includes('googlevideo.com') || h.includes('gvt1.com') || h.includes('youtube.com') || h.includes('ytimg.com') || h.includes('tiktokcdn.com') || h.includes('muscdn.com') || h.includes('bytecdn.cn') || h.includes('byteimg.com') || h.includes('fbcdn.net') || h.includes('cdninstagram.com') || h.includes('vimeocdn.com') || h.includes('vimeo.com') || h.includes('nflxvideo.net') || h.includes('netflix.com') || h.includes('akamaized.net') || h.includes('edgesuite.net') || h.includes('hls') || h.includes('.m3u8')); }
function isMediaHost(h) { return isVideoHost(h) || isTelegramHost(h); }
function isUpload(h) { return h && (h.includes('upload') || h.includes('up.') || h.includes('up-') || h.includes('post') || h.includes('send') || h.includes('share') || h.includes('sns') || h.includes('social') || h.includes('weibo') || h.includes('weixin') || h.includes('qq.com') || h.includes('facebook') || h.includes('instagram') || h.includes('tiktok') || h.includes('twitter') || h.includes('x.com')); }
function base64ToArrayBuffer(b) { if (!b) return { error: null }; try { const d = atob(b.replace(/-/g, '+').replace(/_/g, '/')); return { earlyData: Uint8Array.from(d, c => c.charCodeAt(0)).buffer, error: null }; } catch (e) { return { error: e }; } }
function isValidUUID(u) { return /^[0-9a-f]{8}-[0-9a-f]{4}-[4][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(u); }
const byteToHex = Array.from({ length: 256 }, (v, i) => (i + 256).toString(16).slice(1));
function unsafeStringify(a, o = 0) { return `${byteToHex[a[o+0]]}${byteToHex[a[o+1]]}${byteToHex[a[o+2]]}${byteToHex[a[o+3]]}-${byteToHex[a[o+4]]}${byteToHex[a[o+5]]}-${byteToHex[a[o+6]]}${byteToHex[a[o+7]]}-${byteToHex[a[o+8]]}${byteToHex[a[o+9]]}-${byteToHex[a[o+10]]}${byteToHex[a[o+11]]}${byteToHex[a[o+12]]}${byteToHex[a[o+13]]}${byteToHex[a[o+14]]}${byteToHex[a[o+15]]}`.toLowerCase(); }
function stringify(a, o = 0) { const u = unsafeStringify(a, o); if (!isValidUUID(u)) throw new TypeError('Invalid UUID'); return u; }

// ==================== ④ VLESS 配置生成 ====================
function getVLESSConfig(userID, currentHost) {
    let path = '';
    if (activeProxy.type === 'socks5') {
        path = `/socks5=${activeProxy.raw}`;
    } else if (activeProxy.type === 'proxyip') {
        path = `/proxyip=${activeProxy.raw}`;
    }

    const params = new URLSearchParams({
        encryption: 'none', security: 'tls', sni: currentHost, fp: 'chrome',
        type: 'ws', host: currentHost, path, mux: '1', alpn: 'http/1.1',
    });

    const allVlessUris = preferredDomains.map((domain, idx) => {
        const alias = `T-SNIP_${String(idx + 1).padStart(2, '0')}`;
        return `vless://${userID}@${domain}:443?${params.toString()}#${alias}`;
    });

    return btoa(allVlessUris.join('\n')).replace(/\+/g, '-').replace(/\//g, '_');
}

// ==================== ⑤ 主入口 ====================
if (!isValidUUID(userID)) throw new Error('uuid is not valid');

export default {
    async fetch(request) {
        try {
            const url = new URL(request.url);
            initializeProxyConfig(url); // 统一初始化代理配置

            // 从路径中提取 UUID
            const pathSegments = url.pathname.split('/').filter(Boolean);
            const pathUUID = isValidUUID(pathSegments[pathSegments.length - 1]) ? pathSegments[pathSegments.length - 1] : null;

            if (request.headers.get('Upgrade') !== 'websocket') {
                if (url.pathname === '/' || !pathUUID) {
                    return new Response('欢迎使用！请在路径末尾添加您的 UUID 以获取订阅。', { status: 200 });
                }
                if (pathUUID === userID) {
                    return new Response(getVLESSConfig(pathUUID, request.headers.get('Host')), { status: 200 });
                }
                return new Response('UUID 不正确', { status: 400 });
            }

            return await vlessOverWSHandler(request);
        } catch (err) {
            return new Response(err.toString(), { status: 500 });
        }
    },
};

// ==================== ⑥ WebSocket 处理 (保留所有传输优化) ====================
async function vlessOverWSHandler(request) {
    const url = new URL(request.url);
    initializeProxyConfig(url); // 确保 WebSocket 连接也使用正确的代理配置

    const [client, server] = Object.values(new WebSocketPair());
    server.accept();

    const readableWS = makeReadableWebSocketStream(server, request.headers.get('sec-websocket-protocol') || '');

    const remote = { writer: null, ready: false, started: false, earlyBuf: [], earlyBytes: 0 };
    let udpWrite = null, isDns = false;

    server.addEventListener('close', () => remote.value?.close());
    server.addEventListener('error', () => remote.value?.close());

    readableWS.pipeTo(new WritableStream({
        async write(chunk) {
            if (isDns) return udpWrite?.(chunk);
            if (remote.ready) return remote.writer.write(chunk);

            if (!remote.started) {
                const { hasError, message, portRemote, addressRemote, rawDataIndex, vlessVersion, isUDP } = processVlessHeader(chunk, userID);
                if (hasError) throw new Error(message);
                if (isUDP && portRemote !== 53) throw new Error('UDP proxy only for DNS port 53');
                
                isDns = isUDP;
                const vlessRespHeader = new Uint8Array([vlessVersion[0], 0]);
                const rawClientData = chunk.slice(rawDataIndex);

                if (isDns) {
                    udpWrite = (await handleUDPOutBound(server, vlessRespHeader)).write;
                    udpWrite(rawClientData);
                } else {
                    handleTCPOutBoundOptimized(remote, addressRemote, portRemote, rawClientData, server, vlessRespHeader, {
                        media: isMediaHost(addressRemote.toLowerCase()),
                        upload: isUpload(addressRemote.toLowerCase()),
                        isSmall: rawClientData.byteLength <= SMALL_PKT_SIZE,
                    });
                }
                remote.started = true;
                return;
            }

            if (remote.earlyBytes + chunk.byteLength <= MAX_EARLY_BUFFER_BYTES) {
                remote.earlyBuf.push(chunk);
                remote.earlyBytes += chunk.byteLength;
            } else {
                remote.writer?.write(chunk);
            }
        },
    })).catch(() => {});

    return new Response(null, { status: 101, webSocket: client });
}

// ==================== ⑦ 可读 WebSocket 流 ====================
function makeReadableWebSocketStream(ws, earlyDataHeader) {
    let cancelled = false;
    const { earlyData } = base64ToArrayBuffer(earlyDataHeader);
    return new ReadableStream({
        start(c) {
            if (earlyData) c.enqueue(new Uint8Array(earlyData));
            ws.addEventListener('message', e => !cancelled && c.enqueue(e.data));
            ws.addEventListener('close', () => !cancelled && (safeCloseWebSocket(ws), c.close()));
            ws.addEventListener('error', e => c.error(e));
        },
        cancel() { cancelled = true; safeCloseWebSocket(ws); },
    });
}

// ==================== ⑧ VLESS Header 解析 ====================
function processVlessHeader(buf, userID) {
    try {
        if (buf.byteLength < 24) throw new Error('invalid data');
        if (stringify(new Uint8Array(buf.slice(1, 17))) !== userID.toLowerCase()) throw new Error('invalid user');
        const v = new Uint8Array(buf.slice(0, 1)), o = new Uint8Array(buf.slice(17, 18))[0], cIdx = 18 + o, cmd = new Uint8Array(buf.slice(cIdx, cIdx + 1))[0];
        if (cmd !== 1 && cmd !== 2) throw new Error(`unsupported command ${cmd}`);
        const pIdx = cIdx + 1, port = new DataView(buf.slice(pIdx, pIdx + 2)).getUint16(0);
        let aIdx = pIdx + 2, aType = new Uint8Array(buf.slice(aIdx, aIdx + 1))[0], addr = '', len = 0; aIdx++;
        if (aType === 1) { len = 4; addr = new Uint8Array(buf.slice(aIdx, aIdx + len)).join('.'); }
        else if (aType === 2) { len = new Uint8Array(buf.slice(aIdx, aIdx + 1))[0]; aIdx++; addr = TEXT_DECODER.decode(buf.slice(aIdx, aIdx + len)); }
        else if (aType === 3) { len = 16; const d = new DataView(buf.slice(aIdx, aIdx+len)); addr = Array.from({length:8}, (_,i)=>d.getUint16(i*2).toString(16)).join(':'); }
        else throw new Error(`invalid addressType ${aType}`);
        return { hasError: false, addressRemote: addr, portRemote: port, rawDataIndex: aIdx + len, vlessVersion: v, isUDP: cmd === 2 };
    } catch (e) { return { hasError: true, message: e.message }; }
}

// ==================== ⑨ WS 合帧发送器 ====================
function createWSSender(ws, vH, { hAS, cM, mB, cS }) {
    let hS = !!hAS, p = [], b = 0, t = null, cl = false;
    const sH = () => !hS && (ws.send(vH), hS = true);
    const fl = () => { if (cl || b === 0) return; sH(); const bf = new Uint8Array(b); let of = 0; p.forEach(u=>{bf.set(u,of);of+=u.byteLength}); p.length = b = 0; ws.send(bf); };
    const sc = () => !t && cM > 0 && (t = setTimeout(() => { t = null; fl(); }, cM));
    return {
        push(c) {
            if (cl) return; const u = c instanceof Uint8Array ? c : new Uint8Array(c);
            if (u.byteLength <= cS) { if(t) clearTimeout(t); t=null; fl(); sH(); ws.send(u); return; }
            if (!cM || !mB) { sH(); ws.send(u); return; }
            p.push(u); b += u.byteLength; if (b >= mB) fl(); else sc();
        },
        flush() { if (t) clearTimeout(t); t = null; fl(); },
        close() { if (t) clearTimeout(t); t = null; cl = true; p.length = b = 0; },
    };
}

// ==================== ⑩ TCP 连接处理 ====================
async function handleTCPOutBoundOptimized(remote, address, port, initData, ws, vlessHeader, opts = {}) {
    if (remote._active) return;
    remote._active = true;

    const now = Date.now();
    const inFirst5s = now < (remote.startTime || (remote.startTime = now)) + 5000;
    let raceDelay = inFirst5s ? FIRST_5S_RACE_DELAY_MS : (opts.media ? MEDIA_RACE_DELAY_MS : (opts.upload ? 0 : GEN_RACE_DELAY_MS));
    raceDelay = (RACE_ENABLED && activeProxy.type) ? raceDelay : null;

    let selected = null, directSock = null, proxySock = null, fallbackTimer = null, closed = false, headerSent = false;
    const wsSender = createWSSender(ws, vlessHeader, {
        coalesceMs: opts.media ? VIDEO_COALESCE_MS : GENERAL_COALESCE_MS,
        maxBytes: opts.media ? VIDEO_COALESCE_MAX_BYTES : GENERAL_COALESCE_MAX_BYTES,
        criticalSize: CRITICAL_PKT_SIZE
    });

    const becomeWinner = async (sock, label) => {
        selected = label; if (fallbackTimer) clearTimeout(fallbackTimer);
        if (label === 'direct') proxySock?.close(); else directSock?.close();
        remote.value = sock; remote.writer = sock.writable.getWriter();
        for (const buf of remote.earlyBuf) await remote.writer.write(buf);
        remote.earlyBuf.length = remote.earlyBytes = 0; remote.ready = true;
    };

    const startReader = async (sock, label) => {
        const reader = sock.readable.getReader();
        try {
            while (true) {
                const { value, done } = await reader.read();
                if (done) break; if (closed) break;
                if (!selected) await becomeWinner(sock, label);
                if (!headerSent && SEND_HEADER_EARLY) { wsSender.push(new Uint8Array(0)); headerSent = true; }
                wsSender.push(value);
            }
        } catch {} finally {
            reader.releaseLock();
            if (!closed && selected === label) { wsSender.flush(); closed = true; safeCloseWebSocket(ws); wsSender.close(); }
        }
    };

    directSock = connect({ hostname: address, port });
    try {
        const w = directSock.writable.getWriter(); await w.write(initData); w.releaseLock();
        if (SEND_HEADER_EARLY && !headerSent) { wsSender.push(new Uint8Array(0)); headerSent = true; }
    } catch {}
    startReader(directSock, 'direct');

    const spawnProxy = async () => {
        if (selected || closed) return;
        try {
            if (activeProxy.type === 'socks5') {
                proxySock = connect({ hostname: activeProxy.host, port: activeProxy.port });
                await socks5Connect(proxySock, address, port, activeProxy.username, activeProxy.password);
            } else if (activeProxy.type === 'proxyip') {
                proxySock = connect({ hostname: activeProxy.host, port: activeProxy.port ?? port });
            } else { return; }
            
            const w2 = proxySock.writable.getWriter(); await w2.write(initData); w2.releaseLock();
            if (SEND_HEADER_EARLY && !headerSent) { wsSender.push(new Uint8Array(0)); headerSent = true; }
            startReader(proxySock, 'proxy');
        } catch { proxySock?.close(); }
    };

    if (raceDelay !== null) {
        if (raceDelay <= 0) spawnProxy();
        else fallbackTimer = setTimeout(spawnProxy, raceDelay);
    }
}

// ==================== ⑪ SOCKS5 握手实现 ====================
async function socks5Connect(socket, address, port, username, password) {
    const writer = socket.writable.getWriter();
    const reader = socket.readable.getReader();

    try {
        // Greeting
        const authMethods = username ? [0x05, 0x02, 0x00, 0x02] : [0x05, 0x01, 0x00];
        await writer.write(new Uint8Array(authMethods));
        let { value, done } = await reader.read();
        if (done || value[0] !== 0x05) throw new Error('SOCKS5 greeting failed');
        const chosenMethod = value[1];

        // Authentication
        if (chosenMethod === 0x02) {
            if (!username) throw new Error('SOCKS5 server requires auth, but none provided');
            const user = TEXT_ENCODER.encode(username);
            const pass = TEXT_ENCODER.encode(password);
            const authRequest = new Uint8Array(3 + user.length + pass.length);
            authRequest[0] = 0x01;
            authRequest[1] = user.length;
            authRequest.set(user, 2);
            authRequest[2 + user.length] = pass.length;
            authRequest.set(pass, 3 + user.length);
            await writer.write(authRequest);
            ({ value, done } = await reader.read());
            if (done || value[0] !== 0x01 || value[1] !== 0x00) throw new Error('SOCKS5 authentication failed');
        } else if (chosenMethod !== 0x00) {
            throw new Error(`Unsupported SOCKS5 auth method: ${chosenMethod}`);
        }

        // Connection Request
        let addrType, addrBytes;
        if (/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(address)) { // IPv4
            addrType = 0x01; addrBytes = new Uint8Array(address.split('.').map(Number));
        } else if (address.includes(':')) { // IPv6 (simplistic check)
            addrType = 0x04; const parts = address.split(':').map(p => p.padStart(4,'0')); addrBytes = new Uint8Array(16); const dv = new DataView(addrBytes.buffer); parts.forEach((p,i)=>dv.setUint16(i*2,parseInt(p,16)));
        } else { // Domain
            addrType = 0x03; addrBytes = TEXT_ENCODER.encode(address);
        }

        const portBytes = new Uint8Array(2); new DataView(portBytes.buffer).setUint16(0, port);
        const requestHeader = new Uint8Array(4 + (addrType === 0x03 ? 1 : 0) + addrBytes.length + 2);
        requestHeader.set([0x05, 0x01, 0x00, addrType]);
        if (addrType === 0x03) requestHeader[4] = addrBytes.length;
        requestHeader.set(addrBytes, addrType === 0x03 ? 5 : 4);
        requestHeader.set(portBytes, requestHeader.length - 2);
        
        await writer.write(requestHeader);
        ({ value, done } = await reader.read());
        if (done || value[0] !== 0x05 || value[1] !== 0x00) throw new Error(`SOCKS5 connection request failed with status ${value?.[1]}`);

    } finally {
        writer.releaseLock();
        reader.releaseLock();
    }
}

// ==================== ⑫ DNS (UDP) 与 WebSocket 关闭辅助 ====================
async function handleUDPOutBound(ws, vH) {
    let hS = false;
    const t = new TransformStream({ transform(c, k) { for (let i = 0; i < c.byteLength;) { const l = new DataView(c.buffer, c.byteOffset + i, 2).getUint16(0); k.enqueue(new Uint8Array(c.buffer, c.byteOffset + i + 2, l)); i += 2 + l; } } });
    t.readable.pipeTo(new WritableStream({ async write(q) {
        const r = await fetch('https://dns.google/dns-query', { method: 'POST', headers: { 'Content-Type': 'application/dns-message', 'Accept': 'application/dns-message' }, body: q });
        const a = await r.arrayBuffer(), s = a.byteLength, sB = new Uint8Array([(s >> 8) & 0xff, s & 0xff]);
        if (ws.readyState === 1) { if (!hS) { ws.send(vH); hS = true; } ws.send(sB); ws.send(a); }
    }})).catch(() => {});
    return { write(c) { t.writable.getWriter().write(c) } };
}
const WS_READY_STATE_OPEN = 1, WS_READY_STATE_CLOSING = 2;
function safeCloseWebSocket(s) { try { if (s.readyState === WS_READY_STATE_OPEN || s.readyState === WS_READY_STATE_CLOSING) s.close(); } catch {} }

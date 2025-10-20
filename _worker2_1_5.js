import { connect } from 'cloudflare:sockets';

// ==================== ① 基础配置 ====================
let userID = ''; // 请自行替换
let proxyIP = 'proxyip.cmliussss.net'; // 默认代理，可被 path/query 覆盖

// 速率/资源平衡参数
const RACE_ENABLED = true;                  // 并发回源竞速（直连优先 + 超时并发代理）
const RACE_DELAY_MS = 350;                  // 一般域名并发门限（建议 250–800）
const TG_RACE_DELAY_MS = 0;                 // Telegram 域名门限（0=同时开跑）
const MAX_EARLY_BUFFER_BYTES = 64 * 1024;   // 选路前 WS→TCP 缓冲上限
const SEND_HEADER_EARLY = true;             // 建立出站连接后立即回写 VLESS 响应头
const COALESCE_HEADER = false;              // true=首包合并（更少帧），false=分帧（更少拷贝）

// 预设优选域名（保持原有列表）
const preferredDomains = [
    'store.ubi.com',
    'ip.sb',
    'mfa.gov.ua',
    'shopify.com',
    'cloudflare-dl.byoip.top',
    'staticdelivery.nexusmods.com',
    'bestcf.top',
    'cf.090227.xyz',
    'cf.zhetengsha.eu.org',
    'baipiao.cmliussss.abrdns.com',
    'saas.sin.fan',
];

// ==================== ② 代理信息解析（纯函数） ====================
let proxyConfig = { proxyHost: '', proxyPort: null };
function parseProxyIP(inputProxyIP) {
    proxyConfig = { proxyHost: '', proxyPort: null };
    if (!inputProxyIP) return;
    const parts = inputProxyIP.split(':');
    proxyConfig.proxyHost = parts[0].trim();
    if (parts.length > 1) {
        const p = parseInt(parts[1].trim(), 10);
        if (!isNaN(p) && p > 0 && p <= 65535) proxyConfig.proxyPort = p;
    }
}

// ==================== ③ 工具函数 ====================
// 从路径提取 /proxyip=...（可带后续段）
function extractProxyFromPath(pathname) {
    const m = /^\/proxyip=([^/]+)(?:\/.*)?$/.exec(pathname);
    return m ? m[1] : null;
}
// 计算本次请求生效的 proxyip
function getEffectiveProxyIP(url) {
    const fromQuery = (url.searchParams.get('proxyip') || '').trim();
    const fromPath = extractProxyFromPath(url.pathname);
    return fromQuery || fromPath || proxyIP;
}
// Telegram 域名判定（媒体相关）
function isTelegramHost(host) {
    if (!host) return false;
    const h = host.toLowerCase();
    return (
        /(^|\.)t\.me$/.test(h) ||
        /(^|\.)telegra\.ph$/.test(h) ||
        h.endsWith('.telegram.org') ||
        h.includes('telegram-cdn') ||
        h.includes('cdn-telegram')
    );
}

// 合并多个 Uint8Array 为一个 ArrayBuffer（仅在需要时使用）
function concatArrayBuffers(...arrays) {
    const total = arrays.reduce((sum, a) => sum + a.byteLength, 0);
    const tmp = new Uint8Array(total);
    let offset = 0;
    for (const a of arrays) {
        tmp.set(new Uint8Array(a), offset);
        offset += a.byteLength;
    }
    return tmp.buffer;
}

// base64 → Uint8Array
function base64ToArrayBuffer(base64Str) {
    if (!base64Str) return { error: null };
    try {
        const b64 = base64Str.replace(/-/g, '+').replace(/_/g, '/');
        const dec = atob(b64);
        const u8 = Uint8Array.from(dec, c => c.charCodeAt(0));
        return { earlyData: u8.buffer, error: null };
    } catch (e) {
        return { error: e };
    }
}

// 复用解码器
const TEXT_DECODER = new TextDecoder();

// UUID 检验 & 字符串化
function isValidUUID(uuid) {
    const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[4][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
    return uuidRegex.test(uuid);
}
const byteToHex = [];
for (let i = 0; i < 256; ++i) byteToHex.push((i + 256).toString(16).slice(1));
function unsafeStringify(arr, offset = 0) {
    return (
        byteToHex[arr[offset + 0]] + byteToHex[arr[offset + 1]] + byteToHex[arr[offset + 2]] + byteToHex[arr[offset + 3]] + "-" +
        byteToHex[arr[offset + 4]] + byteToHex[arr[offset + 5]] + "-" +
        byteToHex[arr[offset + 6]] + byteToHex[arr[offset + 7]] + "-" +
        byteToHex[arr[offset + 8]] + byteToHex[arr[offset + 9]] + "-" +
        byteToHex[arr[offset + 10]] + byteToHex[arr[offset + 11]] + byteToHex[arr[offset + 12]] +
        byteToHex[arr[offset + 13]] + byteToHex[arr[offset + 14]] + byteToHex[arr[offset + 15]]
    ).toLowerCase();
}
function stringify(arr, offset = 0) {
    const uuid = unsafeStringify(arr, offset);
    if (!isValidUUID(uuid)) throw TypeError('Stringified UUID is invalid');
    return uuid;
}

// ==================== ④ VLESS 配置生成（省资源参数：mux、alpn） ====================
function getVLESSConfig(userID, currentHost, proxyHostPort) {
    const protocol = 'vless';
    const path = `/proxyip=${proxyHostPort}`;
    const params = new URLSearchParams({
        encryption: 'none',
        security: 'tls',
        sni: currentHost,
        fp: 'chrome',
        type: 'ws',
        host: currentHost,
        path: path,
        mux: '1',
        alpn: 'http/1.1',
    });

    const allVlessUris = preferredDomains.map((domain, idx) => {
        const alias = `T-SNIP_${String(idx + 1).padStart(2, '0')}`;
        return `${protocol}://${userID}@${domain}:443?${params.toString()}#${alias}`;
    });

    const sub = allVlessUris.join('\n');
    return btoa(sub).replace(/\+/g, '-').replace(/\//g, '_');
}

// ==================== ⑤ 主入口 ====================
if (!isValidUUID(userID)) {
    throw new Error('uuid is not valid');
}

export default {
    async fetch(request, env, ctx) {
        try {
            const url = new URL(request.url);

            // 计算本次请求的生效 proxyip，并设置到全局 proxyConfig
            const effectiveProxyIP = getEffectiveProxyIP(url);
            parseProxyIP(effectiveProxyIP);

            // 解析路径中的 UUID（支持 /UUID 与 /proxyip=.../UUID）
            let pathUUID = null;
            const pm = /^\/proxyip=([^/]+)(?:\/([0-9a-f-]{36}))?$/.exec(url.pathname);
            if (pm && pm[2]) {
                pathUUID = pm[2];
            } else if (url.pathname.length > 1) {
                pathUUID = url.pathname.substring(1);
            }

            const upgradeHeader = request.headers.get('Upgrade');
            if (!upgradeHeader || upgradeHeader !== 'websocket') {
                // ---------- 非 WebSocket ----------
                if (url.pathname === '/') {
                    return new Response('恭喜你快成功了，快去添加 UUID 吧。支持 /proxyip=host[:port]/UUID 或 ?proxyip=host[:port]', {
                        status: 200,
                        headers: { 'Content-Type': 'text/plain;charset=utf-8' },
                    });
                }
                if (pathUUID && pathUUID === userID) {
                    const cfg = getVLESSConfig(pathUUID, request.headers.get('Host'), effectiveProxyIP);
                    return new Response(cfg, {
                        status: 200,
                        headers: { 'Content-Type': 'text/plain;charset=utf-8' },
                    });
                }
                return new Response('请填写正确的 UUID', {
                    status: 400,
                    headers: { 'Content-Type': 'text/plain;charset=utf-8' },
                });
            }

            // ---------- WebSocket ----------
            return await vlessOverWSHandler(request);
        } catch (err) {
            return new Response(err.toString(), {
                status: 500,
                headers: { 'Content-Type': 'text/plain;charset=utf-8' },
            });
        }
    },
};

// ==================== ⑥ WebSocket 处理（TG 加速 + 即时回包头） ====================
async function vlessOverWSHandler(request) {
    const url = new URL(request.url);
    const effProxy = getEffectiveProxyIP(url);
    parseProxyIP(effProxy);

    const pair = new WebSocketPair();
    const [client, server] = Object.values(pair);
    server.accept();

    const earlyDataHeader = request.headers.get('sec-websocket-protocol') || '';
    const readableWS = makeReadableWebSocketStream(server, earlyDataHeader);

    // 复用 writer + 有界缓冲
    const remote = {
        value: null,
        writer: null,
        ready: false,
        started: false,
        earlyBuf: [],
        earlyBytes: 0,
    };
    let udpWrite = null;
    let isDns = false;

    // WS 关闭时确保关闭远端 socket，避免悬挂导致卡顿
    server.addEventListener('close', () => {
        try { remote.value && remote.value.close(); } catch {}
    });
    server.addEventListener('error', () => {
        try { remote.value && remote.value.close(); } catch {}
    });

    readableWS.pipeTo(new WritableStream({
        async write(chunk) {
            // DNS 直通
            if (isDns && udpWrite) {
                udpWrite(chunk);
                return;
            }

            // 已选路：直接写入（复用单一 writer）
            if (remote.ready && remote.writer) {
                await remote.writer.write(chunk);
                return;
            }

            // 首次数据：解析 VLESS 头
            if (!remote.started) {
                const {
                    hasError,
                    message,
                    portRemote = 443,
                    addressRemote = '',
                    rawDataIndex,
                    vlessVersion = new Uint8Array([0, 0]),
                    isUDP,
                } = processVlessHeader(chunk, userID);
                if (hasError) throw new Error(message);

                // 仅放行 DNS UDP（53）
                if (isUDP) {
                    if (portRemote === 53) {
                        isDns = true;
                    } else {
                        throw new Error('UDP proxy only enable for DNS which is port 53');
                    }
                }

                const vlessRespHeader = new Uint8Array([vlessVersion[0], 0]);
                const rawClient = chunk.slice(rawDataIndex);

                if (isDns) {
                    const { write } = await handleUDPOutBound(server, vlessRespHeader);
                    udpWrite = write;
                    udpWrite(rawClient);
                    remote.started = true;
                    return;
                }

                // Telegram 媒体域名采用 0ms 并发，减少首字节等待
                const tgBoost = isTelegramHost(addressRemote);

                // 启动 TCP（直连优先 + TG 域名 0ms 并发），并在建立连接后立即回包头
                handleTCPOutBoundOptimized(remote, addressRemote, portRemote, rawClient, server, vlessRespHeader, tgBoost);
                remote.started = true;
                return;
            }

            // 尚未选路：进入早期有界缓冲
            if (remote.earlyBytes + chunk.byteLength <= MAX_EARLY_BUFFER_BYTES) {
                remote.earlyBuf.push(chunk);
                remote.earlyBytes += chunk.byteLength;
            } else {
                // 超出上限：防内存增长
                if (remote.writer) {
                    await remote.writer.write(chunk);
                }
            }
        },
    })).catch(() => { /* 流已在内部处理 */ });

    return new Response(null, { status: 101, webSocket: client });
}

// ==================== ⑦ 可读 WebSocket 流 ====================
function makeReadableWebSocketStream(ws, earlyDataHeader) {
    let cancelled = false;
    const { earlyData } = base64ToArrayBuffer(earlyDataHeader);

    return new ReadableStream({
        start(controller) {
            if (earlyData) controller.enqueue(new Uint8Array(earlyData));
            ws.addEventListener('message', e => {
                if (cancelled) return;
                controller.enqueue(e.data);
            });
            ws.addEventListener('close', () => {
                safeCloseWebSocket(ws);
                if (!cancelled) controller.close();
            });
            ws.addEventListener('error', err => controller.error(err));
        },
        cancel() {
            cancelled = true;
            safeCloseWebSocket(ws);
        },
    });
}

// ==================== ⑧ VLESS Header 解析（防越界） ====================
function processVlessHeader(buf, userID) {
    try {
        if (buf.byteLength < 24) throw new Error('invalid data');

        const version = new Uint8Array(buf.slice(0, 1));
        const uuidStr = stringify(new Uint8Array(buf.slice(1, 17)));
        if (uuidStr !== userID.toLowerCase()) throw new Error('invalid user');

        const optLen = new Uint8Array(buf.slice(17, 18))[0];
        const cmdIdx = 18 + optLen;
        const cmd = new Uint8Array(buf.slice(cmdIdx, cmdIdx + 1))[0];
        const isUDP = cmd === 2;
        if (cmd !== 1 && !isUDP) throw new Error(`unsupported command ${cmd}`);

        const portIdx = cmdIdx + 1;
        if (buf.byteLength < portIdx + 2) throw new Error('missing port');
        const port = new DataView(buf.slice(portIdx, portIdx + 2)).getUint16(0);

        let addrIdx = portIdx + 2;
        if (buf.byteLength < addrIdx + 1) throw new Error('missing address type');
        const addrType = new Uint8Array(buf.slice(addrIdx, addrIdx + 1))[0];
        addrIdx += 1;

        let addr = '', addrLen = 0;
        switch (addrType) {
            case 1: // IPv4
                addrLen = 4;
                if (buf.byteLength < addrIdx + addrLen) throw new Error('incomplete IPv4');
                addr = new Uint8Array(buf.slice(addrIdx, addrIdx + addrLen)).join('.');
                break;
            case 2: // Domain
                addrLen = new Uint8Array(buf.slice(addrIdx, addrIdx + 1))[0];
                addrIdx += 1;
                if (buf.byteLength < addrIdx + addrLen) throw new Error('incomplete domain');
                addr = TEXT_DECODER.decode(buf.slice(addrIdx, addrIdx + addrLen));
                break;
            case 3: // IPv6
                addrLen = 16;
                if (buf.byteLength < addrIdx + addrLen) throw new Error('incomplete IPv6');
                const dv = new DataView(buf.slice(addrIdx, addrIdx + addrLen));
                const parts = [];
                for (let i = 0; i < 8; i++) parts.push(dv.getUint16(i * 2).toString(16));
                addr = parts.join(':');
                break;
            default:
                throw new Error(`invalid addressType ${addrType}`);
        }

        const rawIdx = addrIdx + addrLen;
        return {
            hasError: false,
            addressRemote: addr,
            portRemote: port,
            rawDataIndex: rawIdx,
            vlessVersion: version,
            isUDP,
        };
    } catch (e) {
        return { hasError: true, message: e.message };
    }
}

// ==================== ⑨ TCP：直连优先 + TG 0ms 并发 + 即时回包头 ====================
async function handleTCPOutBoundOptimized(remote, address, port, initData, ws, vlessHeader, tgBoost) {
    if (remote._active) return;
    remote._active = true;

    let selected = null; // 'direct' | 'proxy'
    let directSock = null;
    let proxySock = null;
    let fallbackTimer = null;
    let headerSent = false;
    let closed = false;

    function clearFallbackTimer() {
        if (fallbackTimer) { try { clearTimeout(fallbackTimer); } catch {} fallbackTimer = null; }
    }
    function sendHeaderIfNeeded() {
        if (headerSent) return;
        if (COALESCE_HEADER) {
            // 若需要首包合并，可在首个下行到达时通过 concatArrayBuffers 合并发送
        } else {
            // 分帧发送更省拷贝，且能“即时确认连接”
            ws.send(vlessHeader);
        }
        headerSent = true;
    }
    async function becomeWinner(sock, label) {
        selected = label;
        clearFallbackTimer();

        // 关闭败者
        try { if (label === 'direct' && proxySock) proxySock.close(); } catch {}
        try { if (label === 'proxy' && directSock) directSock.close(); } catch {}

        // 建立 writer，冲刷早期缓冲
        remote.value = sock;
        remote.writer = sock.writable.getWriter();
        if (remote.earlyBuf.length) {
            for (const buf of remote.earlyBuf) {
                await remote.writer.write(buf);
            }
            remote.earlyBuf.length = 0;
            remote.earlyBytes = 0;
        }
        remote.ready = true;
    }
    async function startReader(sock, label) {
        const reader = sock.readable.getReader();
        try {
            let first = true;
            while (true) {
                const { value, done } = await reader.read();
                if (done) break;
                if (closed) break;

                if (!selected) await becomeWinner(sock, label);

                if (first) {
                    if (!headerSent && !COALESCE_HEADER) sendHeaderIfNeeded();
                    first = false;
                }

                if (ws.readyState !== WS_READY_STATE_OPEN) throw new Error('WebSocket not open');

                if (COALESCE_HEADER && !headerSent) {
                    ws.send(concatArrayBuffers(vlessHeader, value));
                    headerSent = true;
                } else {
                    ws.send(value);
                }
            }
        } catch {
            // 忽略读取异常
        } finally {
            try { reader.releaseLock(); } catch {}
            if (selected === label && !closed) {
                closed = true;
                safeCloseWebSocket(ws);
            }
        }
    }

    // 启动直连 + 首包写入
    directSock = connect({ hostname: address, port });
    try {
        const w = directSock.writable.getWriter();
        await w.write(initData);
        w.releaseLock();
        // 直连连接已建立：按需“即时回包头”，加速客户端确认
        if (SEND_HEADER_EARLY && !headerSent && ws.readyState === WS_READY_STATE_OPEN) {
            sendHeaderIfNeeded();
        }
    } catch { /* 写入异常由读侧或并发接管 */ }
    startReader(directSock, 'direct');

    // 并发代理：Telegram 域名 0ms，同时开跑；其他域名采用 RACE_DELAY_MS
    const enableRace = RACE_ENABLED && proxyConfig.proxyHost;
    if (enableRace) {
        const delay = tgBoost ? TG_RACE_DELAY_MS : RACE_DELAY_MS;
        if (delay <= 0) {
            try {
                proxySock = connect({
                    hostname: proxyConfig.proxyHost,
                    port: proxyConfig.proxyPort !== null ? proxyConfig.proxyPort : port,
                });
                const w2 = proxySock.writable.getWriter();
                await w2.write(initData);
                w2.releaseLock();
                // 并发连接也可“即时回包头”（若直连未先发）
                if (SEND_HEADER_EARLY && !headerSent && ws.readyState === WS_READY_STATE_OPEN) {
                    sendHeaderIfNeeded();
                }
                startReader(proxySock, 'proxy');
            } catch { /* 并发失败则维持直连 */ }
        } else {
            fallbackTimer = setTimeout(async () => {
                if (selected || closed) return;
                try {
                    proxySock = connect({
                        hostname: proxyConfig.proxyHost,
                        port: proxyConfig.proxyPort !== null ? proxyConfig.proxyPort : port,
                    });
                    const w2 = proxySock.writable.getWriter();
                    await w2.write(initData);
                    w2.releaseLock();
                    if (SEND_HEADER_EARLY && !headerSent && ws.readyState === WS_READY_STATE_OPEN) {
                        sendHeaderIfNeeded();
                    }
                    startReader(proxySock, 'proxy');
                } catch { /* 保持直连 */ }
            }, delay);
        }
    }
}

// ==================== ⑩ DNS（UDP）处理 – DoH（零拷贝回写） ====================
async function handleUDPOutBound(ws, vlessHeader) {
    let headerSent = false;

    const transform = new TransformStream({
        transform(chunk, controller) {
            // 拆分长度字段为 UDP 包
            for (let i = 0; i < chunk.byteLength;) {
                const len = new DataView(chunk.buffer, chunk.byteOffset + i, 2).getUint16(0);
                const data = new Uint8Array(chunk.buffer, chunk.byteOffset + i + 2, len);
                controller.enqueue(data);
                i += 2 + len;
            }
        },
    });

    transform.readable.pipeTo(new WritableStream({
        async write(dQuery) {
            const resp = await fetch('https://dns.google/dns-query', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/dns-message',
                    'Accept': 'application/dns-message',
                },
                body: dQuery,
            });
            const ans = await resp.arrayBuffer();
            const sz = ans.byteLength;
            const szBuf = new Uint8Array([(sz >> 8) & 0xff, sz & 0xff]);

            if (ws.readyState === WS_READY_STATE_OPEN) {
                if (!headerSent) { ws.send(vlessHeader); headerSent = true; }
                // 分帧发送长度与负载，避免内存合并拷贝
                ws.send(szBuf);
                ws.send(ans);
            }
        },
    })).catch(() => { /* 吞掉内部错误 */ });

    const writer = transform.writable.getWriter();
    return {
        write(chunk) {
            writer.write(chunk);
        },
    };
}

// ==================== ⑪ 辅助：WebSocket 安全关闭 ====================
const WS_READY_STATE_OPEN = 1;
const WS_READY_STATE_CLOSING = 2;
function safeCloseWebSocket(sock) {
    try {
        if (sock.readyState === WS_READY_STATE_OPEN || sock.readyState === WS_READY_STATE_CLOSING) {
            sock.close();
        }
    } catch { /* ignore */ }
}

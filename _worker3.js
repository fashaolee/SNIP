/*=====================================================================
  Cloudflare Workers VLESS + WebSocket  －  全链路加速版
  ①  动态 proxyIP（path /proxyip=host[:port] / query ?proxyip=host[:port]）
  ②  重要目标（Telegram / YouTube / TikTok / 图片 CDN） 0 ms 并发回源
 ③  带宽分配（上传/下载）采用 Token‑Bucket（防止慢启动放大）
 ④  TLS / VLESS 关键首包立即发送（首‑3 秒优先通道）
 ⑤  小文件/API 请求直接透传（无合帧），大文件/长视频使用可选合帧/队列
 ⑥  断流、异常、关闭统一安全处理
=====================================================================*/

import { connect } from 'cloudflare:sockets';

// ==================== ① 基础配置 ====================
let USER_ID = '5c4eed9c-4071-4d02-a00f-4ac58221238f';    // 请自行替换
let DEFAULT_PROXY = 'proxyip.jp.zxcs.dpdns.org';          // 默认代理，可被 path / query 覆盖

// ---------- 资源/性能调参（可自行微调） ----------
const RACE_ENABLED        = true;     // 是否开启并发回源（Happy‑Eyeballs）
const GEN_RACE_DELAY_MS   = 350;      // 普通域名并发延时
const MEDIA_RACE_DELAY_MS = 0;        // 视频/图片等媒体域名并发延时（0 ms 同时启动）
const MAX_EARLY_BUF      = 64 * 1024; // WS→TCP 选路前缓冲上限
const SEND_HEADER_EARLY   = true;     // 直接在 socket 建立后发送 VLESS 回包头
const COALESCE_MS_VIDEO   = 6;        // 视频/图片合帧时间窗口（毫秒），0 为禁用
const COALESCE_MAX_VIDEO  = 64 * 1024;// 合并最大字节数
const COALESCE_MS_SMALL   = 0;        // 小请求（API、图片缩略图）不合帧
const COALESCE_MAX_SMALL  = 0;

// ------- 带宽 Token‑Bucket（上传/下载各自独立） -------
const UP_RATE   = 10 * 1024 * 1024;   // 上传峰值（10 MiB/s）可自行调低
const DOWN_RATE = 100 * 1024 * 1024;  // 下载峰值（100 MiB/s）可自行调高
const BUCKET_REFILL_MS = 100;        // Token补充间隔

// ==================== ② 代理解析（纯函数） ====================
let proxyConf = { host: '', port: null };
function parseProxy(str) {
    proxyConf = { host: '', port: null };
    if (!str) return;
    const [h, p] = str.split(':');
    proxyConf.host = h.trim();
    if (p) {
        const num = parseInt(p.trim(), 10);
        if (!isNaN(num) && num > 0 && num <= 65535) proxyConf.port = num;
    }
}

// ==================== ③ 工具函数 ====================
function extractProxyFromPath(p) {
    const m = /^\/proxyip=([^/]+)(?:\/.*)?$/.exec(p);
    return m ? m[1] : null;
}
function effectiveProxy(url) {
    const fromQ = (url.searchParams.get('proxyip') || '').trim();
    const fromP = extractProxyFromPath(url.pathname);
    return fromQ || fromP || DEFAULT_PROXY;
}
function concatAB(...arr) {                     // 合并，仅在需要时使用
    const tot = arr.reduce((s, a) => s + a.byteLength, 0);
    const out = new Uint8Array(tot);
    let off = 0;
    for (const a of arr) { out.set(new Uint8Array(a), off); off += a.byteLength; }
    return out.buffer;
}
function base64ToAB(str) {
    if (!str) return { error: null };
    try {
        const b64 = str.replace(/-/g, '+').replace(/_/g, '/');
        const dec = atob(b64);
        const u8 = Uint8Array.from(dec, c => c.charCodeAt(0));
        return { early: u8.buffer, error: null };
    } catch (e) { return { error: e }; }
}
const TEXT_DEC = new TextDecoder();

// UUID 校验
function isValidUUID(u) { return /^[0-9a-f]{8}-[0-9a-f]{4}-[4][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(u); }
const BYTE2HEX = [...Array(256)].map((_, i) => (i + 256).toString(16).slice(1));
function unsafeUUID(arr, o = 0) {
    return (
        BYTE2HEX[arr[o + 0]] + BYTE2HEX[arr[o + 1]] + BYTE2HEX[arr[o + 2]] + BYTE2HEX[arr[o + 3]] + '-' +
        BYTE2HEX[arr[o + 4]] + BYTE2HEX[arr[o + 5]] + '-' +
        BYTE2HEX[arr[o + 6]] + BYTE2HEX[arr[o + 7]] + '-' +
        BYTE2HEX[arr[o + 8]] + BYTE2HEX[arr[o + 9]] + '-' +
        BYTE2HEX[arr[o +10]] + BYTE2HEX[arr[o +11]] + BYTE2HEX[arr[o +12]] +
        BYTE2HEX[arr[o +13]] + BYTE2HEX[arr[o +14]] + BYTE2HEX[arr[o +15]]
    ).toLowerCase();
}
function uuidFromBytes(arr, o = 0) {
    const u = unsafeUUID(arr, o);
    if (!isValidUUID(u)) throw new TypeError('Invalid UUID');
    return u;
}

// ---------------- 媒体/视频域名识别 ----------------
function isMediaHost(host) {
    if (!host) return false;
    const h = host.toLowerCase();
    // 常见视频/图片 CDN（可自行增删）
    return (
        h.includes('googlevideo.com') || h.includes('ytimg.com') ||
        h.includes('tiktokcdn.com') || h.includes('bytecdn.cn') ||
        h.includes('cdninstagram.com') || h.includes('fbcdn.net') ||
        h.includes('akamaihd.net') || h.includes('edgesuite.net') ||
        h.includes('cdn77.org') || h.includes('cdn-telegram') ||
        h.includes('telegram.org') || h.includes('t.me') ||
        h.includes('telegra.ph') || h.includes('.m3u8')
    );
}

// ---------------- Token‑Bucket（上传/下载） ----------------
class TokenBucket {
    constructor(rate) { this.rate = rate; this.tokens = rate; this.last = Date.now(); }
    async take(bytes) {
        while (this.tokens < bytes) {
            await new Promise(r => setTimeout(r, BUCKET_REFILL_MS));
            const now = Date.now();
            const add = ((now - this.last) * this.rate) / 1000;
            this.tokens = Math.min(this.rate, this.tokens + add);
            this.last = now;
        }
        this.tokens -= bytes;
    }
}
const upBucket   = new TokenBucket(UP_RATE);
const downBucket = new TokenBucket(DOWN_RATE);

// ==================== ④ 订阅生成（path 中携带当前 proxy） ====================
function makeVlessSub(uid, curHost, proxy) {
    const path = `/proxyip=${proxy}`;
    const p = new URLSearchParams({
        encryption: 'none',
        security: 'tls',
        sni: curHost,
        fp: 'chrome',
        type: 'ws',
        host: curHost,
        path: path,
        // 以下参数降低客户端 CPU/内存（多数客户端会忽略不认）
        mux: '1',
        alpn: 'http/1.1',
    });
    const uris = preferredDomains.map((d, i) => {
        const alias = `T-SNIP_${String(i + 1).padStart(2, '0')}`;
        return `vless://${uid}@${d}:443?${p.toString()}#${alias}`;
    });
    return btoa(uris.join('\n')).replace(/\+/g, '-').replace(/\//g, '_');
}

// ==================== ⑤ 主入口 ====================
if (!isValidUUID(USER_ID)) throw new Error('invalid uuid');

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

export default {
    async fetch(req, env, ctx) {
        try {
            const url = new URL(req.url);
            parseProxy(effectiveProxy(url));                     // 解析本次请求的 proxyIP

            // 解析 UUID（/UUID 或 /proxyip=host[:port]/UUID）
            let uuid = null;
            const m = /^\/proxyip=([^/]+)(?:\/([0-9a-f-]{36}))?$/.exec(url.pathname);
            if (m && m[2]) uuid = m[2];
            else if (url.pathname.length > 1) uuid = url.pathname.slice(1);

            const upgrade = req.headers.get('Upgrade');
            // ----------------- 非 WS（订阅、提示） -----------------
            if (!upgrade || upgrade !== 'websocket') {
                if (url.pathname === '/') {
                    return new Response('✅ 配置成功，使用 UUID 获取订阅。可通过 ?proxyip=host[:port] 或 /proxyip=host[:port]/UUID 覆盖代理', {
                        status: 200,
                        headers: { 'Content-Type': 'text/plain;charset=utf-8' },
                    });
                }
                if (uuid && uuid === USER_ID) {
                    const cfg = makeVlessSub(uuid, req.headers.get('Host'), effectiveProxy(url));
                    return new Response(cfg, { status: 200, headers: { 'Content-Type': 'text/plain;charset=utf-8' } });
                }
                return new Response('❌ UUID 错误', { status: 400, headers: { 'Content-Type': 'text/plain;charset=utf-8' } });
            }

            // ----------------- WebSocket -----------------
            return await handleWS(req);
        } catch (e) {
            return new Response(e.toString(), { status: 500, headers: { 'Content-Type': 'text/plain;charset=utf-8' } });
        }
    },
};

// ==================== ⑥ WebSocket 主处理 ====================
async function handleWS(request) {
    const url = new URL(request.url);
    parseProxy(effectiveProxy(url));

    const pair = new WebSocketPair();
    const [client, server] = Object.values(pair);
    server.accept();

    const earlyHeader = request.headers.get('sec-websocket-protocol') || '';
    const wsRead = makeWSReadable(server, earlyHeader);

    // -------------------------------------------------
    // 远端状态对象（共享）
    // -------------------------------------------------
    const remote = {
        sock: null,
        writer: null,
        ready: false,               // 已选路并可写
        start: false,               // 已解析 VLESS 首包
        earlyBuf: [],               // 选路前缓冲
        earlyBytes: 0,
        media: false,               // 是否媒体（视频/图片）流
    };
    let udpWrite = null;
    let isDNS = false;

    // ---- WS 关闭时同步关闭远端 socket ----
    server.addEventListener('close', () => { try { remote.sock?.close(); } catch {} });
    server.addEventListener('error', () => { try { remote.sock?.close(); } catch {} });

    // -------------------------------------------------
    // WS → Remote（上传）管道
    // -------------------------------------------------
    wsRead.pipeTo(new WritableStream({
        async write(chunk) {
            // DNS 直通
            if (isDNS && udpWrite) { udpWrite(chunk); return; }

            // 已选路，直接写（使用 writer 复用，减锁开销）
            if (remote.ready && remote.writer) {
                await upBucket.take(chunk.byteLength);          // 上传限速
                await remote.writer.write(chunk);
                return;
            }

            // 第一次数据，解析 VLESS 头部
            if (!remote.start) {
                const {
                    hasError,
                    message,
                    portRemote = 443,
                    addressRemote = '',
                    rawDataIndex,
                    vlessVersion = new Uint8Array([0, 0]),
                    isUDP,
                } = processVlessHeader(chunk, USER_ID);
                if (hasError) throw new Error(message);

                // UDP 仅 DNS（53）放行
                if (isUDP) {
                    if (portRemote !== 53) throw new Error('Only DNS UDP allowed');
                    isDNS = true;
                }

                const respHeader = new Uint8Array([vlessVersion[0], 0]); // VLESS REPLY
                const payload = chunk.slice(rawDataIndex);

                // DNS 处理
                if (isDNS) {
                    const { write } = await handleUDPOutBound(server, respHeader);
                    udpWrite = write;
                    udpWrite(payload);
                    remote.start = true;
                    return;
                }

                // 判断是否媒体流（视频/图片），决定后面合帧策略
                remote.media = isMediaHost(addressRemote);

                // 启动 TCP 连接（带并发竞速、带宽调度、首‑3 秒极速响应）
                startTCPWithSpeedControl(remote, addressRemote, portRemote, payload, server, respHeader);
                remote.start = true;
                return;
            }

            // 尚未选路：使用有界缓冲防止内存暴涨
            if (remote.earlyBytes + chunk.byteLength <= MAX_EARLY_BUF) {
                remote.earlyBuf.push(chunk);
                remote.earlyBytes += chunk.byteLength;
            } else {
                // 超出阈值直接写（若 writer 已创建）或丢弃（极端保护）
                if (remote.writer) {
                    await upBucket.take(chunk.byteLength);
                    await remote.writer.write(chunk);
                }
            }
        },
    })).catch(() => { /* 已在内部自行处理 */ });

    return new Response(null, { status: 101, webSocket: client });
}

// ==================== ⑦ 可读 WS 流 ====================
function makeWSReadable(ws, earlyDataHeader) {
    let canceled = false;
    const { earlyData } = base64ToAB(earlyDataHeader);
    return new ReadableStream({
        start(controller) {
            if (earlyData) controller.enqueue(new Uint8Array(earlyData));

            ws.addEventListener('message', e => {
                if (!canceled) controller.enqueue(e.data);
            });
            ws.addEventListener('close', () => {
                safeCloseWebSocket(ws);
                if (!canceled) controller.close();
            });
            ws.addEventListener('error', err => controller.error(err));
        },
        cancel() {
            canceled = true;
            safeCloseWebSocket(ws);
        },
    });
}

// ==================== ⑧ VLESS Header 解析 ====================
function processVlessHeader(buf, uid) {
    try {
        if (buf.byteLength < 24) throw new Error('invalid data');
        const ver = new Uint8Array(buf.slice(0, 1));
        const uuid = uuidFromBytes(new Uint8Array(buf.slice(1, 17)));
        if (uuid !== uid.toLowerCase()) throw new Error('invalid user');
        const optLen = new Uint8Array(buf.slice(17, 18))[0];
        const cmdIdx = 18 + optLen;
        const cmd = new Uint8Array(buf.slice(cmdIdx, cmdIdx + 1))[0];
        const isUDP = cmd === 2;
        if (cmd !== 1 && !isUDP) throw new Error(`unsupported cmd ${cmd}`);
        const port = new DataView(buf.slice(cmdIdx + 1, cmdIdx + 3)).getUint16(0);
        let aIdx = cmdIdx + 3;
        const addrType = new Uint8Array(buf.slice(aIdx, aIdx + 1))[0];
        aIdx += 1;

        let address = '', addrLen = 0;
        switch (addrType) {
            case 1: // IPv4
                addrLen = 4;
                address = new Uint8Array(buf.slice(aIdx, aIdx + 4)).join('.');
                break;
            case 2: // Domain
                addrLen = new Uint8Array(buf.slice(aIdx, aIdx + 1))[0];
                aIdx += 1;
                address = TEXT_DEC.decode(buf.slice(aIdx, aIdx + addrLen));
                break;
            case 3: // IPv6
                addrLen = 16;
                const dv = new DataView(buf.slice(aIdx, aIdx + 16));
                const parts = [];
                for (let i = 0; i < 8; i++) parts.push(dv.getUint16(i * 2).toString(16));
                address = parts.join(':');
                break;
            default:
                throw new Error(`invalid address type ${addrType}`);
        }
        const rawIdx = aIdx + addrLen;
        return {
            hasError: false,
            addressRemote: address,
            portRemote: port,
            rawDataIndex: rawIdx,
            vlessVersion: ver,
            isUDP,
        };
    } catch (e) {
        return { hasError: true, message: e.message };
    }
}

// ==================== ⑨ TCP + 带宽控制 + 竞速 ====================
async function startTCPWithSpeedControl(remote, host, port, initData, ws, vlessHeader) {
    if (remote._active) return;
    remote._active = true;

    const needRace   = RACE_ENABLED && proxyConf.host;                 // 是否要并发代理
    const mediaMode  = remote.media;
    const raceDelay  = mediaMode ? MEDIA_RACE_DELAY_MS : GEN_RACE_DELAY_MS;
    const coalesceMs = mediaMode ? COALESCE_MS_VIDEO : COALESCE_MS_SMALL;
    const coalesceMx = mediaMode ? COALESCE_MAX_VIDEO : COALESCE_MAX_SMALL;

    let chosen = null;      // 'direct' | 'proxy'
    let directSock = null;
    let proxySock = null;
    let timer = null;
    let closed = false;
    let headerSent = false;

    // ----------------- WS 发送器（合帧/分帧） -----------------
    const wsSender = createWSSender(ws, vlessHeader, {
        coalesceMs,
        maxBytes: coalesceMx,
        earlyHeader: SEND_HEADER_EARLY,
    });

    // ----------------- 选路成功后统一处理 -----------------
    async function becomeWinner(sock, label) {
        if (chosen) return;
        chosen = label;
        clearTimeout(timer);
        // 关闭失败方
        try { if (label === 'direct' && proxySock) proxySock.close(); } catch {}
        try { if (label === 'proxy' && directSock) directSock.close(); } catch {}

        remote.sock   = sock;
        remote.writer = sock.writable.getWriter();

        // 先把先前缓冲（选路前的 WS→TCP）写完
        if (remote.earlyBuf.length) {
            for (const b of remote.earlyBuf) await remote.writer.write(b);
            remote.earlyBuf = []; remote.earlyBytes = 0;
        }
        remote.ready = true;
    }

    // ----------------- 读取远端并写回 WS（下载） -----------------
    async function startReader(sock, label) {
        const reader = sock.readable.getReader();
        try {
            let first = true;
            while (true) {
                const { value, done } = await reader.read();
                if (done) break;
                if (closed) break;

                // 选路：第一次收到数据即决定
                if (!chosen) await becomeWinner(sock, label);

                // 第一次到来时立即发送 VLESS 回包头（如果尚未发送）
                if (first && SEND_HEADER_EARLY && !headerSent) {
                    wsSender.sendHeader();          // 只发送一次
                    headerSent = true;
                }
                first = false;

                // 下载限速（Token‑Bucket）
                await downBucket.take(value.byteLength);
                wsSender.push(value);               // 交给合帧器
            }
        } catch { /* ignore */ }
        finally {
            try { reader.releaseLock(); } catch {}
            // 当赢者的流结束时，先把队列冲刷再关闭 WS
            if (chosen === label && !closed) {
                wsSender.flush();   // 确保所有积攒的帧都发送
                closed = true;
                safeCloseWebSocket(ws);
            }
        }
    }

    // ----------------- 直接连接 -----------------
    directSock = connect({ hostname: host, port });
    try {
        const w = directSock.writable.getWriter();
        await w.write(initData);                 // 首包写入
        w.releaseLock();
        if (SEND_HEADER_EARLY && !headerSent) { wsSender.sendHeader(); headerSent = true; }
    } catch { /* 若写入异常，后续会由 reader 处理 */ }
    startReader(directSock, 'direct');

    // ----------------- 代理并发（可选） -----------------
    if (needRace) {
        const launchProxy = async () => {
            if (chosen || closed) return;
            try {
                proxySock = connect({
                    hostname: proxyConf.host,
                    port: proxyConf.port !== null ? proxyConf.port : port,
                });
                const w2 = proxySock.writable.getWriter();
                await w2.write(initData);
                w2.releaseLock();
                if (SEND_HEADER_EARLY && !headerSent) { wsSender.sendHeader(); headerSent = true; }
                startReader(proxySock, 'proxy');
            } catch { /* 代理失败时保持直连 */ }
        };
        if (raceDelay <= 0) launchProxy();                 // 立即并发（媒体域名）
        else timer = setTimeout(launchProxy, raceDelay);   // 延迟并发（普通域名）
    }
}

// ==================== ⑩ WS Sender（合帧/分帧） ====================
function createWSSender(ws, header, opts) {
    const { coalesceMs = 0, maxBytes = 0, earlyHeader = true } = opts;
    let headerSent = false;
    let bufParts = [];
    let bufSize  = 0;
    let timer    = null;
    let closed   = false;

    function sendHeader() {
        if (headerSent) return;
        ws.send(header);
        headerSent = true;
    }

    function scheduleFlush() {
        if (timer || coalesceMs <= 0) return;
        timer = setTimeout(flush, coalesceMs);
    }

    function flush() {
        if (closed) return;
        if (timer) { clearTimeout(timer); timer = null; }
        if (!headerSent) sendHeader();
        if (bufSize === 0) return;
        // 合并一次发送（一次 copy，只在需要合帧时才做）
        const out = new Uint8Array(bufSize);
        let off = 0;
        for (const p of bufParts) { out.set(p, off); off += p.byteLength; }
        ws.send(out);
        bufParts = []; bufSize = 0;
    }

    return {
        // 外部主动发送 header（首‑3 秒极速响应）
        sendHeader,
        push(chunk) {
            if (closed) return;
            // 若不需要合帧，直接发送（最小延迟）
            if (coalesceMs === 0 || maxBytes === 0) {
                if (!headerSent) sendHeader();
                ws.send(chunk);
                return;
            }
            // 需要合帧：累计
            const u8 = chunk instanceof Uint8Array ? chunk : new Uint8Array(chunk);
            bufParts.push(u8);
            bufSize += u8.byteLength;
            if (bufSize >= maxBytes) flush();
            else scheduleFlush();
        },
        flush() { flush(); },
        close() { closed = true; if (timer) clearTimeout(timer); }
    };
}

// ==================== ⑪ UDP（DoH） ====================
async function handleUDPOutBound(ws, vlessHeader) {
    let headerSent = false;
    const tr = new TransformStream({
        transform(chunk, ctrl) {
            // 长度字段拆分成独立 UDP 包
            for (let i = 0; i < chunk.byteLength;) {
                const len = new DataView(chunk.buffer, chunk.byteOffset + i, 2).getUint16(0);
                const data = new Uint8Array(chunk.buffer, chunk.byteOffset + i + 2, len);
                ctrl.enqueue(data);
                i += 2 + len;
            }
        },
    });

    tr.readable.pipeTo(new WritableStream({
        async write(dnsQuery) {
            const r = await fetch('https://dns.google/dns-query', {
                method: 'POST',
                headers: { 'Content-Type': 'application/dns-message', 'Accept': 'application/dns-message' },
                body: dnsQuery,
            });
            const ans = await r.arrayBuffer();
            const sz = ans.byteLength;
            const szBuf = new Uint8Array([(sz >> 8) & 0xff, sz & 0xff]);

            if (!headerSent) { ws.send(vlessHeader); headerSent = true; }
            ws.send(szBuf);
            ws.send(ans);
        },
    })).catch(() => { /* internal ignore */ });

    const w = tr.writable.getWriter();
    return { write: chunk => w.write(chunk) };
}

// ==================== ⑫ 安全关闭 ====================
const WS_OPEN = 1, WS_CLOSING = 2;
function safeCloseWebSocket(ws) {
    try {
        if (ws.readyState === WS_OPEN || ws.readyState === WS_CLOSING) ws.close();
    } catch { /* ignore */ }
}

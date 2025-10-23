import { connect } from 'cloudflare:sockets';

// ==================== ① 基础配置 ====================
let userID = '5c4eed9c-4071-4d02-a00f-4ac58221238f'; // 请自行替换
let proxyIP = 'proxyip.jp.zxcs.dpdns.org';           // 默认代理，可被 path/query 覆盖

// ==================== ② 传输策略配置 ====================
// 通用连接策略
const RACE_ENABLED = true;                 // 是否启用并发回源
const RACE_DELAY_MS = 350;                 // 普通域名并发门限

// 前5秒极速策略
const INITIAL_RACE_DELAY = 0;              // 前5秒内0ms并发
const INITIAL_COALESCE_MS = 1;             // 前5秒聚合窗口1ms
const INITIAL_COALESCE_MAX = 4096;         // 前5秒最大聚合4KB

// 5-15秒加速策略
const ACCEL_RACE_DELAY = 200;              // 5-15秒并发门限
const ACCEL_COALESCE_MS = 3;               // 5-15秒聚合窗口3ms
const ACCEL_COALESCE_MAX = 128 * 1024;      // 5-15秒最大聚合32KB

// 稳定期高效策略
const STABLE_COALESCE_MS = 6;              // 稳定期聚合窗口6ms
const STABLE_COALESCE_MAX = 256 * 1024;     // 稳定期最大聚合64KB

// 媒体特定策略
const VIDEO_COALESCE_MS = 6;               // 视频聚合窗口
const VIDEO_COALESCE_MAX = 512 * 1024;      // 视频最大聚合
const IMAGE_COALESCE_MS = 3;               // 图片聚合窗口
const IMAGE_COALESCE_MAX = 32 * 1024;      // 图片最大聚合

// 其他配置
const MAX_EARLY_BUFFER_BYTES = 64 * 1024;  // WS→TCP 早期缓冲上限
const SEND_HEADER_EARLY = true;            // 出站连接建立后立即回写VLESS头
const SMALL_PACKET_THRESHOLD = 1024;       // 小数据包阈值(1KB)

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

// ==================== ③ 代理信息解析（纯函数） ====================
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

// ==================== ④ 工具函数（域名识别、解析、流） ====================
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
// 域名分类识别
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
function isVideoHost(host) {
    if (!host) return false;
    const h = host.toLowerCase();
    return (
        h.includes('googlevideo.com') || h.includes('gvt1.com') || // YouTube
        h.includes('youtube.com') || h.includes('ytimg.com') ||
        h.includes('tiktokcdn.com') || h.includes('muscdn.com') || // TikTok
        h.includes('bytecdn.cn') || h.includes('byteimg.com') ||
        h.includes('fbcdn.net') || h.includes('cdninstagram.com') ||
        h.includes('vimeocdn.com') || h.includes('vimeo.com') ||
        h.includes('nflxvideo.net') || h.includes('netflix.com') ||
        h.includes('akamaized.net') || h.includes('edgesuite.net') ||
        h.includes('hls') || h.includes('.m3u8') // 粗粒度匹配
    );
}
function isImageHost(host) {
    if (!host) return false;
    const h = host.toLowerCase();
    return (
        h.includes('instagram.com') ||
        h.includes('fbcdn.net') ||
        h.includes('cdninstagram.com') ||
        h.includes('pinterest.com') ||
        h.includes('pinimg.com') ||
        h.includes('twitter.com') ||
        h.includes('twimg.com') ||
        h.includes('tiktok.com') ||
        h.includes('tiktokcdn.com') ||
        h.includes('telegram.org') ||
        h.includes('t.me') ||
        h.includes('telegra.ph') ||
        h.includes('telegram-cdn')
    );
}
function isMediaHost(host) {
    return isVideoHost(host) || isImageHost(host);
}

// TLS握手检测
function isTLSHandshake(chunk) {
    if (!(chunk instanceof Uint8Array) || chunk.byteLength < 5) return false;
    // TLS握手记录类型为0x16 (Handshake)
    return chunk[0] === 0x16;
}

// 合并多个 Uint8Array 为一个 ArrayBuffer
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

// ==================== ⑤ 智能多阶段传输引擎 ====================
class SmartWSSender {
    constructor(ws, vlessHeader) {
        this.ws = ws;
        this.vlessHeader = vlessHeader;
        this.headerSent = false;
        this.parts = [];
        this.totalBytes = 0;
        this.flushTimer = null;
        this.connectionType = 'general';
        this.startTime = Date.now();
        this.trafficLevel = 'low'; // 'low', 'medium', 'high'
        this.lastDataTime = Date.now();
    }

    // 设置连接类型（视频/图片/普通）
    setConnectionType(type) {
        this.connectionType = type;
        this.resetFlushTimer();
    }

    // 获取当前传输策略
    getStrategy() {
        const elapsed = Date.now() - this.startTime;
        
        // 前5秒：极速模式
        if (elapsed < 5000) {
            return {
                coalesceMs: INITIAL_COALESCE_MS,
                maxBytes: INITIAL_COALESCE_MAX,
                immediateTypes: ['tls', 'small']
            };
        }
        
        // 5-15秒：加速模式
        if (elapsed < 15000) {
            return {
                coalesceMs: ACCEL_COALESCE_MS,
                maxBytes: ACCEL_COALESCE_MAX,
                immediateTypes: ['tls']
            };
        }
        
        // 视频连接：高效模式
        if (this.connectionType === 'video') {
            return {
                coalesceMs: VIDEO_COALESCE_MS,
                maxBytes: VIDEO_COALESCE_MAX,
                immediateTypes: ['tls']
            };
        }
        
        // 图片连接：优化加载模式
        if (this.connectionType === 'image') {
            return {
                coalesceMs: IMAGE_COALESCE_MS,
                maxBytes: IMAGE_COALESCE_MAX,
                immediateTypes: ['tls', 'small']
            };
        }
        
        // 普通连接：高效模式
        return {
            coalesceMs: STABLE_COALESCE_MS,
            maxBytes: STABLE_COALESCE_MAX,
            immediateTypes: ['tls']
        };
    }

    // 识别数据包类型
    identifyChunkType(chunk) {
        if (isTLSHandshake(chunk)) return 'tls';
        if (chunk instanceof Uint8Array && chunk.byteLength <= SMALL_PACKET_THRESHOLD) return 'small';
        return 'general';
    }

    // 确保头已发送
    ensureHeaderSent() {
        if (!this.headerSent && this.ws.readyState === WS_READY_STATE_OPEN) {
            this.ws.send(this.vlessHeader);
            this.headerSent = true;
        }
    }

    // 立即发送单个数据块
    sendImmediately(chunk) {
        this.ensureHeaderSent();
        if (this.ws.readyState === WS_READY_STATE_OPEN) {
            this.ws.send(chunk);
        }
    }

    // 冲刷所有聚合数据
    flush() {
        if (this.flushTimer) {
            clearTimeout(this.flushTimer);
            this.flushTimer = null;
        }
        
        if (this.parts.length === 0) return;
        
        try {
            // 合并数据
            const total = this.parts.reduce((sum, p) => sum + p.byteLength, 0);
            const buffer = new Uint8Array(total);
            let offset = 0;
            
            for (const part of this.parts) {
                const u8 = part instanceof Uint8Array ? part : new Uint8Array(part);
                buffer.set(u8, offset);
                offset += u8.byteLength;
            }
            
            // 发送合并数据
            this.ensureHeaderSent();
            if (this.ws.readyState === WS_READY_STATE_OPEN) {
                this.ws.send(buffer);
            }
            
            // 重置状态
            this.parts = [];
            this.totalBytes = 0;
        } catch (e) {
            console.error('SmartWSSender flush error:', e);
        }
    }

    // 重置刷新计时器
    resetFlushTimer() {
        const strategy = this.getStrategy();
        
        if (this.flushTimer) {
            clearTimeout(this.flushTimer);
            this.flushTimer = null;
        }
        
        if (strategy.coalesceMs > 0 && this.totalBytes < strategy.maxBytes) {
            this.flushTimer = setTimeout(() => {
                this.flushTimer = null;
                this.flush();
            }, strategy.coalesceMs);
        } else {
            this.flush();
        }
    }

    // 添加数据块到发送队列
    push(chunk) {
        if (this.ws.readyState !== WS_READY_STATE_OPEN) {
            return;
        }
        
        this.lastDataTime = Date.now();
        const strategy = this.getStrategy();
        const chunkType = this.identifyChunkType(chunk);
        
        // 关键数据包立即发送
        if (strategy.immediateTypes.includes(chunkType)) {
            this.flush(); // 先发送所有积压数据
            this.sendImmediately(chunk);
            return;
        }
        
        // 小数据包特殊处理
        if (chunkType === 'small' && this.parts.length === 0) {
            this.sendImmediately(chunk);
            return;
        }
        
        // 添加到聚合队列
        this.parts.push(chunk);
        this.totalBytes += chunk instanceof Uint8Array ? chunk.byteLength : chunk.byteLength;
        
        // 超过最大聚合大小，立即刷新
        if (this.totalBytes >= strategy.maxBytes) {
            this.flush();
        } else {
            this.resetFlushTimer();
        }
        
        // 更新流量级别
        if (this.totalBytes > 1024 * 1024) {
            this.trafficLevel = 'high';
        } else if (this.totalBytes > 128 * 1024) {
            this.trafficLevel = 'medium';
        } else {
            this.trafficLevel = 'low';
        }
    }

    // 关闭发送器
    close() {
        this.flush();
        
        if (this.flushTimer) {
            clearTimeout(this.flushTimer);
            this.flushTimer = null;
        }
        
        this.parts = [];
        this.totalBytes = 0;
    }
}

// ==================== ⑥ VLESS 配置生成 ====================
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
        // 客户端优化参数
        mux: '1',
        alpn: 'http/1.1',
        // 为媒体连接添加特殊参数
        'video-params': 'buffer=128;maxrate=5000',
        'image-params': 'preload=full;quality=high'
    });

    const allVlessUris = preferredDomains.map((domain, idx) => {
        const alias = `T-SNIP_${String(idx + 1).padStart(2, '0')}`;
        return `${protocol}://${userID}@${domain}:443?${params.toString()}#${alias}`;
    });

    const sub = allVlessUris.join('\n');
    return btoa(sub).replace(/\+/g, '-').replace(/\//g, '_');
}

// ==================== ⑦ 主入口 ====================
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
                    return new Response('服务已启动。请添加UUID访问，支持动态代理设置。', {
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
                return new Response('无效的UUID', {
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

// ==================== ⑧ WebSocket 处理（终极优化版） ====================
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
    let wsSender = null;

    // 断流优化：WS 侧关闭则关闭远端 socket
    server.addEventListener('close', () => { try { remote.value && remote.value.close(); } catch {} });
    server.addEventListener('error', () => { try { remote.value && remote.value.close(); } catch {} });

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

                // 智能连接类型识别
                let connectionType = 'general';
                if (isVideoHost(addressRemote)) {
                    connectionType = 'video';
                } else if (isImageHost(addressRemote)) {
                    connectionType = 'image';
                }

                // 创建智能发送器
                wsSender = new SmartWSSender(server, vlessRespHeader);
                wsSender.setConnectionType(connectionType);

                // 启动 TCP（智能策略）
                handleTCPOutBoundOptimized(remote, addressRemote, portRemote, rawClient, server, wsSender, {
                    connectionType,
                    address: addressRemote
                });
                remote.started = true;
                return;
            }

            // 尚未选路：进入早期有界缓冲
            if (remote.earlyBytes + chunk.byteLength <= MAX_EARLY_BUFFER_BYTES) {
                remote.earlyBuf.push(chunk);
                remote.earlyBytes += chunk.byteLength;
            } else {
                // 超出上限：限制内存增长
                if (remote.writer) {
                    await remote.writer.write(chunk);
                }
            }
        },
    })).catch(() => { /* 流已在内部处理 */ });

    return new Response(null, { status: 101, webSocket: client });
}

// ==================== ⑨ 可读 WebSocket 流 ====================
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

// ==================== ⑩ VLESS Header 解析（防越界） ====================
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

// ==================== ⑪ 智能TCP处理（终极优化版） ====================
async function handleTCPOutBoundOptimized(remote, address, port, initData, ws, wsSender, opts = {}) {
    if (remote._active) return;
    remote._active = true;

    const { connectionType, address: addressRemote } = opts;
    const startTime = Date.now();
    
    // 智能并发策略
    let raceDelay;
    if (!RACE_ENABLED || !proxyConfig.proxyHost) {
        raceDelay = null;
    } else {
        const elapsed = Date.now() - startTime;
        if (elapsed < 5000) {
            raceDelay = INITIAL_RACE_DELAY; // 前5秒0ms并发
        } else if (elapsed < 15000) {
            raceDelay = ACCEL_RACE_DELAY;   // 5-15秒加速并发
        } else {
            raceDelay = RACE_DELAY_MS;      // 稳定期标准并发
        }
    }

    let selected = null; // 'direct' | 'proxy'
    let directSock = null;
    let proxySock = null;
    let fallbackTimer = null;
    let closed = false;

    // 确保头尽早发送
    if (SEND_HEADER_EARLY) {
        wsSender.ensureHeaderSent();
    }

    function clearFallbackTimer() {
        if (fallbackTimer) { try { clearTimeout(fallbackTimer); } catch {} fallbackTimer = null; }
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

                // 首包尽早回头，减少客户端等待转圈
                if (first) {
                    if (SEND_HEADER_EARLY && !wsSender.headerSent && ws.readyState === WS_READY_STATE_OPEN) {
                        wsSender.push(new Uint8Array(0)); // 触发 header 发送
                    }
                    first = false;
                }

                // 远端→WS：根据智能策略发送
                wsSender.push(value);
            }
        } catch (e) {
            console.error('TCP reader error:', e);
        } finally {
            try { reader.releaseLock(); } catch {}
            if (!closed && selected === label) {
                // 断流优化：先刷队列再关闭 WS
                try { wsSender.flush(); } catch {}
                closed = true;
                safeCloseWebSocket(ws);
                wsSender.close();
            }
        }
    }

    // 启动直连 + 首包写入
    try {
        directSock = connect({ hostname: address, port });
        
        const w = directSock.writable.getWriter();
        await w.write(initData);
        w.releaseLock();
        
        // 建连后如需尽早让客户端确认连接，立即送回头（空帧触发 header）
        if (SEND_HEADER_EARLY && !wsSender.headerSent && ws.readyState === WS_READY_STATE_OPEN) {
            wsSender.push(new Uint8Array(0));
        }
    } catch (e) {
        console.error('Direct connection error:', e);
        // 如果直连失败，尝试直接启动代理
        if (RACE_ENABLED && proxyConfig.proxyHost) {
            try {
                proxySock = connect({
                    hostname: proxyConfig.proxyHost,
                    port: proxyConfig.proxyPort !== null ? proxyConfig.proxyPort : port,
                });
                const w2 = proxySock.writable.getWriter();
                await w2.write(initData);
                w2.releaseLock();
                if (SEND_HEADER_EARLY && !wsSender.headerSent && ws.readyState === WS_READY_STATE_OPEN) {
                    wsSender.push(new Uint8Array(0));
                }
                startReader(proxySock, 'proxy');
            } catch (proxyErr) {
                console.error('Proxy connection error:', proxyErr);
                safeCloseWebSocket(ws);
            }
        } else {
            safeCloseWebSocket(ws);
        }
        return;
    }
    
    startReader(directSock, 'direct');

    // 并发代理（媒体域名 0ms，其它域名延迟并发）
    if (raceDelay !== null) {
        const spawnProxy = async () => {
            if (selected || closed) return;
            try {
                proxySock = connect({
                    hostname: proxyConfig.proxyHost,
                    port: proxyConfig.proxyPort !== null ? proxyConfig.proxyPort : port,
                });
                const w2 = proxySock.writable.getWriter();
                await w2.write(initData);
                w2.releaseLock();
                if (SEND_HEADER_EARLY && !wsSender.headerSent && ws.readyState === WS_READY_STATE_OPEN) {
                    wsSender.push(new Uint8Array(0));
                }
                startReader(proxySock, 'proxy');
            } catch (e) {
                console.error('Proxy spawn error:', e);
            }
        };
        
        if (raceDelay <= 0) {
            spawnProxy();
        } else {
            fallbackTimer = setTimeout(spawnProxy, raceDelay);
        }
    }
}

// ==================== ⑫ DNS（UDP）处理 – DoH（零拷贝回写） ====================
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
                // 分帧发送长度与负载，避免合并拷贝
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

// ==================== ⑬ 辅助：WebSocket 安全关闭 ====================
const WS_READY_STATE_OPEN = 1;
const WS_READY_STATE_CLOSING = 2;
function safeCloseWebSocket(sock) {
    try {
        if (sock.readyState === WS_READY_STATE_OPEN || sock.readyState === WS_READY_STATE_CLOSING) {
            sock.close();
        }
    } catch { /* ignore */ }
}

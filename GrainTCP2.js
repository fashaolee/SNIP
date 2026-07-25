const CFG = { id: 'uuid', chunk: 64 * 1024, dnPack: 32 * 1024, dnTail: 512, dnQr: 4, upPack: 20 * 1024, maxED: 8 * 1024, concur: 1 };
export default { fetch: req => req.headers.get('Upgrade')?.toLowerCase() === 'websocket' ? ws(req) : new Response('Hello world!') };

// ==================== UUID 解析 ====================
const hex = c => (c > 64 ? c + 9 : c) & 0xF;
const idB = new Uint8Array(16), dec = new TextDecoder();
for (let i = 0, p = 0, c, h; i < 16; i++) { c = CFG.id.charCodeAt(p++); c === 45 && (c = CFG.id.charCodeAt(p++)); h = hex(c); c = CFG.id.charCodeAt(p++); c === 45 && (c = CFG.id.charCodeAt(p++)); idB[i] = h << 4 | hex(c); }
const [I0, I1, I2, I3, I4, I5, I6, I7, I8, I9, I10, I11, I12, I13, I14, I15] = idB;
const matchID = c => c[1] === I0 && c[2] === I1 && c[3] === I2 && c[4] === I3 && c[5] === I4 && c[6] === I5 && c[7] === I6 && c[8] === I7 && c[9] === I8 && c[10] === I9 && c[11] === I10 && c[12] === I11 && c[13] === I12 && c[14] === I13 && c[15] === I14 && c[16] === I15;

// ==================== 地址解析 ====================
const addr = (t, b) => t === 1 ? `${b[0]}.${b[1]}.${b[2]}.${b[3]}` : t === 3 ? dec.decode(b) : `[${Array.from({ length: 8 }, (_, i) => ((b[i * 2] << 8) | b[i * 2 + 1]).toString(16)).join(':')}]`;
const parseAddr = (b, o, t) => { const l = t === 3 ? b[o++] : t === 1 ? 4 : t === 4 ? 16 : null; if (l === null) return null; const n = o + l; return n > b.length ? null : { targetAddrBytes: b.subarray(o, n), dataOffset: n }; };
const relay = c => { if (c.length < 24 || !matchID(c)) return null; let o = 19 + c[17]; const p = (c[o] << 8) | c[o + 1]; let t = c[o + 2]; if (t !== 1) t += 1; const a = parseAddr(c, o + 3, t); return a ? { addrType: t, ...a, port: p } : null; };

// ==================== 连接工具 ====================
const sprout = (f, h, p, s = f.connect({ hostname: h, port: p })) => s.opened.then(() => s);
const raceSprout = (f, h, p) => { if (!f?.connect) return Promise.reject(new Error('connect unavailable')); if (CFG.concur <= 1) return sprout(f, h, p); const ts = Array(CFG.concur).fill().map(() => sprout(f, h, p)); return Promise.any(ts).then(w => { ts.forEach(t => t.then(s => s !== w && s.close(), () => { })); return w; }); };

// ==================== 正则 & 缓存 ====================
const HOST_PORT_RE = /^((?:[^@]+@)?(?:\[[^\]]+\]|[^:\[\]@]+))(?::(\d+))?$/;
const IPV4_RE = /^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$/;
const IPV6_BRACKET_RE = /^\[[0-9a-fA-F:]+\]$/;
const SK_CACHE = new Map();

// ==================== getSKJson: 解析 s/g/h/gh 参数 ====================
// s/g 支持: ipv4:port, [ipv6]:port, user:pass@ipv4:port, user:pass@[ipv6]:port, url:port, user:pass@url:port
// h/gh 支持: ipv4:port, [ipv6]:port
function getSKJson(path, modes) {
    const ck = `${path}|${modes.join(',')}`;
    const cached = SK_CACHE.get(ck);
    if (cached) return cached;
    try {
        const m = path.match(HOST_PORT_RE);
        if (!m) return null;
        const hostPortPart = m[1];
        const explicitPort = m[2];
        let user = null, pass = null, host = '';
        if (hostPortPart.includes('@')) {
            const atIdx = hostPortPart.lastIndexOf('@');
            const cred = hostPortPart.substring(0, atIdx);
            host = hostPortPart.substring(atIdx + 1);
            const colonIdx = cred.indexOf(':');
            user = colonIdx >= 0 ? cred.substring(0, colonIdx) : cred;
            pass = colonIdx >= 0 ? cred.substring(colonIdx + 1) : null;
        } else {
            host = hostPortPart;
        }
        const port = explicitPort ? parseInt(explicitPort, 10) : 443;
        if (isNaN(port) || port < 1 || port > 65535) return null;
        // 根据模式验证 host
        if (modes.includes('h') || modes.includes('gh')) {
            if (!IPV4_RE.test(host) && !IPV6_BRACKET_RE.test(host)) return null;
        } else if (modes.includes('s') || modes.includes('g')) {
            const bare = host.replace(/^\[/, '').replace(/\]$/, '');
            if (!IPV4_RE.test(bare) && !/^[0-9a-fA-F:]+$/.test(bare) && !/^[\w.-]+$/.test(host.replace(/^\[|\]$/g, ''))) return null;
        }
        const result = { user, pass, host, port };
        SK_CACHE.set(ck, result);
        return result;
    } catch { return null; }
}

// ==================== parseHostPort: 解析 p 参数 ====================
// p 支持: ipv4, ipv4:port, [ipv6], [ipv6]:port, url, url:port
function parseHostPort(input) {
    const m = input.match(HOST_PORT_RE);
    if (!m) return null;
    let host = m[1];
    const port = m[2] ? parseInt(m[2], 10) : 0; // 0 表示使用目标端口
    if (isNaN(port) || port > 65535) return null;
    if (host.startsWith('[') && host.endsWith(']')) host = host.slice(1, -1);
    if (!IPV4_RE.test(host) && !/^[0-9a-fA-F:]+$/.test(host) && !/^(?!:\/\/)([a-zA-Z0-9-_]+\.)*[a-zA-Z0-9][a-zA-Z0-9-_]+\.[a-zA-Z]{2,}$/.test(host)) return null;
    return { host, port };
}

// ==================== 回退顺序 ====================
const orderCache = { p: ['d', 'p'], s: ['d', 's'], g: ['s'], h: ['d', 'h'], gh: ['h'], default: ['d'] };
const getOrder = mode => orderCache[mode] || orderCache['default'];

// ==================== SOCKS5 连接 ====================
async function sConnect(f, targetHost, targetPort, skJson) {
    const sock = await raceSprout(f, skJson.host, skJson.port);
    const w = sock.writable.getWriter();
    const r = sock.readable.getReader();
    // 握手
    await w.write(new Uint8Array([5, 2, 0, 2]));
    const authResp = (await r.read()).value;
    if (authResp[1] === 2 && skJson.user) {
        const ub = new TextEncoder().encode(skJson.user);
        const pb = new TextEncoder().encode(skJson.pass);
        await w.write(new Uint8Array([1, ub.length, ...ub, pb.length, ...pb]));
        await r.read();
    }
    // 去掉 IPv6 方括号
    let host = targetHost;
    if (host.startsWith('[') && host.endsWith(']')) host = host.slice(1, -1);
    const db = new TextEncoder().encode(host);
    await w.write(new Uint8Array([5, 1, 0, 3, db.length, ...db, targetPort >> 8, targetPort & 0xff]));
    await r.read();
    w.releaseLock();
    r.releaseLock();
    return sock;
}

// ==================== HTTP CONNECT 连接 ====================
async function httpConnect(f, targetHost, targetPort, skJson) {
    const sock = await raceSprout(f, skJson.host, skJson.port);
    // 去掉 IPv6 方括号用于 CONNECT 请求
    let host = targetHost;
    if (host.startsWith('[') && host.endsWith(']')) host = host.slice(1, -1);
    const headers = [
        `CONNECT ${host}:${targetPort} HTTP/1.1`,
        `Host: ${host}:${targetPort}`
    ];
    if (skJson.user && skJson.pass) {
        headers.push(`Proxy-Authorization: Basic ${btoa(`${skJson.user}:${skJson.pass}`)}`);
    }
    headers.push('', '');
    const reqStr = headers.join('\r\n');
    const w = sock.writable.getWriter();
    await w.write(new TextEncoder().encode(reqStr));
    w.releaseLock();
    // 读取响应
    const r = sock.readable.getReader();
    let buf = new Uint8Array(0);
    let connected = false;
    try {
        for (;;) {
            const { value, done } = await r.read();
            if (done) throw new Error('HTTP代理连接中断');
            const nb = new Uint8Array(buf.length + value.length);
            nb.set(buf); nb.set(value, buf.length); buf = nb;
            const txt = new TextDecoder().decode(buf);
            const endIdx = txt.indexOf('\r\n\r\n');
            if (endIdx >= 0) {
                const head = txt.substring(0, endIdx);
                if (head.startsWith('HTTP/1.1 200') || head.startsWith('HTTP/1.0 200')) {
                    connected = true;
                    // 处理响应头后的残留数据
                    const bodyStart = endIdx + 4;
                    if (bodyStart < buf.length) {
                        const remaining = buf.slice(bodyStart);
                        const { readable, writable } = new TransformStream();
                        new ReadableStream({ start: c => c.enqueue(remaining) }).pipeTo(writable).catch(() => { });
                        // @ts-ignore
                        sock.readable = readable;
                    }
                } else {
                    throw new Error(`HTTP代理失败: ${head.split('\r\n')[0]}`);
                }
                break;
            }
        }
    } finally { r.releaseLock(); }
    if (!connected) throw new Error('HTTP代理未建立连接');
    return sock;
}

// ==================== 下行数据队列 ====================
const mkK = (cap, cpy = 0) => {
    let q = [], h = 0, b = 0, buf = null;
    const e = () => h >= q.length, trim = () => { h > 32 && h * 2 >= q.length && (q = q.slice(h), h = 0); };
    const take = () => { if (e()) return null; const d = q[h]; q[h++] = undefined; b -= d.byteLength; trim(); return d; };
    const sow = d => { const n = d?.byteLength || 0; return !n || (q.push(d), b += n, 1); };
    const pack = d => {
        d ||= take(); if (!d || e()) return [d, 0];
        let n = d.byteLength, j = h; while (j < q.length) { const x = q[j], nn = n + x.byteLength; if (nn > cap) break; n = nn; j++; }
        if (j === h) return [d, 0]; const out = buf ||= new Uint8Array(cap); out.set(d);
        for (let o = d.byteLength; h < j;) { const x = q[h]; q[h++] = undefined; b -= x.byteLength; out.set(x, o); o += x.byteLength; }
        trim(); const u = out.subarray(0, n); return [cpy ? u.slice() : u, 1];
    };
    return { e, get b() { return b; }, clear: () => { q = []; h = 0; b = 0; }, take, sow, pack };
};
const mkQ = cap => { const k = mkK(cap); return { get empty() { return k.e(); }, clear: k.clear, sow: k.sow, bundle: d => k.pack(d) }; };
const mkDn = w => {
    const cap = CFG.dnPack, tail = CFG.dnTail, low = Math.max(4096, tail * 12), k = mkK(cap, 1);
    let tp = 0, gen = 0, qk = 0, qr = 0;
    const reap = () => { tp && clearTimeout(tp); tp = 0; qr = 0; for (;;) { const [u] = k.pack(); if (!u) break; w.send(u); } };
    const ripen = () => {
        if (k.e() || tp) return; if (k.b >= cap || cap - k.b < tail) return reap();
        tp = setTimeout(() => {
            tp = 0; if (k.e()) return; if (k.b >= cap || cap - k.b < tail) return reap();
            if (qr < CFG.dnQr && (gen !== qk || k.b < low)) { qr++; qk = gen; return ripen(); } reap();
        }, 1);
    };
    return {
        send(u) {
            let o = 0, n = u?.byteLength || 0; if (!n) return;
            while (o < n) { const m = Math.min(cap - k.b, n - o); if (!m) { reap(); continue; } k.sow(o || m !== n ? u.subarray(o, o + m) : u); gen++; o += m; if (k.b >= cap || cap - k.b < tail) reap(); else ripen(); }
        }, reap
    };
};

// ==================== 下行读取 ====================
const mill = async (rd, w) => {
    const r = rd.getReader({ mode: 'byob' }), tx = mkDn(w);
    let buf = new ArrayBuffer(CFG.chunk);
    try {
        for (;;) {
            const { done, value: v } = await r.read(new Uint8Array(buf, 0, CFG.chunk));
            if (done) break;
            if (!v?.byteLength) continue;
            if (v.byteLength >= (CFG.chunk >> 1)) tx.reap(), w.send(v), buf = new ArrayBuffer(CFG.chunk);
            else tx.send(v.slice()), buf = v.buffer;
        }
        tx.reap();
    } catch { } finally { try { tx.reap(); } catch { } try { r.releaseLock(); } catch { } }
};

// ==================== 主 WebSocket 处理 ====================
const ws = async req => {
    // --- URL 解析：提取模式参数 ---
    let mode = 'd', skJson = null, pParsed = null;
    try {
        const u = new URL(req.url);
        if (u.pathname.includes('%3F')) {
            const d = decodeURIComponent(u.pathname);
            const qi = d.indexOf('?');
            if (qi >= 0) { u.search = d.substring(qi); u.pathname = d.substring(0, qi); }
        }
        const sParam = u.pathname.split('/s=')[1];
        if (sParam) { mode = 's'; skJson = getSKJson(sParam, ['s', 'g']); }
        else {
            const gParam = u.pathname.split('/g=')[1];
            if (gParam) { mode = 'g'; skJson = getSKJson(gParam, ['s', 'g']); }
            else {
                const pParam = u.pathname.split('/p=')[1];
                if (pParam) { mode = 'p'; pParsed = parseHostPort(pParam); }
                else {
                    const hParam = u.pathname.split('/h=')[1];
                    if (hParam) { mode = 'h'; skJson = getSKJson(hParam, ['h', 'gh']); }
                    else {
                        const ghParam = u.pathname.split('/gh=')[1];
                        if (ghParam) { mode = 'gh'; skJson = getSKJson(ghParam, ['h', 'gh']); }
                    }
                }
            }
        }
    } catch { }

    const [client, server] = Object.values(new WebSocketPair());
    server.accept({ allowHalfOpen: true });
    server.binaryType = 'arraybuffer';
    const fetcher = req.fetcher;

    const edStr = req.headers.get('sec-websocket-protocol');
    const ed = edStr && edStr.length <= CFG.maxED * 4 / 3 + 4 ? /** @type {*} */ (Uint8Array).fromBase64(edStr, { alphabet: 'base64url' }) : null;
    let curW = null, sock = null, closed = false, busy = false;

    const uq = mkQ(CFG.upPack);
    const wither = () => { if (closed) return; closed = true; uq.clear(); try { curW?.releaseLock(); } catch { } try { sock?.close(); } catch { } try { server.close(); } catch { } };
    const toU8 = d => d instanceof Uint8Array ? d : ArrayBuffer.isView(d) ? new Uint8Array(d.buffer, d.byteOffset, d.byteLength) : new Uint8Array(d);
    const sow = d => { const u = toU8(d), n = u.byteLength; if (!n) return 1; if (uq.sow(u)) return 1; wither(); return 0; };

    // --- 连接工厂：根据 mode 选择连接方式，支持回退 ---
    const connector = async (host, port) => {
        const methods = getOrder(mode);
        let lastErr = null;
        for (const method of methods) {
            try {
                if (method === 'd') return await raceSprout(fetcher, host, port);
                if ((method === 's' || method === 'g') && skJson) return await sConnect(fetcher, host, port, skJson);
                if (method === 'p' && pParsed) {
                    const pHost = pParsed.host;
                    const pPort = pParsed.port || port;
                    return await raceSprout(fetcher, pHost, pPort);
                }
                if ((method === 'h' || method === 'gh') && skJson) return await httpConnect(fetcher, host, port, skJson);
            } catch (e) { lastErr = e; }
        }
        throw lastErr || new Error('all methods failed');
    };

    // --- 上行数据处理 ---
    const thresh = async () => {
        if (busy || closed) return;
        busy = true;
        try {
            for (;;) {
                if (closed) break;
                if (!sock) {
                    const [d] = uq.bundle();
                    if (!d) break;
                    const r = relay(d);
                    if (!r) throw wither();
                    server.send(new Uint8Array([d[0], 0]));
                    const host = addr(r.addrType, r.targetAddrBytes);
                    const port = r.port;
                    const payload = d.subarray(r.dataOffset);
                    sock = await connector(host, port);
                    if (!sock) throw wither();
                    curW = sock.writable.getWriter();
                    const [first] = uq.bundle(payload);
                    first?.byteLength && await curW.write(first);
                    mill(sock.readable, server).finally(() => wither());
                    continue;
                }
                const [d] = uq.bundle();
                if (!d) break;
                await curW.write(d);
            }
        } catch { wither(); } finally { busy = false; !uq.empty && !closed && thresh(); }
    };

    if (ed && sow(ed)) thresh();
    server.addEventListener('message', e => { closed || (sow(e.data) && thresh()); });
    server.addEventListener('close', () => wither());
    server.addEventListener('error', () => wither());

    return new Response(null, { status: 101, webSocket: client, headers: { 'Sec-WebSocket-Extensions': '' } });
};

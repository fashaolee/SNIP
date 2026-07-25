const CFG = { id: 'uuid', chunk: 64 * 1024, dnPack: 32 * 1024, dnTail: 512, dnQr: 4, upPack: 20 * 1024, maxED: 8 * 1024, concur: 1 };
export default { fetch: req => req.headers.get('Upgrade')?.toLowerCase() === 'websocket' ? ws(req) : new Response('Hello world!') };

// UUID 解析
const hex = c => (c > 64 ? c + 9 : c) & 0xF;
const idB = new Uint8Array(16), dec = new TextDecoder();
{
    for (let i = 0, p = 0, c, h; i < 16; i++) {
        c = CFG.id.charCodeAt(p++);
        c === 45 && (c = CFG.id.charCodeAt(p++));
        h = hex(c);
        c = CFG.id.charCodeAt(p++);
        c === 45 && (c = CFG.id.charCodeAt(p++));
        idB[i] = h << 4 | hex(c);
    }
}
const [I0, I1, I2, I3, I4, I5, I6, I7, I8, I9, I10, I11, I12, I13, I14, I15] = idB;
const matchID = c =>
    c[1] === I0 && c[2] === I1 && c[3] === I2 && c[4] === I3 && c[5] === I4 &&
    c[6] === I5 && c[7] === I6 && c[8] === I7 && c[9] === I8 && c[10] === I9 &&
    c[11] === I10 && c[12] === I11 && c[13] === I12 && c[14] === I13 && c[15] === I14 && c[16] === I15;

const addr = (t, b) => t === 1 ? `${b[0]}.${b[1]}.${b[2]}.${b[3]}` : t === 3 ? dec.decode(b) : `[${Array.from({ length: 8 }, (_, i) => ((b[i * 2] << 8) | b[i * 2 + 1]).toString(16)).join(':')}]`;
const sprout = (f, h, p, s = f.connect({ hostname: h, port: p })) => s.opened.then(() => s);
const raceSprout = (f, h, p) => {
    if (!f?.connect) return Promise.reject(new Error('connect unavailable'));
    if (CFG.concur <= 1) return sprout(f, h, p);
    const ts = Array(CFG.concur).fill().map(() => sprout(f, h, p));
    return Promise.any(ts).then(w => {
        ts.forEach(t => t.then(s => s !== w && s.close(), () => {}));
        return w;
    });
};
const parseAddr = (b, o, t) => {
    const l = t === 3 ? b[o++] : t === 1 ? 4 : t === 4 ? 16 : null;
    if (l === null) return null;
    const n = o + l;
    return n > b.length ? null : { targetAddrBytes: b.subarray(o, n), dataOffset: n };
};
const relay = c => {
    if (c.length < 24 || !matchID(c)) return null;
    let o = 19 + c[17];
    const p = (c[o] << 8) | c[o + 1];
    let t = c[o + 2];
    if (t !== 1) t += 1;
    const a = parseAddr(c, o + 3, t);
    return a ? { addrType: t, ...a, port: p } : null;
};

// 数据包队列
const mkK = (cap, cpy = 0) => {
    let q = [], h = 0, b = 0, buf = null;
    const e = () => h >= q.length,
          trim = () => { if (h > 32 && h * 2 >= q.length) { q = q.slice(h); h = 0; } },
          clear = () => { q = []; h = 0; b = 0; },
          take = () => { if (e()) return null; const d = q[h]; q[h++] = undefined; b -= d.byteLength; trim(); return d; },
          sow = d => { const n = d?.byteLength || 0; return !n || (q.push(d), b += n, 1); },
          pack = d => {
              d ||= take(); if (!d || e()) return [d, 0];
              let n = d.byteLength, j = h;
              while (j < q.length) { const x = q[j], nn = n + x.byteLength; if (nn > cap) break; n = nn; j++; }
              if (j === h) return [d, 0];
              const out = buf ||= new Uint8Array(cap); out.set(d);
              for (let o = d.byteLength; h < j;) { const x = q[h]; q[h++] = undefined; b -= x.byteLength; out.set(x, o); o += x.byteLength; }
              trim();
              const u = out.subarray(0, n);
              return [cpy ? u.slice() : u, 1];
          };
    return { e, get b() { return b; }, clear, take, sow, pack };
};
const mkQ = cap => {
    const k = mkK(cap);
    return { get empty() { return k.e(); }, clear: k.clear, sow: k.sow, bundle: d => k.pack(d) };
};
const mkDn = w => {
    const cap = CFG.dnPack, tail = CFG.dnTail, low = Math.max(4096, tail * 12), k = mkK(cap, 1);
    let tp = 0, gen = 0, qk = 0, qr = 0;
    const reap = () => {
        tp && clearTimeout(tp); tp = 0; qr = 0;
        for (;;) { const [u] = k.pack(); if (!u) break; w.send(u); }
    };
    const ripen = () => {
        if (k.e() || tp) return;
        if (k.b >= cap || cap - k.b < tail) return reap();
        tp = setTimeout(() => {
            tp = 0;
            if (k.e()) return;
            if (k.b >= cap || cap - k.b < tail) return reap();
            if (qr < CFG.dnQr && (gen !== qk || k.b < low)) { qr++; qk = gen; return ripen(); }
            reap();
        }, 1);
    };
    return {
        send(u) {
            let o = 0, n = u?.byteLength || 0;
            if (!n) return;
            while (o < n) {
                const m = Math.min(cap - k.b, n - o);
                if (!m) { reap(); continue; }
                k.sow(o || m !== n ? u.subarray(o, o + m) : u);
                gen++;
                o += m;
                if (k.b >= cap || cap - k.b < tail) reap();
                else ripen();
            }
        },
        reap
    };
};
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
    } catch {} finally {
        try { tx.reap(); } catch {}
        try { r.releaseLock(); } catch {}
    }
};

// ---------- 新增：代理模式解析 ----------
const IPV4_REGEX = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
const IPV6_SHORT_REGEX = /^\[[0-9a-fA-F:]+\]$/; // 带方括号的 IPv6
const HOST_PORT_REGEX = /^((?:[^@]+@)?(?:\[.*\]|[^:]+))(?::(\d+))?$/;

const SK_CACHE = new Map();
function getSKJson(path, modes) {
    const key = `${path}|${modes[0]}`; // 简单区分模式组
    const cached = SK_CACHE.get(key);
    if (cached) return cached;
    try {
        const match = path.match(HOST_PORT_REGEX);
        if (!match) return null;
        const hostPortPart = match[1], portStr = match[2];
        if (!portStr) return null; // s/g/h/gh 必须有端口
        const port = parseInt(portStr, 10);
        if (isNaN(port) || port < 1 || port > 65535) return null;

        let user = null, pass = null, host = hostPortPart;
        if (hostPortPart.includes('@')) {
            const [cred, addr] = hostPortPart.split('@');
            [user, pass] = cred.split(':');
            host = addr;
        }

        // 去掉 IPv6 方括号
        host = host.replace(/^\[(.*)\]$/, '$1');

        // 根据模式验证格式
        if (modes.includes('s') || modes.includes('g')) {
            // s/g：支持 IPv4, IPv6, 域名
            if (!IPV4_REGEX.test(host) && !/^[a-fA-F0-9:]+$/.test(host) && !/^[\w.-]+$/.test(host)) return null;
        } else if (modes.includes('h') || modes.includes('gh')) {
            // h/gh：仅支持 IPv4 或 IPv6
            if (!IPV4_REGEX.test(host) && !/^[a-fA-F0-9:]+$/.test(host)) return null;
        } else {
            return null;
        }

        const result = { user, pass, host, port };
        SK_CACHE.set(key, result);
        return result;
    } catch { return null; }
}

function parsePHost(input, defaultPort) {
    const match = input.match(/^(\[.*\]|[^:]+)(?::(\d+))?$/);
    if (!match) return null;
    let host = match[1], port = match[2] ? parseInt(match[2], 10) : defaultPort;
    // 去掉 IPv6 方括号
    host = host.replace(/^\[(.*)\]$/, '$1');
    // 简单校验
    if (!/^[a-zA-Z0-9.:-]+$/.test(host)) return null;
    return { host, port };
}

// SOCKS5 连接
async function sConnect(fetcher, targetHost, targetPort, skJson) {
    const sock = fetcher.connect({ hostname: skJson.host, port: skJson.port });
    await sock.opened;
    const writer = sock.writable.getWriter();
    const reader = sock.readable.getReader();
    try {
        // 协商认证
        await writer.write(new Uint8Array([5, 2, 0, 2]));
        const auth = (await reader.read()).value;
        if (auth[1] === 2 && skJson.user) {
            const userBytes = new TextEncoder().encode(skJson.user);
            const passBytes = new TextEncoder().encode(skJson.pass);
            await writer.write(new Uint8Array([1, userBytes.length, ...userBytes, passBytes.length, ...passBytes]));
            await reader.read();
        }
        // 建立到目标的连接
        const domain = new TextEncoder().encode(targetHost);
        await writer.write(new Uint8Array([5, 1, 0, 3, domain.length, ...domain, targetPort >> 8, targetPort & 0xff]));
        const resp = (await reader.read()).value;
        if (resp[1] !== 0) throw new Error(`SOCKS5 connection refused: ${resp[1]}`);
    } finally {
        writer.releaseLock();
        reader.releaseLock();
    }
    return sock;
}

// HTTP CONNECT 代理连接
async function httpConnect(fetcher, addressRemote, portRemote, skJson) {
    const { user, pass, host, port } = skJson;
    const sock = fetcher.connect({ hostname: host, port: port });
    await sock.opened;

    const writer = sock.writable.getWriter();
    const reader = sock.readable.getReader();
    try {
        // 构造并发送 CONNECT 请求
        const headers = [
            `CONNECT ${addressRemote}:${portRemote} HTTP/1.1`,
            `Host: ${addressRemote}:${portRemote}`
        ];
        if (user && pass) {
            const basic = btoa(`${user}:${pass}`);
            headers.push(`Proxy-Authorization: Basic ${basic}`);
        }
        headers.push('', ''); // 末尾空行
        await writer.write(new TextEncoder().encode(headers.join('\r\n')));
        writer.releaseLock();

        // 读取响应头
        let buffer = new Uint8Array(0);
        let connected = false;
        while (true) {
            const { value, done } = await reader.read();
            if (done) throw new Error('HTTP proxy disconnected');
            const newBuf = new Uint8Array(buffer.length + value.length);
            newBuf.set(buffer); newBuf.set(value, buffer.length);
            buffer = newBuf;
            const text = new TextDecoder().decode(buffer);
            const end = text.indexOf('\r\n\r\n');
            if (end !== -1) {
                const header = text.substring(0, end + 4);
                if (header.startsWith('HTTP/1.1 200') || header.startsWith('HTTP/1.0 200')) {
                    connected = true;
                    // 剩余数据重新推回流
                    if (buffer.length > end + 4) {
                        const leftover = buffer.subarray(end + 4);
                        const { readable, writable } = new TransformStream();
                        const leftoverStream = new ReadableStream({ start(c) { c.enqueue(leftover); c.close(); } });
                        leftoverStream.pipeTo(writable).catch(() => {});
                        // @ts-ignore
                        sock.readable = readable;
                    }
                } else {
                    throw new Error(`HTTP proxy error: ${header.split('\r\n')[0]}`);
                }
                break;
            }
        }
        if (!connected) throw new Error('HTTP proxy connection not established');
    } finally {
        reader.releaseLock();
        if (!writer.locked) writer.releaseLock();
    }
    return sock;
}

// WebSocket 主处理函数
async function ws(req) {
    // 解析 URL 获取代理模式
    const u = new URL(req.url);
    if (u.pathname.includes('%3F')) {
        const decoded = decodeURIComponent(u.pathname);
        const qi = decoded.indexOf('?');
        if (qi !== -1) { u.search = decoded.substring(qi); u.pathname = decoded.substring(0, qi); }
    }

    let mode = 'd';
    let proxyData = {};
    {
        const sParam = u.pathname.split('/s=')[1];
        if (sParam) { mode = 's'; proxyData.skJson = getSKJson(sParam, ['s', 'g']); }
        else {
            const gParam = u.pathname.split('/g=')[1];
            if (gParam) { mode = 'g'; proxyData.skJson = getSKJson(gParam, ['s', 'g']); }
            else {
                const pParam = u.pathname.split('/p=')[1];
                if (pParam) { mode = 'p'; proxyData.pParam = pParam; }
                else {
                    const hParam = u.pathname.split('/h=')[1];
                    if (hParam) { mode = 'h'; proxyData.skJson = getSKJson(hParam, ['h', 'gh']); }
                    else {
                        const ghParam = u.pathname.split('/gh=')[1];
                        if (ghParam) { mode = 'gh'; proxyData.skJson = getSKJson(ghParam, ['h', 'gh']); }
                    }
                }
            }
        }
    }
    Object.assign(req, { mode, proxyData });

    const [client, server] = Object.values(new WebSocketPair());
    server.accept({ allowHalfOpen: true });
    server.binaryType = 'arraybuffer';
    const fetcher = req.fetcher;

    const edStr = req.headers.get('sec-websocket-protocol');
    const ed = edStr && edStr.length <= CFG.maxED * 4 / 3 + 4 ? Uint8Array.fromBase64(edStr, { alphabet: 'base64url' }) : null;

    let curW = null, sock = null, closed = false, busy = false;
    const uq = mkQ(CFG.upPack);
    const wither = () => {
        if (closed) return;
        closed = true;
        uq.clear();
        try { curW?.releaseLock(); } catch {}
        try { sock?.close(); } catch {}
        try { server.close(); } catch {}
    };
    const toU8 = d => d instanceof Uint8Array ? d : ArrayBuffer.isView(d) ? new Uint8Array(d.buffer, d.byteOffset, d.byteLength) : new Uint8Array(d);
    const sow = d => {
        const u = toU8(d), n = u.byteLength;
        if (!n) return 1;
        if (uq.sow(u)) return 1;
        wither(); return 0;
    };

    const thresh = async () => {
        if (busy || closed) return;
        busy = true;
        try {
            for (;;) {
                if (closed) break;
                if (!sock) {
                    const [d] = uq.bundle(); if (!d) break;
                    const r = relay(d); if (!r) { wither(); break; }
                    server.send(new Uint8Array([d[0], 0]));
                    const host = addr(r.addrType, r.targetAddrBytes), port = r.port;
                    const payload = d.subarray(r.dataOffset);

                    // 根据模式选择连接方式
                    let sockPromise;
                    if (req.mode === 'p' && req.proxyData.pParam) {
                        const pInfo = parsePHost(req.proxyData.pParam, port);
                        if (!pInfo) { wither(); break; }
                        sockPromise = raceSprout(fetcher, pInfo.host, pInfo.port);
                    } else if ((req.mode === 's' || req.mode === 'g') && req.proxyData.skJson) {
                        sockPromise = sConnect(fetcher, host, port, req.proxyData.skJson);
                    } else if ((req.mode === 'h' || req.mode === 'gh') && req.proxyData.skJson) {
                        sockPromise = httpConnect(fetcher, host, port, req.proxyData.skJson);
                    } else {
                        sockPromise = raceSprout(fetcher, host, port);
                    }

                    sock = await sockPromise;
                    if (!sock) { wither(); break; }

                    curW = sock.writable.getWriter();
                    const [first] = uq.bundle(payload);
                    first?.byteLength && await curW.write(first);
                    mill(sock.readable, server).finally(() => wither());
                    continue;
                }
                const [d] = uq.bundle(); if (!d) break;
                await curW.write(d);
            }
        } catch { wither(); } finally {
            busy = false;
            if (!uq.empty && !closed) thresh();
        }
    };

    if (ed && sow(ed)) thresh();
    server.addEventListener('message', e => { if (!closed) { sow(e.data) && thresh(); } });
    server.addEventListener('close', () => wither());
    server.addEventListener('error', () => wither());

    return new Response(null, { status: 101, webSocket: client, headers: { 'Sec-WebSocket-Extensions': '' } });
}

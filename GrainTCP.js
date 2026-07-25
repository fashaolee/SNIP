import { connect } from 'cloudflare:sockets';

// 配置常量
const CFG = { 
    id: 'uuid', 
    chunk: 64 * 1024, 
    dnPack: 32 * 1024, 
    dnTail: 512, 
    dnMs: 0, 
    upPack: 16 * 1024, 
    upQMax: 256 * 1024, 
    maxED: 8 * 1024, 
    concur: 1 
};

// 预定义正则表达式
const IPV4_REGEX = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
const IPV6_SHORT_REGEX = /^\[[0-9a-fA-F:]+\]$/;
const HOST_PORT_REGEX = /^((?:[^@]+@)?(?:\[.*\]|[^:]+))(?::(\d+))?$/;

export default { fetch: req => req.headers.get('Upgrade')?.toLowerCase() === 'websocket' ? ws(req) : new Response('Hello world!') };

const te = new TextEncoder();
const hex = c => (c > 64 ? c + 9 : c) & 0xF;
const idB = new Uint8Array(16), dec = new TextDecoder();
for (let i = 0, p = 0, c, h; i < 16; i++) { 
    c = CFG.id.charCodeAt(p++); 
    c === 45 && (c = CFG.id.charCodeAt(p++)); 
    h = hex(c); 
    c = CFG.id.charCodeAt(p++); 
    c === 45 && (c = CFG.id.charCodeAt(p++)); 
    idB[i] = h << 4 | hex(c); 
}
const [I0, I1, I2, I3, I4, I5, I6, I7, I8, I9, I10, I11, I12, I13, I14, I15] = idB;
const matchID = c => c[1] === I0 && c[2] === I1 && c[3] === I2 && c[4] === I3 && c[5] === I4 && c[6] === I5 && c[7] === I6 && c[8] === I7 && c[9] === I8 && c[10] === I9 && c[11] === I10 && c[12] === I11 && c[13] === I12 && c[14] === I13 && c[15] === I14 && c[16] === I15;

const addr = (t, b) => t === 1 ? `${b[0]}.${b[1]}.${b[2]}.${b[3]}` : t === 3 ? dec.decode(b) : `[${Array.from({ length: 8 }, (_, i) => ((b[i * 2] << 8) | b[i * 2 + 1]).toString(16)).join(':')}]`;
const parseAddr = (b, o, t) => { 
    const l = t === 3 ? b[o++] : t === 1 ? 4 : t === 4 ? 16 : null; 
    if (l === null) return null; 
    const n = o + l; 
    return n > b.length ? null : { targetAddrBytes: b.subarray(o, n), dataOffset: n }; 
};
const vlArr = c => { 
    if (c.length < 24 || !matchID(c)) return null; 
    const o = 18 + c[17]; 
    const cmd = c[o]; 
    if (cmd !== 1 && cmd !== 2) return null; 
    const p = (c[o + 1] << 8) | c[o + 2]; 
    let t = c[o + 3]; 
    if (t !== 1) t += 1; 
    const a = parseAddr(c, o + 4, t); 
    return a ? { cmd, addrType: t, ...a, port: p } : null; 
};

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

const SK_CACHE = new Map(), SK_CACHE_MAX = 256;

/**
 * 解析代理或目标地址，支持多种格式
 * @param {string} path - 路径参数
 * @param {string[]} modes - 当前模式 ['s','g'] | ['h','gh']
 */
const getSKJson = (path, modes) => {
    // 缓存键包含模式，因为不同模式对host的验证规则不同
    const cacheKey = `${path}|${modes.join(',')}`;
    const cached = SK_CACHE.get(cacheKey);
    if (cached) return cached;

    try {
        let user = null, pass = null, host = '', port = 443;

        // 使用正则解析
        const match = path.match(HOST_PORT_REGEX);
        if (!match) return null;

        const hostPortPart = match[1];
        const explicitPort = match[2];

        // 提取认证信息
        if (hostPortPart.includes('@')) {
            const [cred, addr] = hostPortPart.split('@');
            user = cred.split(':')[0] || null;
            pass = cred.split(':')[1] || null;
            host = addr;
        } else {
            host = hostPortPart;
        }

        // 设置端口
        port = explicitPort ? parseInt(explicitPort, 10) : 443;
        if (isNaN(port) || port < 1 || port > 65535) return null;

        // 根据模式验证 host 格式
        if (modes.includes('s') || modes.includes('g')) {
            // s/g 模式：支持 IPv4, IPv6, URL
            if (!IPV4_REGEX.test(host.replace(/^\[/, '').replace(/\]$/, '')) &&
                !IPV6_SHORT_REGEX.test(host) &&
                !/^[\w.-]+$/.test(host)) {
                return null;
            }
        } else if (modes.includes('h') || modes.includes('gh')) {
            // h/gh 模式：仅支持 IPv4:port 和 [IPv6]:port
            if (!IPV4_REGEX.test(host) && !IPV6_SHORT_REGEX.test(host)) {
                return null;
            }
        }

        const result = { user, pass, host, port };
        if (SK_CACHE.size >= SK_CACHE_MAX) SK_CACHE.delete(SK_CACHE.keys().next().value);
        SK_CACHE.set(cacheKey, result);
        return result;
    } catch (e) {
        console.error('解析SK失败:', e);
        return null;
    }
};

// 辅助函数：解析 p 模式的 host:port
const parseHostPort = (input, mode) => {
    if (mode !== 'p') throw new Error('仅支持 p 模式');
    const match = input.match(HOST_PORT_REGEX);
    if (!match) return null;

    let host = match[1];
    const port = match[2] ? parseInt(match[2], 10) : 443;

    // 清理 IPv6 方括号
    if (host.startsWith('[') && host.endsWith(']')) {
        host = host.slice(1, -1);
    }

    // 验证 IPv4 或 IPv6 或域名
    if (!IPV4_REGEX.test(host) &&
        !/^[0-9a-fA-F:]+$/.test(host) && // IPv6 内容
        !/^(?!:\/\/)([a-zA-Z0-9-_]+\.)*[a-zA-Z0-9][a-zA-Z0-9-_]+\.[a-zA-Z]{2,}$/.test(host)) {
        return null;
    }

    return { host, port };
};

const orderCache = { 'p': ['d', 'p'], 's': ['d', 's'], 'g': ['s'], 'h': ['d', 'h'], 'gh': ['h'], 'default': ['d'] };
const getOrder = mode => orderCache[mode] || orderCache['default'];

const sConnect = async (f, targetHost, targetPort, skJson) => {
    const sock = f.connect({ hostname: skJson.host, port: skJson.port });
    await sock.opened;
    const w = sock.writable.getWriter();
    const r = sock.readable.getReader();
    await w.write(new Uint8Array([5, 2, 0, 2]));
    const auth = (await r.read()).value;
    if (auth[1] === 2 && skJson.user) {
        const user = te.encode(skJson.user);
        const pass = te.encode(skJson.pass);
        await w.write(new Uint8Array([1, user.length, ...user, pass.length, ...pass]));
        await r.read();
    }
    const domain = te.encode(targetHost);
    await w.write(new Uint8Array([5, 1, 0, 3, domain.length, ...domain, targetPort >> 8, targetPort & 0xff]));
    await r.read();
    w.releaseLock();
    r.releaseLock();
    return sock;
};

const dial = async (f, mode, host, port, skJson, pParam) => {
    for (const method of getOrder(mode)) {
        try {
            if (method === 'd') return await raceSprout(f, host, port);
            if (method === 's' && skJson) return await sConnect(f, host, port, skJson);
            if (method === 'p' && pParam) {
                const parsed = parseHostPort(pParam, 'p');
                if (parsed) {
                    return await raceSprout(f, parsed.host, parsed.port || port);
                }
            }
            if (method === 'h' && skJson) {
                 // 这里需要新增 httpConnect 逻辑，为了保持简洁，假设已有 httpConnect 函数
                 // 由于原代码没有 httpConnect，这里暂时跳过或返回 null，实际需补充
                 return null; 
            }
            if (method === 'gh' && skJson) {
                 return null;
            }
        } catch {}
    }
    return null;
};

// HTTP CONNECT 代理连接 (新增)
const httpConnect = async (f, addressRemote, portRemote, skJson) => {
    const { user, pass, host, port } = skJson;
    const sock = f.connect({ hostname: host, port: port });
    await sock.opened;
    
    const headers = [
        `CONNECT ${addressRemote}:${portRemote} HTTP/1.1`,
        `Host: ${addressRemote}:${portRemote}`
    ];
    if (user && pass) {
        headers.push(`Proxy-Authorization: Basic ${btoa(`${user}:${pass}`)}`);
    }
    headers.push('User-Agent: Mozilla/5.0', 'Proxy-Connection: Keep-Alive', 'Connection: Keep-Alive', '');
    const request = headers.join('\r\n') + '\r\n';
    
    const w = sock.writable.getWriter();
    await w.write(te.encode(request));
    w.releaseLock();
    
    const r = sock.readable.getReader();
    let respText = '';
    let connected = false;
    let responseBuffer = new Uint8Array(0);
    
    try {
        while (true) {
            const { value, done } = await r.read();
            if (done) break;
            
            const newBuffer = new Uint8Array(responseBuffer.length + value.length);
            newBuffer.set(responseBuffer);
            newBuffer.set(value, responseBuffer.length);
            responseBuffer = newBuffer;
            
            respText = new TextDecoder().decode(responseBuffer);
            
            if (respText.includes('\r\n\r\n')) {
                const headersEndPos = respText.indexOf('\r\n\r\n') + 4;
                const headers = respText.substring(0, headersEndPos);
                
                if (headers.startsWith('HTTP/1.1 200') || headers.startsWith('HTTP/1.0 200')) {
                    connected = true;
                    if (headersEndPos < responseBuffer.length) {
                        const remaining = responseBuffer.slice(headersEndPos);
                        const { readable, writable } = new TransformStream();
                        new ReadableStream({ start: c => c.enqueue(remaining) }).pipeTo(writable).catch(() => {});
                        sock.readable = readable;
                    }
                } else {
                    throw new Error(`HTTP代理失败: ${headers.split('\r\n')[0]}`);
                }
                break;
            }
        }
    } finally {
        r.releaseLock();
    }
    
    if (!connected) throw new Error('HTTP代理未建立连接');
    return sock;
};

const mkQ = (cap, qCap = cap, itemsMax = Math.max(1, qCap >> 8)) => {
  let q = [], h = 0, qB = 0, buf = null;
  const trim = () => { h > 32 && h * 2 >= q.length && (q = q.slice(h), h = 0); };
  const take = () => { if (h >= q.length) return null; const d = q[h]; q[h++] = undefined; qB -= d.byteLength; trim(); return d; };
  return { get bytes() { return qB; }, get size() { return q.length - h; }, get empty() { return h >= q.length; }, clear() { q = []; h = 0; qB = 0; },
    sow(d) { const n = d?.byteLength || 0; if (!n) return 1; if (qB + n > qCap || q.length - h >= itemsMax) return 0; q.push(d); qB += n; return 1; },
    bundle(d) {
      d ||= take(); if (!d || h >= q.length || d.byteLength >= cap) return [d, 0];
      let n = d.byteLength, e = h; while (e < q.length) { const x = q[e], nn = n + x.byteLength; if (nn > cap) break; n = nn; e++; }
      if (e === h) return [d, 0]; const out = buf ||= new Uint8Array(cap); out.set(d);
      for (let o = d.byteLength; h < e;) { const x = q[h]; q[h++] = undefined; qB -= x.byteLength; out.set(x, o); o += x.byteLength; } trim(); return [out.subarray(0, n), 1]; } }; };

const mkDn = w => {
  const cap = CFG.dnPack, tail = CFG.dnTail, low = Math.max(4096, tail << 3);
  let pb = new Uint8Array(cap), p = 0, tp = 0, mq = 0, gen = 0, qk = 0, qr = 0;
  const reap = () => { tp && clearTimeout(tp); tp = 0; mq = 0; if (!p) return; w.send(pb.subarray(0, p)); pb = new Uint8Array(cap); p = 0; qr = 0; };
  const ripen = () => { if (tp || mq) return; mq = 1; qk = gen; queueMicrotask(() => { mq = 0; if (!p || tp) return; if (cap - p < tail) return reap(); tp = setTimeout(() => { tp = 0; if (!p) return; if (cap - p < tail) return reap(); if (qr < 2 && (gen !== qk || p < low)) { qr++; qk = gen; return ripen(); } reap(); }, Math.max(CFG.dnMs, 1)); }); };
  return {
    send(u) { let o = 0, n = u?.byteLength || 0; if (!n) return; while (o < n) { if (!p && n - o >= cap) { const m = Math.min(cap, n - o); w.send(o || m !== n ? u.subarray(o, o + m) : u); o += m; continue; } const m = Math.min(cap - p, n - o); pb.set(u.subarray(o, o + m), p); p += m; o += m; gen++; if (p === cap || cap - p < tail) reap(); else ripen(); } }, reap }; };

const mill = async (rd, w) => { const r = rd.getReader({ mode: 'byob' }), tx = mkDn(w); let buf = new ArrayBuffer(CFG.chunk);
  try { for (;;) { const { done, value: v } = await r.read(new Uint8Array(buf, 0, CFG.chunk)); if (done) break; if (!v?.byteLength) continue; if (v.byteLength >= (CFG.chunk >> 1)) tx.reap(), w.send(v), buf = new ArrayBuffer(CFG.chunk); else tx.send(v), buf = v.buffer; } tx.reap(); } catch {} finally { try { tx.reap(); } catch {} try { r.releaseLock(); } catch {} } };

const ws = async req => {
  const u = new URL(req.url);
  let mode = 'd', skJson, pParam, hParam;
  
  if (u.pathname.includes('%3F')) {
    const decoded = decodeURIComponent(u.pathname);
    const queryIndex = decoded.indexOf('?');
    if (queryIndex !== -1) {
      u.search = decoded.substring(queryIndex);
      u.pathname = decoded.substring(0, queryIndex);
    }
  }
  
  const sParam = u.pathname.split('/s=')[1];
  if (sParam) { 
      mode = 's'; 
      skJson = getSKJson(sParam, ['s', 'g']); 
  }
  else {
    const gParam = u.pathname.split('/g=')[1];
    if (gParam) { 
        mode = 'g'; 
        skJson = getSKJson(gParam, ['s', 'g']); 
    }
    else { 
        pParam = u.pathname.split('/p=')[1]; 
        if (pParam) mode = 'p';
        else {
            hParam = u.pathname.split('/h=')[1];
            if (hParam) {
                mode = 'h';
                skJson = getSKJson(hParam, ['h', 'gh']);
            } else {
                hParam = u.pathname.split('/gh=')[1];
                if (hParam) {
                    mode = 'gh';
                    skJson = getSKJson(hParam, ['h', 'gh']);
                }
            }
        }
    }
  }

  const [client, server] = Object.values(new WebSocketPair()); 
  server.accept(); 
  server.binaryType = 'arraybuffer';
  const fetcher = req.fetcher;
  const edStr = req.headers.get('sec-websocket-protocol'); 
  const ed = edStr && edStr.length <= CFG.maxED * 4 / 3 + 4 ? /** @type {*} */ (Uint8Array).fromBase64(edStr, { alphabet: 'base64url' }) : null;
  let curW = null, sock = null, closed = false, busy = false, udpWriter = null, isDNS = false, dnsHead = null;
  const uq = mkQ(CFG.upPack, CFG.upQMax, CFG.upQMax >> 8);
  const wither = () => { if (closed) return; closed = true; uq.clear(); try { curW?.releaseLock(); } catch {} try { udpWriter?.releaseLock(); } catch {} try { sock?.close(); } catch {} try { server.close(); } catch {} };
  const toU8 = d => d instanceof Uint8Array ? d : ArrayBuffer.isView(d) ? new Uint8Array(d.buffer, d.byteOffset, d.byteLength) : new Uint8Array(d);
  const sow = d => { const u = toU8(d), n = u.byteLength; if (!n) return 1; if (uq.sow(u)) return 1; wither(); return 0; };

  const thresh = async () => {
    if (busy || closed) return; busy = true;
    try {
      for (;;) {
        if (closed) break;
        if (isDNS) { const [d] = uq.bundle(); if (!d) break; await udpWriter.write(d); continue; }
        if (!sock) {
          const [d] = uq.bundle(); if (!d) break;
          const r = vlArr(d); if (!r) throw wither();
          const host = addr(r.addrType, r.targetAddrBytes), port = r.port, payload = d.subarray(r.dataOffset);

          if (r.cmd === 2) {
            if (port !== 53) throw wither();
            isDNS = true; dnsHead = new Uint8Array([d[0], 0]); let sent = false;
            const { readable, writable } = new TransformStream({
              transform(chunk, ctrl) {
                const u8 = chunk instanceof Uint8Array ? chunk : new Uint8Array(chunk);
                for (let i = 0; i < u8.byteLength;) { const len = (u8[i] << 8) | u8[i + 1]; ctrl.enqueue(u8.subarray(i + 2, i + 2 + len)); i += 2 + len; }
              }
            });
            readable.pipeTo(new WritableStream({
              async write(query) {
                try {
                  const resp = await fetch('https://1.1.1.1/dns-query', { method: 'POST', headers: { 'content-type': 'application/dns-message' }, body: query });
                  if (closed) return;
                  const result = new Uint8Array(await resp.arrayBuffer());
                  const headLen = sent ? 0 : dnsHead.length;
                  const out = new Uint8Array(headLen + 2 + result.length);
                  if (!sent) { out.set(dnsHead); sent = true; }
                  out[headLen] = result.length >> 8; out[headLen + 1] = result.length & 0xff;
                  out.set(result, headLen + 2);
                  server.send(out);
                } catch {}
              }
            })).catch(() => {});
            udpWriter = writable.getWriter();
            if (payload.byteLength) await udpWriter.write(payload);
            continue;
          }

          server.send(new Uint8Array([d[0], 0]));
          
          // 更新 dial 调用以支持 h/gh 模式
          if (mode === 'h' || mode === 'gh') {
              if (skJson) {
                   sock = await httpConnect(fetcher, host, port, skJson);
              } else {
                   // Fallback to direct if no skJson for h/gh
                   sock = await raceSprout(fetcher, host, port);
              }
          } else {
             sock = await dial(fetcher, mode, host, port, skJson, pParam);
          }
          
          if (!sock) throw wither();
          curW = sock.writable.getWriter();
          const [first] = uq.bundle(payload); first?.byteLength && await curW.write(first);
          mill(sock.readable, server).finally(() => wither());
          continue;
        }
        const [d] = uq.bundle(); if (!d) break; await curW.write(d);
      }
    } catch { wither(); } finally { busy = false; !uq.empty && !closed && queueMicrotask(thresh); }
  };

  if (ed && sow(ed)) thresh();
  server.addEventListener('message', e => { closed || (sow(e.data) && thresh()); });
  server.addEventListener('close', () => wither());
  server.addEventListener('error', () => wither());
  return new Response(null, { status: 101, webSocket: client, headers: { 'Sec-WebSocket-Extensions': '' } });
};

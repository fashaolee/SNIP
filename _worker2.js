import { connect } from 'cloudflare:sockets';

// ==================== ① 基础配置 ====================
let userID = '20efc8d1-d2fa-4e2b-b4b3-773a918cd3ba'; // 请替换成你的 UUID
const DEFAULT_PROXY_STR = 'proxyip.us.cmliussss.net'; // 默认 proxyip（回退使用）

// 节点别名：T-SNIP-01、T-SNIP-02 ...
function nodeAlias(idx) {
  return `T-SNIP-${String(idx + 1).padStart(2, '0')}`;
}

// 订阅展示域名列表
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

// ==================== ② 工具函数 ====================
function parseProxyStr(input) {
  if (!input) return { proxyHost: '', proxyPort: null };
  const parts = String(input).trim().split(':');
  const host = (parts[0] || '').trim();
  let port = null;
  if (parts.length > 1) {
    const p = parseInt(parts[1].trim(), 10);
    if (!isNaN(p) && p > 0 && p <= 65535) port = p;
  }
  return { proxyHost: host, proxyPort: port };
}
const defaultProxyConfig = parseProxyStr(DEFAULT_PROXY_STR);

// 合并 ArrayBuffer/Uint8Array
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

function base64ToArrayBuffer(str) {
  if (!str) return { error: null };
  try {
    const b64 = str.replace(/-/g, '+').replace(/_/g, '/');
    const decoded = atob(b64);
    const u8 = Uint8Array.from(decoded, c => c.charCodeAt(0));
    return { earlyData: u8.buffer, error: null };
  } catch (e) {
    return { error: e };
  }
}

function extractProxyFromPath(pathname) {
  // 支持 /proxyip=host 或 /proxyip=host:port
  const m = /^\/proxyip=([^/]+)/i.exec(pathname);
  return m ? decodeURIComponent(m[1]) : null;
}

// UUID 校验
function isValidUUID(uuid) {
  const re = /^[0-9a-f]{8}-[0-9a-f]{4}-[4][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
  return re.test(uuid);
}
const byteToHex = [];
for (let i = 0; i < 256; ++i) byteToHex.push((i + 256).toString(16).slice(1));
function unsafeStringify(arr, off = 0) {
  return (
    byteToHex[arr[off + 0]] + byteToHex[arr[off + 1]] + byteToHex[arr[off + 2]] + byteToHex[arr[off + 3]] + '-' +
    byteToHex[arr[off + 4]] + byteToHex[arr[off + 5]] + '-' +
    byteToHex[arr[off + 6]] + byteToHex[arr[off + 7]] + '-' +
    byteToHex[arr[off + 8]] + byteToHex[arr[off + 9]] + '-' +
    byteToHex[arr[off + 10]] + byteToHex[arr[off + 11]] + byteToHex[arr[off + 12]] +
    byteToHex[arr[off + 13]] + byteToHex[arr[off + 14]] + byteToHex[arr[off + 15]]
  ).toLowerCase();
}
function stringify(arr, off = 0) {
  const uuid = unsafeStringify(arr, off);
  if (!isValidUUID(uuid)) throw TypeError('Stringified UUID is invalid');
  return uuid;
}

// ==================== ③ 订阅生成（path 带 /proxyip=...） ====================
function getVLESSConfig(uuid, host, selectedProxyStr) {
  const protocol = 'vless';
  const path = `/proxyip=${selectedProxyStr}`; // 路径直观显示当前 proxyip
  const params = new URLSearchParams({
    encryption: 'none',
    security: 'tls',
    sni: host,
    fp: 'chrome',
    type: 'ws',
    host: host,
    path: path,
  });

  const uris = preferredDomains.map((domain, i) => {
    return `${protocol}://${uuid}@${domain}:443?${params.toString()}#${nodeAlias(i)}`;
  });

  const txt = uris.join('\n');
  // URL-safe Base64
  return btoa(txt).replace(/\+/g, '-').replace(/\//g, '_');
}

// ==================== ④ 主入口 ====================
if (!isValidUUID(userID)) throw new Error('uuid is not valid');

export default {
  async fetch(request) {
    try {
      const url = new URL(request.url);
      const upgrade = request.headers.get('Upgrade');

      // 仅订阅链接支持 ?proxyip=xxx 覆盖（WS 实际使用以路径 /proxyip=... 为准）
      const qpProxyStr = url.searchParams.get('proxyip') || '';
      const qpProxy = parseProxyStr(qpProxyStr);
      const qpValid = !!qpProxy.proxyHost;

      // 路径 UUID（用于返回订阅）
      const pathUUID = url.pathname.length > 1 ? url.pathname.slice(1) : null;

      if (!upgrade || upgrade !== 'websocket') {
        // ---------- 非 WebSocket ----------
        // 展示默认/当前 proxyip 的提示页
        if (url.pathname === '/' || /^\/proxyip=/i.test(url.pathname)) {
          const showProxy = extractProxyFromPath(url.pathname) || DEFAULT_PROXY_STR;
          const text =
            `恭喜你快成功了！\n\n`;
          return new Response(text, { status: 200, headers: { 'Content-Type': 'text/plain;charset=utf-8' } });
        }

        // 返回订阅：/{uuid} 或 /{uuid}?proxyip=...
        if (pathUUID && pathUUID === userID) {
          const selected = qpValid ? qpProxyStr : DEFAULT_PROXY_STR;
          const cfg = getVLESSConfig(pathUUID, request.headers.get('Host'), selected);
          return new Response(cfg, { status: 200, headers: { 'Content-Type': 'text/plain;charset=utf-8' } });
        }

        return new Response('请填写正确的 UUID', {
          status: 400,
          headers: { 'Content-Type': 'text/plain;charset=utf-8' },
        });
      }

      // ---------- WebSocket ----------
      return await vlessOverWSHandler(request);
    } catch (e) {
      return new Response(e.toString(), {
        status: 500,
        headers: { 'Content-Type': 'text/plain;charset=utf-8' },
      });
    }
  },
};

// ==================== ⑤ WebSocket 处理（路径决定当前 proxyip） ====================
async function vlessOverWSHandler(request) {
  const pair = new WebSocketPair();
  const [client, server] = Object.values(pair);
  server.accept();

  // 解析路径中的 proxyip（动态），失败时稍后回退到默认 proxyip
  const url = new URL(request.url);
  const pathProxyStr = extractProxyFromPath(url.pathname);
  const currentProxy = pathProxyStr ? parseProxyStr(pathProxyStr) : { proxyHost: '', proxyPort: null };

  const earlyDataHeader = request.headers.get('sec-websocket-protocol') || '';
  const readableWS = makeReadableWebSocketStream(server, earlyDataHeader);

  let remote = { value: null };
  let udpWrite = null;
  let isDns = false;

  readableWS.pipeTo(new WritableStream({
    async write(chunk) {
      // DNS（UDP）阶段
      if (isDns && udpWrite) {
        udpWrite(chunk);
        return;
      }

      // 已建立的 TCP 隧道
      if (remote.value) {
        const w = remote.value.writable.getWriter();
        await w.write(chunk);
        w.releaseLock();
        return;
      }

      // 解析 VLESS 首部
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

      // 仅允许 53 端口的 UDP（DNS）
      if (isUDP) {
        if (portRemote === 53) {
          isDns = true;
        } else {
          throw new Error('UDP proxy only enable for DNS which is port 53');
        }
      }

      const vlessRespHeader = new Uint8Array([vlessVersion[0], 0]); // VLESS reply
      const payload = chunk.slice(rawDataIndex);

      // DNS（UDP）
      if (isDns) {
        const { write } = await handleUDPOutBound(server, vlessRespHeader);
        udpWrite = write;
        udpWrite(payload);
        return;
      }

      // TCP：直连 → 动态 proxyip → 默认 proxyip 的回退链路
      handleTCPOutBound(
        remote,
        addressRemote,
        portRemote,
        payload,
        server,
        vlessRespHeader,
        {
          currentProxy,
          defaultProxy: defaultProxyConfig,
        }
      );
    },
  })).catch(() => { /* 已在内部处理 */ });

  return new Response(null, { status: 101, webSocket: client });
}

// ==================== ⑥ 可读 WebSocket 流 ====================
function makeReadableWebSocketStream(ws, earlyDataHeader) {
  let cancelled = false;
  const { earlyData, error } = base64ToArrayBuffer(earlyDataHeader);
  if (error) console.warn('early‑data decode error:', error);

  return new ReadableStream({
    start(controller) {
      if (earlyData) controller.enqueue(new Uint8Array(earlyData));
      ws.addEventListener('message', e => { if (!cancelled) controller.enqueue(e.data); });
      ws.addEventListener('close', () => { safeCloseWebSocket(ws); if (!cancelled) controller.close(); });
      ws.addEventListener('error', err => controller.error(err));
    },
    cancel() { cancelled = true; safeCloseWebSocket(ws); },
  });
}

// ==================== ⑦ VLESS Header 解析 ====================
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
        addr = new TextDecoder().decode(buf.slice(addrIdx, addrIdx + addrLen));
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

// ==================== ⑧ TCP 出站（含两级回退） ====================
async function handleTCPOutBound(remoteWrap, address, port, initData, ws, respHeader, proxies) {
  const current = proxies?.currentProxy || { proxyHost: '', proxyPort: null };
  const fallback = proxies?.defaultProxy || { proxyHost: '', proxyPort: null };

  const sameProxy = (a, b) =>
    (a?.proxyHost || '') === (b?.proxyHost || '') &&
    (a?.proxyPort ?? null) === (b?.proxyPort ?? null);

  async function connectAndWrite(host, p) {
    const sock = connect({ hostname: host, port: p });
    remoteWrap.value = sock;
    const w = sock.writable.getWriter();
    await w.write(initData);
    w.releaseLock();
    return sock;
  }

  async function tryDefaultProxy() {
    if (fallback.proxyHost) {
      const p = fallback.proxyPort ?? port;
      const sock = await connectAndWrite(fallback.proxyHost, p);
      remoteSocketToWS(sock, ws, respHeader, null);
      sock.closed.catch(() => {}).finally(() => safeCloseWebSocket(ws));
    } else {
      safeCloseWebSocket(ws);
    }
  }

  async function tryCurrentProxy() {
    if (current.proxyHost) {
      const p = current.proxyPort ?? port;
      const sock = await connectAndWrite(current.proxyHost, p);
      // 如果当前动态 proxyip 失败，则回退到默认 proxyip
      const needDefault = !sameProxy(current, fallback);
      remoteSocketToWS(sock, ws, respHeader, needDefault ? tryDefaultProxy : null);
      sock.closed.catch(() => {}).finally(() => { /* ws 由 remoteSocketToWS 管理 */ });
    } else {
      // 未提供当前 proxy，则直接尝试默认 proxy
      await tryDefaultProxy();
    }
  }

  // 首先直连目标；若无返回数据或失败，依次尝试 当前 proxyip → 默认 proxyip
  const directSock = await connectAndWrite(address, port);
  remoteSocketToWS(directSock, ws, respHeader, tryCurrentProxy);
  directSock.closed.catch(() => {}).finally(() => { /* ws 由 remoteSocketToWS 管理 */ });
}

// ==================== ⑨ 回写远端 TCP 数据到 WS（支持失败回退） ====================
async function remoteSocketToWS(remote, ws, vlessHeader, retry) {
  let header = vlessHeader;
  let hasData = false;
  let failed = false;

  await remote.readable.pipeTo(new WritableStream({
    async write(chunk) {
      hasData = true;
      if (ws.readyState !== WS_READY_STATE_OPEN) throw new Error('WebSocket not open');
      if (header) {
        ws.send(concatArrayBuffers(header, chunk));
        header = null;
      } else {
        ws.send(chunk);
      }
    },
  })).catch(() => { failed = true; });

  // 若尚未收到任何数据，按需回退（包括动态 proxyip → 默认 proxyip）
  if (!hasData && retry) {
    return retry();
  }

  // 没有回退可用，或已传输过数据则保持现状/关闭
  if (failed && !retry) safeCloseWebSocket(ws);
}

// ==================== ⑩ DNS（UDP）处理 – DoH + Accept Header ====================
async function handleUDPOutBound(ws, vlessHeader) {
  let sentHeader = false;

  const transform = new TransformStream({
    transform(chunk, controller) {
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
        if (sentHeader) {
          ws.send(concatArrayBuffers(szBuf, ans));
        } else {
          ws.send(concatArrayBuffers(vlessHeader, szBuf, ans));
          sentHeader = true;
        }
      }
    },
  })).catch(() => {});

  const writer = transform.writable.getWriter();
  return { write(chunk) { writer.write(chunk); } };
}

// ==================== ⑪ 辅助：WebSocket 安全关闭 ====================
const WS_READY_STATE_OPEN = 1;
const WS_READY_STATE_CLOSING = 2;
function safeCloseWebSocket(sock) {
  try {
    if (sock.readyState === WS_READY_STATE_OPEN || sock.readyState === WS_READY_STATE_CLOSING) {
      sock.close();
    }
  } catch {}
}

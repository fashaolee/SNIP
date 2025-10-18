import { connect } from 'cloudflare:sockets';

// ==================== ① 基础配置 ====================
let userID = '';          // ← 请自行替换为你的 UUID
let proxyIP = '';                 // 默认后备代理（无端口时使用目标端口）

// 订阅中返回的节点名称改为 “T‑SNIP‑序号” 形式
function nodeAlias(idx) {
  return `T-SNIP-${String(idx + 1).padStart(2, '0')}`;
}

// 需要在订阅中展示的域名列表
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
function parseProxyIP(input) {
  proxyConfig = { proxyHost: '', proxyPort: null };
  if (!input) return;
  const parts = input.split(':');
  proxyConfig.proxyHost = parts[0].trim();
  if (parts.length > 1) {
    const p = parseInt(parts[1].trim(), 10);
    if (!isNaN(p) && p > 0 && p <= 65535) proxyConfig.proxyPort = p;
  }
}
parseProxyIP(proxyIP);

// ==================== ③ 工具函数 ====================
// 合并任意数量的 Uint8Array / ArrayBuffer 为单一 ArrayBuffer（比 Blob 更轻量）
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

// base8Array（用于 early‑data）
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

// UUID 检验 & 字符串化
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

// ==================== ④ VLESS 订阅生成（去掉 ed 参数） ====================
function getVLESSConfig(uuid, host) {
  const protocol = 'vless';
  const path = '/'; // 不再带 ed 参数
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
  // URL‑Safe Base64（直接可用于 Clash / V2Ray 订阅）
  return btoa(txt).replace(/\+/g, '-').replace(/\//g, '_');
}

// ==================== ⑤ 主入口 ====================
if (!isValidUUID(userID)) {
  throw new Error('uuid is not valid');
}

export default {
  async fetch(request, env, ctx) {
    try {
      const url = new URL(request.url);
      let dynamicProxyIP = proxyIP; // 默认
      let pathUUID = null;

      // 动态代理： /proxyip=host:port/<uuid>
      const proxyMatch = /^\/proxyip=([^/]+)\/([0-9a-f-]{36})$/.exec(url.pathname);
      if (proxyMatch) {
        dynamicProxyIP = proxyMatch[1];
        pathUUID = proxyMatch[2];
        parseProxyIP(dynamicProxyIP);
      } else if (url.pathname.length > 1) {
        // 单段路径直接视为 UUID
        pathUUID = url.pathname.substring(1);
      }

      const upgrade = request.headers.get('Upgrade');
      if (!upgrade || upgrade !== 'websocket') {
        // ---------------- 非 WS ----------------
        if (url.pathname === '/') {
          return new Response('恭喜你快成功了，快去添加 UUID 吧', {
            status: 200,
            headers: { 'Content-Type': 'text/plain;charset=utf-8' },
          });
        }
        if (pathUUID && pathUUID === userID) {
          const cfg = getVLESSConfig(pathUUID, request.headers.get('Host'));
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

      // ---------------- WS ----------------
      return await vlessOverWSHandler(request);
    } catch (e) {
      return new Response(e.toString(), {
        status: 500,
        headers: { 'Content-Type': 'text/plain;charset=utf-8' },
      });
    }
  },
};

// ==================== ⑥ WebSocket 处理 ====================
async function vlessOverWSHandler(request) {
  const pair = new WebSocketPair();
  const [client, server] = Object.values(pair);
  server.accept();

  const earlyDataHeader = request.headers.get('sec-websocket-protocol') || '';
  const readableWS = makeReadableWebSocketStream(server, earlyDataHeader);

  let remote = { value: null };
  let udpWrite = null;
  let isDns = false;

  readableWS.pipeTo(
    new WritableStream({
      async write(chunk) {
        // ---- DNS（UDP）阶段 ----
        if (isDns && udpWrite) {
          udpWrite(chunk);
          return;
        }

        // ---- 已建立的 TCP 隧道 ----
        if (remote.value) {
          const w = remote.value.writable.getWriter();
          await w.write(chunk);
          w.releaseLock();
          return;
        }

        // ---- 解析 VLESS 首部 ----
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

        // 只允许 53 端口的 UDP（DNS）
        if (isUDP) {
          if (portRemote === 53) isDns = true;
          else throw new Error('UDP proxy only enable for DNS which is port 53');
        }

        const vlessRespHeader = new Uint8Array([vlessVersion[0], 0]); // VLESS reply
        const payload = chunk.slice(rawDataIndex);

        // ---- DNS 处理 ----
        if (isDns) {
          const { write } = await handleUDPOutBound(server, vlessRespHeader);
          udpWrite = write;
          udpWrite(payload);
          return;
        }

        // ---- TCP 处理 ----
        handleTCPOutBound(remote, addressRemote, portRemote, payload, server, vlessRespHeader);
      },
    })
  ).catch(() => { /* 已在内部自行处理 */ });

  return new Response(null, { status: 101, webSocket: client });
}

// ==================== ⑦ 可读 WebSocket 流 ====================
function makeReadableWebSocketStream(ws, earlyDataHeader) {
  let cancelled = false;
  const { earlyData, error } = base64ToArrayBuffer(earlyDataHeader);
  if (error) console.warn('early‑data decode error:', error);

  return new ReadableStream({
    start(controller) {
      if (earlyData) controller.enqueue(new Uint8Array(earlyData));

      ws.addEventListener('message', e => {
        if (!cancelled) controller.enqueue(e.data);
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
        addr = new TextDecoder().decode(buf.slice(addrIdx, addrIdx + addrLen));
        break;
      case 3: // IPv6
        addrLen = 16;
        if (buf.byteLength < addrIdx + addrLen) throw new Error('incomplete IPv6');
        const dv = new DataView(buf.slice(addrIdx, addrIdx + addrLen));
        const parts = [];
        for (let i = 0; i <8; i++) parts.push(dv.getUint16(i * 2).toString(16));
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

// ==================== ⑨ TCP 处理 ====================
async function handleTCPOutBound(remoteWrap, address, port, initData, ws, respHeader) {
  async function connectAndWrite(host, p) {
    const sock = connect({ hostname: host, port: p });
    remoteWrap.value = sock;
    const w = sock.writable.getWriter();
    await w.write(initData);
    w.releaseLock();
    return sock;
  }

  async function fallback() {
    const host = proxyConfig.proxyHost || address;
    const p = proxyConfig.proxyPort !== null ? proxyConfig.proxyPort : port;
    const sock = await connectAndWrite(host, p);
    sock.closed.catch(() => { }).finally(() => safeCloseWebSocket(ws));
    remoteSocketToWS(sock, ws, respHeader, null);
  }

  // 直接连接目标
  const sock = await connectAndWrite(address, port);
  remoteSocketToWS(sock, ws, respHeader, fallback);
}

// ==================== ⑩ 远端 TCP 数据回写 WS（使用 Uint8Array 合并） ====================
async function remoteSocketToWS(remote, ws, vlessHeader, retry) {
  let header = vlessHeader;
  let hasData = false;

  await remote.readable.pipeTo(
    new WritableStream({
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
    })
  ).catch(() => safeCloseWebSocket(ws));

  // 若目标没有返回任何数据且提供了 retry，则走后备代理
  if (!hasData && retry) retry();
}

// ==================== ⑪ DNS（UDP）处理 – DoH + Accept Header ====================
async function handleUDPOutBound(ws, vlessHeader) {
  let sentHeader = false;

  const transform = new TransformStream({
    transform(chunk, controller) {
      // 把长度字段拆成若干 UDP 包（长度占 2 字节，随后是数据）
      for (let i = 0; i < chunk.byteLength; ) {
        const len = new DataView(chunk.buffer, chunk.byteOffset + i, 2).getUint16(0);
        const data = new Uint8Array(chunk.buffer, chunk.byteOffset + i + 2, len);
        controller.enqueue(data);
        i += 2 + len;
      }
    },
  });

  // 每个 DNS 查询发送到 DoH（Google），把返回的二进制报文写回 WS
  transform.readable.pipeTo(
    new WritableStream({
      async write(dQuery) {
        const resp = await fetch('https://dns.google/dns-query', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/dns-message',
            Accept: 'application/dns-message',
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
    })
  ).catch(() => { /* 已在内部吞掉错误 */ });

  const writer = transform.writable.getWriter();

  return {
    write(chunk) {
      writer.write(chunk);
    },
  };
}

// ==================== ⑫ 辅助：WebSocket 安全关闭 ====================
const WS_READY_STATE_OPEN = 1;
const WS_READY_STATE_CLOSING = 2;
function safeCloseWebSocket(sock) {
  try {
    if (sock.readyState === WS_READY_STATE_OPEN || sock.readyState === WS_READY_STATE_CLOSING) {
      sock.close();
    }
  } catch {}
}

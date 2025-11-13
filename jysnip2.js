import {
	connect
} from 'cloudflare:sockets';

const te = new TextEncoder();
const td = new TextDecoder();
const UUID = '';
const EXPECTED_UUID_BYTES = new Uint8Array(16);
{
	const uuidHex = UUID.replace(/-/g, '');
	for (let i = 0; i < 16; i++) {
		EXPECTED_UUID_BYTES[i] = parseInt(uuidHex.substring(i * 2, i * 2 + 2), 16);
	}
}

// 验证UUID，避免复制数据
function verifyUUID(data) {
	if (data.byteLength < 17) return false;
	const uuidBytes = new Uint8Array(data, 1, 16); // 偏移1取16字节
	for (let i = 0; i < 16; i++) {
		if (uuidBytes[i] !== EXPECTED_UUID_BYTES[i]) return false;
	}
	return true;
}

// 预定义正则表达式（提升性能）
const IPV4_REGEX = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
const IPV6_SHORT_REGEX = /^\[[0-9a-fA-F:]+\]$/; // 匹配 [::1], [2001:db8::1]
const HOST_PORT_REGEX = /^((?:[^@]+@)?(?:\[.*\]|[^:]+))(?::(\d+))?$/; // 支持 user:pass@host:port 或 host:port

export default {
	async fetch(req, env) {

		if (req.headers.get('Upgrade')?.toLowerCase() === 'websocket') {
			const u = new URL(req.url);
			let mode = 'd'; // default mode
			let skJson;
			// 处理URL编码的路径参数
			if (u.pathname.includes('%3F')) {
				const decoded = decodeURIComponent(u.pathname);
				const queryIndex = decoded.indexOf('?');
				if (queryIndex !== -1) {
					u.search = decoded.substring(queryIndex);
					u.pathname = decoded.substring(0, queryIndex);
				}
			}

			let sParam = u.pathname.split('/s=')[1];
			let pParam;
			let hParam;

			if (sParam) {
				mode = 's';
				skJson = getSKJson(sParam, ['s', 'g']);
			} else {
				const gParam = u.pathname.split('/g=')[1];
				if (gParam) {
					sParam = gParam;
					skJson = getSKJson(gParam, ['s', 'g']);
					mode = 'g';
				} else {
					pParam = u.pathname.split('/p=')[1];
					if (pParam) {
						mode = 'p';
					} else {
						hParam = u.pathname.split('/h=')[1];
						if (hParam) {
							skJson = getSKJson(hParam, ['h', 'gh']);
							mode = 'h';
						} else {
							hParam = u.pathname.split('/gh=')[1];
							if (hParam) {
								skJson = getSKJson(hParam, ['h', 'gh']);
								mode = 'gh';
							}
						}
					}
				}
			}

			const [client, ws] = Object.values(new WebSocketPair());
			ws.accept();

			let remote = null, udpWriter = null, isDNS = false;

			new ReadableStream({
				start(ctrl) {
					ws.addEventListener('message', e => ctrl.enqueue(e.data));
					ws.addEventListener('close', () => {
						remote?.close();
						ctrl.close();
					});
					ws.addEventListener('error', () => {
						remote?.close();
						ctrl.error();
					});

					const early = req.headers.get('sec-websocket-protocol');
					if (early) {
						try {
							ctrl.enqueue(Uint8Array.from(atob(early.replace(/-/g, '+').replace(/_/g, '/')),
								c => c.charCodeAt(0)).buffer);
						} catch { }
					}
				}
			}, { highWaterMark: 65536 }).pipeTo(new WritableStream({
				async write(data) {
					if (isDNS) return udpWriter?.write(data);
					if (remote) {
						const w = remote.writable.getWriter();
						await w.write(data);
						w.releaseLock();
						return;
					}

					if (data.byteLength < 24) return;

					if (!verifyUUID(data)) return;

					const view = new DataView(data);
					const optLen = view.getUint8(17);
					const cmd = view.getUint8(18 + optLen);
					if (cmd !== 1 && cmd !== 2) return;

					let pos = 19 + optLen;
					const port = view.getUint16(pos);
					const type = view.getUint8(pos + 2);
					pos += 3;

					let addr = '';
					if (type === 1) {
						addr =
							`${view.getUint8(pos)}.${view.getUint8(pos + 1)}.${view.getUint8(pos + 2)}.${view.getUint8(pos + 3)}`;
						pos += 4;
					} else if (type === 2) {
						const len = view.getUint8(pos++);
						addr = td.decode(data.slice(pos, pos + len));
						pos += len;
					} else if (type === 3) {
						const ipv6 = [];
						for (let i = 0; i < 8; i++, pos += 2) ipv6.push(view.getUint16(pos)
							.toString(16));
						addr = ipv6.join(':');
					} else return;

					const header = new Uint8Array([data[0], 0]);
					const payload = data.slice(pos);

					// UDP DNS
					if (cmd === 2) {
						if (port !== 53) return;
						isDNS = true;
						let sent = false;
						const {
							readable,
							writable
						} = new TransformStream({
							transform(chunk, ctrl) {
								for (let i = 0; i < chunk.byteLength;) {
									const len = new DataView(chunk.slice(i, i + 2))
										.getUint16(0);
									ctrl.enqueue(chunk.slice(i + 2, i + 2 + len));
									i += 2 + len;
								}
							}
						});

						readable.pipeTo(new WritableStream({
							async write(query) {
								try {
									const resp = await fetch(
										'https://dns.google/dns-query', {
										method: 'POST',
										headers: {
											'content-type': 'application/dns-message'
										},
										body: query
									});
									if (ws.readyState === 1) {
										const result = new Uint8Array(await resp
											.arrayBuffer());
										ws.send(new Uint8Array([...(sent ? [] :
											header), result
												.length >> 8, result
													.length & 0xff, ...result
										]));
										sent = true;
									}
								} catch { }
							}
						}));
						udpWriter = writable.getWriter();
						return udpWriter.write(payload);
					}

					// TCP连接
					let sock = null;
					for (const method of getOrder(mode)) {
						try {
							if (method === 'd') {
								sock = connect({
									hostname: addr,
									port
								});
								await sock.opened;
								break;
							} else if ((method === 's' || method === 'g') && skJson) {
								sock = await sConnect(addr, port, skJson);
								break;
							} else if (method === 'p' && pParam) {
								const parsed = parseHostPort(pParam, 'p');
								sock = connect({
									hostname: parsed.host,
									port: parsed.port || port
								});
								await sock.opened;
								break;
							} else if ((method === 'h' || method === 'gh') && hParam && skJson) {
								sock = await httpConnect(addr, port, skJson);
								break;
							}
						} catch (e) {
							console.warn(`连接失败 (${method}):`, e.message);
						}
					}

					if (!sock) return;

					remote = sock;
					const w = sock.writable.getWriter();
					await w.write(payload);
					w.releaseLock();

					const INITIAL_THRESHOLD = 6 * 1024 * 1024;
					let controlThreshold = INITIAL_THRESHOLD;
					let lastCount = 0;

					const reader = sock.readable.getReader();
					let totalBytes = 0;
					let sent = false;
					let writeQueue = Promise.resolve();

					(async () => {
						try {
							while (true) {
								const { done, value } = await reader.read();
								if (done) break;
								if (!value || !value.byteLength) continue;

								totalBytes += value.byteLength;

								writeQueue = writeQueue.then(() => {
									if (ws.readyState === 1) {
										if (!sent) {
											const combined = new Uint8Array(header.length + value.length);
											combined.set(header);
											combined.set(value, header.length);
											ws.send(combined);
											sent = true;
										} else {
											ws.send(value);
										}
									}
								});
								await writeQueue;

								const delta = totalBytes - lastCount;
								if (delta > controlThreshold) {
									controlThreshold = delta;
								} else if (delta > INITIAL_THRESHOLD) {
									await new Promise(r => setTimeout(r, 100 + Math.random() * 200));
									controlThreshold = Math.max(controlThreshold - 2 * 1024 * 1024, INITIAL_THRESHOLD);
								}
								lastCount = totalBytes;
							}
						} catch (_) { }
						finally {
							try { reader.releaseLock(); } catch { }
							if (ws.readyState === 1) ws.close();
						}
					})();

				}
			})).catch(() => { });

			return new Response(null, {
				status: 101,
				webSocket: client
			});
		}

		return new Response("Hello World", { status: 200 });
	}
};

// 缓存解析结果
const SK_CACHE = new Map();

/**
 * 解析支持多种格式的代理或目标地址
 * @param {string} path - 路径参数
 * @param {string[]} modes - 当前模式 ['s','g'] | ['h','gh']
 * @returns {Object|null}
 */
function getSKJson(path, modes) {
	const cacheKey = `${path}|${modes.join(',')}`;
	const cached = SK_CACHE.get(cacheKey);
	if (cached) return cached;

	try {
		let user = null, pass = null, host = '', port = 443;

		// 检查是否包含认证信息
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
		SK_CACHE.set(cacheKey, result);
		return result;
	} catch (e) {
		console.error('解析SK失败:', e);
		return null;
	}
}

// 辅助函数：解析 p 模式的 host:port
function parseHostPort(input, mode) {
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
}

// 连接顺序缓存
const orderCache = {
	'p': ['d', 'p'],
	's': ['d', 's'],
	'g': ['s'],
	'h': ['d', 'h'],
	'gh': ['h'],
	'default': ['d']
};

function getOrder(mode) {
	return orderCache[mode] || orderCache['default'];
}

// SOCKS5 连接
async function sConnect(targetHost, targetPort, skJson) {
	const sock = connect({
		hostname: skJson.host,
		port: skJson.port
	});
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
}

// HTTP CONNECT 代理连接
async function httpConnect(addressRemote, portRemote, skJson) {
	const { user, pass, host, port } = skJson;
	const sock = await connect({
		hostname: host,
		port: port
	});

	const connectRequest = buildConnectRequest(addressRemote, portRemote, user, pass);
	try {
		const writer = sock.writable.getWriter();
		await writer.write(te.encode(connectRequest));
		writer.releaseLock();
	} catch (err) {
		console.error('发送HTTP CONNECT请求失败:', err);
		throw new Error(`发送HTTP CONNECT请求失败: ${err.message}`);
	}

	const reader = sock.readable.getReader();
	let respText = '';
	let connected = false;
	let responseBuffer = new Uint8Array(0);

	try {
		while (true) {
			const { value, done } = await reader.read();
			if (done) break;

			const newBuffer = new Uint8Array(responseBuffer.length + value.length);
			newBuffer.set(responseBuffer);
			newBuffer.set(value, responseBuffer.length);
			responseBuffer = newBuffer;

			respText = new TextDecoder().decode(responseBuffer);

			if (respText.includes('\r\n\r\n')) {
				const headers = respText.substring(0, respText.indexOf('\r\n\r\n') + 4);
				if (headers.startsWith('HTTP/1.1 200') || headers.startsWith('HTTP/1.0 200')) {
					connected = true;
					const bodyStart = respText.indexOf('\r\n\r\n') + 4;
					if (bodyStart < responseBuffer.length) {
						const remaining = responseBuffer.slice(bodyStart);
						const { readable, writable } = new TransformStream();
						new ReadableStream({ start: c => c.enqueue(remaining) })
							.pipeTo(writable).catch(() => { });
						// @ts-ignore
						sock.readable = readable;
					}
				} else {
					throw new Error(`HTTP代理失败: ${headers.split('\r\n')[0]}`);
				}
				break;
			}
		}
	} finally {
		reader.releaseLock();
	}

	if (!connected) throw new Error('HTTP代理未建立连接');

	return sock;
}

// 构建CONNECT请求
function buildConnectRequest(address, port, username, password) {
	const headers = [
		`CONNECT ${address}:${port} HTTP/1.1`,
		`Host: ${address}:${port}`
	];

	if (username && password) {
		const base64Auth = btoa(`${username}:${password}`);
		headers.push(`Proxy-Authorization: Basic ${base64Auth}`);
	}

	headers.push(
		'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
		'Proxy-Connection: Keep-Alive',
		'Connection: Keep-Alive',
		''
	);

	return headers.join('\r\n') + '\r\n';
}

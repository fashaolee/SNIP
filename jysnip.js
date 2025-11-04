import {
	connect
} from 'cloudflare:sockets';

// 常量定义
const DNS_ENDPOINT = 'https://dns.google/dns-query';

// 重用编码器/解码器以避免每次请求都创建新的实例
const te = new TextEncoder();
const td = new TextDecoder();

// 缓存解码后的myID以避免重复计算
const MY_ID_BYTES = (() => {
	const myID = '';
	const expectedmyID = myID.replace(/-/g, '');
	const bytes = new Uint8Array(16);
	for (let i = 0; i < 16; i++) {
		bytes[i] = parseInt(expectedmyID.substr(i * 2, 2), 16);
	}
	return bytes;
})();

const FLOW_CONTROL_DEFAULT_DELAY = 300;
const FLOW_CONTROL_THRESHOLD = 24 * 1024 * 1024; //最大速度24M
const FLOW_CONTROL_EXTRA_DELAY = 500;
const FLOW_CONTROL_CLEANUP_DELAY = 1000;

// 辅助函数：安全转换为 Uint8Array
function toUint8Array(data) {
	if (!data) return null;
	if (data instanceof Uint8Array) return data;
	if (data instanceof ArrayBuffer) return new Uint8Array(data);
	if (ArrayBuffer.isView(data)) return new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
	if (typeof data === 'string') return te.encode(data);
	return null;
}

// 构建DNS响应 - 预分配缓冲区优化
function buildDnsResponse(header, result, sent) {
	if (sent) {
		const buffer = new Uint8Array(2 + result.length);
		buffer[0] = result.length >> 8;
		buffer[1] = result.length & 0xff;
		buffer.set(result, 2);
		return buffer;
	}
	const buffer = new Uint8Array(header.length + 2 + result.length);
	buffer.set(header);
	buffer[header.length] = result.length >> 8;
	buffer[header.length + 1] = result.length & 0xff;
	buffer.set(result, header.length + 2);
	return buffer;
}

const FLOW_CONTROL_DELAY_STEPS = [
	{ size: 1 * 1024 * 1024, delay: 320 },
	{ size: 50 * 1024 * 1024, delay: 340 },
	{ size: 100 * 1024 * 1024, delay: 360 },
	{ size: 200 * 1024 * 1024, delay: 400 }
];

function getFlowControlDelay(totalBytes) {
	for (let i = FLOW_CONTROL_DELAY_STEPS.length - 1; i >= 0; i--) {
		const step = FLOW_CONTROL_DELAY_STEPS[i];
		if (totalBytes >= step.size) {
			return step.delay;
		}
	}
	return FLOW_CONTROL_DEFAULT_DELAY;
}

function sleep(ms) {
	return new Promise(resolve => setTimeout(resolve, ms));
}

const SOCKS5_METHODS = new Uint8Array([5, 2, 0, 2]);
const SOCKS5_REQUEST_PREFIX = new Uint8Array([5, 1, 0]);

export default {
	async fetch(req, env) {
		if (req.headers.get('Upgrade')?.toLowerCase() === 'websocket') {
			const u = new URL(req.url);
			let mode = 'd'; // default mode
			let skJson;
			let sParam = u.pathname.split('/s=')[1];
			let pParam;
			if (sParam) {
				mode = 's';
				skJson = getSKJson(sParam);
			} else {
				const gParam = u.pathname.split('/g=')[1];
				if (gParam) {
					sParam = gParam;
					skJson = getSKJson(gParam);
					mode = 'g';
				} else {
					pParam = u.pathname.split('/p=')[1];
					if (pParam) {
						mode = 'p';
					}
				}
			}
			const [client, ws] = Object.values(new WebSocketPair());
			ws.accept();
			let remote = null, remoteWriter = null, udpWriter = null, isDNS = false;

			const releaseRemoteWriter = () => {
				if (remoteWriter) {
					try {
						remoteWriter.releaseLock();
					} catch { }
					remoteWriter = null;
				}
			};

			const releaseUdpWriter = () => {
				if (udpWriter) {
					try {
						udpWriter.releaseLock();
					} catch { }
					udpWriter = null;
				}
			};

			const terminateRemote = () => {
				if (remote) {
					try {
						remote.close();
					} catch { }
					remote = null;
				}
				releaseRemoteWriter();
			};

			new ReadableStream({
				start(ctrl) {
					ws.addEventListener('message', e => {
						const { data } = e;
						if (typeof data === 'string') {
							ctrl.enqueue(te.encode(data));
						} else {
							ctrl.enqueue(data);
						}
					});
					ws.addEventListener('close', () => {
						terminateRemote();
						releaseUdpWriter();
						ctrl.close();
					});
					ws.addEventListener('error', () => {
						terminateRemote();
						releaseUdpWriter();
						ctrl.error();
					});

					const early = req.headers.get('sec-websocket-protocol');
					if (early) {
						try {
							const binStr = atob(early.replace(/-/g, '+').replace(/_/g, '/'));
							const buffer = new Uint8Array(binStr.length);
							for (let i = 0; i < binStr.length; i++) {
								buffer[i] = binStr.charCodeAt(i);
							}
							ctrl.enqueue(buffer);
						} catch { }
					}
				}
			}).pipeTo(new WritableStream({
				async write(data) {
					const chunk = toUint8Array(data);
					if (!chunk) return;

					if (isDNS) {
						if (udpWriter) {
							try {
								await udpWriter.write(chunk);
							} catch {
								releaseUdpWriter();
							}
						}
						return;
					}

					if (remoteWriter) {
						try {
							await remoteWriter.write(chunk);
						} catch {
							terminateRemote();
						}
						return;
					}

					if (chunk.length < 24) return;

					for (let i = 0; i < 16; i++) {
						if (chunk[1 + i] !== MY_ID_BYTES[i]) return;
					}

					const optLen = chunk[17];
					const cmdIndex = 18 + optLen;
					if (cmdIndex >= chunk.length) return;

					const cmd = chunk[cmdIndex];
					if (cmd !== 1 && cmd !== 2) return;

					let pos = 19 + optLen;
					if (pos + 3 > chunk.length) return;

					const port = (chunk[pos] << 8) | chunk[pos + 1];
					const type = chunk[pos + 2];
					pos += 3;

					let addr = '';
					if (type === 1) {
						if (pos + 4 > chunk.length) return;
						addr = `${chunk[pos]}.${chunk[pos + 1]}.${chunk[pos + 2]}.${chunk[pos + 3]}`;
						pos += 4;
					} else if (type === 2) {
						if (pos >= chunk.length) return;
						const len = chunk[pos++];
						if (pos + len > chunk.length) return;
						addr = td.decode(chunk.subarray(pos, pos + len));
						pos += len;
					} else if (type === 3) {
						if (pos + 16 > chunk.length) return;
						const ipv6 = [];
						for (let i = 0; i < 8; i++, pos += 2) {
							ipv6.push(((chunk[pos] << 8) | chunk[pos + 1]).toString(16));
						}
						addr = `[${ipv6.join(':')}]`;
					} else {
						return;
					}

					const header = new Uint8Array([chunk[0], 0]);
					const payload = chunk.subarray(pos);

					if (cmd === 2) {
						if (port !== 53) return;
						isDNS = true;
						let sent = false;
						const { readable, writable } = new TransformStream({
							transform(chunkData, ctrl) {
								const chunkView = toUint8Array(chunkData);
								if (!chunkView || chunkView.length < 2) return;
								let offset = 0;
								while (offset + 2 <= chunkView.length) {
									const len = (chunkView[offset] << 8) | chunkView[offset + 1];
									offset += 2;
									if (offset + len > chunkView.length) break;
									ctrl.enqueue(chunkView.subarray(offset, offset + len));
									offset += len;
								}
							}
						});

						readable.pipeTo(new WritableStream({
							async write(query) {
								try {
									const resp = await fetch(DNS_ENDPOINT, {
										method: 'POST',
										headers: {
											'content-type': 'application/dns-message'
										},
										body: query
									});
									if (ws.readyState !== 1) return;
									const result = toUint8Array(await resp.arrayBuffer());
									if (!result) return;
									ws.send(buildDnsResponse(header, result, sent));
									sent = true;
								} catch { }
							}
						}));
						udpWriter = writable.getWriter();
						try {
							await udpWriter.write(payload);
						} catch {
							releaseUdpWriter();
						}
						return;
					}

					let conn = null;
					for (const method of getOrder(mode)) {
						try {
							if (method === 'd') {
								conn = connect({
									hostname: addr,
									port
								});
								await conn.opened;
								break;
							} else if (method === 's' && skJson) {
								conn = await sConnect(addr, port, skJson);
								break;
							} else if (method === 'p' && pParam) {
								const proxyInfo = parseProxyAddr(pParam);
								conn = connect({
									hostname: proxyInfo.host,
									port: proxyInfo.port
								});
								await conn.opened;
								break;
							}
						} catch (err) {}
					}

					if (!conn) return;

					remote = conn;
					try {
						remoteWriter = conn.writable.getWriter();
						await remoteWriter.write(payload);
					} catch {
						terminateRemote();
						return;
					}

					let sent = false;
					let totalBytesReceived = 0;
					let lastDelayCheckpoint = 0;
					let shouldCloseWS = false;
					const reader = conn.readable.getReader();

					(async () => {
						try {
							while (true) {
								const { done, value } = await reader.read();

								if (done) {
									sent = true;
									shouldCloseWS = ws.readyState === 1;
									break;
								}

								const chunkView = toUint8Array(value);
								if (!chunkView || !chunkView.length) continue;

								if (ws.readyState !== 1) break;

								totalBytesReceived += chunkView.length;

								if (!sent) {
									const combined = new Uint8Array(header.length + chunkView.length);
									combined.set(header);
									combined.set(chunkView, header.length);
									ws.send(combined);
									sent = true;
								} else {
									ws.send(chunkView);
								}

								if ((totalBytesReceived - lastDelayCheckpoint) > FLOW_CONTROL_THRESHOLD) {
									const currentDelay = getFlowControlDelay(totalBytesReceived);
									await sleep(currentDelay + FLOW_CONTROL_EXTRA_DELAY);
									lastDelayCheckpoint = totalBytesReceived;
								}
							}
						} catch (error) {
							sent = true;
							shouldCloseWS = ws.readyState === 1;
						} finally {
							await sleep(FLOW_CONTROL_CLEANUP_DELAY);
							if (shouldCloseWS && ws.readyState === 1) {
								ws.close();
							}
							try {
								reader.releaseLock();
							} catch { }
							terminateRemote();
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

// 支持解析六种格式：ip[:port], user:pass@ip[:port], host[:port], user:pass@host[:port], [ipv6][:port], user:pass@[ipv6][:port]
function getSKJson(path) {
	if (!path.includes('@')) {
		return parseHostPort(path, 443);
	}

	const atIdx = path.lastIndexOf('@');
	const cred = path.substring(0, atIdx);
	const server = path.substring(atIdx + 1);

	const [user, pass] = cred.split(':', 2);
	const hostPort = parseHostPort(server, 443);

	return {
		user,
		pass,
		host: hostPort.host,
		port: hostPort.port,
		userEncoded: user ? te.encode(user) : null,
		passEncoded: pass ? te.encode(pass) : null
	};
}

// 解析 host:port 或 ip:port 或 [ipv6]:port 格式，支持默认端口
function parseHostPort(str, defaultPort) {
	let host, port = defaultPort;

	// 匹配 IPv6 地址 [xxxx:xxxx:...]:port
	if (str.startsWith('[')) {
		const closeBrace = str.indexOf(']');
		if (closeBrace === -1) throw new Error('Invalid IPv6 address');
		host = str.slice(0, closeBrace + 1);
		const portPart = str.slice(closeBrace + 1);
		if (portPart.startsWith(':')) {
			port = parseInt(portPart.slice(1)) || defaultPort;
		}
	} else {
		const parts = str.split(':');
		if (parts.length > 2 || (parts.length === 2 && isNaN(parts[1]))) {
			// 多个冒号但不是IPv6（如域名含:），按 host:port 解
			const lastColon = str.lastIndexOf(':');
			host = str.substring(0, lastColon);
			port = parseInt(str.substring(lastColon + 1)) || defaultPort;
		} else if (parts.length === 2) {
			host = parts[0];
			port = parseInt(parts[1]) || defaultPort;
		} else {
			host = str;
		}
	}
	return { host, port };
}

// 支持四种格式：host:port, host, ip:port, ip
function parseProxyAddr(str) {
	return parseHostPort(str, 443);
}

// 优化getOrder函数 - 使用缓存避免重复创建数组
const orderCache = {
	'p': ['d', 'p'],
	's': ['d', 's'],
	'g': ['s'],
	'default': ['d']
};

function getOrder(mode) {
	return orderCache[mode] || orderCache['default'];
}

async function sConnect(targetHost, targetPort, skJson) {
	const conn = connect({
		hostname: skJson.host,
		port: skJson.port
	});
	await conn.opened;
	const w = conn.writable.getWriter();
	const r = conn.readable.getReader();

	try {
		await w.write(SOCKS5_METHODS);
		const authResp = await r.read();
		const auth = toUint8Array(authResp.value);
		if (!auth || auth.length < 2) {
			throw new Error('Invalid SOCKS5 auth response');
		}

		if (auth[1] === 2 && skJson.userEncoded) {
			const passBytes = skJson.passEncoded ?? new Uint8Array(0);
			const authBuffer = new Uint8Array(3 + skJson.userEncoded.length + passBytes.length);
			authBuffer[0] = 1;
			authBuffer[1] = skJson.userEncoded.length;
			authBuffer.set(skJson.userEncoded, 2);
			authBuffer[2 + skJson.userEncoded.length] = passBytes.length;
			authBuffer.set(passBytes, 3 + skJson.userEncoded.length);
			await w.write(authBuffer);
			await r.read();
		}

		let addrType, addrBytes;
		if (targetHost.startsWith('[')) {
			// IPv6
			addrType = 4;
			const ipStr = targetHost.slice(1, -1); // remove [ ]
			const parts = ipStr.split(':').map(p => parseInt(p, 16));
			addrBytes = new Uint8Array(16);
			for (let i = 0; i < 8; i++) {
				addrBytes[i * 2] = (parts[i] >> 8) & 0xff;
				addrBytes[i * 2 + 1] = parts[i] & 0xff;
			}
		} else if (/\d+\.\d+\.\d+\.\d+/.test(targetHost)) {
			// IPv4
			addrType = 1;
			addrBytes = new Uint8Array(targetHost.split('.').map(x => parseInt(x)));
		} else {
			// domain
			addrType = 3;
			const domainBytes = te.encode(targetHost);
			addrBytes = new Uint8Array(1 + domainBytes.length);
			addrBytes[0] = domainBytes.length;
			addrBytes.set(domainBytes, 1);
		}

		const reqLength = SOCKS5_REQUEST_PREFIX.length + 1 + addrBytes.length + 2;
		const reqBuffer = new Uint8Array(reqLength);
		reqBuffer.set(SOCKS5_REQUEST_PREFIX, 0);
		reqBuffer[SOCKS5_REQUEST_PREFIX.length] = addrType;
		reqBuffer.set(addrBytes, SOCKS5_REQUEST_PREFIX.length + 1);
		reqBuffer[reqLength - 2] = targetPort >> 8;
		reqBuffer[reqLength - 1] = targetPort & 0xff;

		await w.write(reqBuffer);
		const connectResp = await r.read();
		const resp = toUint8Array(connectResp.value);
		if (!resp || resp[1] !== 0) {
			throw new Error(`SOCKS5 connection failed: ${resp ? resp[1] : 'no response'}`);
		}

		return conn;
	} catch (err) {
		try {
			conn.close();
		} catch { }
		throw err;
	} finally {
		w.releaseLock();
		r.releaseLock();
	}
}

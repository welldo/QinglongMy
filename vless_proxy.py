"""vless_proxy.py — 零依赖（仅 Python 标准库）的 VLESS+WebSocket+TLS 本地 HTTP 代理。

用途：把一条 vless:// 订阅 / 单链接，在本地拉起一个 HTTP 代理（CONNECT 隧道），
供 requests 等客户端经它干净出网，从而绕过被管控 / 被拦截的出口网关。

特点：
  * 不依赖 xray / v2ray / clash 等任何外部客户端，也不下载任何二进制。
  * 仅用标准库：socket / ssl / struct / base64 / hashlib / threading / socketserver / urllib。
  * 支持本签到场景所需的 VLESS 最小子集：security=tls + type=ws + encryption=none + TCP 目标。
  * 不支持 vmess / trojan / mux / udp / aead 加密（未实现，也用不到）。

实现要点的逆向依据（v2ray / XTLS 官方协议）：
  * VLESS 请求头（encryption=none）：
        version(0x00) + UUID(16) + addon(0x00) + cmd(0x01=TCP) + port(2) + atyp(1) + addr
      atyp: 1=IPv4 / 2=域名(1字节长度+域名) / 3=IPv6。none 加密无后续校验段。
  * 传输用 WebSocket(RFC6455)：首帧发 VLESS 请求头，其后每个二进制帧承载透传负载；
    v2ray 侧会把同一条 WS 连接上的二进制帧按顺序拼成一个 VLESS 流。
  * TLS 用标准库 ssl（SNI=链接里的 sni），默认校验证书；若握手因证书失败会自动降级
    为不校验（保证可用，连接仍加密）。

局限：标准库 ssl 无法伪装 uTLS 指纹（链接里的 fp=chrome 仅为提示，未生效），
对个别强行校验 JA3 的站点可能失败；但 VLESS+WS 端点通常不校验，实测可用。
"""

import base64
import hashlib
import ipaddress
import os
import socket
import ssl
import struct
import threading
import urllib.parse
import urllib.request
from socketserver import BaseRequestHandler
from socketserver import ThreadingTCPServer


# ---------------------------------------------------------------------------
# vless:// 链接解析
# ---------------------------------------------------------------------------
def parse_vless(url: str) -> dict:
    """解析 vless://uuid@host:port?query#tag -> dict。失败抛 ValueError。"""
    if not url.startswith("vless://"):
        raise ValueError("不是 vless:// 链接")
    body = url[len("vless://"):]
    if "#" in body:
        body = body.split("#", 1)[0]
    if "?" in body:
        addr, query = body.split("?", 1)
    else:
        addr, query = body, ""
    if "@" not in addr:
        raise ValueError("vless 链接缺少 @（应为 vless://uuid@host:port）")
    uuid, hostport = addr.split("@", 1)
    if ":" not in hostport:
        raise ValueError("vless 链接缺少端口")
    server, port = hostport.rsplit(":", 1)
    q = urllib.parse.parse_qs(query)
    g = lambda k, d="": (q.get(k, [d])[0] if q.get(k) else d)
    return {
        "uuid": uuid,
        "server": server,
        "port": int(port),
        "security": g("security", "tls"),
        "net": g("type", "ws"),
        "host": g("host", server),
        "sni": g("sni", g("host", server)),
        "path": g("path", "/") or "/",
        "fp": g("fp", ""),
        "encryption": g("encryption", "none"),
    }


def fetch_subscription(url: str, timeout: int = 15):
    """抓取订阅地址，返回 vless:// 链接列表。兼容「纯文本多行」与「base64 整段」两种格式。"""
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        text = r.read().decode("utf-8", errors="replace")
    links = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        if line.startswith("vless://"):
            links.append(line)
    if links:
        return links
    # 退路：可能是 base64 整段（部分订阅会包一层）
    try:
        dec = base64.b64decode(text.strip() + "===").decode("utf-8", errors="replace")
        for line in dec.splitlines():
            line = line.strip()
            if line.startswith("vless://"):
                links.append(line)
    except Exception:
        pass
    return links


# ---------------------------------------------------------------------------
# WebSocket 客户端（RFC6455，自实现；仅 binary 帧 + 控制帧）
# ---------------------------------------------------------------------------
_WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


class _WS:
    def __init__(self, sock, leftover: bytes = b""):
        self.sock = sock
        self._buf = leftover
        self._closed = False

    def _recv_n(self, n: int) -> bytes:
        while len(self._buf) < n:
            chunk = self.sock.recv(4096)
            if not chunk:
                raise ConnectionError("WS 连接断开")
            self._buf += chunk
        data = self._buf[:n]
        self._buf = self._buf[n:]
        return data

    def _read_frame(self):
        h = self._recv_n(2)
        fin = (h[0] & 0x80) != 0
        opcode = h[0] & 0x0F
        masked = (h[1] & 0x80) != 0
        length = h[1] & 0x7F
        if length == 126:
            length = struct.unpack(">H", self._recv_n(2))[0]
        elif length == 127:
            length = struct.unpack(">Q", self._recv_n(8))[0]
        if masked:
            self._recv_n(4)  # 服务端不应掩码，直接丢弃
        return fin, opcode, self._recv_n(length)

    def recv_message(self):
        """读取下一条数据帧（opcode=1/2）；自动处理 ping/pong/close 控制帧。"""
        while True:
            fin, opcode, payload = self._read_frame()
            if opcode == 0x8:  # close
                self._closed = True
                try:
                    self._send_frame(0x8, b"")
                except Exception:
                    pass
                raise ConnectionError("WS 收到 close")
            if opcode == 0x9:  # ping -> pong
                self._send_frame(0xA, payload)
                continue
            if opcode == 0xA:  # pong
                continue
            # 1=text / 2=binary；VLESS over WS 统一走 binary，这里两种都当数据返回
            return payload

    def _send_frame(self, opcode: int, data: bytes):
        header = bytes([0x80 | opcode])
        mask = os.urandom(4)
        n = len(data)
        if n < 126:
            header += bytes([0x80 | n])
        elif n < 65536:
            header += bytes([0x80 | 126]) + struct.pack(">H", n)
        else:
            header += bytes([0x80 | 127]) + struct.pack(">Q", n)
        masked = bytes(b ^ mask[i & 3] for i, b in enumerate(data))
        self.sock.sendall(header + mask + masked)

    def send_binary(self, data: bytes):
        self._send_frame(0x2, data)

    def close(self):
        if self._closed:
            try:
                self.sock.close()
            except Exception:
                pass
            return
        try:
            self._send_frame(0x8, b"")
        except Exception:
            pass
        try:
            self.sock.close()
        except Exception:
            pass


def _ws_handshake(sock, host: str, path: str) -> _WS:
    key = base64.b64encode(os.urandom(16)).decode()
    req = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Upgrade: websocket\r\n"
        f"Connection: Upgrade\r\n"
        f"Sec-WebSocket-Key: {key}\r\n"
        f"Sec-WebSocket-Version: 13\r\n"
        f"User-Agent: Mozilla/5.0\r\n"
        f"\r\n"
    ).encode()
    sock.sendall(req)
    buf = b""
    while b"\r\n\r\n" not in buf:
        chunk = sock.recv(4096)
        if not chunk:
            raise ConnectionError("WS 握手中断")
        buf += chunk
    head, _, rest = buf.partition(b"\r\n\r\n")
    lines = head.decode(errors="replace").split("\r\n")
    if "101" not in lines[0]:
        raise ConnectionError(f"WS 握手失败：{lines[0]}")
    accept_ok = False
    for ln in lines[1:]:
        if ln.lower().startswith("sec-websocket-accept:"):
            got = ln.split(":", 1)[1].strip()
            exp = base64.b64encode(
                hashlib.sha1((key + _WS_GUID).encode()).digest()
            ).decode()
            accept_ok = (got == exp)
            break
    if not accept_ok:
        raise ConnectionError("WS Sec-WebSocket-Accept 校验失败")
    return _WS(sock, rest)


# ---------------------------------------------------------------------------
# VLESS 请求头
# ---------------------------------------------------------------------------
def _vless_header(uuid_str: str, host: str, port: int) -> bytes:
    ver = b"\x00"
    try:
        uid = uuid_str.encode() if len(uuid_str) == 16 else bytes.fromhex(uuid_str.replace("-", ""))
        if len(uid) != 16:
            raise ValueError
    except Exception:
        uid = uuid_str.encode()[:16]
    addon = b"\x00"
    cmd = b"\x01"  # TCP
    port_b = struct.pack(">H", port)
    try:
        ip = ipaddress.ip_address(host)
        atyp = b"\x01" if ip.version == 4 else b"\x03"
        addr = ip.packed
    except ValueError:
        atyp = b"\x02"
        addr = bytes([len(host)]) + host.encode()
    return ver + uid + addon + cmd + port_b + atyp + addr


class _VlessStream:
    """一条到目标 host:port 的 VLESS+WS 隧道。send() 写负载，recv() 读负载。"""

    def __init__(self, ws: _WS, header: bytes):
        self.ws = ws
        ws.send_binary(header)  # 首帧：VLESS 请求头
        # VLESS 对 TCP 目标的响应以 2 字节响应头开头（version + addon），
        # 这 2 字节不是应用数据，必须剥掉再交给上层（否则 HTTPS 客户端会把
        # 它当成 TLS 记录而报 WRONG_VERSION_NUMBER）。
        self._hdr_left = 2

    def send(self, data: bytes):
        if data:
            self.ws.send_binary(data)

    def recv(self) -> bytes:
        while True:
            data = self.ws.recv_message()
            if self._hdr_left:
                if len(data) <= self._hdr_left:
                    self._hdr_left -= len(data)
                    continue  # 响应头还没收全，继续读
                data = data[self._hdr_left:]
                self._hdr_left = 0
            if data:
                return data
            # 空帧（TCP 中继几乎不会出现）：继续读，直到有数据或连接关闭

    def close(self):
        self.ws.close()


# ---------------------------------------------------------------------------
# 本地 HTTP 代理
# ---------------------------------------------------------------------------
class VlessProxy:
    def __init__(self, links, local_port: int = 10808, verify: bool = True, timeout: int = 20):
        self.links = [l for l in (links or []) if l and l.startswith("vless://")]
        self.local_port = local_port
        self.verify = verify
        self.timeout = timeout
        self._server = None
        self._nodes = []
        self._good_node = None
        self._lock = threading.Lock()
        self.http_url = f"http://127.0.0.1:{local_port}"

    def start(self):
        for u in self.links:
            try:
                self._nodes.append(parse_vless(u))
            except Exception as e:
                print(f"[vless] 跳过无法解析的链接：{e}")
        if not self._nodes:
            raise RuntimeError("没有可用的 vless 节点（链接均解析失败）")
        srv = ThreadingTCPServer(("127.0.0.1", self.local_port), self._make_handler())
        srv.daemon_threads = True
        srv.allow_reuse_address = True
        self._server = srv
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        print(f"[vless] 本地 HTTP 代理已启动：{self.http_url}（{len(self._nodes)} 个节点）")
        return self.http_url

    def stop(self):
        if self._server is not None:
            try:
                self._server.shutdown()
                self._server.server_close()
            except Exception:
                pass
            self._server = None

    def open_upstream(self, host: str, port: int) -> _VlessStream:
        with self._lock:
            nodes = self._nodes
            if self._good_node:
                order = [self._good_node] + [n for n in nodes if n is not self._good_node]
            else:
                order = list(nodes)
        last_err = None
        for node in order:
            try:
                return self._connect(node, host, port)
            except Exception as e:
                last_err = e
                continue
        raise ConnectionError(f"所有节点均不可达：{last_err}")

    def _connect(self, node: dict, host: str, port: int) -> _VlessStream:
        # verify 优先；若因证书失败则自动降级为不校验（连接仍加密）
        for verify in ([self.verify, False] if self.verify else [False]):
            try:
                raw = socket.create_connection((node["server"], node["port"]), timeout=self.timeout)
                raw.settimeout(self.timeout)
                ctx = ssl.create_default_context()
                if not verify:
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                tls = ctx.wrap_socket(raw, server_hostname=node["sni"])
                ws = _ws_handshake(tls, node["host"], node["path"])
                header = _vless_header(node["uuid"], host, port)
                return _VlessStream(ws, header)
            except Exception as e:
                last_err = e
                continue
        raise ConnectionError(f"节点 {node['server']}:{node['port']} 连接失败：{last_err}")

    # ---- 下面是 HTTP 代理服务器实现 ----
    def _make_handler(self):
        proxy = self

        class _Handler(BaseRequestHandler):
            def handle(self_inner):
                proxy._handle(self_inner.request)

            def finish(self_inner):
                try:
                    self_inner.request.close()
                except Exception:
                    pass

        return _Handler

    def _handle(self, client: socket.socket):
        try:
            client.settimeout(self.timeout)
            req = client.recv(65536)
            if not req:
                return
            first_line = req.split(b"\r\n", 1)[0].decode(errors="replace")
            parts = first_line.split()
            if len(parts) < 2:
                return
            method, target = parts[0], parts[1]
            if method == "CONNECT":
                host, port = target.rsplit(":", 1)
                port = int(port)
                upstream = None
                try:
                    upstream = self.open_upstream(host, port)
                    client.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                    self._pipe(client, upstream)
                except Exception as e:
                    print(f"[vless] CONNECT {target} 失败：{e}")
                finally:
                    if upstream is not None:
                        upstream.close()
                return
            # 绝对形式 GET http://host:port/path（明文 HTTP 代理）
            u = urllib.parse.urlparse(target)
            host = u.hostname or ""
            port = u.port or (443 if u.scheme == "https" else 80)
            upstream = None
            try:
                upstream = self.open_upstream(host, port)
                upstream.send(req)
                self._pipe(client, upstream)
            except Exception as e:
                print(f"[vless] 转发 {target} 失败：{e}")
            finally:
                if upstream is not None:
                    upstream.close()
        except Exception as e:
            print(f"[vless] 处理连接出错：{e}")

    def _pipe(self, client: socket.socket, upstream: _VlessStream):
        def to_upstream():
            try:
                while True:
                    data = client.recv(65536)
                    if not data:
                        break
                    upstream.send(data)
            except Exception:
                pass
            finally:
                try:
                    upstream.close()
                except Exception:
                    pass

        def to_client():
            try:
                while True:
                    data = upstream.recv()
                    if not data:
                        break
                    client.sendall(data)
            except Exception:
                pass
            finally:
                try:
                    client.shutdown(socket.SHUT_WR)
                except Exception:
                    pass

        t1 = threading.Thread(target=to_upstream, daemon=True)
        t2 = threading.Thread(target=to_client, daemon=True)
        t1.start()
        t2.start()
        t1.join()
        t2.join()
        try:
            client.close()
        except Exception:
            pass
        try:
            upstream.close()
        except Exception:
            pass


if __name__ == "__main__":
    # 简易自检：用订阅或单链接拉起代理，并验证能经其出网取回本机 IP
    import sys

    src = sys.argv[1] if len(sys.argv) > 1 else os.environ.get("MINIMAX_SUB", "")
    if not src:
        print("用法：python vless_proxy.py <订阅URL 或 vless://链接> [本地端口]")
        sys.exit(1)
    links = fetch_subscription(src) if src.startswith("http") else [src]
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 10808
    p = VlessProxy(links, local_port=port)
    p.start()
    try:
        import requests

        r = requests.get("https://api.ipify.org?format=json",
                         proxies={"http": p.http_url, "https": p.http_url}, timeout=20)
        print("出网测试：", r.text)
    except Exception as e:
        print("出网测试失败：", e)
    finally:
        p.stop()

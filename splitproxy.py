#!/usr/bin/env python3
"""
splitproxy - per-host split tunnelling for macOS + GlobalProtect.

Keep GlobalProtect connected (full tunnel). Point apps at this local proxy.
Hosts matching VPN_HOSTS are dialled with the socket pinned to the VPN
interface; everything else is pinned to the physical interface (en0), so it
bypasses the tunnel. Pinning uses the IP_BOUND_IF socket option, which
overrides the routing table without touching GlobalProtect's routes.

Listens as an HTTP/HTTPS (CONNECT) proxy and as a SOCKS5 proxy.
Configuration is via environment variables (or a .env file next to this
script). See .env.example.
"""

import asyncio
import ipaddress
import json
import logging
import os
import random
import re
import socket
import struct
import subprocess
import sys
import time

IP_BOUND_IF = 25      # darwin: <netinet/in.h>
IPV6_BOUND_IF = 125   # darwin: <netinet6/in6.h>

VPN = "vpn"
DIRECT = "direct"

log = logging.getLogger("splitproxy")


def errstr(e):
    return f"{type(e).__name__}: {e}" if str(e) else type(e).__name__


# --------------------------------------------------------------------------- config

def load_dotenv(path):
    """Load KEY=VALUE lines into os.environ without overriding existing vars."""
    if not os.path.isfile(path):
        return
    with open(path) as fh:
        for raw in fh:
            line = raw.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            if line.startswith("export "):
                line = line[7:]
            key, _, val = line.partition("=")
            key, val = key.strip(), val.strip()
            if len(val) >= 2 and val[0] == val[-1] and val[0] in "\"'":
                val = val[1:-1]
            os.environ.setdefault(key, val)


def env(name, default=""):
    return os.environ.get(name, default).strip()


def env_list(name):
    return [p.strip() for p in re.split(r"[,\s]+", env(name)) if p.strip()]


class Rule:
    """
    Host pattern:
      bitbucket.juspay.net   exact host
      *.juspay.net           host and every subdomain
      .juspay.net            same as above
      10.0.0.0/8             CIDR (only applies when the target is an IP literal)
    """

    def __init__(self, text):
        self.text = text.strip().lower().rstrip(".")
        self.net = None
        try:
            self.net = ipaddress.ip_network(self.text, strict=False)
        except ValueError:
            pass
        if self.text.startswith("*."):
            self.suffix = self.text[2:]
        elif self.text.startswith("."):
            self.suffix = self.text[1:]
        else:
            self.suffix = None

    def matches(self, host):
        if self.net is not None:
            try:
                return ipaddress.ip_address(host) in self.net
            except ValueError:
                return False
        if self.suffix is not None:
            return host == self.suffix or host.endswith("." + self.suffix)
        return host == self.text

    def specificity(self):
        if self.net is not None:
            return self.net.prefixlen
        return len(self.suffix if self.suffix is not None else self.text) + 1000


class Config:
    def __init__(self):
        self.http_listen = env("HTTP_LISTEN", "127.0.0.1:8080")
        self.socks_listen = env("SOCKS_LISTEN", "127.0.0.1:1080")
        self.vpn_iface = env("VPN_IFACE", "auto")
        self.direct_iface = env("DIRECT_IFACE", "auto")
        self.vpn_dns = env_list("VPN_DNS")          # empty => auto-detect
        self.direct_dns = env_list("DIRECT_DNS") or ["1.1.1.1", "8.8.8.8"]
        self.vpn_rules = [Rule(r) for r in env_list("VPN_HOSTS")]
        self.direct_rules = [Rule(r) for r in env_list("DIRECT_HOSTS")]
        dr = env("DEFAULT_ROUTE", DIRECT).lower()
        if dr not in (VPN, DIRECT):
            raise SystemExit(f"DEFAULT_ROUTE must be 'vpn' or 'direct', got {dr!r}")
        self.default_route = dr
        self.connect_timeout = float(env("CONNECT_TIMEOUT", "15"))
        self.refresh_secs = float(env("REFRESH_SECS", "5"))
        self.relay_idle_timeout = float(env("RELAY_IDLE_TIMEOUT", "300"))

    def decide(self, host):
        host = host.lower().rstrip(".")
        best = None  # (specificity, route)
        for route, rules in ((VPN, self.vpn_rules), (DIRECT, self.direct_rules)):
            for r in rules:
                if r.matches(host):
                    s = r.specificity()
                    if best is None or s > best[0] or (s == best[0] and route == VPN):
                        best = (s, route)
        return best[1] if best else self.default_route


# --------------------------------------------------------------------------- interface detection

def _run(cmd):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=5).stdout
    except Exception:
        return ""


def list_ifaces():
    """{name: {"flags": set, "inet": [ipv4,...]}} from ifconfig."""
    out = {}
    cur = None
    for line in _run(["ifconfig"]).splitlines():
        m = re.match(r"^(\S+): flags=\d+<([^>]*)>", line)
        if m:
            cur = m.group(1)
            out[cur] = {"flags": set(m.group(2).split(",")) if m.group(2) else set(), "inet": []}
            continue
        m = re.match(r"^\s+inet (\d+\.\d+\.\d+\.\d+)", line)
        if m and cur:
            out[cur]["inet"].append(m.group(1))
    return out


def default_route_iface():
    m = re.search(r"^\s*interface:\s*(\S+)", _run(["route", "-n", "get", "default"]), re.M)
    return m.group(1) if m else None


def _usable(info, need_running=True):
    if "UP" not in info["flags"]:
        return False
    if need_running and "RUNNING" not in info["flags"]:
        return False
    return any(not ip.startswith("169.254.") for ip in info["inet"])


VPN_IFACE_RE = re.compile(r"^(utun|gpd|ipsec|ppp)\d+$")
PHYS_IFACE_RE = re.compile(r"^en\d+$")


def detect_vpn_iface(cfg, ifaces, default_if):
    if cfg.vpn_iface and cfg.vpn_iface != "auto":
        return cfg.vpn_iface if cfg.vpn_iface in ifaces else None
    if default_if and VPN_IFACE_RE.match(default_if) and default_if in ifaces:
        return default_if
    cands = [n for n, i in ifaces.items() if VPN_IFACE_RE.match(n) and _usable(i)]
    return sorted(cands)[0] if cands else None


def detect_direct_iface(cfg, ifaces, default_if):
    if cfg.direct_iface and cfg.direct_iface != "auto":
        return cfg.direct_iface if cfg.direct_iface in ifaces else None
    cands = [n for n, i in ifaces.items() if PHYS_IFACE_RE.match(n) and _usable(i)]
    if default_if in cands:
        return default_if
    return sorted(cands)[0] if cands else None


def detect_vpn_dns(vpn_ifindex):
    """Pick the DNS servers GlobalProtect pushed, from `scutil --dns`."""
    blocks = []
    cur = None
    for line in _run(["scutil", "--dns"]).splitlines():
        if re.match(r"^resolver #\d+", line):
            cur = {"ns": [], "if_index": None, "domain": None}
            blocks.append(cur)
            continue
        if cur is None:
            continue
        m = re.match(r"^\s+nameserver\[\d+\]\s*:\s*(\S+)", line)
        if m:
            cur["ns"].append(m.group(1))
            continue
        m = re.match(r"^\s+if_index\s*:\s*(\d+)", line)
        if m:
            cur["if_index"] = int(m.group(1))
            continue
        m = re.match(r"^\s+domain\s*:\s*(\S+)", line)
        if m:
            cur["domain"] = m.group(1)

    def v4(ns):
        return [n for n in ns if re.match(r"^\d+\.\d+\.\d+\.\d+$", n)]

    if vpn_ifindex is not None:
        for b in blocks:
            if b["if_index"] == vpn_ifindex and v4(b["ns"]):
                return v4(b["ns"])
    for b in blocks:  # resolver #1 of the main section: what the system uses by default
        if b["domain"] is None and v4(b["ns"]):
            return v4(b["ns"])
    return []


class NetState:
    def __init__(self, cfg):
        self.cfg = cfg
        self.vpn_if = None
        self.vpn_idx = None
        self.direct_if = None
        self.direct_idx = None
        self.vpn_dns = []
        self.direct_dns = cfg.direct_dns
        self.updated = 0.0

    def refresh(self):
        ifaces = list_ifaces()
        default_if = default_route_iface()
        vpn_if = detect_vpn_iface(self.cfg, ifaces, default_if)
        direct_if = detect_direct_iface(self.cfg, ifaces, default_if)

        def idx(name):
            try:
                return socket.if_nametoindex(name) if name else None
            except OSError:
                return None

        vpn_idx, direct_idx = idx(vpn_if), idx(direct_if)
        vpn_dns = self.cfg.vpn_dns or detect_vpn_dns(vpn_idx)

        changed = (vpn_if, direct_if, vpn_dns) != (self.vpn_if, self.direct_if, self.vpn_dns)
        self.vpn_if, self.vpn_idx = vpn_if, vpn_idx
        self.direct_if, self.direct_idx = direct_if, direct_idx
        self.vpn_dns = vpn_dns
        self.updated = time.time()
        if changed:
            log.info(
                "interfaces: vpn=%s direct=%s default_route=%s vpn_dns=%s direct_dns=%s",
                vpn_if or "NOT FOUND (is GlobalProtect connected?)",
                direct_if or "NOT FOUND", default_if, vpn_dns or "system", self.direct_dns,
            )

    def for_route(self, route):
        """-> (ifname, ifindex, dns_servers)"""
        if route == VPN:
            return self.vpn_if, self.vpn_idx, self.vpn_dns
        return self.direct_if, self.direct_idx, self.direct_dns

    def snapshot(self):
        return {
            "vpn_iface": self.vpn_if, "direct_iface": self.direct_if,
            "vpn_dns": self.vpn_dns or "system resolver", "direct_dns": self.direct_dns,
            "default_route": self.cfg.default_route,
            "vpn_hosts": [r.text for r in self.cfg.vpn_rules],
            "direct_hosts": [r.text for r in self.cfg.direct_rules],
            "updated": time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(self.updated)),
        }


# --------------------------------------------------------------------------- sockets

def bind_iface(sock, ifindex):
    if not ifindex:
        return
    if sock.family == socket.AF_INET6:
        sock.setsockopt(socket.IPPROTO_IPV6, IPV6_BOUND_IF, ifindex)
    else:
        sock.setsockopt(socket.IPPROTO_IP, IP_BOUND_IF, ifindex)


async def open_bound(ip, port, ifindex, timeout):
    loop = asyncio.get_running_loop()
    fam = socket.AF_INET6 if ":" in ip else socket.AF_INET
    s = socket.socket(fam, socket.SOCK_STREAM)
    s.setblocking(False)
    try:
        bind_iface(s, ifindex)
        await asyncio.wait_for(loop.sock_connect(s, (ip, port)), timeout)
    except BaseException:
        s.close()
        raise
    return await asyncio.open_connection(sock=s)


# --------------------------------------------------------------------------- tiny DNS client

class DNSError(Exception):
    pass


def _encode_name(name):
    return b"".join(bytes([len(p)]) + p.encode("idna") for p in name.split(".") if p) + b"\x00"


def _skip_name(data, off):
    while True:
        length = data[off]
        if length == 0:
            return off + 1
        if length & 0xC0 == 0xC0:
            return off + 2
        off += 1 + length


def _parse_a(data, qid):
    if len(data) < 12:
        raise DNSError("short response")
    rid, flags, qd, an, _, _ = struct.unpack("!HHHHHH", data[:12])
    if rid != qid:
        raise DNSError("id mismatch")
    rcode = flags & 0xF
    if rcode != 0:
        raise DNSError(f"rcode {rcode}")
    off = 12
    for _ in range(qd):
        off = _skip_name(data, off) + 4
    ips, ttl = [], None
    for _ in range(an):
        off = _skip_name(data, off)
        rtype, _, rttl, rdlen = struct.unpack("!HHIH", data[off:off + 10])
        off += 10
        if rtype == 1 and rdlen == 4:
            ips.append(socket.inet_ntoa(data[off:off + 4]))
            ttl = rttl if ttl is None else min(ttl, rttl)
        off += rdlen
    if not ips:
        raise DNSError("no A records")
    return ips, (ttl if ttl is not None else 60)


async def udp_query(name, server, ifindex, timeout=3.0):
    loop = asyncio.get_running_loop()
    host, _, port = server.partition(":")
    port = int(port or 53)
    qid = random.randint(0, 0xFFFF)
    pkt = struct.pack("!HHHHHH", qid, 0x0100, 1, 0, 0, 0) + _encode_name(name) + struct.pack("!HH", 1, 1)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setblocking(False)
    try:
        bind_iface(s, ifindex)
        s.connect((host, port))
        await loop.sock_sendall(s, pkt)
        data = await asyncio.wait_for(loop.sock_recv(s, 4096), timeout)
    finally:
        s.close()
    return _parse_a(data, qid)


class Resolver:
    def __init__(self, state):
        self.state = state
        self.cache = {}  # (host, route) -> (ips, expiry)
        self._last_prune = 0.0

    def _prune(self):
        now = time.time()
        if now - self._last_prune < 60:
            return
        self._last_prune = now
        expired = [k for k, (_, exp) in self.cache.items() if exp <= now]
        for k in expired:
            del self.cache[k]

    async def resolve(self, host, route):
        self._prune()
        try:
            ipaddress.ip_address(host)
            return [host]
        except ValueError:
            pass
        key = (host, route)
        hit = self.cache.get(key)
        if hit and hit[1] > time.time():
            return hit[0]

        ifname, ifindex, servers = self.state.for_route(route)
        last_err = None
        for server in servers:
            for _ in range(2):
                try:
                    ips, ttl = await udp_query(host, server, ifindex)
                    self.cache[key] = (ips, time.time() + max(30, min(ttl, 600)))
                    return ips
                except (DNSError, OSError, asyncio.TimeoutError) as e:
                    last_err = e
        # Fall back to the system resolver (follows GlobalProtect's DNS config).
        if servers:
            log.warning("dns %s via %s(%s) failed (%s); falling back to system resolver", host, route, ifname, errstr(last_err))
        loop = asyncio.get_running_loop()
        try:
            infos = await asyncio.wait_for(
                loop.getaddrinfo(host, None, family=socket.AF_INET, type=socket.SOCK_STREAM),
                10,
            )
        except (socket.gaierror, asyncio.TimeoutError) as e:
            raise DNSError(str(e)) from e
        ips = list(dict.fromkeys(i[4][0] for i in infos))
        if not ips:
            raise DNSError("no addresses")
        self.cache[key] = (ips, time.time() + 60)
        return ips


# --------------------------------------------------------------------------- routed connect + relay

class Proxy:
    def __init__(self, cfg):
        self.cfg = cfg
        self.state = NetState(cfg)
        self.resolver = Resolver(self.state)
        self.active = 0

    async def connect(self, host, port, via):
        route = self.cfg.decide(host)
        ifname, ifindex, _ = self.state.for_route(route)
        if ifindex is None:
            log.warning("%s %s:%d -> %s but no %s interface found; dialling unbound", via, host, port, route, route)
        ips = await self.resolver.resolve(host, route)
        last_err = None
        for ip in ips:
            try:
                r, w = await open_bound(ip, port, ifindex, self.cfg.connect_timeout)
                log.info("%s %s:%d -> %s(%s) %s", via, host, port, route, ifname or "unbound", ip)
                return r, w
            except (OSError, asyncio.TimeoutError) as e:
                last_err = e
        log.warning("%s %s:%d -> %s(%s) FAILED: %s", via, host, port, route, ifname or "unbound", errstr(last_err))
        raise last_err or OSError("connect failed")

    async def _pipe(self, reader, writer, sibling_reader):
        try:
            while True:
                data = await asyncio.wait_for(reader.read(65536), self.cfg.relay_idle_timeout)
                if not data:
                    break
                writer.write(data)
                await writer.drain()
        except (ConnectionError, asyncio.IncompleteReadError, OSError, asyncio.TimeoutError):
            pass
        finally:
            try:
                if writer.can_write_eof():
                    writer.write_eof()
            except Exception:
                pass
            try:
                sibling_reader.feed_eof()
            except Exception:
                pass

    async def relay(self, r1, w1, r2, w2):
        self.active += 1
        try:
            await asyncio.gather(self._pipe(r1, w2, r2), self._pipe(r2, w1, r1))
        finally:
            self.active -= 1
            for w in (w1, w2):
                try:
                    w.close()
                    await asyncio.wait_for(w.wait_closed(), 5)
                except Exception:
                    pass

    # ---- HTTP / HTTPS proxy ------------------------------------------------

    async def handle_http(self, reader, writer):
        try:
            try:
                head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 30)
            except (asyncio.IncompleteReadError, asyncio.LimitOverrunError, asyncio.TimeoutError):
                return
            lines = head.decode("latin-1").split("\r\n")
            parts = lines[0].split()
            if len(parts) != 3:
                writer.write(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
                await writer.drain()
                return
            method, target, version = parts
            headers = [l for l in lines[1:] if l]

            if method.upper() == "CONNECT":
                host, _, port = target.rpartition(":")
                host = host.strip("[]") or target
                port = int(port) if port.isdigit() else 443
                try:
                    ur, uw = await self.connect(host, port, "CONNECT")
                except (OSError, DNSError, asyncio.TimeoutError) as e:
                    writer.write(f"HTTP/1.1 502 Bad Gateway\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\nsplitproxy: {errstr(e)}\n".encode())
                    await writer.drain()
                    return
                writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                await writer.drain()
                await self.relay(reader, writer, ur, uw)
                return

            if target.lower().startswith("http://"):
                rest = target[7:]
                hostport, slash, path = rest.partition("/")
                path = slash + path or "/"
                host, _, port = hostport.rpartition(":")
                if not host or not port.isdigit():
                    host, port = hostport, "80"
                host = host.strip("[]")
                try:
                    ur, uw = await self.connect(host, int(port), method)
                except (OSError, DNSError, asyncio.TimeoutError) as e:
                    writer.write(f"HTTP/1.1 502 Bad Gateway\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\nsplitproxy: {errstr(e)}\n".encode())
                    await writer.drain()
                    return
                drop = ("proxy-connection", "proxy-authorization", "connection", "keep-alive")
                fwd = [h for h in headers if h.split(":", 1)[0].strip().lower() not in drop]
                fwd.append("Connection: close")
                uw.write((f"{method} {path} {version}\r\n" + "\r\n".join(fwd) + "\r\n\r\n").encode("latin-1"))
                await uw.drain()
                await self.relay(reader, writer, ur, uw)
                return

            # Plain request to the proxy itself.
            await self.local_http(writer, method, target)
        except Exception as e:  # keep the server alive
            log.debug("http handler error: %r", e)
        finally:
            try:
                writer.close()
            except Exception:
                pass

    async def local_http(self, writer, method, path):
        if path.split("?")[0] in ("/", "/status"):
            body = json.dumps({**self.state.snapshot(), "active_connections": self.active,
                               "http_listen": self.cfg.http_listen, "socks_listen": self.cfg.socks_listen},
                              indent=2).encode()
            ctype = b"application/json"
        elif path.startswith("/proxy.pac"):
            h, p = self.cfg.http_listen.rsplit(":", 1)
            sh, sp = self.cfg.socks_listen.rsplit(":", 1)
            body = (
                "function FindProxyForURL(url, host) {\n"
                "  if (isPlainHostName(host) || shExpMatch(host, '*.local') || host == 'localhost'\n"
                "      || isInNet(dnsResolve(host), '127.0.0.0', '255.0.0.0')) return 'DIRECT';\n"
                f"  return 'PROXY {h}:{p}; SOCKS5 {sh}:{sp}; DIRECT';\n"
                "}\n"
            ).encode()
            ctype = b"application/x-ns-proxy-autoconfig"
        else:
            body, ctype = b"splitproxy: not found\n", b"text/plain"
            writer.write(b"HTTP/1.1 404 Not Found\r\nContent-Type: text/plain\r\nContent-Length: %d\r\nConnection: close\r\n\r\n" % len(body) + body)
            await writer.drain()
            return
        writer.write(b"HTTP/1.1 200 OK\r\nContent-Type: " + ctype + b"\r\nContent-Length: %d\r\nConnection: close\r\n\r\n" % len(body) + body)
        await writer.drain()

    # ---- SOCKS5 -------------------------------------------------------------

    async def handle_socks(self, reader, writer):
        try:
            try:
                ver, nmethods = await asyncio.wait_for(reader.readexactly(2), 30)
                await reader.readexactly(nmethods)
                if ver != 5:
                    return
                writer.write(b"\x05\x00")  # no auth
                await writer.drain()
                ver, cmd, _, atyp = await reader.readexactly(4)
                if atyp == 1:
                    host = socket.inet_ntoa(await reader.readexactly(4))
                elif atyp == 3:
                    n = (await reader.readexactly(1))[0]
                    host = (await reader.readexactly(n)).decode("idna")
                elif atyp == 4:
                    host = socket.inet_ntop(socket.AF_INET6, await reader.readexactly(16))
                else:
                    writer.write(b"\x05\x08\x00\x01" + b"\x00" * 6)
                    await writer.drain()
                    return
                port = struct.unpack("!H", await reader.readexactly(2))[0]
            except (asyncio.IncompleteReadError, asyncio.TimeoutError):
                return
            if cmd != 1:  # only CONNECT
                writer.write(b"\x05\x07\x00\x01" + b"\x00" * 6)
                await writer.drain()
                return
            try:
                ur, uw = await self.connect(host, port, "SOCKS5")
            except (OSError, DNSError, asyncio.TimeoutError):
                writer.write(b"\x05\x04\x00\x01" + b"\x00" * 6)
                await writer.drain()
                return
            writer.write(b"\x05\x00\x00\x01" + b"\x00" * 6)
            await writer.drain()
            await self.relay(reader, writer, ur, uw)
        except Exception as e:
            log.debug("socks handler error: %r", e)
        finally:
            try:
                writer.close()
            except Exception:
                pass

    # ---- lifecycle ----------------------------------------------------------

    async def refresher(self):
        while True:
            try:
                await asyncio.get_running_loop().run_in_executor(None, self.state.refresh)
            except Exception as e:
                log.warning("interface refresh failed: %r", e)
            await asyncio.sleep(self.cfg.refresh_secs)

    def _restart_refresher(self, task):
        if task.cancelled():
            return
        exc = task.exception()
        if exc:
            log.warning("refresher task crashed: %r", exc)
        self._refresher_task = asyncio.create_task(self.refresher())
        self._refresher_task.add_done_callback(self._restart_refresher)

    async def serve(self):
        self.state.refresh()
        hh, hp = self.cfg.http_listen.rsplit(":", 1)
        sh, sp = self.cfg.socks_listen.rsplit(":", 1)
        http_srv = await asyncio.start_server(self.handle_http, hh, int(hp))
        socks_srv = await asyncio.start_server(self.handle_socks, sh, int(sp))
        log.info("HTTP proxy on %s, SOCKS5 proxy on %s (status: http://%s/status)",
                 self.cfg.http_listen, self.cfg.socks_listen, self.cfg.http_listen)
        log.info("default route: %s | vpn hosts: %s | direct hosts: %s",
                 self.cfg.default_route,
                 ", ".join(r.text for r in self.cfg.vpn_rules) or "-",
                 ", ".join(r.text for r in self.cfg.direct_rules) or "-")
        self._refresher_task = asyncio.create_task(self.refresher())
        self._refresher_task.add_done_callback(self._restart_refresher)
        async with http_srv, socks_srv:
            await asyncio.gather(http_srv.serve_forever(), socks_srv.serve_forever())


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    env_file = os.path.join(here, ".env")
    args = sys.argv[1:]
    if len(args) >= 2 and args[0] in ("-e", "--env"):
        env_file = args[1]
    load_dotenv(env_file)

    logging.basicConfig(level=getattr(logging, env("LOG_LEVEL", "INFO").upper(), logging.INFO),
                        format="%(asctime)s %(levelname)s %(message)s", datefmt="%H:%M:%S")
    if sys.platform != "darwin":
        log.warning("IP_BOUND_IF is a macOS socket option; this tool is written for macOS")

    cfg = Config()
    if not cfg.vpn_rules and not cfg.direct_rules:
        log.warning("no VPN_HOSTS or DIRECT_HOSTS configured; everything will go %s", cfg.default_route)
    try:
        asyncio.run(Proxy(cfg).serve())
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()

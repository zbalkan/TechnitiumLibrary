"""Local stand-ins for the Technitium HTTP API and DNS listeners.

These are fakes of an external system, built from APIDOCS.md rather than from
the real server's behaviour. They let the scripts' own logic be tested
quickly; the fuzz-fixture workflow is the test against the real server.
"""

from __future__ import annotations

import email.parser
import email.policy
import json
import socket
import socketserver
import struct
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

# Settings that settings/get returns as JSON arrays (APIDOCS "Get DNS Settings").
LIST_SETTINGS = {
    "dnsServerLocalEndPoints", "webServiceLocalAddresses", "dnsReverseProxyNetworkACL",
    "recursionNetworkACL", "forwarders", "blockListUrls", "zoneTransferAllowedNetworks",
    "notifyAllowedNetworks", "qpmLimitBypassList",
}
TABLE_SETTINGS = {
    "qpmPrefixLimitsIPv4": ("prefix", "udpLimit", "tcpLimit"),
    "qpmPrefixLimitsIPv6": ("prefix", "udpLimit", "tcpLimit"),
    "tsigKeys": ("keyName", "sharedSecret", "algorithmName"),
}
LIST_ZONE_OPTIONS = {"zoneTransferNetworkACL", "zoneTransferTsigKeyNames", "updateNetworkACL"}
WRITE_ONLY = {"proxyType"}
NX_STATUS = {"NSEC": "SignedWithNSEC", "NSEC3": "SignedWithNSEC3"}


def _scalar(raw: str) -> Any:
    if raw in ("true", "false"):
        return raw == "true"
    if raw.lstrip("-").isdigit():
        return int(raw)
    return raw


def _table(raw: str, columns: tuple[str, ...]) -> list[dict[str, Any]]:
    if raw in ("", "false"):
        return []
    cells = raw.split("|")
    width = len(columns)
    return [
        {col: _scalar(val) for col, val in zip(columns, cells[i:i + width])}
        for i in range(0, len(cells), width)
    ]


def _list(raw: str) -> list[str]:
    return [] if raw in ("", "false") else raw.split(",")


class FakeTechnitium:
    def __init__(self, user: str, password: str) -> None:
        self.user = user
        self.password = password
        self.token = "stub-token"
        self.settings: dict[str, Any] = {}
        self.zones: dict[str, dict[str, Any]] = {}
        self.blocked: set[str] = set()
        self.fail_paths: set[str] = set()
        self.restored: list[bytes] = []
        self.calls: list[str] = []

    # -- request handling -------------------------------------------------
    def handle(self, path: str, query: dict[str, str], form: dict[str, str],
               body: bytes, auth: str | None, content_type: str) -> tuple[int, str, bytes]:
        self.calls.append(path)
        params = {**query, **form}
        if path in self.fail_paths:
            return self._json({"status": "error", "errorMessage": f"injected failure on {path}"})
        if path == "/api/user/login":
            if params.get("user") == self.user and params.get("pass") == self.password:
                return self._json({"status": "ok", "token": self.token})
            return self._json({"status": "error", "errorMessage": "Invalid username or password."})
        if auth != f"Bearer {self.token}":
            return self._json({"status": "invalid-token", "errorMessage": "Invalid token"})

        handler = getattr(self, "_" + path.removeprefix("/api/").replace("/", "_"), None)
        if handler is None:
            return 404, "text/plain", b"not found"
        return handler(params, body, content_type)

    @staticmethod
    def _json(doc: dict[str, Any]) -> tuple[int, str, bytes]:
        return 200, "application/json", json.dumps(doc).encode()

    def _ok(self, response: dict[str, Any] | None = None) -> tuple[int, str, bytes]:
        doc: dict[str, Any] = {"status": "ok"}
        if response is not None:
            doc["response"] = response
        return self._json(doc)

    def _error(self, message: str) -> tuple[int, str, bytes]:
        return self._json({"status": "error", "errorMessage": message})

    # -- settings ---------------------------------------------------------
    def _settings_set(self, params, _body, _ct):
        for key, raw in params.items():
            if key in WRITE_ONLY:
                continue
            if key in TABLE_SETTINGS:
                self.settings[key] = _table(raw, TABLE_SETTINGS[key])
            elif key in LIST_SETTINGS:
                self.settings[key] = _list(raw)
            else:
                self.settings[key] = _scalar(raw)
        return self._ok(self.settings)

    def _settings_get(self, _params, _body, _ct):
        return self._ok(dict(self.settings))

    def _settings_backup(self, _params, _body, _ct):
        return 200, "application/zip", b"PK\x03\x04stub-backup"

    def _settings_restore(self, _params, body, content_type):
        message = email.parser.BytesParser(policy=email.policy.HTTP).parsebytes(
            f"Content-Type: {content_type}\r\n\r\n".encode() + body
        )
        parts = [p.get_payload(decode=True) for p in message.iter_parts()]
        if not parts or not parts[0].startswith(b"PK"):
            return self._error("Backup zip file is missing.")
        self.restored.append(parts[0])
        return self._ok(self.settings)

    def _cache_flush(self, _params, _body, _ct):
        return self._ok()

    # -- zones ------------------------------------------------------------
    def _zones_list(self, _params, _body, _ct):
        return self._ok({"zones": [dict(z) for z in self.zones.values()]})

    def _zones_create(self, params, _body, _ct):
        name = params["zone"]
        if name in self.zones:
            return self._error(f"Zone already exists: {name}")
        self.zones[name] = {"name": name, "type": params.get("type", "Primary"),
                            "dnssecStatus": "Unsigned", "records": ""}
        return self._ok({"domain": name})

    def _zones_delete(self, params, _body, _ct):
        if self.zones.pop(params["zone"], None) is None:
            return self._error("No such zone was found.")
        return self._ok()

    def _zones_import(self, params, body, content_type):
        zone = self.zones.get(params["zone"])
        if zone is None:
            return self._error("No such zone was found.")
        if not content_type.startswith("text/plain"):
            return self._error("Zone file content type must be text/plain.")
        zone["records"] = body.decode()
        return self._ok()

    def _zones_dnssec_sign(self, params, _body, _ct):
        zone = self.zones.get(params["zone"])
        if zone is None:
            return self._error("No such zone was found.")
        zone["dnssecStatus"] = NX_STATUS[params.get("nxProof", "NSEC")]
        return self._ok()

    def _zones_options_get(self, params, _body, _ct):
        zone = self.zones.get(params["zone"])
        if zone is None:
            return self._error("No such zone was found.")
        return self._ok({k: v for k, v in zone.items() if k != "records"})

    def _zones_options_set(self, params, _body, _ct):
        zone = self.zones.get(params["zone"])
        if zone is None:
            return self._error("No such zone was found.")
        for key, raw in params.items():
            if key == "zone":
                continue
            if key == "updateSecurityPolicies":
                rows = _table(raw, ("tsigKeyName", "domain", "allowedTypes"))
                for row in rows:
                    row["allowedTypes"] = str(row["allowedTypes"]).split(",")
                zone[key] = rows
            elif key in LIST_ZONE_OPTIONS:
                zone[key] = _list(raw)
            else:
                zone[key] = _scalar(raw)
        return self._ok()

    def _blocked_add(self, params, _body, _ct):
        self.blocked.add(params["domain"])
        return self._ok()


def start_api(fake: FakeTechnitium) -> tuple[ThreadingHTTPServer, str]:
    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:  # noqa: N802 - http.server naming
            url = urllib.parse.urlsplit(self.path)
            query = dict(urllib.parse.parse_qsl(url.query, keep_blank_values=True))
            body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
            content_type = self.headers.get("Content-Type", "")
            form = (dict(urllib.parse.parse_qsl(body.decode(), keep_blank_values=True))
                    if content_type.startswith("application/x-www-form-urlencoded") else {})
            status, ctype, payload = fake.handle(
                url.path, query, form, body, self.headers.get("Authorization"), content_type
            )
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, *_args) -> None:
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, f"http://127.0.0.1:{server.server_address[1]}"


# -- DNS --------------------------------------------------------------------

def _qname(msg: bytes) -> str:
    labels, pos = [], 12
    while msg[pos]:
        length = msg[pos]
        labels.append(msg[pos + 1:pos + 1 + length].decode())
        pos += 1 + length
    return ".".join(labels)


def dns_answer(fake: FakeTechnitium, query: bytes) -> bytes:
    txid = struct.unpack("!H", query[:2])[0]
    rd = bool(struct.unpack("!H", query[2:4])[0] & 0x0100)
    name = _qname(query)
    if name in fake.zones:
        flags, ancount = 0x8400, 1  # QR + AA, NOERROR
    elif (name in fake.blocked and fake.settings.get("enableBlocking") is True and rd and
          (fake.settings.get("recursion") == "Allow" or
           (fake.settings.get("recursion") == "UseSpecifiedNetworkACL" and
            "127.0.0.1" in fake.settings.get("recursionNetworkACL", [])))):
        flags, ancount = 0x8003, 0  # QR, NXDOMAIN
    else:
        flags, ancount = 0x8005, 0  # QR, REFUSED
    response = struct.pack("!HHHHHH", txid, flags, 1, ancount, 0, 0) + query[12:]
    if ancount:
        rdata = b"\x00\x00" + struct.pack("!IIIII", 1, 3600, 600, 86400, 300)
        response += b"\xc0\x0c" + struct.pack("!HHIH", 6, 1, 300, len(rdata)) + rdata
    return response


class _UdpHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        data, sock = self.request
        sock.sendto(dns_answer(self.server.fake, data), self.client_address)


class _TcpHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        def read_exact(size):
            data = bytearray()
            while len(data) < size:
                chunk = self.request.recv(size - len(data))
                if not chunk:
                    return None
                data.extend(chunk)
            return bytes(data)

        prefix = read_exact(2)
        if prefix is None:
            return
        length = struct.unpack("!H", prefix)[0]
        packet = read_exact(length)
        if packet is None:
            return
        reply = dns_answer(self.server.fake, packet)
        self.request.sendall(struct.pack("!H", len(reply)) + reply)


def start_dns(fake: FakeTechnitium) -> tuple[list[socketserver.BaseServer], int]:
    # Bind TCP first on a free port, then UDP on the same number.
    tcp = socketserver.ThreadingTCPServer(("127.0.0.1", 0), _TcpHandler)
    port = tcp.server_address[1]
    udp = socketserver.ThreadingUDPServer(("127.0.0.1", port), _UdpHandler)
    for server in (tcp, udp):
        server.fake = fake
        threading.Thread(target=server.serve_forever, daemon=True).start()
    return [tcp, udp], port


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]

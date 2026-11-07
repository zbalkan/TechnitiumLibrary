"""Minimal Technitium DNS Server HTTP API client for the fuzzing fixture.

Standard library only, so CI needs no package installation step. Every call
goes through ``Client.call``, which raises unless the JSON ``status`` is
``ok``: the API reports failures in the body while still answering HTTP 200.
"""

from __future__ import annotations

import json
import os
import re
import socket
import struct
import tomllib
import urllib.error
import urllib.parse
import urllib.request
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# Parameters that the API documents as clearable with the literal "false".
CLEARABLE_SETTINGS = frozenset(
    {
        "qpmPrefixLimitsIPv4",
        "qpmPrefixLimitsIPv6",
        "tsigKeys",
        "recursionNetworkACL",
        "blockListUrls",
        "forwarders",
    }
)
CLEARABLE_ZONE_OPTIONS = frozenset(
    {
        "zoneTransferNetworkACL",
        "zoneTransferTsigKeyNames",
        "updateNetworkACL",
        "updateSecurityPolicies",
    }
)

_ENV_REF = re.compile(r"\$\{ENV:([A-Za-z_]\w*)\}", flags=re.ASCII)


class ApiError(RuntimeError):
    """The API answered, but not with ``status: ok``."""


class FixtureError(RuntimeError):
    """The profile or zone data is inconsistent."""


# --------------------------------------------------------------------------
# HTTP client
# --------------------------------------------------------------------------


class Client:
    def __init__(self, base_url: str, timeout: float = 30.0) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.token: str | None = None

    def _request(
        self, path: str, body: bytes, content_type: str, query: dict[str, str] | None = None
    ) -> bytes:
        url = f"{self.base_url}{path}"
        if query:
            url = f"{url}?{urllib.parse.urlencode(query)}"
        headers = {"Content-Type": content_type}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        req = urllib.request.Request(url, data=body, headers=headers, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                return resp.read()
        except urllib.error.HTTPError as exc:
            raise ApiError(f"{path}: HTTP {exc.code}") from exc

    @staticmethod
    def _decode(path: str, raw: bytes) -> dict[str, Any]:
        try:
            doc = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise ApiError(f"{path}: response is not JSON") from exc
        if not isinstance(doc, dict):
            raise ApiError(f"{path}: expected a JSON object")
        status = doc.get("status")
        if status != "ok":
            message = doc.get("errorMessage") or doc.get("innerErrorMessage") or status
            raise ApiError(f"{path}: {message}")
        return doc

    def call(self, path: str, params: dict[str, str] | None = None) -> dict[str, Any]:
        body = urllib.parse.urlencode(params or {}).encode()
        raw = self._request(path, body, "application/x-www-form-urlencoded")
        return self._decode(path, raw)

    def call_text(self, path: str, query: dict[str, str], text: str) -> dict[str, Any]:
        raw = self._request(path, text.encode(), "text/plain", query)
        return self._decode(path, raw)

    def call_upload(
        self, path: str, query: dict[str, str], field_name: str, filename: str, data: bytes
    ) -> dict[str, Any]:
        boundary = uuid.uuid4().hex
        body = b"".join(
            [
                f"--{boundary}\r\n".encode(),
                f'Content-Disposition: form-data; name="{field_name}"; filename="{filename}"\r\n'.encode(),
                b"Content-Type: application/zip\r\n\r\n",
                data,
                f"\r\n--{boundary}--\r\n".encode(),
            ]
        )
        raw = self._request(path, body, f"multipart/form-data; boundary={boundary}", query)
        return self._decode(path, raw)

    def download(self, path: str, params: dict[str, str]) -> bytes:
        body = urllib.parse.urlencode(params).encode()
        raw = self._request(path, body, "application/x-www-form-urlencoded")
        if raw[:1] == b"{":
            # A JSON body here means the call failed instead of returning a zip.
            self._decode(path, raw)
            raise ApiError(f"{path}: expected a file, got JSON")
        return raw

    def login(self, user: str, password: str) -> None:
        doc = self.call("/api/user/login", {"user": user, "pass": password})
        token = doc.get("token")
        if not token:
            raise ApiError("/api/user/login: no token in response")
        self.token = token


def client_from_env(timeout: float = 30.0) -> Client:
    """Build and log in a client from FIXTURE_* environment variables."""
    base_url = os.environ.get("FIXTURE_API_URL", "http://127.0.0.1:5380")
    user = os.environ.get("FIXTURE_API_USER", "admin")
    password = _password_from_env()
    client = Client(base_url, timeout=timeout)
    client.login(user, password)
    return client


def _password_from_env() -> str:
    path = os.environ.get("FIXTURE_API_PASSWORD_FILE")
    if path:
        return Path(path).read_text(encoding="utf-8").strip()
    password = os.environ.get("FIXTURE_API_PASSWORD")
    if not password:
        raise FixtureError("set FIXTURE_API_PASSWORD_FILE or FIXTURE_API_PASSWORD")
    return password


# --------------------------------------------------------------------------
# Profiles
# --------------------------------------------------------------------------


@dataclass
class Zone:
    name: str
    type: str
    file: Path | None
    sign: dict[str, Any] | None
    options: dict[str, Any]


@dataclass
class Profile:
    name: str
    settings: dict[str, Any] = field(default_factory=dict)
    settings_write_only: dict[str, Any] = field(default_factory=dict)
    zones: list[Zone] = field(default_factory=list)
    blocked: list[str] = field(default_factory=list)


def load_profile(path: Path) -> Profile:
    """Load a profile, applying its ``extends`` chain (base first)."""
    return _load(path.resolve(), seen=set())


def _load(path: Path, seen: set[Path]) -> Profile:
    if path in seen:
        raise FixtureError(f"profile inheritance loop at {path}")
    seen.add(path)
    with path.open("rb") as fh:
        doc = tomllib.load(fh)

    meta = doc.get("meta", {})
    parent_ref = meta.get("extends")
    profile = _load((path.parent / parent_ref).resolve(), seen) if parent_ref else Profile(name="")
    profile.name = meta.get("name", path.stem)

    profile.settings.update(_expand(doc.get("settings", {})))
    profile.settings_write_only.update(_expand(doc.get("settings_write_only", {})))

    zones_by_name = {z.name: z for z in profile.zones}
    for entry in doc.get("zones", []):
        zone_file = entry.get("file")
        zones_by_name[entry["name"]] = Zone(
            name=entry["name"],
            type=entry.get("type", "Primary"),
            file=(path.parent / zone_file).resolve() if zone_file else None,
            sign=entry.get("sign"),
            options=_expand(entry.get("options", {})),
        )
    # A variant can change options of an inherited zone without restating it.
    for zone_name, overrides in doc.get("zone_options", {}).items():
        if zone_name not in zones_by_name:
            raise FixtureError(f"{path.name}: zone_options for unknown zone {zone_name}")
        zones_by_name[zone_name].options.update(_expand(overrides))
    profile.zones = list(zones_by_name.values())

    blocked = doc.get("blocked", {}).get("domains", [])
    profile.blocked = sorted(set(profile.blocked) | set(blocked))
    return profile


def _expand(value: Any) -> Any:
    """Replace ${ENV:NAME} references so secrets stay out of the profile files."""
    if isinstance(value, str):
        def repl(match: re.Match[str]) -> str:
            name = match.group(1)
            if name not in os.environ:
                raise FixtureError(f"environment variable {name} is not set")
            return os.environ[name]

        return _ENV_REF.sub(repl, value)
    if isinstance(value, list):
        return [_expand(v) for v in value]
    if isinstance(value, dict):
        return {k: _expand(v) for k, v in value.items()}
    return value


# --------------------------------------------------------------------------
# Serialisation (profile shape -> settings/set and zones/options/set form)
# --------------------------------------------------------------------------


def to_form_value(key: str, value: Any, clearable: frozenset[str]) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if value is None:
        return ""
    if isinstance(value, (int, float, str)):
        return str(value)
    if isinstance(value, list):
        if not value:
            return "false" if key in clearable else ""
        if all(isinstance(v, dict) for v in value):
            return "|".join(_row(key, v) for v in value)
        return ",".join(str(v) for v in value)
    raise FixtureError(f"{key}: unsupported value type {type(value).__name__}")


def _row(key: str, item: dict[str, Any]) -> str:
    # The API uses '|' as both row and column separator for these tables.
    if key in ("qpmPrefixLimitsIPv4", "qpmPrefixLimitsIPv6"):
        return f"{item['prefix']}|{item['udpLimit']}|{item['tcpLimit']}"
    if key == "tsigKeys":
        return f"{item['keyName']}|{item['sharedSecret']}|{item['algorithmName']}"
    if key == "updateSecurityPolicies":
        types = ",".join(item["allowedTypes"])
        return f"{item['tsigKeyName']}|{item['domain']}|{types}"
    raise FixtureError(f"{key}: no table serialiser for this key")


def settings_form(profile: Profile) -> dict[str, str]:
    merged = {**profile.settings, **profile.settings_write_only}
    return {k: to_form_value(k, v, CLEARABLE_SETTINGS) for k, v in merged.items()}


def zone_options_form(zone: Zone) -> dict[str, str]:
    form = {k: to_form_value(k, v, CLEARABLE_ZONE_OPTIONS) for k, v in zone.options.items()}
    form["zone"] = zone.name
    return form


# --------------------------------------------------------------------------
# Comparison (profile shape vs settings/get and zones/options/get)
# --------------------------------------------------------------------------


_EMPTY = object()


def _normalise(value: Any) -> Any:
    # The server reports "unset" as null, "" or [] depending on the field;
    # the profile can only express "" or []. Treat all three as one value.
    if value is None or value == "" or value == []:
        return _EMPTY
    if isinstance(value, dict):
        return {k: _normalise(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_normalise(v) for v in value]
    return value


def diff(expected: dict[str, Any], actual: dict[str, Any], scope: str) -> list[str]:
    """Return one line per mismatch; keys missing from ``actual`` are mismatches."""
    problems: list[str] = []
    for key, want in expected.items():
        if key not in actual:
            problems.append(f"{scope}.{key}: not reported by the server (move it to a write-only table?)")
            continue
        exp_norm, act_norm = _normalise(want), _normalise(actual[key])
        if exp_norm != act_norm:
            problems.append(f"{scope}.{key}: expected {want!r}, server has {actual[key]!r}")
    return problems


# --------------------------------------------------------------------------
# DNS smoke query (stdlib only) to prove the UDP and TCP listeners answer
# --------------------------------------------------------------------------

QTYPE_SOA = 6


def build_query(qname: str, qtype: int, txid: int, *, recursion_desired: bool = False) -> bytes:
    # Authoritative checks use RD=0; blocked-domain checks must request
    # recursion to reach Technitium's blocking handler.
    flags = 0x0100 if recursion_desired else 0x0000
    header = struct.pack("!HHHHHH", txid, flags, 1, 0, 0, 0)
    labels = b"".join(
        bytes([len(part)]) + part.encode("ascii") for part in qname.rstrip(".").split(".") if part
    )
    return header + labels + b"\x00" + struct.pack("!HH", qtype, 1)


@dataclass
class DnsReply:
    txid: int
    aa: bool
    rcode: int
    ancount: int
    answer_types: tuple[int, ...] = ()


def _skip_pointer(data: bytes, offset: int, label: int) -> int:
    if offset >= len(data):
        raise FixtureError("truncated compression pointer")
    target = ((label & 0x3F) << 8) | data[offset]
    if target >= len(data):
        raise FixtureError("out-of-range compression pointer")
    return offset + 1


def _skip_label(data: bytes, offset: int, label: int, wire_length: int) -> int:
    if wire_length + label + 1 > 255 or offset + label > len(data):
        raise FixtureError("truncated or oversized name")
    return offset + label


def _skip_name(data: bytes, offset: int) -> int:
    wire_length = 0
    while True:
        if offset >= len(data):
            raise FixtureError("truncated DNS name")
        label = data[offset]
        offset += 1
        if label & 0xC0 == 0xC0:
            return _skip_pointer(data, offset, label)
        if label & 0xC0:
            raise FixtureError("invalid label type")
        if label == 0:
            return offset
        offset = _skip_label(data, offset, label, wire_length)
        wire_length += label + 1


def _skip_questions(data: bytes, offset: int, count: int) -> int:
    for _ in range(count):
        offset = _skip_name(data, offset)
        if offset + 4 > len(data):
            raise FixtureError("truncated DNS question")
        offset += 4
    return offset


def _validate_soa(data: bytes, offset: int, rdlength: int) -> None:
    end = offset + rdlength
    soa_pos = _skip_name(data, offset)
    if soa_pos > end:
        raise FixtureError("invalid SOA MNAME")
    soa_pos = _skip_name(data, soa_pos)
    if soa_pos + 20 != end:
        raise FixtureError("invalid SOA RDATA")


def _read_records(data: bytes, offset: int, count: int, answers: int) -> tuple[int, tuple[int, ...]]:
    answer_types = []
    for index in range(count):
        offset = _skip_name(data, offset)
        if offset + 10 > len(data):
            raise FixtureError("truncated DNS resource record")
        rrtype, _, _, rdlength = struct.unpack_from("!HHIH", data, offset)
        offset += 10
        if offset + rdlength > len(data):
            raise FixtureError("truncated DNS RDATA")
        if index < answers:
            if rrtype == QTYPE_SOA:
                _validate_soa(data, offset, rdlength)
            answer_types.append(rrtype)
        offset += rdlength
    return offset, tuple(answer_types)


def parse_reply_header(data: bytes) -> DnsReply:
    if len(data) < 12:
        raise FixtureError("DNS reply shorter than a header")
    txid, flags, questions, answers, authority, additional = struct.unpack("!HHHHHH", data[:12])
    if not flags & 0x8000:
        raise FixtureError("DNS packet is not a response")
    if flags & 0x0200:
        raise FixtureError("truncated DNS response")
    offset = _skip_questions(data, 12, questions)
    offset, types = _read_records(data, offset, answers + authority + additional, answers)
    if offset != len(data):
        raise FixtureError("trailing bytes in DNS response")
    return DnsReply(txid=txid, aa=bool(flags & 0x0400), rcode=flags & 0x000F,
                    ancount=answers, answer_types=types)


def query_udp(host: str, port: int, qname: str, qtype: int, timeout: float = 3.0,
              *, recursion_desired: bool = False) -> DnsReply:
    txid = int.from_bytes(os.urandom(2), "big")
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(timeout)
        sock.sendto(build_query(qname, qtype, txid, recursion_desired=recursion_desired), (host, port))
        data, _ = sock.recvfrom(65535)
    reply = parse_reply_header(data)
    if reply.txid != txid:
        raise FixtureError(f"UDP reply ID mismatch for {qname}")
    return reply


def query_tcp(host: str, port: int, qname: str, qtype: int, timeout: float = 3.0,
              *, recursion_desired: bool = False) -> DnsReply:
    txid = int.from_bytes(os.urandom(2), "big")
    msg = build_query(qname, qtype, txid, recursion_desired=recursion_desired)
    with socket.create_connection((host, port), timeout=timeout) as sock:
        sock.sendall(struct.pack("!H", len(msg)) + msg)
        length = struct.unpack("!H", _recv_exact(sock, 2))[0]
        data = _recv_exact(sock, length)
    reply = parse_reply_header(data)
    if reply.txid != txid:
        raise FixtureError(f"TCP reply ID mismatch for {qname}")
    return reply


def _recv_exact(sock: socket.socket, size: int) -> bytes:
    chunks = bytearray()
    while len(chunks) < size:
        chunk = sock.recv(size - len(chunks))
        if not chunk:
            raise FixtureError("TCP connection closed mid-message")
        chunks.extend(chunk)
    return bytes(chunks)

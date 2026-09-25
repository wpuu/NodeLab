"""Real probe: start Mihomo, measure latency, verify exit IPs via two sources.

All output is redacted; no secret ever reaches a result dict, log, or error.
"""

from __future__ import annotations

import json
import os
import socket
from pathlib import Path

import httpx

from nodelab.mihomo_config import DELAY_URL, PROBE_GROUP, write_probe_config
from nodelab.mihomo_process import MihomoProcess, find_mihomo_exe, test_config
from nodelab.parser import redact_uri
from nodelab.redaction import redacted_node_dict, redacted_result_dict
from nodelab.types import ParsedNode

IP_INFO_LITE_URL = "https://ipinfo.io/{ip}"
_IPIFY = "https://api.ipify.org?format=json"
_CF_TRACE = "https://www.cloudflare.com/cdn-cgi/trace"


def resolve_entry(host: str, port: int) -> list[str]:
    """Local DNS resolution of entry host; returns IP strings or []."""
    if not host:
        return []
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        ips: list[str] = []
        for info in infos:
            ip = info[4][0]
            if ip not in ips:
                ips.append(ip)
        return ips
    except Exception:  # noqa: BLE001
        return []


def _delay_via_controller(controller: str, secret: str, group: str = PROBE_GROUP) -> tuple[int | None, str | None]:
    url = f"{controller}/proxies/{group}/delay"
    headers = {}
    if secret:
        headers["Authorization"] = f"Bearer {secret}"
    try:
        with httpx.Client(timeout=30) as client:
            r = client.get(url, params={"url": DELAY_URL, "timeout": 5000}, headers=headers)
            if r.status_code != 200:
                return None, f"delay HTTP {r.status_code}: {redact_uri(r.text[:200])}"
            data = r.json()
            latency = (data or {}).get("delay")
            if latency and isinstance(latency, (int, float)) and latency > 0:
                return int(latency), None
            return None, "delay endpoint returned no usable value"
    except Exception as exc:  # noqa: BLE001
        return None, f"delay request failed: {redact_uri(str(exc))}"


def _cloudflare_exit_ip(client: httpx.Client) -> str | None:
    r = client.get(_CF_TRACE, timeout=30)
    if r.status_code != 200:
        return None
    for line in r.text.splitlines():
        if line.startswith("ip="):
            return line.split("=", 1)[1].strip()
    return None


def probe_node(node: ParsedNode) -> dict:
    """Full probe of one node; returns a redacted result dict."""
    base = redacted_node_dict(node)
    base.update(
        {
            "resolved_entry_ips": resolve_entry(node.entry_host, node.entry_port),
            "config_ok": False,
            "proxy_http_ok": False,
            "exit_ip_source_1": None,
            "exit_ip_source_2": None,
            "sources_agree": None,
            "entry_exit_same": None,
            "latency_ms": None,
            "ipinfo_status": "SKIPPED_NO_TOKEN",
            "country": None,
            "country_code": None,
            "asn": None,
            "as_name": None,
            "probe_status": "FAIL",
            "error": None,
            "errors": [],
        }
    )

    exe = find_mihomo_exe()
    if exe is None:
        base["error"] = "mihomo.exe not found (run bootstrap_mihomo.ps1 first)"
        return redacted_result_dict(base)

    config_path, controller_secret, mixed_port, controller_port, group = write_probe_config(node)
    proc: MihomoProcess | None = None
    proxy_client: httpx.Client | None = None
    try:
        ok, err = test_config(exe, config_path)
        if not ok:
            base["error"] = f"config test failed: {err}"
            return redacted_result_dict(base)
        base["config_ok"] = True

        proc = MihomoProcess.start(exe, config_path, wait_seconds=8)
        controller = f"http://127.0.0.1:{controller_port}"
        latency, latency_err = _delay_via_controller(controller, controller_secret, group)
        if latency is not None:
            base["latency_ms"] = latency
        elif latency_err:
            base["errors"].append(latency_err)

        proxy_client = httpx.Client(timeout=30, proxy=f"http://127.0.0.1:{mixed_port}")

        try:
            r1 = proxy_client.get(_IPIFY, timeout=30)
            base["exit_ip_source_1"] = r1.json().get("ip") if r1.status_code == 200 else None
        except Exception as exc:  # noqa: BLE001
            base["errors"].append(f"ipify: {redact_uri(str(exc))}")

        try:
            base["exit_ip_source_2"] = _cloudflare_exit_ip(proxy_client)
        except Exception as exc:  # noqa: BLE001
            base["errors"].append(f"cloudflare trace: {redact_uri(str(exc))}")

        src1 = base["exit_ip_source_1"]
        src2 = base["exit_ip_source_2"]
        if src1 and src2:
            base["sources_agree"] = src1 == src2
            confirmed = src1
        elif src1 or src2:
            confirmed = src1 or src2
        else:
            confirmed = None

        if confirmed:
            base["proxy_http_ok"] = True
            entry_ips = base.get("resolved_entry_ips") or []
            base["entry_exit_same"] = (confirmed in entry_ips) if entry_ips else None
            token = os.environ.get("IPINFO_TOKEN", "").strip()
            if token:
                try:
                    r3 = proxy_client.get(
                        IP_INFO_LITE_URL.format(ip=confirmed),
                        headers={"Authorization": f"Bearer {token}"},
                        timeout=20,
                    )
                    if r3.status_code == 200:
                        j = r3.json()
                        base["country"] = j.get("country")
                        base["country_code"] = j.get("country_code")
                        base["asn"] = j.get("asn")
                        base["as_name"] = j.get("org") or j.get("as_name")
                        base["ipinfo_status"] = "OK"
                    else:
                        base["ipinfo_status"] = f"HTTP_{r3.status_code}"
                except Exception as exc:  # noqa: BLE001
                    base["ipinfo_status"] = f"ERROR: {redact_uri(str(exc))}"
        else:
            base["proxy_http_ok"] = False

        if src1 and src2 and src1 == src2:
            base["probe_status"] = "PASS"
        elif src1 or src2:
            base["probe_status"] = "PARTIAL"
        else:
            base["probe_status"] = "FAIL"
        return redacted_result_dict(base)
    except Exception as exc:  # noqa: BLE001
        base["error"] = f"probe failed: {redact_uri(str(exc))}"
        base["probe_status"] = "FAIL"
        return redacted_result_dict(base)
    finally:
        if proxy_client is not None:
            try:
                proxy_client.close()
            except Exception:  # noqa: BLE001
                pass
        if proc is not None:
            proc.close()


def probe_from_file(path: str, limit: int = 2) -> list[dict]:
    from nodelab.parser import parse_uris

    text = Path(path).read_text(encoding="utf-8")
    nodes = [n for n in parse_uris(text) if n is not None]
    return [probe_node(node) for node in nodes[: max(0, limit)]]


def save_probe_results(results: list[dict], out_dir: str = "data/probe-results") -> Path:
    out_path = Path(out_dir)
    out_path.mkdir(parents=True, exist_ok=True)
    target = out_path / "latest.json"
    target.write_text(json.dumps(results, indent=2, ensure_ascii=False), encoding="utf-8")
    return target

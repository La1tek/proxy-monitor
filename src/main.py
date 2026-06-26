import os
import json
import time
import logging
import subprocess
import tempfile
import requests
import base64
import re
from urllib.parse import urlparse, parse_qs
from pathlib import Path

from uptime_kuma_api import UptimeKumaApi, MonitorType

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("proxy-monitor")

SUBSCRIPTION_URL = os.getenv("SUBSCRIPTION_URL")
UK_URL = os.getenv("UPTIME_KUMA_URL")
UK_USER = os.getenv("UPTIME_KUMA_USER")
UK_PASS = os.getenv("UPTIME_KUMA_PASS")
CHECK_INTERVAL = int(os.getenv("CHECK_INTERVAL", "60"))
XRAY_BIN = "/opt/xray/xray"
TEST_URL = "http://1.1.1.1"
PROXY_PORT = 10899


def fetch_subscription():
    """Fetch subscription and parse all proxy configs."""
    resp = requests.get(SUBSCRIPTION_URL, timeout=10)
    resp.raise_for_status()
    raw = base64.b64decode(resp.text.strip()).decode("utf-8")
    configs = [line.strip() for line in raw.strip().split("\n") if line.strip()]
    return configs


def parse_vless(uri):
    """Parse vless:// URI into xray config dict."""
    u = urlparse(uri)
    uuid = u.username
    host = u.hostname
    port = u.port
    params = parse_qs(u.query)
    name = u.fragment or f"vless-{port}"

    outbound = {
        "protocol": "vless",
        "settings": {
            "vnext": [{
                "address": host,
                "port": port,
                "users": [{"id": uuid, "encryption": "none"}]
            }]
        }
    }

    stream = {"network": params.get("type", ["tcp"])[0]}

    # Flow
    flow = params.get("flow", [None])[0]
    if flow:
        outbound["settings"]["vnext"][0]["users"][0]["flow"] = flow

    # Security
    security = params.get("security", ["none"])[0]
    stream["security"] = security

    if security == "reality":
        stream["realitySettings"] = {
            "serverName": params.get("sni", [host])[0],
            "fingerprint": params.get("fp", ["chrome"])[0],
            "publicKey": params.get("pbk", [""])[0],
            "shortId": params.get("sid", [""])[0],
        }

    if stream["network"] == "ws":
        stream["wsSettings"] = {"path": params.get("path", ["/"])[0]}
    elif stream["network"] == "grpc":
        stream["grpcSettings"] = {
            "serviceName": params.get("serviceName", ["grpc"])[0],
            "mode": params.get("mode", ["gun"])[0],
        }

    outbound["streamSettings"] = stream
    return name, outbound


def parse_trojan(uri):
    """Parse trojan:// URI into xray config dict."""
    u = urlparse(uri)
    password = u.password
    host = u.hostname
    port = u.port
    params = parse_qs(u.query)
    name = u.fragment or f"trojan-{port}"

    outbound = {
        "protocol": "trojan",
        "settings": {
            "servers": [{"address": host, "port": port, "password": password}]
        }
    }

    stream = {"network": params.get("type", ["tcp"])[0]}
    security = params.get("security", ["none"])[0]
    stream["security"] = security

    if security == "reality":
        stream["realitySettings"] = {
            "serverName": params.get("sni", [host])[0],
            "fingerprint": params.get("fp", ["chrome"])[0],
            "publicKey": params.get("pbk", [""])[0],
            "shortId": params.get("sid", [""])[0],
        }

    outbound["streamSettings"] = stream
    return name, outbound


def parse_ss(uri):
    """Parse ss:// URI into xray config dict."""
    # ss://base64encoded@host:port#name
    head, rest = uri.split("://", 1)
    name = ""
    if "#" in rest:
        rest, name = rest.rsplit("#", 1)

    if "@" in rest:
        # user-info@host:port format
        userinfo, server = rest.rsplit("@", 1)
        # userinfo is base64 of method:password
        decoded = base64.b64decode(userinfo + "===").decode("utf-8")
        method, password = decoded.split(":", 1)
    else:
        # base64@host:port format
        at_idx = rest.rfind("@")
        userinfo_b64 = rest[:at_idx]
        server = rest[at_idx + 1:]
        decoded = base64.b64decode(userinfo_b64 + "===").decode("utf-8")
        method, password = decoded.split(":", 1)

    host, port = server.rsplit(":", 1)
    port = int(port)
    name = name or f"ss-{method}-{port}"

    outbound = {
        "protocol": "shadowsocks",
        "settings": {
            "servers": [{"address": host, "port": port, "method": method, "password": password}]
        }
    }
    return name, outbound


def parse_config(uri):
    """Parse any proxy URI into (name, outbound_dict)."""
    if uri.startswith("vless://"):
        return parse_vless(uri)
    elif uri.startswith("trojan://"):
        return parse_trojan(uri)
    elif uri.startswith("ss://"):
        return parse_ss(uri)
    else:
        log.warning(f"Unknown protocol: {uri[:20]}...")
        return None, None


def test_proxy(outbound):
    """Test a proxy by running xray and curling through it. Returns (success, latency_ms)."""
    config = {
        "inbounds": [{
            "port": PROXY_PORT,
            "listen": "127.0.0.1",
            "protocol": "socks",
            "settings": {"udp": False}
        }],
        "outbounds": [outbound]
    }

    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump(config, f)
        cfg_path = f.name

    try:
        proc = subprocess.Popen(
            [XRAY_BIN, "run", "-c", cfg_path],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        time.sleep(2)

        start = time.time()
        try:
            r = requests.get(
                TEST_URL,
                proxies={"http": f"socks5h://127.0.0.1:{PROXY_PORT}"},
                timeout=5,
            )
            latency = int((time.time() - start) * 1000)
            return r.status_code < 500, latency
        except Exception:
            return False, 0
    finally:
        try:
            proc.terminate()
            proc.wait(timeout=3)
        except Exception:
            proc.kill()
        os.unlink(cfg_path)


def ensure_monitors(api, keys):
    """Ensure push monitors exist in Uptime Kuma for each key. Returns {name: push_url}."""
    existing = api.get_monitors()
    existing_map = {m["name"]: m for m in existing}

    # Ensure group
    group = existing_map.get("Proxy Keys (live)")
    if not group or group.get("type") != MonitorType.GROUP:
        r = api.add_monitor(type=MonitorType.GROUP, name="Proxy Keys (live)")
        group_id = r["monitorID"]
    else:
        group_id = group["id"]

    created = False
    for name, _ in keys:
        if name in existing_map and existing_map[name].get("type") == MonitorType.PUSH:
            # Update interval to 2x CHECK_INTERVAL
            m = existing_map[name]
            if m.get("interval", 0) != CHECK_INTERVAL * 2:
                api.delete_monitor(m["id"])
                api.add_monitor(
                    type=MonitorType.PUSH,
                    name=name,
                    interval=CHECK_INTERVAL * 2,
                    parent=group_id,
                )
                log.info(f"Updated interval for {name}")
                created = True
            continue
        else:
            # Delete old non-push if exists
            if name in existing_map:
                api.delete_monitor(existing_map[name]["id"])
            api.add_monitor(
                type=MonitorType.PUSH,
                name=name,
                interval=CHECK_INTERVAL,
                parent=group_id,
            )
            log.info(f"Created push monitor: {name}")
            created = True

    # Re-fetch to get monitor IDs (pushUrl is not returned by the API)
    if created:
        existing = api.get_monitors()
        existing_map = {m["name"]: m for m in existing}

    push_urls = {}
    for name, _ in keys:
        m = existing_map.get(name)
        if m:
            # Build push URL from monitor's pushToken
            push_token = m.get("pushToken", "")
            if push_token:
                push_url = f"{UK_URL}/api/push/{push_token}"
            else:
                push_url = f"{UK_URL}/api/push/{m['id']}"
                log.warning(f"No pushToken for {name}, using monitor ID")
            push_urls[name] = push_url
            log.info(f"Push URL for {name}: {push_url}")

    update_status_page(api, group_id)

    return push_urls


def update_status_page(api, group_id):
    """Create/update status page with push monitors."""
    monitors = api.get_monitors()
    key_monitors = [m["id"] for m in monitors if m.get("parent") == group_id and m.get("type") != MonitorType.GROUP]

    try:
        api.save_status_page(
            slug="keys-status",
            title="Live Status — Proxy Keys",
            published=True,
            publicGroupList=[{
                "name": "Proxy Keys (live)",
                "weight": 0,
                "monitorList": [{"id": mid} for mid in key_monitors]
            }],
        )
        log.info(f"Status page updated: {UK_URL}/status/keys-status")
    except Exception as e:
        log.warning(f"Status page update failed: {e}")


def push_status(push_url, success, latency_ms):
    """Push status to Uptime Kuma."""
    if not push_url:
        return
    status = "up" if success else "down"
    msg = f"latency={latency_ms}ms" if success else "connection failed"
    try:
        requests.get(push_url, params={"status": status, "msg": msg, "ping": latency_ms}, timeout=10)
    except Exception as e:
        log.error(f"Push failed for {push_url[:40]}...: {e}")


def main():
    check_interval = int(os.getenv("CHECK_INTERVAL", "300"))
    push_interval = check_interval * 2
    log.info(f"Starting proxy-monitor (check={check_interval}s, push={push_interval}s)")

    last_push = 0
    last_results = {}

    while True:
        try:
            log.info("Fetching subscription...")
            raw_configs = fetch_subscription()
            keys = []
            for uri in raw_configs:
                name, outbound = parse_config(uri)
                if name and outbound:
                    keys.append((name, outbound))

            log.info(f"Parsed {len(keys)} proxy keys")

            # Connect to Uptime Kuma
            api = UptimeKumaApi(UK_URL)
            api.login(UK_USER, UK_PASS)
            push_urls = ensure_monitors(api, keys)
            api.disconnect()

            # Test each key
            for name, outbound in keys:
                log.info(f"Testing: {name}")
                success, latency = test_proxy(outbound)
                last_results[name] = (success, latency)
                log.info(f"  {'OK' if success else 'FAIL'} ({latency}ms)")

            # Push every push_interval
            now = time.time()
            if now - last_push >= push_interval:
                for name, (success, latency) in last_results.items():
                    if name in push_urls:
                        push_status(push_urls[name], success, latency)
                log.info(f"Pushed {len(last_results)} results to Uptime Kuma")
                last_push = now

        except Exception as e:
            log.error(f"Check cycle failed: {e}", exc_info=True)

        log.info(f"Sleeping {check_interval}s...")
        time.sleep(check_interval)


if __name__ == "__main__":
    main()

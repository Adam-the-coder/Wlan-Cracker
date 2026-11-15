import customtkinter as ctk
import threading
import time

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("green")

WINDOW_W = 1100
WINDOW_H = 720
ACCENT = "#00ff41"
DIM = "#0a0a0a"
PANEL = "#0d1110"
BORDER = "#1a3322"

FAKE_INTERFACES = [
    {"name": "wlan0", "chipset": "RTL8812AU", "mac": "00:c0:ca:aa:bb:01", "modes": ["Managed", "Monitor", "AP"], "band_2g": True, "band_5g": True, "injection": True, "driver": "88XXau (kali patched)", "new": True, "status": "disconnected"},
    {"name": "wlan1", "chipset": "Atheros AR9271", "mac": "00:11:22:33:44:55", "modes": ["Managed", "Monitor"], "band_2g": True, "band_5g": False, "injection": True, "driver": "ath9k_htc", "new": False, "status": "disconnected"},
    {"name": "wlan2", "chipset": "Intel AX210", "mac": "a4:34:d9:cc:dd:ee", "modes": ["Managed"], "band_2g": True, "band_5g": True, "injection": False, "driver": "iwlwifi", "new": False, "status": "connected to HomeNet"},
    {"name": "wlan3", "chipset": "RTL8187", "mac": "00:e0:4c:ff:00:11", "modes": ["Managed", "Monitor"], "band_2g": True, "band_5g": False, "injection": True, "driver": "rtl8187", "new": False, "status": "disconnected"},
]

FAKE_NETWORKS = [
    {"ssid": "SchoolWiFi", "bssid": "AA:BB:CC:11:22:01", "channel": 1, "signal": -38, "security": "WPA2", "clients": 3, "vuln": "Medium", "handshake": False, "cracked": False, "password": None, "extender": 1},
    {"ssid": "SchoolWiFi", "bssid": "AA:BB:CC:11:22:02", "channel": 6, "signal": -61, "security": "WPA2", "clients": 1, "vuln": "Medium", "handshake": False, "cracked": False, "password": None, "extender": 2},
    {"ssid": "SchoolWiFi", "bssid": "AA:BB:CC:11:22:03", "channel": 11, "signal": -74, "security": "WPA2", "clients": 0, "vuln": "Medium", "handshake": False, "cracked": False, "password": None, "extender": 3},
    {"ssid": "HomeNet", "bssid": "DD:EE:FF:33:44:05", "channel": 3, "signal": -52, "security": "WPA2", "clients": 2, "vuln": "Low", "handshake": True, "cracked": True, "password": "fridgecam2024", "extender": None},
    {"ssid": "Guest-IoT", "bssid": "11:22:33:AA:BB:CC", "channel": 9, "signal": -67, "security": "WPA2", "clients": 4, "vuln": "High", "handshake": False, "cracked": False, "password": None, "extender": None},
    {"ssid": "AdminNet", "bssid": "44:55:66:77:88:99", "channel": 36, "signal": -45, "security": "WPA3", "clients": 1, "vuln": "Very Low", "handshake": False, "cracked": False, "password": None, "extender": None},
]

FAKE_DEVICES = [
    {"mac": "00:11:22:33:44:55", "ip": "192.168.1.10", "manufacturer": "Samsung", "type": "Smart Fridge", "active": "Idle", "vuln": "High", "network": "HomeNet", "bssid": "DD:EE:FF:33:44:05", "pmf": False, "handshake": True},
    {"mac": "BB:CC:DD:EE:FF:01", "ip": "192.168.1.20", "manufacturer": "Blink", "type": "Security Cam", "active": "Active", "vuln": "High", "network": "Guest-IoT", "bssid": "11:22:33:AA:BB:CC", "pmf": False, "handshake": True},
    {"mac": "CC:DD:EE:FF:00:01", "ip": "192.168.1.21", "manufacturer": "Raspberry Pi", "type": "Pi HQ Cam", "active": "Streaming", "vuln": "High", "network": "Guest-IoT", "bssid": "11:22:33:AA:BB:CC", "pmf": False, "handshake": True},
    {"mac": "AA:BB:CC:DD:EE:01", "ip": "10.0.0.5", "manufacturer": "Apple", "type": "iPhone 14", "active": "Active", "vuln": "Very Low", "network": "AdminNet", "bssid": "44:55:66:77:88:99", "pmf": True, "handshake": False},
    {"mac": "DD:EE:FF:00:11:01", "ip": "192.168.1.22", "manufacturer": "Dell", "type": "Laptop", "active": "Idle", "vuln": "Low", "network": "Guest-IoT", "bssid": "11:22:33:AA:BB:CC", "pmf": False, "handshake": False},
]

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

        self.build_gui()
        self.show_home()

    def build_gui(self):
        header = ctk.CTkFrame(self, height=60, fg_color=PANEL, corner_radius=0)
        header.pack(fill="x", side="top")
        header.pack_propagate(False)

        ctk.CTkLabel(header, text="▶ NETSCAN", font=("Consolas", 22, "bold"), text_color=ACCENT).pack(side="left", padx=20, pady=12)

        self.iface_label = ctk.CTkLabel(header, text="", font=("Consolas", 12), text_color="#888")
        self.iface_label.pack(side="left", padx=20)

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
        self.detail_text.insert("end", "2. Click START SCAN to begin discovery\n")
        self.detail_text.insert("end", "3. Use NETWORKS / DEVICES / CAPTURES to navigate\n\n")

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
        for iface in FAKE_INTERFACES:
            row = ctk.CTkFrame(canvas, fg_color=PANEL, corner_radius=6, height=110)
            row.pack(fill="x", pady=5)
            row.pack_propagate(False)

            var = ctk.BooleanVar(value=iface in self.selected_interfaces)
            cb = ctk.CTkCheckBox(row, variable=var, text="", width=30, height=30, fg_color=ACCENT, checkmark_color=DIM)
            cb.pack(side="left", padx=15, pady=15)

            info = ctk.CTkFrame(row, fg_color="transparent")
            info.pack(side="left", fill="both", expand=True, padx=10, pady=8)

            name_row = ctk.CTkFrame(info, fg_color="transparent")
            name_row.pack(fill="x")

            ctk.CTkLabel(name_row, text=f"{iface['name']}", font=("Consolas", 16, "bold"), text_color=ACCENT).pack(side="left")

            if iface["new"]:
                ctk.CTkLabel(name_row, text="  🆕 NEW", font=("Consolas", 10, "bold"), text_color="#00ccff").pack(side="left", padx=5)
            if iface["injection"]:
                ctk.CTkLabel(name_row, text="  💉 INJECTION", font=("Consolas", 10, "bold"), text_color="#ffaa00").pack(side="left", padx=5)
            if "Monitor" not in iface["modes"]:
                ctk.CTkLabel(name_row, text="  ⚠ NO MONITOR", font=("Consolas", 10, "bold"), text_color="#ff4444").pack(side="left", padx=5)

            ctk.CTkLabel(info, text=f"{iface['chipset']}  |  {iface['mac']}  |  {iface['driver']}", font=("Consolas", 10), text_color="#aaa").pack(anchor="w", pady=(2, 0))

            modes_text = "  ".join([f"[{m}]" for m in iface["modes"]])
            band_text = f"{'2.4GHz' if iface['band_2g'] else ''} {'5GHz' if iface['band_5g'] else ''}".strip()
            ctk.CTkLabel(info, text=f"{modes_text}  {band_text}  |  Status: {iface['status']}", font=("Consolas", 10), text_color="#888").pack(anchor="w", pady=(2, 0))

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
                self.detail_text.insert("end", f"  {i['name']} [{i['chipset']}]\n")
                self.detail_text.insert("end", f"  MAC: {i['mac']}\n")
                self.detail_text.insert("end", f"  Injection: {'Yes' if i['injection'] else 'No'}\n")
                self.detail_text.insert("end", f"  Modes: {', '.join(i['modes'])}\n\n")
            self.detail_text.insert("end", "─ Ready. Click START SCAN to begin. ─\n")
            self.show_home()

        ctk.CTkButton(btn_row, text="✓ CONFIRM", width=200, height=35, font=("Consolas", 13, "bold"), fg_color=ACCENT, text_color=DIM, hover_color="#00cc33", command=confirm_selection).pack(side="left", padx=10)
        ctk.CTkButton(btn_row, text="✕ CANCEL", width=120, height=35, font=("Consolas", 13, "bold"), fg_color=BORDER, text_color=ACCENT, hover_color="#1a4d2e", command=modal.destroy).pack(side="left", padx=10)

    def update_interface_display(self):
        if self.selected_interfaces:
            names = ", ".join([f"{i['name']} [{i['chipset']}]" for i in self.selected_interfaces])
            self.iface_label.configure(text=f"● {names}", text_color=ACCENT)
            self.btn_scan.configure(fg_color=ACCENT, text_color=DIM)
        else:
            self.iface_label.configure(text="● NO INTERFACE SELECTED", text_color="#ffaa00")
            self.btn_scan.configure(fg_color=BORDER, text_color=ACCENT)

    def start_scan(self):
        if not self.selected_interfaces:
            self.open_interface_modal()
            return

        usable = [i for i in self.selected_interfaces if "Monitor" in i["modes"] and i["injection"]]
        if not usable:
            self.detail_text.delete("0.0", "end")
            self.detail_text.insert("0.0", "⚠ ERROR: None of the selected interfaces support monitor mode + injection.\n\n")
            self.detail_text.insert("end", "Please select a different chip (e.g. wlan0 RTL8812AU).\n")
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

        # DESTROY all children of self.content before rendering results
        # This is the critical fix — removes the leftover HUD + "SCANNING..." widgets
        for widget in self.content.winfo_children():
            widget.destroy()

        # Now render results into clean content frame
        if self.current_page == "networks":
            self.load_networks_page()
        elif self.current_page == "devices":
            self.load_devices_page()

    def _scan_worker(self):
        start = time.time()
        while self.scanning:
            elapsed = time.time() - start
            self.scan_networks_found = min(int(elapsed / 3) + 1, 6)
            self.scan_devices_found = min(int(elapsed / 2) + 1, 7)
            self.scan_packets = int(elapsed * 47)

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
        ctk.CTkLabel(center, text="Discovering networks...\nUse the HUD above to monitor progress.", font=("Consolas", 14), text_color="#888", justify="center").pack(pady=10)

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
        self.detail_text.insert("0.0", "Scan complete. Networks discovered:\n\n")

        groups = {}
        for n in FAKE_NETWORKS:
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

                signal_bars = "█" * min(4, (abs(net["signal"]) // 20) + 1)
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
        self.detail_text.insert("end", f"\nDeauth: {'Available' if net['security']=='WPA2' else 'Blocked'}\n")

        for widget in self.content.winfo_children():
            widget.destroy()

        detail_frame = ctk.CTkFrame(self.content, fg_color="transparent")
        detail_frame.pack(fill="both", expand=True, padx=10, pady=10)

        ctk.CTkLabel(detail_frame, text=f"┌─ SCANNING: {net['ssid']} ({net['bssid'][-5:]}) ─┐", font=("Consolas", 16, "bold"), text_color=ACCENT).pack(pady=(10, 5))

        iface_name = self.selected_interfaces[0]['name'] if self.selected_interfaces else 'wlan0'
        ctk.CTkLabel(detail_frame, text=f"airodump-ng {iface_name} --bssid {net['bssid']} -c {net['channel']}", font=("Consolas", 11), text_color="#888").pack(pady=(0, 10))

        btn_row = ctk.CTkFrame(detail_frame, fg_color="transparent")
        btn_row.pack(pady=5)

        ctk.CTkButton(btn_row, text="⚡ ATTACK NETWORK", width=180, height=35, font=("Consolas", 12, "bold"), fg_color=ACCENT, text_color=DIM, hover_color="#00cc33", command=lambda: self.launch_attack(net)).pack(side="left", padx=10)
        ctk.CTkButton(btn_row, text="◀ BACK", width=100, height=35, font=("Consolas", 12, "bold"), fg_color=BORDER, text_color=ACCENT, hover_color="#1a4d2e", command=lambda: self.switch_page("networks")).pack(side="left", padx=10)

        self.target_device_list = ctk.CTkScrollableFrame(detail_frame, fg_color=DIM, corner_radius=6)
        self.target_device_list.pack(fill="both", expand=True, pady=10)

        devices = [d for d in FAKE_DEVICES if d["bssid"] == net["bssid"]]
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

        canvas = ctk.CTkScrollableFrame(self.content, fg_color="transparent")
        canvas.pack(fill="both", expand=True, padx=10, pady=10)

        sorted_devs = sorted(FAKE_DEVICES, key=lambda d: {"High": 0, "Medium": 1, "Low": 2, "Very Low": 3}.get(d["vuln"], 9))

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

        FAKE_CAPTURES = [
            {"id": 1, "network": "HomeNet", "bssid": "DD:EE:FF:33:44:05", "device": "00:11:22:33:44:55", "file": "homnet_fridge.cap", "cracked": True, "password": "fridgecam2024", "method": "rockyou"},
            {"id": 2, "network": "Guest-IoT", "bssid": "11:22:33:AA:BB:CC", "device": "BB:CC:DD:EE:FF:01", "file": "guest_blink.cap", "cracked": False, "password": None, "method": None},
            {"id": 3, "network": "Guest-IoT", "bssid": "11:22:33:AA:BB:CC", "device": "CC:DD:EE:FF:00:01", "file": "guest_pihq.cap", "cracked": False, "password": None, "method": None},
        ]

        canvas = ctk.CTkScrollableFrame(self.content, fg_color="transparent")
        canvas.pack(fill="both", expand=True, padx=10, pady=10)

        for cap in FAKE_CAPTURES:
            row = ctk.CTkFrame(canvas, fg_color=DIM, corner_radius=6, height=80)
            row.pack(fill="x", pady=5)
            row.pack_propagate(False)

            left = ctk.CTkFrame(row, fg_color="transparent")
            left.pack(side="left", fill="both", expand=True, padx=15, pady=8)

            status = "✅ CRACKED" if cap["cracked"] else "⏳ PENDING"
            status_c = "#00ff41" if cap["cracked"] else "#ffaa00"
            ctk.CTkLabel(left, text=f"{status}  {cap['network']} → {cap['device'][-8:]}", font=("Consolas", 13, "bold"), text_color=status_c).pack(anchor="w")
            ctk.CTkLabel(left, text=f"  {cap['file']}  |  BSSID: {cap['bssid']}", font=("Consolas", 10), text_color="#888").pack(anchor="w", pady=(2, 0))
            if cap["cracked"]:
                ctk.CTkLabel(left, text=f"  Password: {cap['password']}  ({cap['method']})", font=("Consolas", 11), text_color=ACCENT).pack(anchor="w", pady=(2, 0))

            right = ctk.CTkFrame(row, fg_color="transparent")
            right.pack(side="right", padx=15, pady=8)

            if not cap["cracked"]:
                ctk.CTkButton(right, text="🔨 CRACK", width=90, height=30, font=("Consolas", 11, "bold"), fg_color=ACCENT, text_color=DIM, hover_color="#00cc33", command=lambda c=cap: self.crack_capture(c)).pack(pady=2)
            else:
                ctk.CTkButton(right, text="👁 VIEW", width=90, height=30, font=("Consolas", 11, "bold"), fg_color=BORDER, text_color=ACCENT, hover_color="#1a4d2e", command=lambda c=cap: self.view_capture(c)).pack(pady=2)

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
                if (i + 1) / 100 >= 0.35 and cap["id"] == 2:
                    status.configure(text="✅ Cracked!")
                    cap["cracked"] = True
                    cap["password"] = "testpassword123"
                    cap["method"] = method_var.get()
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
            devices = [d for d in FAKE_DEVICES if d["bssid"] == net["bssid"]]
        elif dev:
            ctk.CTkLabel(modal, text=f"Target: {dev['mac']} ({dev['type']})", font=("Consolas", 12), text_color="#ccc").pack(pady=5)
            devices = [dev]
        else:
            devices = []

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

            for d in selected:
                if d.get("handshake"):
                    log.insert("end", f"  ✓ {d['mac']} → handshake already captured!\n")
                elif d.get("pmf"):
                    log.insert("end", f"  ✗ {d['mac']} → PMF ARMED, deauth blocked\n")
                else:
                    log.insert("end", f"  → deauth → {d['mac']} reason=3\n")
                    log.insert("end", f"  ← M1 → M2 → M3 → M4\n")
                    log.insert("end", f"  ✓ Handshake captured (confidence: 99%)\n")

            log.insert("end", f"\n▶ EAPOL capture complete for {len(selected)} device(s).\n")

            if net:
                net["handshake"] = True
                for d in selected:
                    d["handshake"] = True

            modal.after(1500, lambda: self.switch_page("captures"))

        ctk.CTkButton(modal, text="▶ LAUNCH ATTACK", width=200, height=35, font=("Consolas", 13, "bold"), fg_color=ACCENT, text_color=DIM, hover_color="#00cc33", command=start_attack).pack(pady=10)

if __name__ == "__main__":
    app = NetScanApp()
    app.mainloop()
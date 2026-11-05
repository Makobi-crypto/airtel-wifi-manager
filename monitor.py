import time
import threading
import logging
import subprocess
import re
from datetime import datetime
import database

logger = logging.getLogger("Monitor")
logging.basicConfig(level=logging.INFO)

class NetworkMonitor:
    def __init__(self, router_client):
        self.client = router_client
        self.running = False
        self.thread = None
        self.sweep_thread = None
        self.lock = threading.Lock()
        self.last_poll_time = time.time()
        self.cached_devices = {}
        self.cached_summary = {
            "online_count": 0,
            "blocked_count": 0,
            "total_down_rate_kbs": 0.0,
            "total_up_rate_kbs": 0.0,
            "total_consumed_today_mb": 0.0,
            "total_consumed_all_mb": 0.0,
            "router_connected": False,
            "router_logged_in": False,
            "last_updated": ""
        }

    def start(self):
        if self.running:
            return
        self.running = True
        
        # 1. Main polling loop
        self.thread = threading.Thread(target=self._run_loop, daemon=True)
        self.thread.start()
        
        # 2. Fast background ARP sweep thread to keep mobile phones awake & tracked
        self.sweep_thread = threading.Thread(target=self._sweep_loop, daemon=True)
        self.sweep_thread.start()
        
        logger.info("Network monitor & background sweep threads started")

    def stop(self):
        self.running = False
        if self.thread:
            self.thread.join(timeout=2)
        if self.sweep_thread:
            self.sweep_thread.join(timeout=2)

    def _sweep_loop(self):
        """Continuously pings the subnet to discover devices even if they are in power-saving mode."""
        while self.running:
            try:
                router_ip = database.get_setting("router_ip", "192.168.3.1")
                base = router_ip.rsplit('.', 1)[0]
                subprocess.run(
                    ["fping", "-a", "-g", "-r", "1", "-t", "120", f"{base}.1", f"{base}.254"],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=5
                )
            except Exception as e:
                logger.debug(f"Sweep error: {e}")
            time.sleep(4)

    def _get_my_ip_mac(self):
        """Detect local IP and MAC address of this machine."""
        my_ip, my_mac = '', ''
        try:
            router_ip = database.get_setting("router_ip", "192.168.3.1")
            out = subprocess.check_output(["ip", "route", "get", router_ip], text=True)
            m_ip = re.search(r'src\s+(\d+\.\d+\.\d+\.\d+)', out)
            m_dev = re.search(r'dev\s+(\S+)', out)
            if m_ip:
                my_ip = m_ip.group(1)
            if m_dev:
                dev = m_dev.group(1)
                l_out = subprocess.check_output(["ip", "link", "show", dev], text=True)
                m_mac = re.search(r'link/ether\s+([0-9a-fA-F:]{17})', l_out)
                if m_mac:
                    my_mac = m_mac.group(1).upper()
        except Exception as e:
            logger.debug(f"get_my_ip_mac error: {e}")
        return my_ip, my_mac

    def _get_local_arp(self):
        """Read IP neighbors from kernel ARP cache + this PC itself."""
        arp_map = {}
        try:
            output = subprocess.check_output(["ip", "neigh"], text=True)
            for line in output.splitlines():
                parts = line.split()
                if len(parts) >= 5 and "lladdr" in parts:
                    ip = parts[0]
                    mac = parts[parts.index("lladdr") + 1].upper()
                    state = parts[-1]
                    if state not in ("FAILED", "INCOMPLETE") and mac != "FF:FF:FF:FF:FF:FF":
                        arp_map[mac] = {"ip": ip, "state": state, "is_self": False}
        except Exception as e:
            logger.debug(f"Error reading arp: {e}")

        # Add this PC itself
        my_ip, my_mac = self._get_my_ip_mac()
        if my_ip and my_mac:
            arp_map[my_mac] = {"ip": my_ip, "state": "REACHABLE", "is_self": True}

        return arp_map

    def _run_loop(self):
        while self.running:
            try:
                self._poll_once()
            except Exception as e:
                logger.error(f"Error in monitor loop: {e}", exc_info=True)
            
            interval = float(database.get_setting("auto_refresh_sec", "3"))
            time.sleep(max(1.5, interval))

    def _poll_once(self):
        now = time.time()
        delta_time = max(0.5, now - self.last_poll_time)
        self.last_poll_time = now

        # Ensure database is initialized
        database.init_db()
        
        # Check router authentication
        pwd = database.get_setting("router_password", "")
        router_ip = database.get_setting("router_ip", "192.168.3.1")
        self.client.router_ip = router_ip
        self.client.base_url = f"http://{router_ip}"

        if not self.client.device_info:
            self.client.get_public_device_info()

        if pwd and not self.client.is_logged_in:
            success, msg = self.client.login(pwd)
            if not success:
                logger.warning(f"Router login attempt failed: {msg}")

        hosts = []
        filter_list = []
        logged_in = self.client.is_logged_in

        if logged_in:
            try:
                hosts = self.client.get_hosts()
                filter_list = self.client.get_filter_list()
            except Exception as e:
                logger.error(f"Failed to fetch router stats: {e}")
                self.client.is_logged_in = False

        # Build blacklist map
        blocked_macs = set()
        if isinstance(filter_list, list):
            for band in filter_list:
                for b_entry in band.get("BMACAddresses", []):
                    b_mac = b_entry.get("MACAddress", "").upper()
                    if b_mac:
                        blocked_macs.add(b_mac)

        local_arp = self._get_local_arp()
        db_devices = {d["mac"].upper(): d for d in database.get_all_devices()}

        live_devices = {}
        total_down_rate = 0.0
        total_up_rate = 0.0
        online_count = 0

        # 1. Process hosts reported by router
        for h in hosts:
            mac = h.get("MACAddress", "").upper()
            if not mac:
                continue
            
            ip = h.get("IPAddress", "")
            hostname = h.get("HostName", "") or h.get("ActualName", "")
            router_actual_name = h.get("ActualName", "")
            device_id = h.get("ID", "")
            
            # Rate in KB/s
            try:
                down_rate = float(h.get("DownRate", 0.0))
            except:
                down_rate = 0.0
            try:
                up_rate = float(h.get("UpRate", 0.0))
            except:
                up_rate = 0.0

            total_down_rate += down_rate
            total_up_rate += up_rate

            is_active = bool(h.get("Active46", 1))
            if is_active:
                online_count += 1

            is_in_black = bool(h.get("Inblack", 0)) or (mac in blocked_macs)
            if is_in_black:
                blocked_macs.add(mac)

            # Calculate MB consumed this tick: (KB/s * seconds) / 1024
            down_mb = (down_rate * delta_time) / 1024.0
            up_mb = (up_rate * delta_time) / 1024.0

            # Update database
            database.update_device_usage(
                mac=mac,
                ip=ip,
                hostname=hostname,
                down_delta_mb=down_mb,
                up_delta_mb=up_mb,
                is_blocked=1 if is_in_black else 0
            )

            # Get user custom nickname from DB if set
            db_rec = db_devices.get(mac, {})
            custom_name = db_rec.get("custom_name", "") or router_actual_name or hostname

            live_devices[mac] = {
                "mac": mac,
                "ip": ip,
                "hostname": hostname,
                "custom_name": custom_name,
                "is_online": is_active,
                "is_blocked": is_in_black,
                "down_rate_kbs": round(down_rate, 2),
                "up_rate_kbs": round(up_rate, 2),
                "device_id": device_id,
                "notes": db_rec.get("notes", ""),
                "last_seen": now
            }

        # 2. Add local ARP entries (including this PC and any devices not yet queried by router)
        my_ip, my_mac = self._get_my_ip_mac()
        for mac, arp_info in local_arp.items():
            if mac not in live_devices:
                db_rec = db_devices.get(mac, {})
                is_in_black = mac in blocked_macs
                
                # Friendly default label for self and router
                ip_addr = arp_info["ip"]
                if arp_info.get("is_self", False):
                    default_name = "This PC (Host Manager)"
                    default_host = "ThinkPad Linux"
                elif ip_addr == router_ip:
                    default_name = "Airtel ODU Router (Gateway)"
                    default_host = "Huawei AX3S ODU"
                else:
                    default_name = db_rec.get("custom_name", "") or f"Device ({ip_addr.split('.')[-1]})"
                    default_host = db_rec.get("hostname", "Wi-Fi Client")

                custom_name = db_rec.get("custom_name", "") or default_name
                hostname = db_rec.get("hostname", "") or default_host

                database.update_device_usage(
                    mac=mac,
                    ip=ip_addr,
                    hostname=hostname,
                    down_delta_mb=0.0,
                    up_delta_mb=0.0,
                    is_blocked=1 if is_in_black else 0
                )
                live_devices[mac] = {
                    "mac": mac,
                    "ip": ip_addr,
                    "hostname": hostname,
                    "custom_name": custom_name,
                    "is_online": True,
                    "is_blocked": is_in_black,
                    "down_rate_kbs": 0.0,
                    "up_rate_kbs": 0.0,
                    "device_id": "",
                    "notes": db_rec.get("notes", ""),
                    "last_seen": now
                }
                online_count += 1

        # 3. Pull refreshed DB data to include historical totals
        updated_db_devices = database.get_all_devices()
        total_today_mb = sum(d["today_down_mb"] + d["today_up_mb"] for d in updated_db_devices)
        total_all_mb = sum(d["total_down_mb"] + d["total_up_mb"] for d in updated_db_devices)

        full_device_list = []
        for d in updated_db_devices:
            mac = d["mac"].upper()
            live = live_devices.get(mac, {})
            merged = dict(d)
            merged["is_online"] = live.get("is_online", (now - d["last_seen"]) < 90)
            merged["down_rate_kbs"] = live.get("down_rate_kbs", 0.0)
            merged["up_rate_kbs"] = live.get("up_rate_kbs", 0.0)
            merged["device_id"] = live.get("device_id", "")
            merged["is_blocked"] = 1 if (mac in blocked_macs or d["is_blocked"]) else 0
            
            # Format friendly MB/GB values
            today_total = round(d["today_down_mb"] + d["today_up_mb"], 2)
            all_total = round(d["total_down_mb"] + d["total_up_mb"], 2)
            merged["today_total_mb"] = today_total
            merged["all_total_mb"] = all_total
            
            full_device_list.append(merged)

        with self.lock:
            self.cached_devices = full_device_list
            self.cached_summary = {
                "online_count": online_count,
                "blocked_count": len(blocked_macs),
                "total_devices_count": len(full_device_list),
                "total_down_rate_kbs": round(total_down_rate, 2),
                "total_up_rate_kbs": round(total_up_rate, 2),
                "total_consumed_today_mb": round(total_today_mb, 2),
                "total_consumed_all_mb": round(total_all_mb, 2),
                "router_connected": bool(self.client.device_info or logged_in),
                "router_logged_in": logged_in,
                "last_updated": datetime.now().strftime("%H:%M:%S")
            }

    def get_data(self):
        with self.lock:
            return {
                "summary": dict(self.cached_summary),
                "devices": list(self.cached_devices)
            }

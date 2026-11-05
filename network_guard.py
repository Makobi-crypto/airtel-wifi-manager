import threading
import logging
import subprocess
import time
import re
from datetime import datetime
import database

logger = logging.getLogger("NetworkGuard")
logging.basicConfig(level=logging.INFO)

class NetworkGuard:
    """
    Manages:
    1. Real-time DNS search & domain lookup logging per connected device.
    2. Anti-Hotspot / Anti-Tethering enforcement and detection using TTL inspection.
    """
    def __init__(self, monitor_ref=None):
        self.monitor = monitor_ref
        self.running = False
        self.sniff_thread = None
        self.has_permission = True
        self.error_message = ""
        self.recent_queries = []  # Ring buffer of latest queries
        self.max_recent = 150
        self.lock = threading.Lock()
        self.tethering_enabled = (database.get_setting("anti_tethering_enabled", "1") == "1")
        self.dns_logging_enabled = (database.get_setting("dns_logging_enabled", "1") == "1")

    def start(self):
        if self.running:
            return
        self.running = True

        # Apply firewall rules if enabled
        if self.tethering_enabled:
            self._apply_iptables_rules(enable=True)

        # Start background packet sniffer thread
        self.sniff_thread = threading.Thread(target=self._sniffer_loop, daemon=True)
        self.sniff_thread.start()
        logger.info("NetworkGuard started (DNS Logger & Anti-Tethering)")

    def stop(self):
        self.running = False
        if self.tethering_enabled:
            self._apply_iptables_rules(enable=False)

    def _resolve_device(self, ip):
        """Map IP address to MAC address and Friendly Name."""
        mac = ""
        name = ""

        # 1. Check live monitor cached devices
        if self.monitor:
            try:
                data = self.monitor.get_data()
                for d in data.get("devices", []):
                    if d.get("ip") == ip:
                        mac = d.get("mac", "")
                        name = d.get("custom_name") or d.get("hostname") or ""
                        break
            except Exception:
                pass

        # 2. Check local database
        if not mac or not name:
            try:
                conn = database.get_db()
                c = conn.cursor()
                c.execute("SELECT mac, custom_name, hostname FROM devices WHERE ip = ? LIMIT 1", (ip,))
                row = c.fetchone()
                if row:
                    mac = row["mac"]
                    name = row["custom_name"] or row["hostname"] or ""
                conn.close()
            except Exception:
                pass

        if not name:
            name = f"Client ({ip.split('.')[-1]})" if "." in ip else "Client"

        return mac, name

    def _sniffer_loop(self):
        """Packet capture thread for DNS traffic and TTL tethering detection."""
        try:
            from scapy.all import sniff, IP, IPv6, DNS, DNSQR
        except Exception as e:
            self.has_permission = False
            self.error_message = f"Scapy import error: {e}"
            logger.warning(self.error_message)
            return

        def process_packet(packet):
            if not self.running:
                return

            if not packet.haslayer(IP):
                return

            ip_layer = packet[IP]
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst
            ttl = getattr(ip_layer, "ttl", 64)

            # Ignore loopback traffic
            if src_ip.startswith("127.") or dst_ip.startswith("127."):
                return

            # A. Anti-Hotspot / Tethering Detection
            # When a mobile or laptop shares connection as a hotspot, packets routed through it
            # have their standard TTL (64 for Android/Linux/macOS, 128 for Windows) decremented by 1.
            # Thus arriving with TTL 63, 127, or TTL < 64 (non-standard for direct clients).
            if self.tethering_enabled and (ttl in (63, 127) or (30 < ttl < 64)):
                mac, name = self._resolve_device(src_ip)
                action = "Blocked / Flagged" if self.tethering_enabled else "Detected"
                database.log_tethering_alert(src_ip, mac, name, ttl, action=action)
                logger.info(f"[ANTI-HOTSPOT] Tethered packet detected from {name} ({src_ip}, TTL={ttl})")

            # B. DNS Query Logging (Domain lookups / search queries)
            # Only capture client DNS requests (qr == 0) originating from private network IPs
            is_private_src = src_ip.startswith("192.168.") or src_ip.startswith("10.") or src_ip.startswith("172.")
            is_dns_query = packet.haslayer(DNS) and getattr(packet[DNS], "qr", 0) == 0

            if self.dns_logging_enabled and is_dns_query and is_private_src and packet.haslayer(DNSQR):
                try:
                    qname = packet[DNSQR].qname
                    if isinstance(qname, bytes):
                        domain = qname.decode("utf-8", errors="ignore").rstrip(".")
                    else:
                        domain = str(qname).rstrip(".")

                    # Filter out local reverse lookups or empty domains
                    if domain and not domain.endswith(".arpa") and "." in domain:
                        mac, name = self._resolve_device(src_ip)
                        now = time.time()
                        time_str = datetime.fromtimestamp(now).strftime("%Y-%m-%d %H:%M:%S")

                        entry = {
                            "timestamp": now,
                            "time_str": time_str,
                            "ip": src_ip,
                            "mac": mac,
                            "device_name": name,
                            "domain": domain
                        }

                        with self.lock:
                            self.recent_queries.insert(0, entry)
                            if len(self.recent_queries) > self.max_recent:
                                self.recent_queries.pop()

                        # Persist to database
                        database.log_domain_query(src_ip, mac, name, domain)
                except Exception as ex:
                    logger.debug(f"DNS parse error: {ex}")

        # Attempt to sniff
        try:
            logger.info("Starting Scapy packet capture filter for DNS & TTL...")
            sniff(filter="udp port 53 or (ip[8] == 63 or ip[8] == 127)", prn=process_packet, store=0)
        except PermissionError as pe:
            self.has_permission = False
            self.error_message = "Requires CAP_NET_RAW / root permissions to sniff network packets."
            logger.warning(f"NetworkGuard: {self.error_message} ({pe})")
        except Exception as e:
            if "Operation not permitted" in str(e) or "Permission denied" in str(e):
                self.has_permission = False
                self.error_message = "Requires CAP_NET_RAW / root permissions to sniff network packets."
                logger.warning(f"NetworkGuard: {self.error_message}")
            else:
                logger.error(f"NetworkGuard sniffer terminated: {e}")

    def _apply_iptables_rules(self, enable=True):
        """
        Enforce or remove kernel firewall rules to drop secondary hotspot/tethered packets.
        """
        rules = [
            ["-m", "ttl", "--ttl-eq", "63", "-j", "DROP"],
            ["-m", "ttl", "--ttl-eq", "127", "-j", "DROP"],
            ["-m", "ttl", "--ttl-lt", "64", "-j", "DROP"]
        ]

        for rule in rules:
            try:
                # Check if rule exists
                check_cmd = ["iptables", "-C", "FORWARD"] + rule
                res = subprocess.run(check_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                exists = (res.returncode == 0)

                if enable and not exists:
                    add_cmd = ["iptables", "-I", "FORWARD", "1"] + rule
                    subprocess.run(add_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                elif not enable and exists:
                    del_cmd = ["iptables", "-D", "FORWARD"] + rule
                    subprocess.run(del_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            except Exception as e:
                logger.debug(f"iptables error ({rule}): {e}")

    def set_tethering_guard(self, enabled=True):
        self.tethering_enabled = enabled
        database.set_setting("anti_tethering_enabled", "1" if enabled else "0")
        self._apply_iptables_rules(enable=enabled)
        logger.info(f"Anti-Tethering guard set to: {enabled}")

    def set_dns_logging(self, enabled=True):
        self.dns_logging_enabled = enabled
        database.set_setting("dns_logging_enabled", "1" if enabled else "0")
        logger.info(f"DNS search logging set to: {enabled}")

    def get_recent_queries(self, limit=50, search=None, mac_or_ip=None):
        """Retrieve recent queries, combining memory cache and database."""
        return database.get_domain_queries(limit=limit, search=search, mac_or_ip=mac_or_ip)

    def get_status(self):
        return {
            "has_permission": self.has_permission,
            "error_message": self.error_message,
            "anti_tethering_active": self.tethering_enabled,
            "dns_logging_active": self.dns_logging_enabled,
            "cached_queries_count": len(self.recent_queries),
            "alerts": database.get_tethering_alerts(limit=20)
        }

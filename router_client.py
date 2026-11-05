import hashlib
import hmac
import json
import logging
import os
import secrets
import time
import requests

logger = logging.getLogger("RouterClient")
logging.basicConfig(level=logging.INFO)

class HuaweiScramClient:
    """
    Client for Huawei / Airtel ODU Wi-Fi routers (AX3, AX3S, B310, etc.)
    Implements the Huawei SCRAM-SHA256 authentication protocol.
    """
    def __init__(self, router_ip="192.168.3.1"):
        self.router_ip = router_ip.strip()
        self.base_url = f"http://{self.router_ip}"
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Accept": "application/json, text/javascript, */*; q=0.01",
            "X-Requested-With": "XMLHttpRequest",
            "_ResponseFormat": "JSON"
        })
        self.csrf_param = ""
        self.csrf_token = ""
        self.is_logged_in = False
        self.last_login_time = 0
        self.device_info = {}

    @staticmethod
    def _hmac_sha256(key_bytes, msg_bytes):
        return hmac.new(key_bytes, msg_bytes, hashlib.sha256).digest()

    @classmethod
    def _scram_proof(cls, password, salt_hex, iterations, auth_msg):
        salt_bytes = bytes.fromhex(salt_hex)
        salted_pwd = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt_bytes, iterations, 32)
        client_key = cls._hmac_sha256(b'Client Key', salted_pwd)
        server_key = cls._hmac_sha256(b'Server Key', salted_pwd)
        stored_key = hashlib.sha256(client_key).digest()
        sign_pwd = cls._hmac_sha256(auth_msg.encode('utf-8'), stored_key)
        client_proof = bytes(a ^ b for a, b in zip(client_key, sign_pwd))
        server_proof = cls._hmac_sha256(auth_msg.encode('utf-8'), server_key)
        return client_proof.hex(), server_proof.hex()

    def fetch_csrf(self):
        """Fetches index.html to extract cookies and CSRF tokens."""
        try:
            resp = self.session.get(f"{self.base_url}/html/index.html", timeout=4)
            if resp.status_code == 200:
                html = resp.text
                for line in html.splitlines():
                    if 'name="csrf_param"' in line and 'content="' in line:
                        self.csrf_param = line.split('content="')[1].split('"')[0]
                    if 'name="csrf_token"' in line and 'content="' in line:
                        self.csrf_token = line.split('content="')[1].split('"')[0]
                return True
        except Exception as e:
            logger.error(f"Error fetching CSRF: {e}")
        return False

    def api_get(self, endpoint, params=None):
        """Perform authenticated GET request."""
        url = f"{self.base_url}/api/{endpoint.lstrip('/')}"
        headers = {}
        if self.csrf_param and self.csrf_token:
            headers["csrf_param"] = self.csrf_param
            headers["csrf_token"] = self.csrf_token
        try:
            resp = self.session.get(url, params=params, headers=headers, timeout=5)
            if resp.headers.get("csrf_param"):
                self.csrf_param = resp.headers.get("csrf_param")
            if resp.headers.get("csrf_token"):
                self.csrf_token = resp.headers.get("csrf_token")
            if resp.status_code == 200:
                return resp.json()
            elif resp.status_code in (403, 404):
                self.is_logged_in = False
        except Exception as e:
            logger.debug(f"api_get {endpoint} failed: {e}")
        return None

    def api_post(self, endpoint, data=None):
        """Perform authenticated POST request."""
        url = f"{self.base_url}/api/{endpoint.lstrip('/')}"
        payload = {
            "csrf": {
                "csrf_param": self.csrf_param,
                "csrf_token": self.csrf_token
            }
        }
        if data is not None:
            payload["data"] = data

        headers = {
            "Content-Type": "application/json; charset=utf-8"
        }
        if self.csrf_param and self.csrf_token:
            headers["csrf_param"] = self.csrf_param
            headers["csrf_token"] = self.csrf_token

        try:
            resp = self.session.post(url, json=payload, headers=headers, timeout=6)
            if resp.status_code == 200:
                res_json = resp.json()
                if "csrf_param" in res_json:
                    self.csrf_param = res_json["csrf_param"]
                if "csrf_token" in res_json:
                    self.csrf_token = res_json["csrf_token"]
                return res_json
        except Exception as e:
            logger.error(f"api_post {endpoint} failed: {e}")
        return None

    def get_public_device_info(self):
        """Fetches basic router information without requiring login."""
        self.fetch_csrf()
        info = self.api_get("system/deviceinfo")
        if info:
            self.device_info = info
        return info

    def login(self, password, username="admin"):
        """Performs full SCRAM authentication with the router."""
        self.fetch_csrf()
        first_nonce = secrets.token_hex(32)

        # Step 1: Request server nonce and salt
        nonce_payload = {
            "username": username,
            "firstnonce": first_nonce
        }
        step1 = self.api_post("system/user_login_nonce", nonce_payload)
        if not step1:
            return False, "Failed to connect to router"
        
        if step1.get("err") != 0:
            err_code = step1.get("err")
            return False, f"Router returned error on nonce request (code {err_code})"

        salt = step1.get("salt")
        server_nonce = step1.get("servernonce")
        iterations = step1.get("iterations", 100)

        if not salt or not server_nonce:
            return False, "Router did not return salt or server nonce"

        # Step 2: Compute client proof
        auth_msg = f"{first_nonce},{server_nonce},{server_nonce}"
        client_proof, server_proof = self._scram_proof(password, salt, iterations, auth_msg)

        # Step 3: Send proof to router
        proof_payload = {
            "clientproof": client_proof,
            "finalnonce": server_nonce
        }
        step2 = self.api_post("system/user_login_proof", proof_payload)
        if not step2:
            return False, "No response to login proof"

        err = step2.get("err", -1)
        if err == 0:
            self.is_logged_in = True
            self.last_login_time = time.time()
            logger.info("Successfully logged into Airtel router!")
            return True, "Login successful"
        
        category = step2.get("errorCategory", "")
        if "user_pass_err" in category or err == 4784230:
            fails = step2.get("count", 1)
            max_fails = step2.get("maxfailtimes", 3)
            return False, f"Incorrect password ({fails}/{max_fails} attempts)"

        return False, f"Login failed: {category or err}"

    def get_hosts(self):
        """
        Retrieves connected host list from router.
        Returns list of host dicts.
        """
        data = self.api_get("system/HostInfo")
        if isinstance(data, list):
            return data
        elif isinstance(data, dict):
            # Sometimes wrapped in {"HostInfo": [...]}
            return data.get("HostInfo", [])
        return []

    def get_filter_list(self):
        """
        Retrieves blacklist/whitelist configuration.
        """
        data = self.api_get("ntwk/wlanfilterenhance")
        return data

    def rename_device(self, device_id, new_name):
        """
        Updates device ActualName on router.
        """
        payload = {
            "action": "update",
            "data": [{
                "ID": device_id,
                "ActualName": new_name[:64]
            }]
        }
        res = self.api_post("system/changedevicename", payload)
        return res and res.get("errcode", 0) == 0

    def block_device(self, mac_address, hostname="Device"):
        """
        Adds device MAC to blacklist on router.
        """
        mac = mac_address.upper()
        current_filters = self.get_filter_list()
        if not current_filters or not isinstance(current_filters, list):
            # Try to build initial structure
            current_filters = [
                {"WMACAddresses": [], "BMACAddresses": []},
                {"WMACAddresses": [], "BMACAddresses": []}
            ]

        # Add to BMACAddresses in all bands (2.4G & 5G)
        new_entry = {"HostName": hostname, "MACAddress": mac}
        for band in current_filters:
            b_list = band.get("BMACAddresses", [])
            w_list = band.get("WMACAddresses", [])
            # Filter out any duplicate
            b_list = [x for x in b_list if x.get("MACAddress", "").upper() != mac]
            w_list = [x for x in w_list if x.get("MACAddress", "").upper() != mac]
            b_list.append(new_entry)
            band["BMACAddresses"] = b_list
            band["WMACAddresses"] = w_list

        # Transform keys as required by router
        post_data = {}
        band_names = ["config2g", "config5g"]
        for idx, band in enumerate(current_filters[:2]):
            name = band_names[idx]
            post_data[name] = {}
            for k, v in band.items():
                if k.endswith("Addresses"):
                    new_k = k.replace("Addresses", "Filters").replace("MAC", "Mac")
                    post_data[name][new_k] = v
                else:
                    post_data[name][k] = v

        res = self.api_post("ntwk/wlanfilterenhance", post_data)
        return res is not None

    def unblock_device(self, mac_address):
        """
        Removes device MAC from blacklist on router.
        """
        mac = mac_address.upper()
        current_filters = self.get_filter_list()
        if not current_filters or not isinstance(current_filters, list):
            return False

        for band in current_filters:
            b_list = band.get("BMACAddresses", [])
            band["BMACAddresses"] = [x for x in b_list if x.get("MACAddress", "").upper() != mac]

        post_data = {}
        band_names = ["config2g", "config5g"]
        for idx, band in enumerate(current_filters[:2]):
            name = band_names[idx]
            post_data[name] = {}
            for k, v in band.items():
                if k.endswith("Addresses"):
                    new_k = k.replace("Addresses", "Filters").replace("MAC", "Mac")
                    post_data[name][new_k] = v
                else:
                    post_data[name][k] = v

        res = self.api_post("ntwk/wlanfilterenhance", post_data)
        return res is not None

    def set_speed_limit(self, host_obj, max_down_kbps, max_up_kbps, enabled=True):
        """
        Applies download and upload rate limits to a device.
        """
        updated = dict(host_obj)
        updated["DeviceDownRateEnable"] = 1 if enabled else 0
        updated["DeviceMaxDownLoadRate"] = int(max_down_kbps)
        updated["DeviceMaxUpLoadRate"] = int(max_up_kbps)
        res = self.api_post("app/qosclass_host", updated)
        return res and res.get("errcode", 0) == 0

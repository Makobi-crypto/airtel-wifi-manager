import os
import io
import csv
from flask import Flask, render_template, jsonify, request, Response
import database
from router_client import HuaweiScramClient
from monitor import NetworkMonitor
from network_guard import NetworkGuard

app = Flask(__name__, template_folder="templates", static_folder="static")

# Initialize database
database.init_db()

# Initialize Router Client, Monitor & Network Guard
router_ip = database.get_setting("router_ip", "192.168.3.1")
router = HuaweiScramClient(router_ip=router_ip)
monitor = NetworkMonitor(router)
monitor.start()

guard = NetworkGuard(monitor_ref=monitor)
guard.start()

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/api/live")
def api_live():
    return jsonify(monitor.get_data())

@app.route("/api/setup", methods=["POST"])
def api_setup():
    data = request.get_json() or {}
    pwd = data.get("password", "").strip()
    r_ip = data.get("router_ip", "").strip() or "192.168.3.1"
    
    if not pwd:
        return jsonify({"success": False, "message": "Password cannot be empty"}), 400

    database.set_setting("router_ip", r_ip)
    router.router_ip = r_ip
    router.base_url = f"http://{r_ip}"
    
    success, msg = router.login(pwd)
    if success:
        database.set_setting("router_password", pwd)
        # Trigger immediate refresh
        monitor._poll_once()
        return jsonify({"success": True, "message": "Successfully connected and logged into Airtel ODU!"})
    else:
        return jsonify({"success": False, "message": msg}), 400

@app.route("/api/devices/rename", methods=["POST"])
def api_rename():
    data = request.get_json() or {}
    mac = data.get("mac", "").strip().upper()
    new_name = data.get("name", "").strip()
    device_id = data.get("device_id", "")
    
    if not mac or not new_name:
        return jsonify({"success": False, "message": "MAC and Name required"}), 400

    database.set_device_name(mac, new_name)
    
    # Also sync to router firmware if device_id is present and router is logged in
    router_synced = False
    if router.is_logged_in and device_id:
        try:
            router_synced = router.rename_device(device_id, new_name)
        except Exception as e:
            app.logger.error(f"Router rename failed: {e}")

    # Immediately update cache
    monitor._poll_once()
    return jsonify({
        "success": True,
        "message": f"Renamed to '{new_name}' (Router sync: {'Yes' if router_synced else 'Local only'})"
    })

@app.route("/api/devices/block", methods=["POST"])
def api_block():
    data = request.get_json() or {}
    mac = data.get("mac", "").strip().upper()
    block = bool(data.get("block", True))
    hostname = data.get("hostname", "Device")
    
    if not mac:
        return jsonify({"success": False, "message": "MAC required"}), 400

    if not router.is_logged_in:
        return jsonify({"success": False, "message": "Router not logged in. Please enter admin password first in Settings."}), 400

    if block:
        ok = router.block_device(mac, hostname)
    else:
        ok = router.unblock_device(mac)

    if ok:
        monitor._poll_once()
        return jsonify({
            "success": True,
            "message": f"Device {'blocked' if block else 'unblocked'} successfully!"
        })
    else:
        return jsonify({
            "success": False,
            "message": "Failed to update router blacklist. Please check router connection."
        }), 500

@app.route("/api/devices/reset", methods=["POST"])
def api_reset():
    data = request.get_json() or {}
    mac = data.get("mac", "").strip().upper()
    reset_all = data.get("all", False)
    
    if reset_all:
        database.reset_all_usage()
        monitor._poll_once()
        return jsonify({"success": True, "message": "All device usage counters reset to 0 MB"})
    
    if not mac:
        return jsonify({"success": False, "message": "MAC required"}), 400

    database.reset_device_usage(mac)
    monitor._poll_once()
    return jsonify({"success": True, "message": f"Usage counter for {mac} reset to 0 MB"})

@app.route("/api/devices/notes", methods=["POST"])
def api_notes():
    data = request.get_json() or {}
    mac = data.get("mac", "").strip().upper()
    notes = data.get("notes", "").strip()
    
    if not mac:
        return jsonify({"success": False, "message": "MAC required"}), 400

    database.set_device_notes(mac, notes)
    monitor._poll_once()
    return jsonify({"success": True, "message": "Notes saved"})

@app.route("/api/devices/speed-limit", methods=["POST"])
def api_speed_limit():
    data = request.get_json() or {}
    mac = data.get("mac", "").strip().upper()
    device_id = data.get("device_id", "")
    max_down = int(data.get("max_down", 0)) # in KB/s
    max_up = int(data.get("max_up", 0))     # in KB/s
    enabled = bool(data.get("enabled", True))
    
    if not router.is_logged_in:
        return jsonify({"success": False, "message": "Router not logged in"}), 400

    # Find the host object from router
    hosts = router.get_hosts()
    target_host = None
    for h in hosts:
        if h.get("MACAddress", "").upper() == mac or h.get("ID") == device_id:
            target_host = h
            break

    if not target_host:
        return jsonify({"success": False, "message": "Device not currently active on router"}), 404

    ok = router.set_speed_limit(target_host, max_down, max_up, enabled)
    if ok:
        monitor._poll_once()
        return jsonify({"success": True, "message": "Speed limit updated"})
    else:
        return jsonify({"success": False, "message": "Failed to update speed limit on router"}), 500

@app.route("/api/export-csv")
def export_csv():
    devices = database.get_all_devices()
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "Custom Name", "Original Hostname", "MAC Address", "IP Address",
        "Today Down (MB)", "Today Up (MB)", "Today Total (MB)",
        "All-Time Total (MB)", "Status", "Notes"
    ])
    
    for d in devices:
        today_total = round(d["today_down_mb"] + d["today_up_mb"], 2)
        all_total = round(d["total_down_mb"] + d["total_up_mb"], 2)
        status = "Blocked" if d["is_blocked"] else "Allowed"
        writer.writerow([
            d["custom_name"] or d["hostname"] or "Unknown",
            d["hostname"] or "",
            d["mac"],
            d["ip"] or "",
            round(d["today_down_mb"], 2),
            round(d["today_up_mb"], 2),
            today_total,
            all_total,
            status,
            d["notes"] or ""
        ])
        
    output.seek(0)
    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment;filename=airtel_wifi_usage_report.csv"}
    )

@app.route("/api/history/domains")
def api_history_domains():
    limit = request.args.get("limit", 100)
    search = request.args.get("search", None)
    mac = request.args.get("mac", None)
    queries = guard.get_recent_queries(limit=limit, search=search, mac_or_ip=mac)
    return jsonify({
        "queries": queries,
        "status": guard.get_status()
    })

@app.route("/api/history/clear", methods=["POST"])
def api_history_clear():
    data = request.get_json() or {}
    days = data.get("days", None)
    if days is not None:
        try:
            days = int(days)
        except ValueError:
            days = None
    database.clear_domain_queries(days=days)
    return jsonify({"success": True, "message": "Search and domain query history cleared"})

@app.route("/api/guard/status")
def api_guard_status():
    return jsonify(guard.get_status())

@app.route("/api/guard/toggle-tethering", methods=["POST"])
def api_toggle_tethering():
    data = request.get_json() or {}
    enabled = bool(data.get("enabled", True))
    guard.set_tethering_guard(enabled)
    return jsonify({
        "success": True,
        "enabled": enabled,
        "message": f"Anti-Hotspot / Tethering Guard is now {'ACTIVE' if enabled else 'DISABLED'}"
    })

@app.route("/api/guard/clear-alerts", methods=["POST"])
def api_clear_alerts():
    database.clear_tethering_alerts()
    return jsonify({"success": True, "message": "Tethering alerts cleared"})

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=8765, debug=False)

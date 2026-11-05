# airtel-wifi-manager (Thinkpad6g.net)

A lightweight, real-time Wi-Fi & network monitoring dashboard built with Flask, Scapy, and SQLite. Designed for monitoring local network devices, bandwidth consumption, search query traffic, and router management.

## Features

- **Live Bandwidth Tracker:** Real-time upload and download speeds, per-device consumption statistics, and daily tracking.
- **Anti-Hotspot & Packet Inspection:** Scapy-powered packet inspection to monitor TTL discrepancies and DNS queries across connected devices.
- **Device Management:** Friendly custom naming, blocking/unblocking, and bandwidth rate limits.
- **Router Integration:** SCRAM-authenticated client interface for compatible router/ODU units.
- **Local Web Dashboard:** Clean, responsive UI running locally at `http://127.0.0.1:8765`.
- **Systemd Integration:** Optional daemon setup for headless background monitoring.

## Installation

```bash
# Clone the repository
git clone https://github.com/Makobi-crypto/airtel-wifi-manager.git
cd airtel-wifi-manager

# Install dependencies
pip install -r requirements.txt
```

## Running the Dashboard

```bash
./launch.sh
```

Or run directly with Python:

```bash
python3 app.py
```

Open your browser at `http://127.0.0.1:8765`.

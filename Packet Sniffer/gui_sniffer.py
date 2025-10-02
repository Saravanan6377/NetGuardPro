# Enhanced Packet Sniffer with Improved Detection Logic
# Requirements: pip install scapy websockets
import asyncio
import csv
import json
import os
import sys
import threading
import ipaddress
from collections import defaultdict, deque
from datetime import datetime

import websockets
from scapy.all import ICMP, IP, TCP, UDP, Raw, sniff

# --- Configuration ---
LOG_DIR = "sniffer_logs"
CSV_LOG_FILE = os.path.join(LOG_DIR, "packet_log.csv")
JSON_LOG_FILE = os.path.join(LOG_DIR, "packet_log.json")
WEBSOCKET_HOST = "localhost"
WEBSOCKET_PORT = 8765

# --- Improved Detection Thresholds ---
PORT_SCAN_THRESHOLD = 20        # Increased to reduce false positives
BRUTE_FORCE_THRESHOLD = 25      # Increased threshold
BRUTE_FORCE_WINDOW = 30         # Longer time window (30 seconds)
DIFFERENT_PORTS_THRESHOLD = 5   # Must target different ports for brute-force

# --- Global State & WebSocket Management ---
lock = threading.Lock()
packet_counts = defaultdict(int)
total_packets = 0
port_scan_tracker = defaultdict(set)
brute_force_tracker = defaultdict(lambda: deque())
connection_tracker = defaultdict(lambda: defaultdict(
    lambda: deque()))  # [src][dst_port] = timestamps
connected_clients = set()
main_loop = None
local_network = None

# --- Network Detection ---


def detect_local_network():
    """Automatically detect the local network range."""
    global local_network
    try:
        # Get local IP from a sample packet or system info
        import socket
        hostname = socket.gethostname()
        local_ip = socket.gethostbyname(hostname)
        # Assume /24 subnet for most home networks
        network = ipaddress.IPv4Network(f"{local_ip}/24", strict=False)
        local_network = network
        print(f"Detected local network: {local_network}")
    except Exception:
        # Fallback to common private ranges
        local_network = ipaddress.IPv4Network("192.168.0.0/16")


def is_local_ip(ip):
    """Check if an IP is in the local network."""
    try:
        ip_addr = ipaddress.IPv4Address(ip)
        return ip_addr.is_private or (local_network and ip_addr in local_network)
    except Exception:
        return False


def is_common_service_port(port):
    """Check if port is a common legitimate service."""
    common_ports = {80, 443, 22, 21, 25, 53, 110, 143, 993, 995, 587, 465}
    return port in common_ports

# --- Initialization ---


def initialize_logging():
    if not os.path.exists(LOG_DIR):
        os.makedirs(LOG_DIR)
    # Init CSV
    with open(CSV_LOG_FILE, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['Timestamp', 'Source IP', 'Destination IP', 'Protocol',
                         'Source Port', 'Destination Port', 'Packet Size', 'Traffic Type'])
    # Init JSON
    with open(JSON_LOG_FILE, 'w') as f:
        json.dump([], f)

# --- WebSocket Coroutines ---


async def send_to_clients(message):
    """Sends a JSON message to all connected clients."""
    if connected_clients:
        disconnected = set()
        for client in connected_clients.copy():
            try:
                await client.send(message)
            except websockets.exceptions.ConnectionClosed:
                disconnected.add(client)
            except Exception as e:
                print(f"Error sending to client: {e}")
                disconnected.add(client)

        connected_clients.difference_update(disconnected)


async def register(websocket):
    """Adds a new client to the set of connected clients."""
    connected_clients.add(websocket)
    print(f"Client connected: {websocket.remote_address}")
    try:
        await websocket.wait_closed()
    finally:
        connected_clients.discard(websocket)
        print(f"Client disconnected: {websocket.remote_address}")

# --- Enhanced Threat Detection ---


def schedule_alert(alert_type, message, severity="medium"):
    """Schedules an alert to be sent to clients."""
    print(f"\n[!] {alert_type.upper()}: {message}")
    if main_loop and connected_clients:
        alert_message = json.dumps({
            "type": "alert",
            "alert_type": alert_type,
            "message": message,
            "severity": severity,
            "timestamp": datetime.now().strftime('%H:%M:%S')
        })
        asyncio.run_coroutine_threadsafe(
            send_to_clients(alert_message), main_loop)


def schedule_packet_update(packet_data):
    """Schedules a packet update to be sent to clients."""
    if main_loop and connected_clients:
        message = json.dumps({"type": "packet", "data": packet_data})
        asyncio.run_coroutine_threadsafe(send_to_clients(message), main_loop)


def detect_port_scan(src_ip, dst_ip, dst_port):
    """Improved port scan detection."""
    # Skip detection for local traffic and common services
    if is_local_ip(src_ip) and is_local_ip(dst_ip):
        return

    if is_common_service_port(dst_port):
        return

    port_scan_tracker[(src_ip, dst_ip)].add(dst_port)
    unique_ports = len(port_scan_tracker[(src_ip, dst_ip)])

    if unique_ports >= PORT_SCAN_THRESHOLD:
        msg = f"{src_ip} scanning {dst_ip} on {unique_ports} unique ports"
        schedule_alert("Port Scan", msg, "high")
        # Reset to avoid spam
        port_scan_tracker[(src_ip, dst_ip)].clear()


def detect_brute_force(src_ip, dst_ip, dst_port):
    """Improved brute-force detection with better filtering."""
    # Skip detection for:
    # 1. Internal network traffic
    # 2. HTTPS/HTTP traffic (legitimate keep-alive connections)
    # 3. DNS traffic
    if is_local_ip(src_ip) or dst_port in {80, 443, 53}:
        return

    current_time = datetime.now().timestamp()
    tracker = connection_tracker[src_ip][dst_port]

    # Remove old timestamps
    while tracker and tracker[0] < current_time - BRUTE_FORCE_WINDOW:
        tracker.popleft()

    tracker.append(current_time)

    # Only alert if targeting multiple different ports AND high frequency
    ports_targeted = len(connection_tracker[src_ip])

    if len(tracker) >= BRUTE_FORCE_THRESHOLD and ports_targeted >= DIFFERENT_PORTS_THRESHOLD:
        msg = f"External IP {src_ip} making {len(tracker)} attempts to {dst_ip}:{dst_port} in {BRUTE_FORCE_WINDOW}s (targeting {ports_targeted} different ports)"
        schedule_alert("Brute-Force Attack", msg, "high")
        # Clear to avoid repeated alerts
        connection_tracker[src_ip][dst_port].clear()


def categorize_traffic(src_ip, dst_ip, src_port, dst_port, protocol):
    """Categorize traffic type for better analysis."""
    if protocol == "UDP":
        if dst_port == 53 or src_port == 53:
            return "DNS"
        elif dst_port == 5353:
            return "mDNS"
        else:
            return "UDP"
    elif protocol == "TCP":
        if dst_port == 443 or src_port == 443:
            return "HTTPS"
        elif dst_port == 80 or src_port == 80:
            return "HTTP"
        elif dst_port == 22 or src_port == 22:
            return "SSH"
        else:
            return "TCP"
    else:
        return protocol


def analyze_packet(packet):
    """Enhanced packet analysis with improved detection."""
    global total_packets
    if not IP in packet:
        return

    with lock:
        total_packets += 1
        timestamp = datetime.now()

        ip_src, ip_dst = packet[IP].src, packet[IP].dst
        proto, sport, dport = "Other", 0, 0

        if TCP in packet:
            proto, sport, dport = "TCP", packet[TCP].sport, packet[TCP].dport
        elif UDP in packet:
            proto, sport, dport = "UDP", packet[UDP].sport, packet[UDP].dport
        elif ICMP in packet:
            proto = "ICMP"

        packet_counts[proto] += 1
        packet_size = len(packet)

        # Categorize traffic
        traffic_type = categorize_traffic(ip_src, ip_dst, sport, dport, proto)

        # Create packet data dictionary
        packet_data = {
            "timestamp": timestamp.strftime('%H:%M:%S'),
            "src_ip": ip_src,
            "dst_ip": ip_dst,
            "protocol": proto,
            "src_port": sport,
            "dst_port": dport,
            "size": packet_size,
            "traffic_type": traffic_type
        }

        # Prepare full log data (for files)
        log_data = [timestamp.strftime(
            '%Y-%m-%d %H:%M:%S'), ip_src, ip_dst, proto, sport, dport, packet_size, traffic_type]

        # Schedule WebSocket update
        schedule_packet_update(packet_data)

        # --- Enhanced Suspicious Activity Detection ---
        if proto == "TCP" and dport > 0:
            detect_port_scan(ip_src, ip_dst, dport)
            detect_brute_force(ip_src, ip_dst, dport)

        # --- File Logging ---
        try:
            with open(CSV_LOG_FILE, 'a', newline='') as f:
                csv.writer(f).writerow(log_data)
        except Exception as e:
            print(f"Error writing to log: {e}")

# --- Sniffer Thread ---


def start_sniffer():
    """Starts the Scapy sniffer in a separate thread."""
    print("Starting packet sniffer with enhanced detection...")
    try:
        sniff(prn=analyze_packet, store=False)
    except Exception as e:
        print(f"[!] Sniffer Error: {e}")

# --- Main Server ---


async def main():
    """Sets up the sniffer thread and WebSocket server."""
    global main_loop
    main_loop = asyncio.get_running_loop()

    initialize_logging()
    detect_local_network()

    # Run Scapy in a separate thread
    sniffer_thread = threading.Thread(target=start_sniffer, daemon=True)
    sniffer_thread.start()

    # Start WebSocket server
    print(
        f"Starting WebSocket server on ws://{WEBSOCKET_HOST}:{WEBSOCKET_PORT}")
    print("Enhanced detection logic active - fewer false positives!")
    print("Open index.html in your browser to view the dashboard.")
    print("Press Ctrl+C to stop.")

    async with websockets.serve(register, WEBSOCKET_HOST, WEBSOCKET_PORT):
        await asyncio.Future()  # Run forever

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nServer is shutting down.")
    except Exception as e:
        print(f"Error: {e}")

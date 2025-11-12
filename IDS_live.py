
"""
IDS_live.py

Intrusion Detection System (live capture) using scapy and signature rules.

"""

import threading
import time
import json
import logging
import re
import sqlite3
from datetime import datetime, timedelta
from collections import defaultdict, deque

try:
    from scapy.all import sniff, Raw, IP, TCP, UDP, Ether
except Exception as e:
    raise SystemExit("scapy is required (pip install scapy). Also ensure you run as root to capture packets. Error: " + str(e))

# --------------------
# DBManager
# --------------------
class DBManager:
    def __init__(self, db_name="ids_live.db"):
        self.conn = sqlite3.connect(db_name, check_same_thread=False)
        self.cursor = self.conn.cursor()
        self._create_tables()

    def _create_tables(self):
        self.cursor.execute('''CREATE TABLE IF NOT EXISTS connections (
                                id INTEGER PRIMARY KEY AUTOINCREMENT,
                                timestamp TEXT,
                                src_ip TEXT,
                                dest_ip TEXT,
                                src_port INTEGER,
                                dest_port INTEGER,
                                protocol TEXT,
                                summary TEXT)''')

        self.cursor.execute('''CREATE TABLE IF NOT EXISTS alerts (
                                id INTEGER PRIMARY KEY AUTOINCREMENT,
                                timestamp TEXT,
                                rule_id TEXT,
                                src_ip TEXT,
                                dest_ip TEXT,
                                dest_port INTEGER,
                                protocol TEXT,
                                message TEXT)''')
        self.conn.commit()

    def log_connection(self, src_ip, dest_ip, src_port, dest_port, protocol, summary):
        self.cursor.execute(
            "INSERT INTO connections (timestamp, src_ip, dest_ip, src_port, dest_port, protocol, summary) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (datetime.utcnow().isoformat(), src_ip, dest_ip, src_port, dest_port, protocol, summary)
        )
        self.conn.commit()

    def log_alert(self, rule_id, src_ip, dest_ip, dest_port, protocol, message):
        self.cursor.execute(
            "INSERT INTO alerts (timestamp, rule_id, src_ip, dest_ip, dest_port, protocol, message) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (datetime.utcnow().isoformat(), rule_id, src_ip, dest_ip, dest_port, protocol, message)
        )
        self.conn.commit()

    def close(self):
        self.conn.close()

# --------------------
# Alerter
# --------------------
class Alerter:
    def __init__(self, log_file="alerts.log"):
        self.log_file = log_file
        self.logged_alerts = set()  
        logging.basicConfig(filename=self.log_file,
                            level=logging.INFO,
                            format="%(asctime)s - %(message)s")

    def _make_alert_key(self, rule_id, src_ip, dest_ip, dest_port):
        return f"{rule_id}|{src_ip}|{dest_ip}|{dest_port}"

    def alert(self, rule_id, src_ip, dest_ip, dest_port, protocol, message):
        key = self._make_alert_key(rule_id, src_ip, dest_ip, dest_port)
        if key not in self.logged_alerts:
            self.logged_alerts.add(key)
            alert_text = f"[ALERT] rule={rule_id} src={src_ip} dst={dest_ip}:{dest_port} proto={protocol} msg={message}"
            print(alert_text)                    
            logging.info(alert_text)               
            threading.Thread(target=self._expire_key, args=(key, 60), daemon=True).start()

    def _expire_key(self, key, ttl_seconds):
        time.sleep(ttl_seconds)
        self.logged_alerts.discard(key)

# --------------------
# Responder
# --------------------
class Responder:
    def __init__(self):
        self.blocked_ips = set()

    def block_ip(self, ip_address):
        # In this demo we only maintain an in-memory blocklist and print it.
        # For production, implement firewall integration (iptables, nft, windows firewall) carefully.
        if ip_address not in self.blocked_ips:
            self.blocked_ips.add(ip_address)
            print(f"[RESPONDER] BLOCKED IP: {ip_address}")

    def is_blocked(self, ip_address):
        return ip_address in self.blocked_ips

    def show_blocked(self):
        if not self.blocked_ips:
            print("[RESPONDER] No blocked IPs.")
        else:
            print("[RESPONDER] Blocked IPs:")
            for ip in sorted(self.blocked_ips):
                print(" -", ip)

# --------------------
# Signature Engine
# --------------------
class SignatureEngine:
    def __init__(self, signature_file="signatures.json"):
        self.signature_file = signature_file
        self.signatures = []
        self._load_signatures()

    def _load_signatures(self):
        try:
            with open(self.signature_file, "r") as f:
                raw = json.load(f)
        except Exception as e:
            print(f"[SIG] Failed to load signatures from {self.signature_file}: {e}")
            raw = []

        normalized = []
        for r in raw:
            if not all(k in r for k in ("id", "field", "match_type", "value")):
                continue
            compiled = None
            if r["match_type"] == "regex":
                try:
                    compiled = re.compile(r["value"], re.IGNORECASE)
                except re.error:
                    compiled = None
            r["_compiled"] = compiled
            normalized.append(r)
        self.signatures = normalized
        print(f"[SIG] Loaded {len(self.signatures)} signatures.")

    def match(self, packet_meta):
        """
        packet_meta: dict with keys like src_ip, dest_ip, src_port, dest_port, protocol, payload (string)
        Returns list of matched signature dicts.
        """
        matches = []
        payload = packet_meta.get("payload", "")
        for sig in self.signatures:
            field = sig.get("field")
            mtype = sig.get("match_type")
            value = sig.get("value")
            field_val = packet_meta.get(field)
            try:
                if mtype == "contains" and isinstance(field_val, str):
                    if value.lower() in field_val.lower():
                        matches.append(sig)
                elif mtype == "regex" and isinstance(field_val, str) and sig.get("_compiled") is not None:
                    if sig["_compiled"].search(field_val):
                        matches.append(sig)
                elif mtype == "eq":
                    if str(field_val) == str(value):
                        matches.append(sig)
                elif mtype == "in":
                    if isinstance(value, list) and field_val in value:
                        matches.append(sig)
                elif mtype == "exists":
                    if field in packet_meta and packet_meta[field] is not None:
                        matches.append(sig)
            except Exception:
                continue
        return matches

# --------------------
# Analyzer
# --------------------
class Analyzer:
    def __init__(self, db_manager, alerter, responder, sig_engine, dos_threshold_per_minute=100):
        self.db = db_manager
        self.alerter = alerter
        self.responder = responder
        self.sig_engine = sig_engine
        self.ip_activity = defaultdict(lambda: deque())
        self.dos_threshold_per_minute = dos_threshold_per_minute  

    def analyze(self, packet_meta):
        src_ip = packet_meta.get("src_ip")
        dest_ip = packet_meta.get("dest_ip")
        src_port = packet_meta.get("src_port")
        dest_port = packet_meta.get("dest_port")
        protocol = packet_meta.get("protocol")
        payload = packet_meta.get("payload", "")[:2000]  

        summary = (payload[:200] + "...") if payload else ""
        try:
            self.db.log_connection(src_ip, dest_ip, src_port, dest_port, protocol, summary)
        except Exception as e:
            print(f"[DB] Failed to log connection: {e}")

        matches = self.sig_engine.match(packet_meta)
        for sig in matches:
            rule_id = sig.get("id")
            message = sig.get("description", f"Signature {rule_id} matched")
    
            self.alerter.alert(rule_id, src_ip, dest_ip, dest_port, protocol, message)
            self.db.log_alert(rule_id, src_ip, dest_ip, dest_port, protocol, message)
    
            if sig.get("action") in ("alert", "block"):
                self.responder.block_ip(src_ip)

        now = datetime.utcnow()
        dq = self.ip_activity[src_ip]
        dq.append(now)
        cutoff = now - timedelta(seconds=60)
        while dq and dq[0] < cutoff:
            dq.popleft()

        pkt_count_last_min = len(dq)
        if pkt_count_last_min > self.dos_threshold_per_minute:
            rule_id = "BEHAV_DoS"
            message = f"High packet rate: {pkt_count_last_min} pkt/min (> {self.dos_threshold_per_minute})"
            self.alerter.alert(rule_id, src_ip, dest_ip, dest_port, protocol, message)
            self.db.log_alert(rule_id, src_ip, dest_ip, dest_port, protocol, message)
            self.responder.block_ip(src_ip)

# --------------------
# Sensor (scapy sniff)
# --------------------
class Sensor(threading.Thread):
    def __init__(self, analyzer, iface=None, bpf_filter=None):
        super().__init__(daemon=True)
        self.analyzer = analyzer
        self.iface = iface
        self.bpf_filter = bpf_filter
        self._stop_event = threading.Event()

    def run(self):
        print("[SENSOR] Starting live capture (press Ctrl+C to stop)...")
        try:
            sniff(iface=self.iface, filter=self.bpf_filter, prn=self._handle_pkt, store=False, stop_filter=self._stop_filter)
        except Exception as e:
            print(f"[SENSOR] sniff() failed: {e}")

    def _stop_filter(self, pkt):
        return self._stop_event.is_set()

    def stop(self):
        self._stop_event.set()
        print("[SENSOR] Stop requested. Waiting for sniff to exit...")

    def _handle_pkt(self, pkt):
        try:
            if IP in pkt:
                ip_layer = pkt[IP]
                src_ip = ip_layer.src
                dest_ip = ip_layer.dst
                protocol = None
                src_port = None
                dest_port = None
                payload_str = ""

                if TCP in pkt:
                    protocol = "TCP"
                    src_port = pkt[TCP].sport
                    dest_port = pkt[TCP].dport
                    if Raw in pkt:
                        try:
                            payload_bytes = bytes(pkt[Raw].load)
                            payload_str = payload_bytes.decode('latin-1', errors='ignore')
                        except Exception:
                            payload_str = ""
                elif UDP in pkt:
                    protocol = "UDP"
                    src_port = pkt[UDP].sport
                    dest_port = pkt[UDP].dport
                    if Raw in pkt:
                        try:
                            payload_bytes = bytes(pkt[Raw].load)
                            payload_str = payload_bytes.decode('latin-1', errors='ignore')
                        except Exception:
                            payload_str = ""
                else:
                    protocol = str(ip_layer.proto)

                if self.analyzer.responder.is_blocked(src_ip):
                    self.analyzer.db.log_connection(src_ip, dest_ip, src_port, dest_port, protocol, "blocked-src-suppressed")
                    return

                pkt_meta = {
                    "src_ip": src_ip,
                    "dest_ip": dest_ip,
                    "src_port": src_port,
                    "dest_port": dest_port,
                    "protocol": protocol,
                    "payload": payload_str
                }
                self.analyzer.analyze(pkt_meta)
        except Exception as e:
            print(f"[SENSOR] Packet handling error: {e}")

# --------------------
# CentralConsole
# --------------------
class CentralConsole:
    def __init__(self, iface=None, bpf_filter=None, signature_file="signatures.json"):
        self.db_manager = DBManager()
        self.alerter = Alerter()
        self.responder = Responder()
        self.sig_engine = SignatureEngine(signature_file)
        self.analyzer = Analyzer(self.db_manager, self.alerter, self.responder, self.sig_engine, dos_threshold_per_minute=200)
        self.sensor = Sensor(self.analyzer, iface=iface, bpf_filter=bpf_filter)

    def start(self):
        print("[CONSOLE] Starting IDS...")
        self.sensor.start()

    def stop(self):
        print("[CONSOLE] Stopping IDS...")
        self.sensor.stop()
        self.sensor.join(timeout=5)
        self.responder.show_blocked()
        self.db_manager.close()
        print("[CONSOLE] IDS stopped.")

# --------------------
# Main
# --------------------
if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Live IDS using scapy and rule signatures.")
    parser.add_argument("--iface", help="Network interface to sniff (e.g., eth0). Default: None (scapy default)", default=None)
    parser.add_argument("--filter", help="BPF filter for scapy (e.g., 'tcp and port 80')", default=None)
    parser.add_argument("--sigs", help="Signature file (JSON)", default="signatures.json")
    args = parser.parse_args()

    console = CentralConsole(iface=args.iface, bpf_filter=args.filter, signature_file=args.sigs)
    try:
        console.start()
    
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[MAIN] Keyboard interrupt received.")
    finally:
        console.stop()

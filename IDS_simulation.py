import threading
import time
import random
import sqlite3
import logging
from datetime import datetime

# -------------------------------------------------------
# 1. DBManager
# -------------------------------------------------------
class DBManager:
    def __init__(self, db_name="ids_logs.db"):
        self.conn = sqlite3.connect(db_name, check_same_thread=False)
        self.cursor = self.conn.cursor()
        self._create_tables()

    def _create_tables(self):
        self.cursor.execute('''CREATE TABLE IF NOT EXISTS connections (
                                id INTEGER PRIMARY KEY AUTOINCREMENT,
                                timestamp TEXT,
                                src_ip TEXT,
                                dest_ip TEXT,
                                status TEXT)''')

        self.cursor.execute('''CREATE TABLE IF NOT EXISTS alerts (
                                id INTEGER PRIMARY KEY AUTOINCREMENT,
                                timestamp TEXT,
                                src_ip TEXT,
                                threat_type TEXT,
                                message TEXT)''')
        self.conn.commit()

    def log_connection(self, src_ip, dest_ip, status):
        self.cursor.execute("INSERT INTO connections (timestamp, src_ip, dest_ip, status) VALUES (?, ?, ?, ?)",
                            (datetime.now(), src_ip, dest_ip, status))
        self.conn.commit()

    def log_alert(self, src_ip, threat_type, message):
        self.cursor.execute("INSERT INTO alerts (timestamp, src_ip, threat_type, message) VALUES (?, ?, ?, ?)",
                            (datetime.now(), src_ip, threat_type, message))
        self.conn.commit()

    def close(self):
        self.conn.close()


# -------------------------------------------------------
# 2. Alerter
# -------------------------------------------------------
class Alerter:
    def __init__(self, log_file="alerts.log"):
        self.logged_alerts = set()
        logging.basicConfig(filename=log_file, level=logging.INFO, format="%(asctime)s - %(message)s")

    def alert(self, src_ip, threat_type, message):
        alert_msg = f"[ALERT] {src_ip} | Threat: {threat_type} | {message}"
        if alert_msg not in self.logged_alerts:
            self.logged_alerts.add(alert_msg)
            print(alert_msg)
            logging.info(alert_msg)


# -------------------------------------------------------
# 3. Responder
# -------------------------------------------------------
class Responder:
    def __init__(self):
        self.blocked_ips = set()

    def block_ip(self, ip_address):
        if ip_address not in self.blocked_ips:
            self.blocked_ips.add(ip_address)
            print(f"[RESPONDER] IP {ip_address} has been BLOCKED due to suspicious activity.")

    def show_blocked_ips(self):
        if not self.blocked_ips:
            print("[RESPONDER] No IP addresses blocked yet.")
        else:
            print("[RESPONDER] Blocked IPs:")
            for ip in self.blocked_ips:
                print(f" - {ip}")


# -------------------------------------------------------
# 4. Analyzer
# -------------------------------------------------------
class Analyzer:
    def __init__(self, db_manager, alerter, responder):
        self.db = db_manager
        self.alerter = alerter
        self.responder = responder

    def analyze_packet(self, packet):
        src_ip = packet["src_ip"]
        dest_ip = packet["dest_ip"]
        payload = packet["payload"]

        # Log every connection
        self.db.log_connection(src_ip, dest_ip, "OK")

        # Simulated threat detection
        if "malware" in payload.lower():
            self.alerter.alert(src_ip, "Malware", "Malicious payload detected in packet.")
            self.db.log_alert(src_ip, "Malware", "Malicious payload detected.")
            self.responder.block_ip(src_ip)

        elif "dos" in payload.lower():
            self.alerter.alert(src_ip, "DoS Attack", "High packet frequency detected.")
            self.db.log_alert(src_ip, "DoS Attack", "Denial of Service pattern found.")
            self.responder.block_ip(src_ip)


# -------------------------------------------------------
# 5. Sensor (runs in a separate thread)
# -------------------------------------------------------
class Sensor(threading.Thread):
    def __init__(self, analyzer):
        super().__init__()
        self.analyzer = analyzer
        self.running = False

    def run(self):
        self.running = True
        print("[SENSOR] Packet sniffing started...")
        while self.running:
            packet = self._generate_mock_packet()
            self.analyzer.analyze_packet(packet)
            time.sleep(random.uniform(1, 3))  

    def stop(self):
        self.running = False
        print("[SENSOR] Stopping packet sniffing...")

    def _generate_mock_packet(self):
        ips = ["192.168.1.5", "10.0.0.8", "172.16.0.3", "203.0.113.15"]
        src_ip = random.choice(ips)
        dest_ip = "192.168.1.1"
        payloads = ["Normal traffic", "File upload", "malware signature", "DoS flood"]
        return {"src_ip": src_ip, "dest_ip": dest_ip, "payload": random.choice(payloads)}


# -------------------------------------------------------
# 6. CentralConsole
# -------------------------------------------------------
class CentralConsole:
    def __init__(self):
        self.db_manager = DBManager()
        self.alerter = Alerter()
        self.responder = Responder()
        self.analyzer = Analyzer(self.db_manager, self.alerter, self.responder)
        self.sensor = Sensor(self.analyzer)

    def start(self):
        print("[CONSOLE] Starting Intrusion Detection System...")
        self.sensor.start()

    def stop(self):
        print("[CONSOLE] Stopping Intrusion Detection System...")
        self.sensor.stop()
        self.sensor.join()
        self.responder.show_blocked_ips()
        self.db_manager.close()
        print("[CONSOLE] IDS stopped successfully.")


# -------------------------------------------------------
# MAIN EXECUTION
# -------------------------------------------------------
if __name__ == "__main__":
    console = CentralConsole()
    try:
        console.start()
        time.sleep(15)  
    except KeyboardInterrupt:
        pass
    finally:
        console.stop()

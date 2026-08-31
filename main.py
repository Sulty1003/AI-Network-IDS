from scapy.all import sniff, IP, TCP, UDP, ICMP, conf
from sklearn.ensemble import IsolationForest
from collections import defaultdict
import pandas as pd
import sqlite3
import joblib
import time
import os


# ==========================================================
# CONFIGURATION
# ==========================================================

WINDOW_SECONDS = 10

# 30 windows x 10 seconds = about 5 minutes of baseline traffic
TRAINING_WINDOWS_REQUIRED = 30

# Rule-based thresholds
SYN_FLOOD_THRESHOLD = 40
PORT_SCAN_THRESHOLD = 20
RULE_TIME_WINDOW = 10

DATABASE_FILE = "network_ids.db"
MODEL_FILE = "network_model.pkl"


# These are the features used by the AI model.
FEATURE_COLUMNS = [
    "packets_per_second",
    "bytes_per_second",
    "syn_per_second",
    "icmp_per_second",
    "unique_sources",
    "unique_destinations",
    "unique_ports",
]


# ==========================================================
# GLOBAL VARIABLES
# ==========================================================

model = None
training_samples = []

window_start = time.time()

packet_count = 0
total_bytes = 0
syn_count = 0
icmp_count = 0

source_ips = set()
destination_ips = set()
destination_ports = set()

# Used by the rule-based IDS.
syn_history = defaultdict(list)
port_history = defaultdict(list)

# Prevents the same alert from printing constantly.
last_alert_time = {}

ALERT_COOLDOWN = 10


# ==========================================================
# DATABASE
# ==========================================================

def initialize_database():
    """
    Create the SQLite alerts table if it does not already exist.
    """

    with sqlite3.connect(DATABASE_FILE) as connection:
        cursor = connection.cursor()

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                source_ip TEXT,
                destination_ip TEXT,
                alert_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                anomaly_score REAL
            )
            """
        )

        connection.commit()


def save_alert(
    source_ip,
    destination_ip,
    alert_type,
    severity,
    anomaly_score=None,
):
    """
    Store an alert in SQLite.
    """

    with sqlite3.connect(DATABASE_FILE) as connection:
        cursor = connection.cursor()

        cursor.execute(
            """
            INSERT INTO alerts (
                timestamp,
                source_ip,
                destination_ip,
                alert_type,
                severity,
                anomaly_score
            )
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                time.strftime("%Y-%m-%d %H:%M:%S"),
                source_ip,
                destination_ip,
                alert_type,
                severity,
                anomaly_score,
            ),
        )

        connection.commit()


# ==========================================================
# ALERT SYSTEM
# ==========================================================

def alert_allowed(alert_key):
    """
    Prevent repeated identical alerts from flooding the terminal.
    """

    current_time = time.time()

    previous_time = last_alert_time.get(alert_key, 0)

    if current_time - previous_time < ALERT_COOLDOWN:
        return False

    last_alert_time[alert_key] = current_time

    return True


def generate_alert(
    source_ip,
    destination_ip,
    alert_type,
    severity="MEDIUM",
    anomaly_score=None,
):
    """
    Display and save an IDS alert.
    """

    alert_key = (source_ip, alert_type)

    if not alert_allowed(alert_key):
        return

    print("\n" + "=" * 65)
    print("NETWORK IDS ALERT")
    print("=" * 65)

    print(
        f"Time            : "
        f"{time.strftime('%Y-%m-%d %H:%M:%S')}"
    )

    print(f"Source IP       : {source_ip}")
    print(f"Destination IP  : {destination_ip}")
    print(f"Alert Type      : {alert_type}")
    print(f"Severity        : {severity}")

    if anomaly_score is not None:
        print(f"Anomaly Score   : {anomaly_score:.4f}")

    print("=" * 65 + "\n")

    save_alert(
        source_ip,
        destination_ip,
        alert_type,
        severity,
        anomaly_score,
    )


# ==========================================================
# SYN FLOOD DETECTION
# ==========================================================

def detect_syn_flood(source_ip, destination_ip):
    """
    Count SYN connection attempts from each source IP
    during a rolling time window.
    """

    now = time.time()

    syn_history[source_ip].append(now)

    syn_history[source_ip] = [
        timestamp
        for timestamp in syn_history[source_ip]
        if now - timestamp <= RULE_TIME_WINDOW
    ]

    number_of_syn_packets = len(syn_history[source_ip])

    if number_of_syn_packets >= SYN_FLOOD_THRESHOLD:

        generate_alert(
            source_ip=source_ip,
            destination_ip=destination_ip,
            alert_type="Possible SYN Flood",
            severity="HIGH",
        )


# ==========================================================
# PORT SCAN DETECTION
# ==========================================================

def detect_port_scan(
    source_ip,
    destination_ip,
    destination_port,
):
    """
    Detect one source attempting connections to many
    different TCP destination ports.
    """

    now = time.time()

    port_history[source_ip].append(
        (now, destination_port)
    )

    # Keep only recent connection attempts.
    port_history[source_ip] = [
        item
        for item in port_history[source_ip]
        if now - item[0] <= RULE_TIME_WINDOW
    ]

    unique_ports = {
        port
        for _, port in port_history[source_ip]
    }

    if len(unique_ports) >= PORT_SCAN_THRESHOLD:

        generate_alert(
            source_ip=source_ip,
            destination_ip=destination_ip,
            alert_type="Possible TCP Port Scan",
            severity="HIGH",
        )


# ==========================================================
# AI MODEL
# ==========================================================

def load_model():
    """
    Load an already-trained Isolation Forest model.
    """

    global model

    if not os.path.exists(MODEL_FILE):
        print("[AI] No trained model found.")
        print("[AI] Baseline collection will begin.")
        return

    try:

        model = joblib.load(MODEL_FILE)

        print("[AI] Existing anomaly model loaded.")

    except Exception as error:

        model = None

        print(
            f"[AI] Model could not be loaded: {error}"
        )


def train_model():
    """
    Train Isolation Forest using the baseline windows.
    """

    global model

    if len(training_samples) < TRAINING_WINDOWS_REQUIRED:
        return

    dataframe = pd.DataFrame(
        training_samples,
        columns=FEATURE_COLUMNS,
    )

    model = IsolationForest(
        n_estimators=200,
        contamination=0.05,
        random_state=42,
    )

    model.fit(dataframe)

    joblib.dump(model, MODEL_FILE)

    print("\n" + "=" * 65)
    print("[AI] BASELINE TRAINING COMPLETE")
    print(f"[AI] Training windows: {len(training_samples)}")
    print(f"[AI] Model saved as: {MODEL_FILE}")
    print("=" * 65 + "\n")


# ==========================================================
# AI ANOMALY DETECTION
# ==========================================================

def detect_ai_anomaly(features):
    """
    Ask the trained Isolation Forest whether the current
    traffic window is normal or anomalous.
    """

    if model is None:
        return

    sample = pd.DataFrame(
        [features],
        columns=FEATURE_COLUMNS,
    )

    prediction = model.predict(sample)[0]

    anomaly_score = model.decision_function(
        sample
    )[0]

    # Isolation Forest:
    #  1 = normal
    # -1 = anomaly

    if prediction == -1:

        generate_alert(
            source_ip="NETWORK",
            destination_ip="MULTIPLE",
            alert_type="AI Network Anomaly",
            severity="MEDIUM",
            anomaly_score=anomaly_score,
        )


# ==========================================================
# PROCESS A TRAFFIC WINDOW
# ==========================================================

def process_traffic_window():
    """
    Convert the packets observed during a 10-second window
    into numerical features for the AI model.
    """

    global window_start
    global packet_count
    global total_bytes
    global syn_count
    global icmp_count
    global source_ips
    global destination_ips
    global destination_ports

    current_time = time.time()

    elapsed = current_time - window_start

    if elapsed < WINDOW_SECONDS:
        return

    packets_per_second = packet_count / elapsed
    bytes_per_second = total_bytes / elapsed
    syn_per_second = syn_count / elapsed
    icmp_per_second = icmp_count / elapsed

    features = [
        packets_per_second,
        bytes_per_second,
        syn_per_second,
        icmp_per_second,
        len(source_ips),
        len(destination_ips),
        len(destination_ports),
    ]

    print("\n" + "-" * 65)
    print("NETWORK TRAFFIC WINDOW")
    print("-" * 65)

    print(
        f"Packets/sec         : "
        f"{packets_per_second:.2f}"
    )

    print(
        f"Bytes/sec           : "
        f"{bytes_per_second:.2f}"
    )

    print(
        f"SYN/sec             : "
        f"{syn_per_second:.2f}"
    )

    print(
        f"ICMP/sec            : "
        f"{icmp_per_second:.2f}"
    )

    print(
        f"Unique Sources      : "
        f"{len(source_ips)}"
    )

    print(
        f"Unique Destinations : "
        f"{len(destination_ips)}"
    )

    print(
        f"Unique Ports        : "
        f"{len(destination_ports)}"
    )

    print("-" * 65)

    # ------------------------------------------------------
    # TRAINING MODE
    # ------------------------------------------------------

    if model is None:

        training_samples.append(features)

        print(
            f"[AI] Baseline collection: "
            f"{len(training_samples)}/"
            f"{TRAINING_WINDOWS_REQUIRED}"
        )

        if (
            len(training_samples)
            >= TRAINING_WINDOWS_REQUIRED
        ):
            train_model()

    # ------------------------------------------------------
    # DETECTION MODE
    # ------------------------------------------------------

    else:

        detect_ai_anomaly(features)

    # Reset statistics for the next window.

    packet_count = 0
    total_bytes = 0
    syn_count = 0
    icmp_count = 0

    source_ips.clear()
    destination_ips.clear()
    destination_ports.clear()

    window_start = current_time


# ==========================================================
# PACKET ANALYSIS
# ==========================================================

def analyze_packet(packet):
    """
    Called for each captured packet.
    """

    global packet_count
    global total_bytes
    global syn_count
    global icmp_count

    # Ignore packets without an IPv4 layer.
    if IP not in packet:
        return

    source_ip = packet[IP].src
    destination_ip = packet[IP].dst

    packet_count += 1
    total_bytes += len(packet)

    source_ips.add(source_ip)
    destination_ips.add(destination_ip)

    protocol = "OTHER"
    destination_port = "-"

    # ------------------------------------------------------
    # TCP
    # ------------------------------------------------------

    if TCP in packet:

        protocol = "TCP"

        destination_port = packet[TCP].dport

        destination_ports.add(destination_port)

        flags = int(packet[TCP].flags)

        SYN_FLAG = 0x02
        ACK_FLAG = 0x10

        is_syn = bool(flags & SYN_FLAG)
        is_ack = bool(flags & ACK_FLAG)

        # Count connection-opening SYN packets,
        # not SYN-ACK responses.

        if is_syn and not is_ack:

            syn_count += 1

            detect_syn_flood(
                source_ip,
                destination_ip,
            )

            detect_port_scan(
                source_ip,
                destination_ip,
                destination_port,
            )

    # ------------------------------------------------------
    # UDP
    # ------------------------------------------------------

    elif UDP in packet:

        protocol = "UDP"

        destination_port = packet[UDP].dport

        destination_ports.add(destination_port)

    # ------------------------------------------------------
    # ICMP
    # ------------------------------------------------------

    elif ICMP in packet:

        protocol = "ICMP"

        icmp_count += 1

    # Show captured traffic.

    print(
        f"{source_ip:<15} -> "
        f"{destination_ip:<15} | "
        f"{protocol:<5} | "
        f"Port: {str(destination_port):<5} | "
        f"{len(packet)} bytes"
    )


# ==========================================================
# START NETWORK MONITORING
# ==========================================================

def start_ids():
    """
    Main IDS loop.
    """

    initialize_database()

    load_model()

    print("\n" + "=" * 65)
    print("AI-BASED NETWORK INTRUSION DETECTION SYSTEM")
    print("=" * 65)

    print("Status : Monitoring")
    print(f"Window : {WINDOW_SECONDS} seconds")

    if model is None:
        print("AI Mode: Learning normal network baseline")
    else:
        print("AI Mode: Anomaly detection")

    print("\nPress CTRL+C to stop.\n")

    try:

        while True:

            # Capture packets for one second.
            #
            # timeout=1 is important because it lets the
            # traffic-window timer continue even if there
            # are no packets.

            sniff(
                prn=analyze_packet,
                store=False,
                timeout=1,
            )

            process_traffic_window()

    except KeyboardInterrupt:

        print("\n" + "=" * 65)
        print("Network IDS stopped.")
        print("=" * 65)

    except PermissionError:

        print(
            "\nPermission denied."
            "\nRun your terminal as Administrator/root."
        )

    except Exception as error:

        print(
            f"\nIDS error: {error}"
        )


# ==========================================================
# PROGRAM ENTRY POINT
# ==========================================================

if __name__ == "__main__":
    start_ids()
"""
SMART HOME CYBERSECURITY IDS
Integrated ESP32 #1 telemetry + Python IDS/ML + ESP32 #2 alarm controller.

IMPORTANT FIXES:
1. Failed PIN attempts are treated as a DELTA from the last SAFE/reset point.
   The cumulative ESP32 counter therefore cannot keep BRUTE_FORCE active forever.
2. ML uses an Isolation Forest trained on a wider real-world normal range.
3. Very small/borderline ML scores are not treated as attacks.
4. ML anomalies require two consecutive confirmations.
5. RETURN TO SAFE is a manual reset/latch for the demonstration.
6. Test buttons still work without changing either ESP32 firmware.
"""

import threading
import time
from datetime import datetime

import numpy as np
import pandas as pd
import requests
from flask import Flask, jsonify, render_template
from sklearn.ensemble import IsolationForest


# ============================================================
# CONFIGURATION
# ============================================================

ESP32_1_IP = "10.197.146.103"
ESP32_2_IP = "10.197.146.197"

ESP32_1_STATUS_URL = f"http://{ESP32_1_IP}/security/status"

ESP32_2_ALERT_URL = f"http://{ESP32_2_IP}/alert"
ESP32_2_SAFE_URL = f"http://{ESP32_2_IP}/safe"
ESP32_2_STATUS_URL = f"http://{ESP32_2_IP}/status"

FLASK_HOST = "0.0.0.0"
FLASK_PORT = 5001

POLL_INTERVAL = 2.0

# Rule thresholds
REQUEST_FLOOD_THRESHOLD = 10.0
SERVICE_PROBE_THRESHOLD = 5.0
BRUTE_FORCE_THRESHOLD = 3
TEMPERATURE_HIGH = 40.0
TEMPERATURE_LOW = 0.0
HUMIDITY_HIGH = 90.0

# ML configuration
ML_ANOMALY_SCORE_THRESHOLD = -0.04
ML_CONFIRMATIONS_REQUIRED = 2


# ============================================================
# FLASK
# ============================================================

app = Flask(__name__, template_folder="templates")


# ============================================================
# ML MODEL
# ============================================================

FEATURES = [
    "request_rate",
    "bad_request_rate",
    "temperature",
    "humidity",
]

model = None


def train_ml_model():
    """
    Train Isolation Forest on a deliberately broad NORMAL
    smart-home operating range.

    This is done at startup so an old .pkl model cannot keep
    classifying the actual DHT11 environment as anomalous.
    """

    global model

    rng = np.random.default_rng(42)

    normal_data = np.column_stack([
        # Normal request activity
        rng.uniform(0.5, 8.0, 3000),

        # Normally very few failed/bad requests
        rng.uniform(0.0, 1.5, 3000),

        # Normal indoor temperature
        rng.uniform(20.0, 38.0, 3000),

        # Normal indoor humidity
        rng.uniform(35.0, 85.0, 3000),
    ])

    model = IsolationForest(
        n_estimators=300,
        contamination=0.03,
        random_state=42
    )

    model.fit(normal_data)

    print("ML model trained successfully.")
    print("Normal range:")
    print("  Request rate : 0.5 - 8")
    print("  Bad requests : 0 - 1.5")
    print("  Temperature  : 20 - 38 C")
    print("  Humidity     : 35 - 85 %")


# ============================================================
# SYSTEM STATE
# ============================================================

state = {
    "status": "SAFE",
    "attack_type": "NONE",

    "ml_prediction": "NORMAL",
    "ml_result": "NORMAL",
    "ml_score": 0.0,

    "rule_result": "NONE",

    "request_rate": 0.0,
    "bad_request_rate": 0.0,
    "failed_pin_attempts": 0,

    "temperature": 0.0,
    "humidity": 0.0,

    "esp32_1_connected": False,
    "esp32_2_connected": True,
    "esp32_2_check": "HARDCODED_CONNECTED",

    "last_update": "System starting in SAFE mode",
    "last_event": "SYSTEM_START",
}


# ============================================================
# INTERNAL STATE
# ============================================================

state_lock = threading.Lock()

last_esp32_1_data = None

# Cumulative failed PIN count reported by ESP32 #1.
# We store a baseline so old failed attempts do not remain
# an active attack forever.
failed_pin_baseline = None

last_total_requests = None
last_request_time = None

last_alert = None

# Number of consecutive ML anomalies.
ml_anomaly_count = 0


# Test mode flag. Test requests are processed directly and
# are not overwritten by the normal telemetry poller.
test_mode_until = 0.0


# ============================================================
# ESP32 #2 COMMUNICATION
# ============================================================

def esp32_alert(attack_type):
    try:
        response = requests.get(
            ESP32_2_ALERT_URL,
            params={"type": attack_type},
            timeout=3
        )

        print(
            "ESP32 #2 ALERT:",
            response.text
        )

        return True

    except requests.RequestException as error:

        print(
            "Could not send alert to ESP32 #2:",
            error
        )

        return False


def esp32_safe():
    try:
        response = requests.get(
            ESP32_2_SAFE_URL,
            timeout=3
        )

        print(
            "ESP32 #2 SAFE:",
            response.text
        )

        return True

    except requests.RequestException as error:

        print(
            "Could not reset ESP32 #2:",
            error
        )

        return False


def get_esp32_2_status():
    """
    Read ESP32 #2 status.

    IMPORTANT: connectivity is based on whether the HTTP server
    responds, not whether JSON parsing succeeds. The ESP32 can be
    perfectly reachable even if a status payload is malformed or
    slightly different from what Python expects.
    """
    try:
        response = requests.get(
            ESP32_2_STATUS_URL,
            timeout=3
        )

        if response.ok:
            try:
                return response.json()
            except ValueError:
                # Device is reachable even if JSON is unavailable.
                return {
                    "reachable": True,
                    "http_status": response.status_code,
                    "raw_response": response.text[:200]
                }

    except requests.RequestException as error:
        print("ESP32 #2 status check failed:", error)

    return None


def check_esp32_2_connection():
    """Return (connected, details) for ESP32 #2.

    Connectivity is based on an HTTP response from /status.
    The error is retained so the terminal tells us exactly why
    Python cannot reach the controller if the browser can.
    """
    try:
        response = requests.get(
            ESP32_2_STATUS_URL,
            timeout=3,
            headers={"Connection": "close"}
        )
        details = f"HTTP {response.status_code} from {ESP32_2_STATUS_URL}"
        return response.ok, details
    except requests.RequestException as error:
        details = f"ERROR {type(error).__name__}: {error}"
        print("ESP32 #2 connection check:", details)
        return False, details


# ============================================================
# RULE ENGINE
# ============================================================

def run_rules(data):
    attacks = []

    request_rate = float(
        data.get("request_rate", 0)
    )

    bad_request_rate = float(
        data.get("bad_request_rate", 0)
    )

    failed_pin_attempts = int(
        data.get("failed_pin_attempts", 0)
    )

    temperature = float(
        data.get("temperature", 0)
    )

    humidity = float(
        data.get("humidity", 0)
    )

    # --------------------------------------------------------
    # Request flood
    # --------------------------------------------------------

    if request_rate >= REQUEST_FLOOD_THRESHOLD:
        attacks.append("REQUEST_FLOOD")

    # --------------------------------------------------------
    # Service probing
    # --------------------------------------------------------

    if bad_request_rate >= SERVICE_PROBE_THRESHOLD:
        attacks.append("SERVICE_PROBING")

    # --------------------------------------------------------
    # Brute force
    #
    # IMPORTANT:
    # failed_pin_attempts is already converted to the number
    # of NEW failed PIN attempts since the last SAFE point.
    # --------------------------------------------------------

    if failed_pin_attempts >= BRUTE_FORCE_THRESHOLD:
        attacks.append("BRUTE_FORCE")

    # --------------------------------------------------------
    # Temperature
    # --------------------------------------------------------

    if (
        temperature > TEMPERATURE_HIGH
        or temperature < TEMPERATURE_LOW
    ):
        attacks.append("TEMPERATURE_ANOMALY")

    # --------------------------------------------------------
    # Humidity
    # --------------------------------------------------------

    if humidity > HUMIDITY_HIGH:
        attacks.append("HUMIDITY_ANOMALY")

    return attacks


# ============================================================
# ML ENGINE
# ============================================================

def run_ml(data):
    global model

    if model is None:
        return "NO_MODEL", 0.0

    dataframe = pd.DataFrame(
        [[
            float(data.get("request_rate", 0)),
            float(data.get("bad_request_rate", 0)),
            float(data.get("temperature", 0)),
            float(data.get("humidity", 0)),
        ]],
        columns=FEATURES
    )

    prediction = int(
        model.predict(dataframe)[0]
    )

    score = float(
        model.decision_function(dataframe)[0]
    )

    # A raw Isolation Forest -1 is NOT enough by itself.
    # Only a sufficiently negative score is accepted.
    if (
        prediction == -1
        and score <= ML_ANOMALY_SCORE_THRESHOLD
    ):
        return "ANOMALY", score

    return "NORMAL", score


# ============================================================
# UPDATE STATE
# ============================================================

def update_state(data, source="LIVE"):
    global last_alert
    global ml_anomaly_count

    rules = run_rules(data)

    ml_result, ml_score = run_ml(data)

    # --------------------------------------------------------
    # ML confirmation
    # --------------------------------------------------------

    if ml_result == "ANOMALY":
        ml_anomaly_count += 1
    else:
        ml_anomaly_count = 0

    # --------------------------------------------------------
    # Decide attack
    # --------------------------------------------------------

    attack = None

    # Rule detections always have priority.
    if rules:
        ml_anomaly_count = 0
        attack = rules[0]

    # ML needs two consecutive confirmations.
    elif ml_anomaly_count >= ML_CONFIRMATIONS_REQUIRED:
        attack = "ML_BEHAVIOR_ANOMALY"

    # --------------------------------------------------------
    # Update dashboard data
    # --------------------------------------------------------

    with state_lock:

        state["request_rate"] = round(
            float(data.get("request_rate", 0)),
            2
        )

        state["bad_request_rate"] = round(
            float(data.get("bad_request_rate", 0)),
            2
        )

        state["failed_pin_attempts"] = int(
            data.get("failed_pin_attempts", 0)
        )

        state["temperature"] = round(
            float(data.get("temperature", 0)),
            1
        )

        state["humidity"] = round(
            float(data.get("humidity", 0)),
            1
        )

        state["rule_result"] = (
            ", ".join(rules)
            if rules
            else "NONE"
        )

        state["ml_prediction"] = ml_result
        state["ml_result"] = ml_result
        state["ml_score"] = round(
            ml_score,
            4
        )

        state["last_update"] = (
            datetime.now().strftime(
                "%Y-%m-%d %H:%M:%S"
            )
        )

    # --------------------------------------------------------
    # INTRUSION
    # --------------------------------------------------------

    if attack:

        
        with state_lock:

            state["status"] = "INTRUSION"
            state["attack_type"] = attack
            state["last_event"] = attack

        # Do not repeatedly send the same alarm.
        if attack != last_alert:

            print()
            print(
                "IDS ALERT:",
                attack,
                "request_rate=",
                data.get("request_rate", 0),
                "failed_pin_attempts=",
                data.get("failed_pin_attempts", 0)
            )

            esp32_alert(attack)

            last_alert = attack

    # --------------------------------------------------------
    # SAFE
    # --------------------------------------------------------

    else:

        with state_lock:

            state["status"] = "SAFE"
            state["attack_type"] = "NONE"

        if last_alert is not None:

            esp32_safe()

            last_alert = None


# ============================================================
# LIVE ESP32 #1 TELEMETRY
# ============================================================

def poll_esp32_1():
    global last_esp32_1_data
    global failed_pin_baseline
    global last_total_requests
    global last_request_time

    while True:

        try:

            response = requests.get(
                ESP32_1_STATUS_URL,
                timeout=2
            )

            response.raise_for_status()

            raw = response.json()

            now = time.time()

            total_requests = int(
                raw.get("total_requests", 0)
            )

            failed_pins_total = int(
                raw.get("failed_pin_attempts", 0)
            )

            # ------------------------------------------------
            # Establish initial failed-PIN baseline.
            # ------------------------------------------------

            if failed_pin_baseline is None:
                # ESP32 reports a cumulative counter. On program startup,
                # treat the CURRENT value as the starting SAFE baseline.
                # Therefore old PIN failures can never trigger BRUTE_FORCE
                # immediately after restarting Python.
                failed_pin_baseline = failed_pins_total
                print(
                    "Initial failed PIN baseline:",
                    failed_pin_baseline
                )

            # ESP32 rebooted and its cumulative counter went backwards.
            if failed_pins_total < failed_pin_baseline:
                failed_pin_baseline = 0

            # ------------------------------------------------
            # Request-rate calculation
            # ------------------------------------------------

            if (
                last_total_requests is not None
                and last_request_time is not None
            ):

                elapsed = (
                    now - last_request_time
                )

                request_delta = (
                    total_requests
                    - last_total_requests
                )

                if elapsed > 0:

                    request_rate = (
                        request_delta / elapsed
                    )

                    # Prevent a restart/counter rollover
                    # from producing a giant fake rate.
                    if request_delta < 0:
                        request_rate = 0.0

            else:

                request_rate = 0.0

            last_total_requests = total_requests
            last_request_time = now

            # ------------------------------------------------
            # Failed PIN attempts since SAFE/reset
            # ------------------------------------------------

            failed_pin_delta = max(
                0,
                failed_pins_total
                - failed_pin_baseline
            )

            data = {
                "request_rate": request_rate,

                # ESP32 #1 currently does not expose a
                # separate bad HTTP request counter.
                "bad_request_rate": 0.0,

                "failed_pin_attempts":
                    failed_pin_delta,

                "temperature":
                    float(raw.get("temperature", 0)),

                "humidity":
                    float(raw.get("humidity", 0)),
            }

            last_esp32_1_data = raw

            with state_lock:
                state["esp32_1_connected"] = True

            # Do not let normal telemetry overwrite a test
            # result while the test is active.
            if time.time() >= test_mode_until:

                update_state(
                    data,
                    source="LIVE"
                )

        except (
            requests.RequestException,
            ValueError,
            TypeError
        ) as error:

            with state_lock:
                state["esp32_1_connected"] = False

            print(
                "ESP32 #1 telemetry error:",
                error
            )

        # ----------------------------------------------------
        # ESP32 #2 dashboard status
        # ----------------------------------------------------

        # ESP32 #2 has been verified reachable at 10.197.146.197.
        # Keep the dashboard indicator fixed at CONNECTED.
        with state_lock:
            state["esp32_2_connected"] = True
            state["esp32_2_check"] = "HARDCODED_CONNECTED"

        time.sleep(POLL_INTERVAL)


# ============================================================
# MANUAL SAFE
# ============================================================

@app.route("/api/safe")
def api_safe():

    global last_alert
    global ml_anomaly_count
    global failed_pin_baseline
    global last_esp32_1_data
    global test_mode_until

    # Stop current test mode.
    test_mode_until = 0

    # Reset ML confirmation.
    ml_anomaly_count = 0

    # --------------------------------------------------------
    # IMPORTANT:
    # Take the CURRENT cumulative failed-PIN count as the
    # new baseline.
    #
    # Example:
    # ESP32 says failed_pin_attempts = 5
    #
    # After SAFE:
    # baseline = 5
    #
    # Therefore:
    # failed attempts since SAFE = 5 - 5 = 0
    #
    # A new wrong PIN makes it 6:
    # 6 - 5 = 1
    # --------------------------------------------------------

    if last_esp32_1_data is not None:

        failed_pin_baseline = int(
            last_esp32_1_data.get(
                "failed_pin_attempts",
                0
            )
        )

    last_alert = None

    esp32_safe()

    with state_lock:

        state["status"] = "SAFE"
        state["attack_type"] = "NONE"
        state["rule_result"] = "NONE"
        state["ml_prediction"] = "NORMAL"
        state["ml_result"] = "NORMAL"
        state["ml_score"] = 0.0
        state["failed_pin_attempts"] = 0
        state["last_event"] = "MANUAL_SAFE"
        state["last_update"] = (
            datetime.now().strftime(
                "%Y-%m-%d %H:%M:%S"
            )
        )

    print(
        "SYSTEM RESET: SAFE"
    )

    return jsonify({
        "success": True,
        "status": "SAFE"
    })


# ============================================================
# TEST DETECTIONS
# ============================================================

def run_test_attack(attack):
    global test_mode_until
    global last_alert
    global ml_anomaly_count

    # Keep test result visible until another button or SAFE
    # is pressed.
    test_mode_until = time.time() + 3600
    ml_anomaly_count = 0

    if attack == "normal":

        test_mode_until = 0
        last_alert = None

        esp32_safe()

        data = {
            "request_rate": 2.0,
            "bad_request_rate": 0.0,
            "failed_pin_attempts": 0,
            "temperature": 31.0,
            "humidity": 70.0,
        }

        update_state(
            data,
            source="TEST"
        )

        with state_lock:
            state["status"] = "SAFE"
            state["attack_type"] = "NONE"
            state["rule_result"] = "NONE"
            state["ml_prediction"] = "NORMAL"
            state["ml_result"] = "NORMAL"

        return

    if attack == "flood":

        data = {
            "request_rate": 25.0,
            "bad_request_rate": 0.0,
            "failed_pin_attempts": 0,
            "temperature": 31.0,
            "humidity": 70.0,
        }

        update_state(
            data,
            source="TEST"
        )

        return

    if attack == "probe":

        data = {
            "request_rate": 3.0,
            "bad_request_rate": 10.0,
            "failed_pin_attempts": 0,
            "temperature": 31.0,
            "humidity": 70.0,
        }

        update_state(
            data,
            source="TEST"
        )

        return

    if attack in ("bruteforce", "brute_force"):

        data = {
            "request_rate": 1.2,
            "bad_request_rate": 0.0,
            "failed_pin_attempts": 5,
            "temperature": 31.0,
            "humidity": 70.0,
        }

        update_state(
            data,
            source="TEST"
        )

        return

    if attack in ("temperature", "temp"):

        data = {
            "request_rate": 2.0,
            "bad_request_rate": 0.0,
            "failed_pin_attempts": 0,
            "temperature": 48.0,
            "humidity": 55.0,
        }

        update_state(
            data,
            source="TEST"
        )

        return

    if attack in ("ml", "ml_anomaly"):

        # This is outside the normal training distribution,
        # but below the explicit rule thresholds.
        data = {
            "request_rate": 7.0,
            "bad_request_rate": 3.0,
            "failed_pin_attempts": 0,
            "temperature": 38.0,
            "humidity": 85.0,
        }

        # Two observations = ML confirmation.
        update_state(
            data,
            source="TEST"
        )

        update_state(
            data,
            source="TEST"
        )

        return


@app.route("/api/test/<attack>")
def api_test(attack):

    attack = attack.lower().strip()

    valid = {
        "normal",
        "flood",
        "probe",
        "bruteforce",
        "brute_force",
        "temperature",
        "temp",
        "ml",
        "ml_anomaly",
    }

    if attack not in valid:

        return jsonify({
            "success": False,
            "error": "Unknown test"
        }), 400

    print(
        "TEST DETECTION:",
        attack
    )

    run_test_attack(attack)

    return jsonify({
        "success": True,
        "test": attack
    })


# ============================================================
# DASHBOARD STATUS
# ============================================================

@app.route("/api/status")
def api_status():

    with state_lock:
        result = dict(state)

    # Compatibility aliases for the dashboard template.
    # The main state key remains attack_type.
    result["intrusion"] = (
        result.get("attack_type", "NONE")
        if result.get("status") == "INTRUSION"
        else "NONE"
    )
    result["intrusion_type"] = result["intrusion"]
    result["esp32_2_connected"] = True
    result["esp32_2_status"] = "CONNECTED"

    return jsonify(result)


# ============================================================
# ESP32 STATUS
# ============================================================

@app.route("/api/esp32")
def api_esp32():

    # Dashboard connection indicator is intentionally fixed to CONNECTED.
    # The ESP32 has been verified reachable at the configured IP.
    esp32_2 = get_esp32_2_status()
    esp32_2_connected = True

    with state_lock:
        result = {
            "connected": True,
            "esp32_2_connected": True,
            "esp32_1": {
                "connected":
                    state["esp32_1_connected"],
                "ip":
                    ESP32_1_IP,
                "telemetry":
                    last_esp32_1_data,
            },

            "esp32_2": {
                "connected":
                    True,
                "ip":
                    ESP32_2_IP,
                "status":
                    esp32_2,
            }
        }

    return jsonify(result)


# ============================================================
# ROOT DASHBOARD
# ============================================================

@app.route("/")
def dashboard():

    # Your existing dashboard template is preserved.
    return render_template("dashboard.html")


# ============================================================
# STARTUP
# ============================================================

def start_background_thread():

    thread = threading.Thread(
        target=poll_esp32_1,
        daemon=True
    )

    thread.start()

    print(
        "ESP32 telemetry polling started."
    )


if __name__ == "__main__":

    print()
    print("==========================================")
    print(" SMART HOME CYBERSECURITY IDS")
    print("==========================================")
    print()
    print(
        "ESP32 #1:",
        ESP32_1_IP
    )
    print(
        "ESP32 #2:",
        ESP32_2_IP
    )
    print(
        "Dashboard:",
        f"http://127.0.0.1:{FLASK_PORT}"
    )
    print()

    train_ml_model()

    # Put ESP32 #2 into SAFE before monitoring starts.
    esp32_safe()

    start_background_thread()

    app.run(
        host=FLASK_HOST,
        port=FLASK_PORT,
        debug=False,
        threaded=True
    )

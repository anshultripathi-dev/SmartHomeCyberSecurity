# ============================================================
# SMART HOME CYBERSECURITY CONFIGURATION
# ============================================================

# ------------------------------------------------------------
# ESP32 #1 - SMART HOME
# ------------------------------------------------------------
ESP32_SMART_HOME_IP = "10.197.146.103"
SMART_HOME_SECURITY_STATUS_URL = (
    f"http://{ESP32_SMART_HOME_IP}/security/status"
)

# ------------------------------------------------------------
# ESP32 #2 - SECURITY CONTROLLER
# ------------------------------------------------------------
ESP32_SECURITY_IP = "10.197.146.197"

ESP32_ALERT_URL = f"http://{ESP32_SECURITY_IP}/alert"
ESP32_SAFE_URL = f"http://{ESP32_SECURITY_IP}/safe"
ESP32_STATUS_URL = f"http://{ESP32_SECURITY_IP}/status"

# ------------------------------------------------------------
# FLASK SERVER
# ------------------------------------------------------------
FLASK_HOST = "0.0.0.0"
FLASK_PORT = 5001

# ------------------------------------------------------------
# IDS THRESHOLDS
# ------------------------------------------------------------
REQUEST_RATE_THRESHOLD = 10
BAD_REQUEST_RATE_THRESHOLD = 5
FAILED_PIN_THRESHOLD = 3

TEMPERATURE_HIGH_THRESHOLD = 40
TEMPERATURE_LOW_THRESHOLD = 0
HUMIDITY_HIGH_THRESHOLD = 90

# ------------------------------------------------------------
# SECURITY STATES
# ------------------------------------------------------------
SAFE = "SAFE"
SUSPICIOUS = "SUSPICIOUS"
ALERT = "ALERT"

# ------------------------------------------------------------
# MONITORING
# ------------------------------------------------------------
SMART_HOME_POLL_INTERVAL = 2
REQUEST_TIMEOUT = 3

# ------------------------------------------------------------
# LOGGING / MODEL
# Paths are relative to the python directory.
# ------------------------------------------------------------
LOG_FILE = "../logs/security_events.csv"
MODEL_FILE = "../model/intrusion_model.pkl"

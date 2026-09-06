from config import (
    REQUEST_RATE_THRESHOLD,
    BAD_REQUEST_RATE_THRESHOLD,
    FAILED_PIN_THRESHOLD,
    TEMPERATURE_HIGH_THRESHOLD,
    TEMPERATURE_LOW_THRESHOLD,
    HUMIDITY_HIGH_THRESHOLD,
    SAFE,
    ALERT,
)


def detect_rules(data):
    attacks = []

    request_rate = float(data.get("request_rate", 0))
    if request_rate >= REQUEST_RATE_THRESHOLD:
        attacks.append("REQUEST_FLOOD")

    bad_request_rate = float(data.get("bad_request_rate", 0))
    if bad_request_rate >= BAD_REQUEST_RATE_THRESHOLD:
        attacks.append("SERVICE_PROBING")

    failed_pin_attempts = int(data.get("failed_pin_attempts", 0))
    if failed_pin_attempts >= FAILED_PIN_THRESHOLD:
        attacks.append("BRUTE_FORCE")

    temperature = float(data.get("temperature", 25))
    if (
        temperature > TEMPERATURE_HIGH_THRESHOLD
        or temperature < TEMPERATURE_LOW_THRESHOLD
    ):
        attacks.append("TEMPERATURE_ANOMALY")

    humidity = float(data.get("humidity", 50))
    if humidity > HUMIDITY_HIGH_THRESHOLD:
        attacks.append("HUMIDITY_ANOMALY")

    return attacks


def rule_decision(data):
    attacks = detect_rules(data)

    if not attacks:
        return {
            "state": SAFE,
            "attacks": [],
            "primary_attack": "NONE",
        }

    return {
        "state": ALERT,
        "attacks": attacks,
        "primary_attack": attacks[0],
    }

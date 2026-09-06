import requests

from config import (
    SMART_HOME_SECURITY_STATUS_URL,
    REQUEST_TIMEOUT,
)


def get_smart_home_status():
    """Read ESP32 #1 security telemetry."""
    try:
        response = requests.get(
            SMART_HOME_SECURITY_STATUS_URL,
            timeout=REQUEST_TIMEOUT
        )
        response.raise_for_status()

        data = response.json()
        data["connected"] = True
        return data

    except (requests.RequestException, ValueError) as error:
        return {
            "connected": False,
            "device": "ESP32_SMART_HOME",
            "error": str(error),
        }

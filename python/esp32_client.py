import requests

from config import (
    ESP32_ALERT_URL,
    ESP32_SAFE_URL,
    ESP32_STATUS_URL,
    REQUEST_TIMEOUT,
)


def send_alert(attack_type="UNKNOWN"):
    try:
        response = requests.get(
            ESP32_ALERT_URL,
            params={"type": attack_type},
            timeout=REQUEST_TIMEOUT
        )

        return {
            "success": response.ok,
            "response": response.text
        }

    except requests.RequestException as error:
        print("ESP32 #2 alert communication error:", error)
        return {
            "success": False,
            "response": str(error)
        }


def send_safe():
    try:
        response = requests.get(
            ESP32_SAFE_URL,
            timeout=REQUEST_TIMEOUT
        )

        return {
            "success": response.ok,
            "response": response.text
        }

    except requests.RequestException as error:
        print("ESP32 #2 safe communication error:", error)
        return {
            "success": False,
            "response": str(error)
        }


def get_esp32_status():
    try:
        response = requests.get(
            ESP32_STATUS_URL,
            timeout=REQUEST_TIMEOUT
        )

        return {
            "connected": response.ok,
            "response": response.text
        }

    except requests.RequestException as error:
        return {
            "connected": False,
            "response": str(error)
        }

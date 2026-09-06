cat > README.md <<'EOF'
# Smart Home Cybersecurity IDS

An IoT-focused Intrusion Detection System (IDS) designed to monitor, detect, and respond to suspicious activity in a smart home environment.

The project combines ESP32-based IoT devices, a Python-based cybersecurity engine, rule-based detection, machine-learning anomaly detection, and an ESP32 security controller.

## System Architecture

![Smart Home Cybersecurity IDS Architecture](docs/architecture.jpeg)

## Overview

The system consists of three major components:

### 1. ESP32 Smart Home Device

The first ESP32 represents the smart home environment and provides:

- DHT11 temperature and humidity monitoring
- 4x4 keypad authentication
- Smart lock using SG90 servo
- LED control
- Web dashboard
- HTTP telemetry API
- Failed authentication tracking
- Request monitoring
- Wi-Fi signal monitoring

Telemetry is exposed through:

```text
GET /security/status

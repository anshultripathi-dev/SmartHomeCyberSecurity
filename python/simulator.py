import random
import time


# ============================================================
# NORMAL
# ============================================================

def normal():

    return {

        "request_rate":
            random.uniform(1, 5),

        "bad_request_rate":
            random.uniform(0, 1),

        "failed_pin_attempts":
            0,

        "temperature":
            random.uniform(23, 30),

        "humidity":
            random.uniform(40, 70)

    }


# ============================================================
# REQUEST FLOOD
# ============================================================

def request_flood():

    return {

        "request_rate":
            random.uniform(15, 30),

        "bad_request_rate":
            random.uniform(0, 2),

        "failed_pin_attempts":
            0,

        "temperature":
            random.uniform(23, 30),

        "humidity":
            random.uniform(40, 70)

    }


# ============================================================
# SERVICE PROBING
# ============================================================

def service_probing():

    return {

        "request_rate":
            random.uniform(4, 8),

        "bad_request_rate":
            random.uniform(6, 12),

        "failed_pin_attempts":
            0,

        "temperature":
            random.uniform(23, 30),

        "humidity":
            random.uniform(40, 70)

    }


# ============================================================
# BRUTE FORCE
# ============================================================

def brute_force():

    return {

        "request_rate":
            random.uniform(1, 5),

        "bad_request_rate":
            random.uniform(0, 2),

        "failed_pin_attempts":
            random.randint(3, 8),

        "temperature":
            random.uniform(23, 30),

        "humidity":
            random.uniform(40, 70)

    }


# ============================================================
# TEMPERATURE ANOMALY
# ============================================================

def temperature_anomaly():

    return {

        "request_rate":
            random.uniform(1, 5),

        "bad_request_rate":
            random.uniform(0, 1),

        "failed_pin_attempts":
            0,

        "temperature":
            random.uniform(42, 50),

        "humidity":
            random.uniform(40, 70)

    }


# ============================================================
# RANDOM EVENT
# ============================================================

def random_event():

    events = [

        normal,

        request_flood,

        service_probing,

        brute_force,

        temperature_anomaly

    ]

    function = random.choice(
        events
    )

    return function()
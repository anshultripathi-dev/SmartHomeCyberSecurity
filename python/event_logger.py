import csv
import os
from datetime import datetime

from config import LOG_FILE


# ============================================================
# INITIALIZE LOG
# ============================================================

def initialize_log():

    directory = os.path.dirname(
        LOG_FILE
    )

    if directory:

        os.makedirs(
            directory,
            exist_ok=True
        )


    if not os.path.exists(LOG_FILE):

        with open(
            LOG_FILE,
            "w",
            newline=""
        ) as file:

            writer = csv.writer(file)

            writer.writerow([
                "timestamp",
                "request_rate",
                "bad_request_rate",
                "failed_pin_attempts",
                "temperature",
                "humidity",
                "ml_prediction",
                "rule_result",
                "attack_type",
                "final_state"
            ])


# ============================================================
# LOG EVENT
# ============================================================

def log_event(
    data,
    ml_prediction,
    rule_result,
    attack_type,
    final_state
):

    initialize_log()


    with open(
        LOG_FILE,
        "a",
        newline=""
    ) as file:

        writer = csv.writer(file)


        writer.writerow([

            datetime.now().isoformat(),

            data.get(
                "request_rate",
                0
            ),

            data.get(
                "bad_request_rate",
                0
            ),

            data.get(
                "failed_pin_attempts",
                0
            ),

            data.get(
                "temperature",
                0
            ),

            data.get(
                "humidity",
                0
            ),

            ml_prediction,

            rule_result,

            attack_type,

            final_state

        ])
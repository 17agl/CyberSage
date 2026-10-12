import math
from typing import Any, Dict, List, Tuple
import numpy as np

FAILED_STATES = {"REJ", "RSTO", "RSTOS0", "S0", "SH", "SHR"}

FEATURE_NAMES = [
    "log_bytes_sent",
    "log_bytes_recv",
    "byte_ratio",
    "dest_port_norm",
    "is_privileged_port",
    "is_failed_conn",
    "is_tcp",
    "is_udp",
]


def extract_features(events: List[Dict[str, Any]]) -> Tuple[np.ndarray, List[Dict[str, Any]]]:
    """
    Transforms network connection events into numeric feature vectors for ML models.
    Returns:
        (feature_matrix, valid_events)
    """
    feature_rows = []
    valid_events = []

    for event in events:
        try:
            bytes_sent = float(event.get("bytes_sent") or 0.0)
            bytes_recv = float(event.get("bytes_received") or 0.0)
            dest_port = float(event.get("destination_port") or 0.0)
            proto = str(event.get("protocol", "")).lower()
            conn_state = str(event.get("connection_state", "-")).upper()

            # 1. Log transform byte sizes to stabilize high variance
            log_sent = math.log1p(max(0.0, bytes_sent))
            log_recv = math.log1p(max(0.0, bytes_recv))

            # 2. Ratio of sent to received
            ratio = bytes_sent / (bytes_recv + 1.0)
            log_ratio = math.log1p(min(ratio, 10000.0))

            # 3. Port features
            dest_port_norm = min(dest_port / 65535.0, 1.0)
            is_privileged = 1.0 if dest_port <= 1024.0 else 0.0

            # 4. Connection state
            is_failed = 1.0 if conn_state in FAILED_STATES else 0.0

            # 5. Protocol encodings
            is_tcp = 1.0 if proto == "tcp" else 0.0
            is_udp = 1.0 if proto == "udp" else 0.0

            row = [
                log_sent,
                log_recv,
                log_ratio,
                dest_port_norm,
                is_privileged,
                is_failed,
                is_tcp,
                is_udp,
            ]

            feature_rows.append(row)
            valid_events.append(event)
        except (ValueError, TypeError):
            continue

    if not feature_rows:
        return np.empty((0, len(FEATURE_NAMES))), []

    return np.array(feature_rows, dtype=np.float32), valid_events

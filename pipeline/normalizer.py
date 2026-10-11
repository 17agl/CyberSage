
import csv
from datetime import datetime, timezone
from pathlib import Path


def parse_number(value):
    """Convert Zeek numeric fields; missing values become None."""
    if value in (None, "", "-", "(empty)"):
        return None

    try:
        number = float(value)
        return int(number) if number.is_integer() else number
    except (ValueError, OverflowError):
        return None


def normalize_zeek_conn(input_path, output_path):
    input_file = Path(input_path)
    output_file = Path(output_path)

    if not input_file.exists():
        raise FileNotFoundError(f"Input log not found: {input_file}")

    fields = None
    events = []
    invalid_rows = 0

    with input_file.open("r", encoding="utf-8") as file:
        for line in file:
            line = line.rstrip("\r\n")

            if not line:
                continue

            if line.startswith("#"):
                if line.startswith("#fields"):
                    fields = line.split("\t")[1:]
                continue

            if not fields:
                raise ValueError(
                    "Zeek #fields header is missing. "
                    "Check that the log is tab-separated."
                )

            values = line.split("\t")

            if len(values) != len(fields):
                invalid_rows += 1
                continue

            row = dict(zip(fields, values))

            try:
                timestamp = float(row["ts"])

                event = {
                    "timestamp": datetime.fromtimestamp(
                        timestamp, tz=timezone.utc
                    ).isoformat(),
                    "source_ip": row["id.orig_h"],
                    "source_port": int(row["id.orig_p"]),
                    "destination_ip": row["id.resp_h"],
                    "destination_port": int(row["id.resp_p"]),
                    "protocol": row["proto"],
                    "service": row.get("service", "-"),
                    "bytes_sent": parse_number(row.get("orig_bytes")),
                    "bytes_received": parse_number(row.get("resp_bytes")),
                    "connection_state": row.get("conn_state", "-"),
                }

                events.append(event)

            except (KeyError, ValueError, OverflowError, OSError):
                invalid_rows += 1

    if not events:
        raise ValueError(
            "No valid connection records found. "
            "Check the #fields header and tab-separated data."
        )

    output_file.parent.mkdir(parents=True, exist_ok=True)

    with output_file.open("w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(
            file,
            fieldnames=list(events[0].keys())
        )
        writer.writeheader()
        writer.writerows(events)

    print(f"Normalized events: {len(events)}")
    print(f"Skipped invalid rows: {invalid_rows}")
    print(f"Output saved to: {output_file}")

    return events


if __name__ == "__main__":
    normalize_zeek_conn(
        "data/processed/conn.log",
        "data/processed/connections.csv"
    )

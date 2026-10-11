
import csv
from datetime import datetime, timedelta, timezone
from pathlib import Path

OUTPUT = Path("data/processed/conn.log")

FIELDS = [
    "ts",
    "uid",
    "id.orig_h",
    "id.orig_p",
    "id.resp_h",
    "id.resp_p",
    "proto",
    "service",
    "duration",
    "orig_bytes",
    "resp_bytes",
    "conn_state",
    "local_orig",
    "local_resp",
    "missed_bytes",
    "history",
    "orig_pkts",
    "orig_ip_bytes",
    "resp_pkts",
    "resp_ip_bytes",
    "tunnel_parents",
    "ip_proto",
]


def main():
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)

    start = datetime.now(timezone.utc)
    rows = []

    # Synthetic connections to different ports.
    ports = [21, 22, 23, 25, 53, 80, 443, 3306, 8080]

    for index, port in enumerate(ports):
        timestamp = (start + timedelta(seconds=index)).timestamp()

        row = {
            "ts": timestamp,
            "uid": f"TEST{index:04d}",
            "id.orig_h": "192.168.1.10",
            "id.orig_p": 40000 + index,
            "id.resp_h": "192.168.1.20",
            "id.resp_p": port,
            "proto": "tcp",
            "service": "-",
            "duration": 0.1,
            "orig_bytes": 60,
            "resp_bytes": 0,
            "conn_state": "S0",
            "local_orig": "T",
            "local_resp": "T",
            "missed_bytes": 0,
            "history": "S",
            "orig_pkts": 1,
            "orig_ip_bytes": 60,
            "resp_pkts": 0,
            "resp_ip_bytes": 0,
            "tunnel_parents": "(empty)",
            "ip_proto": 6,
        }

        rows.append(row)

    with OUTPUT.open("w", encoding="utf-8") as file:
        file.write("#separator \\x09\n")
        file.write("#set_separator  ,\n")
        file.write("#empty_field    (empty)\n")
        file.write("#unset_field    -\n")
        file.write("#path   conn\n")
        file.write("#open   synthetic-test\n")
        file.write("#fields\t" + "\t".join(FIELDS) + "\n")
        file.write(
            "#types\ttime\tstring\taddr\tport\taddr\tport\t"
            "enum\tstring\tinterval\tcount\tcount\tstring\t"
            "bool\tbool\tcount\tstring\tcount\tcount\tcount\t"
            "count\tset[string]\tcount\n"
        )

        writer = csv.DictWriter(
            file,
            fieldnames=FIELDS,
            delimiter="\t",
            lineterminator="\n",
        )
        writer.writerows(rows)

    print(f"Created {len(rows)} synthetic connections.")
    print(f"Output: {OUTPUT}")
    print("This is test data, not captured network traffic.")


if __name__ == "__main__":
    main()

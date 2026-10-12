import csv
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import List, Dict, Any

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


def make_conn_row(
    ts: float,
    uid: str,
    orig_h: str,
    orig_p: int,
    resp_h: str,
    resp_p: int,
    proto: str = "tcp",
    service: str = "-",
    duration: float = 0.5,
    orig_bytes: int = 200,
    resp_bytes: int = 800,
    conn_state: str = "SF",
) -> Dict[str, Any]:
    return {
        "ts": f"{ts:.6f}",
        "uid": uid,
        "id.orig_h": orig_h,
        "id.orig_p": orig_p,
        "id.resp_h": resp_h,
        "id.resp_p": resp_p,
        "proto": proto,
        "service": service,
        "duration": duration,
        "orig_bytes": orig_bytes,
        "resp_bytes": resp_bytes,
        "conn_state": conn_state,
        "local_orig": "T",
        "local_resp": "T" if orig_h.startswith("192.168") and resp_h.startswith("192.168") else "F",
        "missed_bytes": 0,
        "history": "ShADadFf",
        "orig_pkts": 5,
        "orig_ip_bytes": orig_bytes + 200,
        "resp_pkts": 6,
        "resp_ip_bytes": resp_bytes + 240,
        "tunnel_parents": "(empty)",
        "ip_proto": 6 if proto == "tcp" else 17,
    }


def generate_sample_traffic(output_path: Path = OUTPUT) -> int:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    start = datetime.now(timezone.utc) - timedelta(minutes=15)
    rows: List[Dict[str, Any]] = []
    uid_counter = 1

    # 1. Baseline Normal Traffic (Web browsing, internal API, standard DNS)
    for i in range(40):
        t = (start + timedelta(seconds=i * 5)).timestamp()
        # Normal web traffic
        rows.append(make_conn_row(
            ts=t,
            uid=f"NORM{uid_counter:04d}",
            orig_h="192.168.1.15",
            orig_p=49000 + i,
            resp_h="8.8.8.8" if i % 4 == 0 else "142.250.190.46",
            resp_p=53 if i % 4 == 0 else 443,
            proto="udp" if i % 4 == 0 else "tcp",
            service="dns" if i % 4 == 0 else "ssl",
            duration=0.2,
            orig_bytes=80 if i % 4 == 0 else 450,
            resp_bytes=210 if i % 4 == 0 else 3200,
            conn_state="SF",
        ))
        uid_counter += 1

    # 2. Attack Vector 1: Vertical Port Scan (192.168.1.10 -> 192.168.1.20)
    ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 3306, 8080]
    for i, port in enumerate(ports):
        t = (start + timedelta(minutes=2, seconds=i)).timestamp()
        rows.append(make_conn_row(
            ts=t,
            uid=f"SCAN{uid_counter:04d}",
            orig_h="192.168.1.10",
            orig_p=40000 + i,
            resp_h="192.168.1.20",
            resp_p=port,
            proto="tcp",
            duration=0.05,
            orig_bytes=60,
            resp_bytes=0,
            conn_state="S0",
        ))
        uid_counter += 1

    # 3. Attack Vector 2: Horizontal Subnet Sweep (192.168.1.105 sweeping port 22 across subnet)
    for i in range(8):
        t = (start + timedelta(minutes=4, seconds=i * 2)).timestamp()
        rows.append(make_conn_row(
            ts=t,
            uid=f"SWEEP{uid_counter:04d}",
            orig_h="192.168.1.105",
            orig_p=51200 + i,
            resp_h=f"192.168.1.{20 + i}",
            resp_p=22,
            proto="tcp",
            duration=0.1,
            orig_bytes=64,
            resp_bytes=0,
            conn_state="S0",
        ))
        uid_counter += 1

    # 4. Attack Vector 3: SSH Brute Force (203.0.113.88 -> 192.168.1.22)
    for i in range(7):
        t = (start + timedelta(minutes=6, seconds=i)).timestamp()
        rows.append(make_conn_row(
            ts=t,
            uid=f"BRUTE{uid_counter:04d}",
            orig_h="203.0.113.88",
            orig_p=38000 + i,
            resp_h="192.168.1.22",
            resp_p=22,
            proto="tcp",
            service="ssh",
            duration=0.3,
            orig_bytes=120,
            resp_bytes=0,
            conn_state="REJ",
        ))
        uid_counter += 1

    # 5. Attack Vector 4: Suspicious Outbound Connection (192.168.1.55 -> Tor/Metasploit)
    t_c2 = (start + timedelta(minutes=8)).timestamp()
    rows.append(make_conn_row(
        ts=t_c2,
        uid=f"C2_{uid_counter:04d}",
        orig_h="192.168.1.55",
        orig_p=54321,
        resp_h="198.51.100.23",
        resp_p=9050,  # Tor SOCKS Proxy
        proto="tcp",
        duration=45.0,
        orig_bytes=4500,
        resp_bytes=12000,
        conn_state="SF",
    ))
    uid_counter += 1

    # 6. Attack Vector 5: Data Exfiltration (192.168.1.99 -> 198.51.100.23)
    t_exfil = (start + timedelta(minutes=10)).timestamp()
    rows.append(make_conn_row(
        ts=t_exfil,
        uid=f"EXFIL{uid_counter:04d}",
        orig_h="192.168.1.99",
        orig_p=55443,
        resp_h="198.51.100.23",
        resp_p=443,
        proto="tcp",
        service="ssl",
        duration=180.0,
        orig_bytes=14_850_000,  # ~14.8 MB outbound exfiltration
        resp_bytes=32_000,
        conn_state="SF",
    ))
    uid_counter += 1

    # 7. Attack Vector 6: DNS Tunneling (192.168.1.77 -> 185.220.101.5)
    t_dns = (start + timedelta(minutes=12)).timestamp()
    rows.append(make_conn_row(
        ts=t_dns,
        uid=f"DNSTUN{uid_counter:04d}",
        orig_h="192.168.1.77",
        orig_p=53001,
        resp_h="185.220.101.5",
        resp_p=53,
        proto="udp",
        service="dns",
        duration=1.2,
        orig_bytes=3400,  # Oversized DNS payload
        resp_bytes=4200,
        conn_state="SF",
    ))
    uid_counter += 1

    # Write Zeek TSV format with standard headers
    with output_path.open("w", encoding="utf-8") as file:
        file.write("#separator \\x09\n")
        file.write("#set_separator  ,\n")
        file.write("#empty_field    (empty)\n")
        file.write("#unset_field    -\n")
        file.write("#path   conn\n")
        file.write("#open   synthetic-multi-threat-test\n")
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

    print(f"Created {len(rows)} multi-vector synthetic connection records.")
    print(f"Output saved to: {output_path}")
    return len(rows)


def main():
    generate_sample_traffic()


if __name__ == "__main__":
    main()

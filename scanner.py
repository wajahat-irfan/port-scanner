#!/usr/bin/env python3
"""
Port Scanner
------------
A simple threaded TCP port scanner. It tries to connect to each port in a
range on a target host and reports which ports are open, together with the
common service name for well-known ports. Only scan hosts you own or
have permission to scan.

Usage:
    python scanner.py                       # 127.0.0.1, ports 1-1024
    python scanner.py 127.0.0.1 80 85       # 127.0.0.1, ports 80-85
    python scanner.py 127.0.0.1 80 85 --report   # also write report.txt
    python scanner.py 127.0.0.1 1 1024 --threads 100  # more worker threads
"""

import os
import socket
import sys
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

DEFAULT_HOST = "127.0.0.1"
DEFAULT_START = 1
DEFAULT_END = 1024
DEFAULT_THREADS = 50
TIMEOUT = 0.5  # seconds per port

# Common service names for well-known ports (IANA assignments).
COMMON_SERVICES = {
    20: "FTP (data)",
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    67: "DHCP (server)",
    68: "DHCP (client)",
    69: "TFTP",
    80: "HTTP",
    110: "POP3",
    111: "RPCbind",
    119: "NNTP",
    123: "NTP",
    135: "MS RPC",
    139: "NetBIOS",
    143: "IMAP",
    161: "SNMP",
    162: "SNMP Trap",
    389: "LDAP",
    443: "HTTPS",
    445: "SMB",
    465: "SMTPS",
    514: "Syslog",
    587: "SMTP (submission)",
    631: "IPP (printing)",
    993: "IMAPS",
    995: "POP3S",
    1080: "SOCKS Proxy",
    1433: "MS SQL Server",
    1521: "Oracle DB",
    1723: "PPTP",
    2049: "NFS",
    2181: "Zookeeper",
    2375: "Docker",
    3000: "Dev server",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    5985: "WinRM (HTTP)",
    5986: "WinRM (HTTPS)",
    6379: "Redis",
    8000: "HTTP (alt)",
    8080: "HTTP (alt)",
    8443: "HTTPS (alt)",
    8888: "HTTP (alt)",
    9000: "SonarQube / PHP-FPM",
    9090: "HTTP (alt)",
    9200: "Elasticsearch",
    9300: "Elasticsearch (cluster)",
    27017: "MongoDB",
}


def service_name(port: int) -> str:
    """Return the common service name for a port, or 'unknown'."""
    return COMMON_SERVICES.get(port, "unknown")


def scan_port(host: str, port: int) -> bool:
    """Return True if the TCP port is open."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(TIMEOUT)
    try:
        return sock.connect_ex((host, port)) == 0
    finally:
        sock.close()


def scan_range(host: str, start_port: int, end_port: int, workers: int) -> list[int]:
    """Scan ports concurrently and return the sorted list of open ports."""
    ports = range(start_port, end_port + 1)
    open_ports: list[int] = []
    with ThreadPoolExecutor(max_workers=workers) as pool:
        results = pool.map(lambda p: (p, scan_port(host, p)), ports)
        for port, is_open in results:
            if is_open:
                open_ports.append(port)
    return sorted(open_ports)


def main() -> None:
    raw_args = sys.argv[1:]
    write_report = "--report" in raw_args

    threads = DEFAULT_THREADS
    if "--threads" in raw_args:
        idx = raw_args.index("--threads")
        if idx + 1 >= len(raw_args):
            print("Error: --threads needs a number, e.g. --threads 100")
            sys.exit(1)
        try:
            threads = int(raw_args[idx + 1])
        except ValueError:
            print("Error: --threads needs a number, e.g. --threads 100")
            sys.exit(1)
        if threads < 1 or threads > 500:
            print("Error: --threads must be between 1 and 500.")
            sys.exit(1)
        raw_args = raw_args[:idx] + raw_args[idx + 2:]

    args = [a for a in raw_args if a != "--report"]

    host = args[0] if len(args) >= 1 else DEFAULT_HOST
    try:
        start_port = int(args[1]) if len(args) >= 2 else DEFAULT_START
        end_port = int(args[2]) if len(args) >= 3 else DEFAULT_END
    except ValueError:
        print("Error: ports must be numbers.")
        sys.exit(1)

    if not (1 <= start_port <= 65535 and 1 <= end_port <= 65535):
        print("Error: ports must be between 1 and 65535.")
        sys.exit(1)
    if start_port > end_port:
        print("Error: start port must be <= end port.")
        sys.exit(1)

    print(f"Scanning {host} — ports {start_port} to {end_port} "
          f"({end_port - start_port + 1} ports, {threads} threads) ...")
    started = datetime.now()
    open_ports = scan_range(host, start_port, end_port, threads)

    for port in open_ports:
        print(f"  Port {port} ({service_name(port)}): OPEN")

    elapsed = (datetime.now() - started).total_seconds()
    print(f"\nScan complete in {elapsed:.2f}s.")
    if open_ports:
        summary = ", ".join(f"{p} ({service_name(p)})" for p in open_ports)
        print(f"Open ports ({len(open_ports)}): {summary}")
    else:
        print("No open ports found in this range.")

    if write_report:
        report_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "report.txt")
        lines = [
            f"Port scan report — {host}",
            f"Date: {started.strftime('%Y-%m-%d %H:%M:%S')}",
            f"Range: {start_port}-{end_port}",
            f"Duration: {elapsed:.2f}s",
            f"Threads: {threads}",
            "",
            "Open ports:",
        ]
        lines += [f"  - {port} ({service_name(port)})" for port in open_ports] or ["  (none)"]
        with open(report_path, "w") as f:
            f.write("\n".join(lines) + "\n")
        print(f"Report written to {report_path}")


if __name__ == "__main__":
    main()

# Port Scanner

A TCP port scanner that checks which ports are open on a target host and can save a report.

**Author:** Wajahat Irfan — BS Computer Science student (7th semester), GPGC No. 1 Abbottabad

> Only scan hosts you own or have permission to scan.

## What it does

- Connects to each TCP port in a range (default host `127.0.0.1`, ports 1–1024) with a short 0.5-second timeout
- **NEW — threaded scanning:** ports are checked concurrently with a thread pool (default 50 workers, adjustable with `--threads N`), so a 1–1024 scan finishes in seconds instead of minutes
- **NEW — service names:** every open port is shown with its common service, e.g. `Port 80 (HTTP): OPEN`, `Port 22 (SSH): OPEN`
- Prints every open port as it is found, plus a summary and scan time
- With `--report`, writes the results to `report.txt` (now including service names)

## How to run

```bash
python scanner.py                    # scan 127.0.0.1, ports 1-1024
python scanner.py 127.0.0.1 80 85    # scan 127.0.0.1, ports 80-85
python scanner.py 127.0.0.1 80 85 --report   # also write report.txt
python scanner.py 127.0.0.1 1 1024 --threads 100   # scan with 100 worker threads
```

No extra packages needed — Python 3 standard library only.

## Example output

```
$ python scanner.py 127.0.0.1 80 85
Scanning 127.0.0.1 — ports 80 to 85 (6 ports, 50 threads) ...

Scan complete in 0.00s.
No open ports found in this range.
```

(On a machine running a local web server, port 80 would show as `Port 80 (HTTP): OPEN`.)

With `--report`, a `report.txt` is created:

```
Port scan report — 127.0.0.1
Date: 2026-11-15 21:50:00
Range: 80-85
Duration: 0.03s
Threads: 50

Open ports:
  - 80 (HTTP)
```

## Skills shown

- TCP sockets (`socket` module) and connection testing with `connect_ex`
- Timeouts and resource cleanup
- Concurrent scanning with `concurrent.futures.ThreadPoolExecutor`
- Well-known port/service mapping
- CLI argument parsing and input validation
- Writing a plain-text report file
- Responsible scanning: localhost by default, permission reminder

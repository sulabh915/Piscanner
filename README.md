
# Piscanner Advanced Port Scanner

A comprehensive and high-performance network scanning tool designed for security professionals, ethical hackers, and network administrators. This tool enables users to perform in-depth TCP and UDP port scanning, detect running services on open ports, and retrieve detailed banner information for deeper insights into network configurations. With multi-threading capabilities, it ensures fast and efficient scanning, allowing users to analyze multiple hosts and ports simultaneously, making it an essential tool for vulnerability assessment and network auditing.


## Features

✅ Supports TCP & UDP Scans

✅ Single-Port & Range Scanning 

✅ Multi-threading for Faster Scans

✅ Service Detection & Banner Grabbing

✅ Scan Results Saved to File (-o option)

✅ Handles CIDR Ranges & Hostname Resolution


## Requirements :



```bash
1. Python 3.x: Ensure Python is installed on your system. You can download it from the official website.

2. tabulate module

```
    
## Installation :
Step by step guide for installation :
```bash
git clone https://github.com/sulabh915/piscanner.git
cd piscanner
pip install -r requirement.txt
chmod +x piscanner.py
python3 piscanner.py -h
```
## Usage/Examples      :

```bash
python3 piscanner.py -tT 192.167.1.1
```
### Available Arguments :

Positional Argument:

IPv4: Target IP, CIDR range, or domain to scan.

Options:

```bash
Option             Long Option          Description

-h                 --help               Show this help message and exit
-tT                --tcp                Perform a TCP scan
-tU                --udp                Perform a UDP scan
-sp                --single-port        Scan a single port
-rp                --range-port         Scan a range of ports (e.g., 1-1000)
-th                --threads            Number of threads to use (default: 200)
-sd                --service            Enable service detection
-b                 --banner             Enable banner grabbing
-o                 --output             Save scan results to a file
-V                 --verbose            Enable verbose output
-v                 --version            Display scanner version
```

### Example Commands

- TCP Scan on a Domain with Service & Banner Detection:
```bash
python3 piscanner.py -tT -rp 1-1000 -sd -b scanme.nmap.org
```
- UDP Scan on a Single IP & Save Output to File:
```bash
python3 main.py -tU 192.168.1.1 -sp 53 -o results.txt
```
- Multi-threaded TCP Scan on a CIDR Range:
```bash
python3 main.py -tT -rp 20-80 -th 300 192.168.1.0/24
```

### console output :
```bash
Starting main.py 1.0 at 2025-03-17 11:23 AM
3 alive hosts found

Scanning Target: 192.168.1.1
+------+----------+--------+---------+-------------------------------+
| Port | Protocol | State  | Service | Banner                        |
+------+----------+--------+---------+-------------------------------+
| 22   | TCP      | Open   | ssh     | SSH-2.0-OpenSSH_8.2p1 Ubuntu  |
+------+----------+--------+---------+-------------------------------+
```

## Video guide :
video is here:
## Authors

- [@sulabh915](https://github.com/sulabh915/)


## Future Improvements

-  Detect OS & Service Versions
- Export Reports in JSON & CSV
- Add Support for SYN Scanning
- Improve Scan Speed with Asynchronous Processing


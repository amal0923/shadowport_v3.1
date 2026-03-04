#!/usr/bin/env python3

import socket
import threading
import argparse
from datetime import datetime

# -----------------------------
# Argument Parser
# -----------------------------
parser = argparse.ArgumentParser(
    prog="shadowport_v3.py",
    description="ShadowPort v3.1 - Lightweight Port Scanner with Risk Assessment Engine",
    
)

parser.add_argument("target", help="Target IP address or domain name")

parser.add_argument("-p", "--ports",
                    metavar="RANGE",
                    default="1-1024",
                    help="Port range (example: 1-5000). Default: 1-1024")

parser.add_argument("-rL", "--risk-levels",
                    action="store_true",
                    help="Display risk classification for each open port")

parser.add_argument("-aM", "--all-modules",
                    action="store_true",
                    help="Enable all scanning modules (currently only risk levels)")

parser.add_argument("-o", "--output",
                    metavar="FILE",
                    help="Save scan results to a file")

args = parser.parse_args()

# -----------------------------
# Enable All Modules Mode
# -----------------------------
if args.all_modules:
    args.risk_levels = True

# -----------------------------
# Validate Port Range
# -----------------------------
try:
    start_port, end_port = map(int, args.ports.split("-"))
except ValueError:
    print("Invalid port range format. Use example: 1-5000")
    exit()

target = args.target

print(r"""
  ███████╗██╗  ██╗ █████╗ ██████╗  ██████╗ ██╗    ██╗
  ██╔════╝██║  ██║██╔══██╗██╔══██╗██╔═══██╗██║    ██║
  ███████╗███████║███████║██║  ██║██║   ██║██║ █╗ ██║
  ╚════██║██╔══██║██╔══██║██║  ██║██║   ██║██║███╗██║
  ███████║██║  ██║██║  ██║██████╔╝╚██████╔╝╚███╔███╔╝
  ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝  ╚═════╝  ╚══╝╚══╝
  
   ██████╗  ██████╗ ██████╗ ████████╗
   ██╔══██╗██╔═══██╗██╔══██╗╚══██╔══╝
   ██████╔╝██║   ██║██████╔╝   ██║   
   ██╔═══╝ ██║   ██║██╔══██╗   ██║   
   ██║     ╚██████╔╝██║  ██║   ██║   
   ╚═╝      ╚═════╝ ╚═╝  ╚═╝   ╚═╝  

        S H A D O W   P O R T  3.1
        Advanced Intelligence Mode
        BUILT BY AMAL
""")

print(f"\nScanning Target: {target}")
print(f"Port Range: {start_port}-{end_port}")
print("Started at:", datetime.now())
print("-" * 55)

# -----------------------------
# Risk Definitions
# -----------------------------
HIGH_RISK = {21, 23, 445, 3389}
MEDIUM_RISK = {22, 139, 3306, 8080}

risk_score = 0
open_ports = []
lock = threading.Lock()

# -----------------------------
# Banner Grab
# -----------------------------
def grab_banner(sock):
    try:
        sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
        return sock.recv(1024).decode(errors="ignore").strip()
    except:
        return None

# -----------------------------
# Port Scanner
# -----------------------------
def scan_port(port):
    global risk_score

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)
        result = sock.connect_ex((target, port))

        if result == 0:
            with lock:
                open_ports.append(port)

                try:
                    service = socket.getservbyport(port, "tcp")
                except:
                    service = "Unknown"

                print(f"[OPEN] Port {port} - {service}")

                if args.risk_levels:
                    if port in HIGH_RISK:
                        print("   🔴 HIGH RISK")
                        risk_score += 20
                    elif port in MEDIUM_RISK:
                        print("   🟠 MEDIUM RISK")
                        risk_score += 10
                    else:
                        print("   🟢 LOW RISK")
                        risk_score += 3

                banner = grab_banner(sock)
                if banner:
                    print("   📡 Banner:", banner.split("\n")[0])

        sock.close()

    except:
        pass

# -----------------------------
# Multithreading
# -----------------------------
threads = []

for port in range(start_port, end_port + 1):
    t = threading.Thread(target=scan_port, args=(port,))
    threads.append(t)
    t.start()

for t in threads:
    t.join()

# -----------------------------
# Grade Calculation
# -----------------------------
if risk_score <= 10:
    grade = "A (Secure)"
elif risk_score <= 30:
    grade = "B (Good)"
elif risk_score <= 60:
    grade = "C (Moderate)"
elif risk_score <= 90:
    grade = "D (Risky)"
else:
    grade = "F (Critical)"

# -----------------------------
# Final Summary
# -----------------------------
print("\n" + "-" * 55)
print("Scan Completed.")
print(f"Total Open Ports: {len(open_ports)}")
print(f"Overall Risk Score: {risk_score}")
print(f"Security Grade: {grade}")

# -----------------------------
# Save Report
# -----------------------------
if args.output:
    with open(args.output, "w") as f:
        f.write("SHADOW PORT 3.1 Report\n")
        f.write(f"Target: {target}\n")
        f.write(f"Ports Scanned: {start_port}-{end_port}\n")
        f.write(f"Open Ports: {open_ports}\n")
        f.write(f"Risk Score: {risk_score}\n")
        f.write(f"Grade: {grade}\n")

    print(f"\nReport saved to {args.output}")

print("\nFinished at:", datetime.now())

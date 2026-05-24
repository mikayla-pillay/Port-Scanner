"""
Port Scanner - Mikayla Pillay
Scans a target host for open TCP ports using Python sockets.
Supports single port, port range, and common port presets.
"""
 
import socket
import threading
import argparse
import sys
from datetime import datetime
 
#Common ports with service names
COMMON_PORTS = {
    21:   "FTP",
    22:   "SSH",
    23:   "Telnet",
    25:   "SMTP",
    53:   "DNS",
    80:   "HTTP",
    110:  "POP3",
    143:  "IMAP",
    443:  "HTTPS",
    445:  "SMB",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    6379: "Redis",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
}
 
 
def resolve_host(target: str) -> str:
    #Resolve hostname to IP address.
    try:
        ip = socket.gethostbyname(target)
        return ip
    except socket.gaierror:
        print(f"[ERROR] Could not resolve host: {target}")
        sys.exit(1)
 
 
def scan_port(ip: str, port: int, timeout: float, open_ports: list, lock: threading.Lock):
    #Attempt a TCP connection to a single port. Record if open.
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        sock.close()
        if result == 0:
            with lock:
                open_ports.append(port)
    except socket.error:
        pass
 
 
def grab_banner(ip: str, port: int, timeout: float) -> str:
    #Try to grab a service banner from an open port.
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, port))
        # Send a generic HTTP request to provoke a response
        sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
        banner = sock.recv(1024).decode(errors="ignore").strip()
        sock.close()
        # Return just the first line
        return banner.splitlines()[0] if banner else ""
    except Exception:
        return ""
 
 
def print_banner(target: str, ip: str, port_range: tuple):
    print("\nPYTHON PORT SCANNER")
    print(f"  Target   : {target}")
    if target != ip:
        print(f"  Resolved : {ip}")
    print(f"  Ports    : {port_range[0]} – {port_range[1]}")
    print(f"  Started  : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
 
 
def scan(target: str, start_port: int, end_port: int, timeout: float, threads: int, banners: bool):
    ip = resolve_host(target)
    print_banner(target, ip, (start_port, end_port))
 
    open_ports = []
    lock = threading.Lock()
    active_threads = []
 
    ports = list(range(start_port, end_port + 1))
    total = len(ports)
 
    print(f"\nScanning {total} port(s) with {threads} thread(s)...\n")
 
    for i, port in enumerate(ports):
        #Progress indicator every 100 ports
        if total > 100 and i % 100 == 0:
            print(f"  Progress: {i}/{total} ports scanned...", end="\r")
 
        t = threading.Thread(
            target=scan_port,
            args=(ip, port, timeout, open_ports, lock),
            daemon=True
        )
        active_threads.append(t)
        t.start()
 
        #Throttle: wait when we hit thread limit
        if len(active_threads) >= threads:
            for t in active_threads:
                t.join()
            active_threads = []
 
    # Wait for remaining threads
    for t in active_threads:
        t.join()
 
    print(" " * 50, end="\r")  # clear progress line
 
    #Results
    print(f"\n{'PORT':<10} {'SERVICE':<15} {'STATUS':<10} {'BANNER'}")
    print("-" * 55)
 
    if not open_ports:
        print("  No open ports found in the specified range.")
    else:
        for port in sorted(open_ports):
            service = COMMON_PORTS.get(port, "Unknown")
            banner = grab_banner(ip, port, timeout) if banners else ""
            print(f"  {port:<8} {service:<15} {'OPEN':<10} {banner[:30]}")
 
    print(f"\n  Scan complete. {len(open_ports)} open port(s) found.")
    print(f"  Finished : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
 
 
def main():
    parser = argparse.ArgumentParser(
        description="TCP Port Scanner - scan a host for open ports",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""
Examples:
  python scanner.py localhost
  python scanner.py 192.168.1.1 -p 1-1024
  python scanner.py scanme.nmap.org -p 22,80,443
  python scanner.py example.com --common
  python scanner.py 10.0.0.1 -p 1-65535 --threads 200 --banners
        """
    )
    parser.add_argument("target", help="Hostname or IP address to scan")
    parser.add_argument("-p", "--ports", default="1-1024",
                        help="Port range (e.g. 1-1024) or comma-separated list (e.g. 22,80,443)")
    parser.add_argument("--common", action="store_true",
                        help="Scan only the common ports preset")
    parser.add_argument("--timeout", type=float, default=0.5,
                        help="Connection timeout per port in seconds (default: 0.5)")
    parser.add_argument("--threads", type=int, default=100,
                        help="Number of concurrent threads (default: 100)")
    parser.add_argument("--banners", action="store_true",
                        help="Attempt to grab service banners from open ports")
 
    args = parser.parse_args()
 
    # Determine port range
    if args.common:
        ports = list(COMMON_PORTS.keys())
        start_port = min(ports)
        end_port = max(ports)
    elif "," in args.ports:
        # Comma-separated list — wrap into a pseudo range and filter
        port_list = [int(p.strip()) for p in args.ports.split(",")]
        start_port = min(port_list)
        end_port = max(port_list)
    elif "-" in args.ports:
        parts = args.ports.split("-")
        start_port, end_port = int(parts[0]), int(parts[1])
    else:
        start_port = end_port = int(args.ports)
 
    if not (0 < start_port <= 65535 and 0 < end_port <= 65535):
        print("[ERROR] Ports must be between 1 and 65535.")
        sys.exit(1)
 
    scan(args.target, start_port, end_port, args.timeout, args.threads, args.banners)
 
 
if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
Multi-IP Port Scanner - Created by Sayooj
Enhanced with colorful CLI & MSF-style banner
"""

import socket
import threading
import sys
from datetime import datetime
import ipaddress
import os
import time
import re

# Color codes for terminal output
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    DIM = '\033[2m'
    RESET = '\033[0m'
    BLACK = '\033[30m'
    WHITE = '\033[97m'
    MAGENTA = '\033[95m'
    
    # Background colors
    BG_GREEN = '\033[42m'
    BG_RED = '\033[41m'
    BG_BLUE = '\033[44m'
    BG_YELLOW = '\033[43m'
    
    # Effects
    BLINK = '\033[5m'
    REVERSE = '\033[7m'

# Configuration
TIMEOUT = 0.5
MAX_THREADS = 100
ENABLE_VERSION_DETECTION = True
COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 111: "RPC", 135: "RPC", 139: "NetBIOS",
    143: "IMAP", 443: "HTTPS", 445: "SMB", 993: "IMAPS", 995: "POP3S",
    1433: "MSSQL", 1521: "Oracle", 3306: "MySQL", 3389: "RDP",
    5432: "PostgreSQL", 5900: "VNC", 6379: "Redis", 8080: "HTTP-Alt",
    8443: "HTTPS-Alt", 27017: "MongoDB"
}

# ============ SERVICE VERSION DETECTION FUNCTIONS ============

def get_http_version(ip, port):
    """Get HTTP server version"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2.0)
        sock.connect((ip, port))
        sock.send(b'HEAD / HTTP/1.1\r\nHost: ' + ip.encode() + b'\r\nConnection: close\r\n\r\n')
        response = sock.recv(1024).decode('utf-8', errors='ignore')
        sock.close()
        
        match = re.search(r'Server:\s*(.+)', response, re.IGNORECASE)
        if match:
            return match.group(1).strip()
        return None
    except:
        return None

def get_ssh_version(ip, port):
    """Get SSH version banner"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2.0)
        sock.connect((ip, port))
        banner = sock.recv(256).decode('utf-8', errors='ignore')
        sock.close()
        
        match = re.search(r'SSH-[\d\.]+-([^\s]+)', banner)
        if match:
            return match.group(1)
        return None
    except:
        return None

def get_ftp_version(ip, port):
    """Get FTP server version"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2.0)
        sock.connect((ip, port))
        banner = sock.recv(256).decode('utf-8', errors='ignore')
        sock.close()
        
        match = re.search(r'220[\s\-]*(.+)', banner)
        if match:
            return match.group(1).strip()
        return None
    except:
        return None

def get_smtp_version(ip, port):
    """Get SMTP server version"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2.0)
        sock.connect((ip, port))
        banner = sock.recv(256).decode('utf-8', errors='ignore')
        sock.close()
        
        match = re.search(r'220[\s\-]*(.+)', banner)
        if match:
            return match.group(1).strip()
        return None
    except:
        return None

def get_mysql_version(ip, port):
    """Get MySQL version"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2.0)
        sock.connect((ip, port))
        data = sock.recv(1024)
        sock.close()
        
        match = re.search(b'[\x00-\xff]{4}([^\x00]+)\x00', data)
        if match:
            version = match.group(1).decode('utf-8', errors='ignore')
            return version[:50]
        return None
    except:
        return None

def get_pop3_version(ip, port):
    """Get POP3 server version"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2.0)
        sock.connect((ip, port))
        banner = sock.recv(256).decode('utf-8', errors='ignore')
        sock.close()
        
        match = re.search(r'\+OK[\s\-]*(.+)', banner)
        if match:
            return match.group(1).strip()
        return None
    except:
        return None

def get_imap_version(ip, port):
    """Get IMAP server version"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2.0)
        sock.connect((ip, port))
        banner = sock.recv(256).decode('utf-8', errors='ignore')
        sock.close()
        
        match = re.search(r'\* OK[\s\-]*(.+)', banner, re.IGNORECASE)
        if match:
            return match.group(1).strip()
        return None
    except:
        return None

def get_version(ip, port, service):
    """Main version detection dispatcher"""
    if not ENABLE_VERSION_DETECTION:
        return None
    
    version_detectors = {
        80: get_http_version,
        443: get_http_version,
        8080: get_http_version,
        8443: get_http_version,
        22: get_ssh_version,
        21: get_ftp_version,
        25: get_smtp_version,
        3306: get_mysql_version,
        110: get_pop3_version,
        143: get_imap_version,
    }
    
    detector = version_detectors.get(port)
    if detector:
        try:
            version = detector(ip, port)
            if version:
                return version
        except:
            pass
    return None

# ============ END OF VERSION DETECTION FUNCTIONS ============

def display_msf_banner():
    """Display Metasploit-style animated banner"""
    os.system('clear' if os.name == 'posix' else 'cls')
    
    banner = f"""
{Colors.RED}{Colors.BOLD}
    ╔═══════════════════════════════════════════════════════════════════╗
    ║{Colors.RESET}{Colors.CYAN}                                                                   {Colors.RED}║
    ║{Colors.RESET}{Colors.RED}     ██████╗  ██████╗ ██████╗ ████████╗    ███████╗ ██████╗ █████╗ ███╗   ██╗███╗   ██╗███████╗██████╗ {Colors.RED}║
    ║{Colors.RESET}{Colors.RED}     ██╔══██╗██╔══██╗██╔══██╗╚══██╔══╝    ██╔════╝██╔════╝██╔══██╗████╗  ██║████╗  ██║██╔════╝██╔══██╗{Colors.RED}║
    ║{Colors.RESET}{Colors.RED}     ██████╔╝██████╔╝██████╔╝   ██║       ███████╗██║     ███████║██╔██╗ ██║██╔██╗ ██║█████╗  ██████╔╝{Colors.RED}║
    ║{Colors.RESET}{Colors.RED}     ██╔═══╝ ██╔══██╗██╔══██╗   ██║       ╚════██║██║     ██╔══██║██║╚██╗██║██║╚██╗██║██╔══╝  ██╔══██╗{Colors.RED}║
    ║{Colors.RESET}{Colors.RED}     ██║     ██║  ██║██║  ██║   ██║       ███████║╚██████╗██║  ██║██║ ╚████║██║ ╚████║███████╗██║  ██║{Colors.RED}║
    ║{Colors.RESET}{Colors.RED}     ╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝       ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝{Colors.RED}║
    ║{Colors.RESET}{Colors.CYAN}                                                                   {Colors.RED}║
    ╚═══════════════════════════════════════════════════════════════════╝{Colors.RESET}
    
{Colors.MAGENTA}{Colors.BOLD}                  PORT SCANNER v2.0 | Created by Sayooj{Colors.RESET}
{Colors.CYAN}    ═══════════════════════════════════════════════════════════════════{Colors.RESET}
    """
    
    print(banner)
    
    # Animated loading
    print(f"{Colors.CYAN}    System Ready", end="")
    for _ in range(3):
        for char in "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏":
            sys.stdout.write(f"\r{Colors.CYAN}    System Ready {char}{Colors.RESET}")
            sys.stdout.flush()
            time.sleep(0.03)
    
    print(f"\r{Colors.GREEN}    ✓ System Ready{Colors.RESET}{' ' * 30}\n")
    time.sleep(0.5)

def scan_port(ip, port, results):
    """Scan a single port on a given IP with version detection"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(TIMEOUT)
        result = sock.connect_ex((ip, port))
        
        if result == 0:
            service = COMMON_PORTS.get(port, "Unknown")
            
            # Get service version
            version = get_version(ip, port, service)
            
            results[ip].append((port, service, version))
            
            # Color-code based on port type
            if port in [80, 443, 8080, 8443]:
                port_color = Colors.GREEN
            elif port in [22, 3389, 5900]:
                port_color = Colors.BLUE
            elif port in [21, 25, 110, 143]:
                port_color = Colors.YELLOW
            elif port in [3306, 5432, 1433, 27017]:
                port_color = Colors.MAGENTA
            else:
                port_color = Colors.CYAN
            
            # Display with version if available
            if version:
                print(f"\n{Colors.GREEN}[+]{Colors.RESET} {Colors.BOLD}{ip}{Colors.RESET}:{port_color}{port}{Colors.RESET} [{Colors.WHITE}{service}{Colors.RESET}] {Colors.DIM}-> {Colors.CYAN}{version}{Colors.RESET}")
            else:
                print(f"\n{Colors.GREEN}[+]{Colors.RESET} {Colors.BOLD}{ip}{Colors.RESET}:{port_color}{port}{Colors.RESET} [{Colors.WHITE}{service}{Colors.RESET}]")
        
        sock.close()
    except Exception:
        pass

def scan_ip_range(ip, start_port, end_port, results):
    """Scan a range of ports for a single IP"""
    results[ip] = []
    threads = []
    
    # Show scanning header
    print(f"\n{Colors.BLUE}┌──[{Colors.CYAN}sayooj@scanner{Colors.BLUE}]─[{Colors.YELLOW}{ip}{Colors.BLUE}]")
    print(f"{Colors.BLUE}└──{Colors.GREEN}╼${Colors.RESET} Scanning ports {Colors.CYAN}{start_port}-{end_port}{Colors.RESET}")
    
    for port in range(start_port, end_port + 1):
        thread = threading.Thread(target=scan_port, args=(ip, port, results))
        threads.append(thread)
        thread.start()
        
        if len(threads) >= MAX_THREADS:
            for t in threads:
                t.join()
            threads = []
    
    for t in threads:
        t.join()

def validate_ips(ip_input):
    """Parse and validate IP addresses"""
    ips_to_scan = []
    invalid_ips = []
    
    ip_list = ip_input.replace(',', ' ').split()
    
    for item in ip_list:
        item = item.strip()
        
        # CIDR range
        if '/' in item:
            try:
                network = ipaddress.ip_network(item, strict=False)
                for ip in network.hosts():
                    ips_to_scan.append(str(ip))
                print(f"{Colors.GREEN}[✓]{Colors.RESET} Added CIDR: {Colors.CYAN}{item}{Colors.RESET}")
                continue
            except ValueError:
                pass
        
        # IP range
        if '-' in item and '/' not in item:
            try:
                if '.' in item.split('-')[0] and '.' in item.split('-')[1]:
                    start_ip, end_ip = item.split('-')
                    start_parts = list(map(int, start_ip.split('.')))
                    end_parts = list(map(int, end_ip.split('.')))
                    
                    for i in range(start_parts[3], end_parts[3] + 1):
                        ips_to_scan.append(f"{start_parts[0]}.{start_parts[1]}.{start_parts[2]}.{i}")
                    print(f"{Colors.GREEN}[✓]{Colors.RESET} Added range: {Colors.CYAN}{item}{Colors.RESET}")
                else:
                    base_ip, last_range = item.split('-')
                    base_parts = base_ip.split('.')
                    prefix = '.'.join(base_parts[:3])
                    start_octet = int(base_parts[3])
                    end_octet = int(last_range)
                    
                    for i in range(start_octet, end_octet + 1):
                        ips_to_scan.append(f"{prefix}.{i}")
                    print(f"{Colors.GREEN}[✓]{Colors.RESET} Added range: {Colors.CYAN}{item}{Colors.RESET}")
                continue
            except (ValueError, IndexError):
                pass
        
        # Single IP or hostname
        try:
            ipaddress.ip_address(item)
            ips_to_scan.append(item)
            print(f"{Colors.GREEN}[✓]{Colors.RESET} Added IP: {Colors.CYAN}{item}{Colors.RESET}")
        except ValueError:
            try:
                resolved = socket.gethostbyname(item)
                print(f"{Colors.YELLOW}[→]{Colors.RESET} Resolved {Colors.CYAN}{item}{Colors.RESET} → {Colors.GREEN}{resolved}{Colors.RESET}")
                ips_to_scan.append(resolved)
            except socket.gaierror:
                print(f"{Colors.RED}[✗]{Colors.RESET} Invalid: {Colors.RED}{item}{Colors.RESET}")
                invalid_ips.append(item)
    
    if invalid_ips:
        print(f"\n{Colors.YELLOW}[!]{Colors.RESET} Skipped {len(invalid_ips)} invalid target(s)")
    
    return list(dict.fromkeys(ips_to_scan))

def get_port_range():
    """Get port range from user input"""
    print(f"\n{Colors.CYAN}{Colors.BOLD}┌──[ PORT SCAN MODE ]{Colors.RESET}")
    print(f"{Colors.CYAN}├──{Colors.GREEN} 1){Colors.RESET} Common ports {Colors.YELLOW}(1-1024){Colors.RESET}")
    print(f"{Colors.CYAN}├──{Colors.GREEN} 2){Colors.RESET} All ports {Colors.YELLOW}(1-65535){Colors.RESET}")
    print(f"{Colors.CYAN}└──{Colors.GREEN} 3){Colors.RESET} Custom range")
    
    choice = input(f"\n{Colors.GREEN}╼${Colors.RESET} Select option {Colors.YELLOW}(1-3){Colors.RESET}: ").strip()
    
    if choice == '1':
        print(f"{Colors.GREEN}[✓]{Colors.RESET} Using ports {Colors.CYAN}1-1024{Colors.RESET}")
        return 1, 1024
    elif choice == '2':
        print(f"{Colors.GREEN}[✓]{Colors.RESET} Using ports {Colors.CYAN}1-65535{Colors.RESET}")
        return 1, 65535
    elif choice == '3':
        try:
            start = int(input(f"{Colors.GREEN}╼${Colors.RESET} Start port: "))
            end = int(input(f"{Colors.GREEN}╼${Colors.RESET} End port: "))
            if start < 1 or end > 65535 or start > end:
                print(f"{Colors.RED}[✗]{Colors.RESET} Invalid range. Using defaults.")
                return 1, 1024
            print(f"{Colors.GREEN}[✓]{Colors.RESET} Custom range: {Colors.CYAN}{start}-{end}{Colors.RESET}")
            return start, end
        except ValueError:
            print(f"{Colors.RED}[✗]{Colors.RESET} Invalid input. Using defaults.")
            return 1, 1024
    else:
        print(f"{Colors.RED}[✗]{Colors.RESET} Invalid choice. Using defaults.")
        return 1, 1024

def save_results(results, scan_time, total_ips, total_ports):
    """Save results to file"""
    print(f"\n{Colors.CYAN}{Colors.BOLD}┌──[ SAVE RESULTS ]{Colors.RESET}")
    print(f"{Colors.CYAN}├──{Colors.GREEN} 1){Colors.RESET} Save to file")
    print(f"{Colors.CYAN}└──{Colors.GREEN} 2){Colors.RESET} Don't save")
    
    choice = input(f"\n{Colors.GREEN}╼${Colors.RESET} Save results? {Colors.YELLOW}(1-2){Colors.RESET}: ").strip()
    
    if choice == '2':
        print(f"{Colors.YELLOW}[!]{Colors.RESET} Results not saved")
        return
    
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    filename = f"portscan_{timestamp}.txt"
    
    with open(filename, 'w') as f:
        f.write("="*60 + "\n")
        f.write("PORT SCANNER RESULTS - Created by Sayooj\n")
        f.write("="*60 + "\n")
        f.write(f"Scan Date: {scan_time}\n")
        f.write(f"Total Targets: {total_ips}\n")
        f.write(f"Total Open Ports: {total_ports}\n")
        f.write("="*60 + "\n\n")
        
        for ip, open_ports in results.items():
            if open_ports:
                f.write(f"► {ip}\n")
                f.write("-"*40 + "\n")
                for port, service, version in sorted(open_ports):
                    if version:
                        f.write(f"  {port}:{service} -> {version}\n")
                    else:
                        f.write(f"  {port}:{service}\n")
                f.write("\n")
            else:
                f.write(f"► {ip} - No open ports found\n\n")
    
    print(f"{Colors.GREEN}[✓]{Colors.RESET} Saved: {Colors.CYAN}{filename}{Colors.RESET}")

def main():
    """Main function"""
    display_msf_banner()
    
    # Get target IPs
    print(f"{Colors.CYAN}{Colors.BOLD}┌──[ TARGETS ]{Colors.RESET}")
    print(f"{Colors.CYAN}│{Colors.RESET}")
    print(f"{Colors.CYAN}├──{Colors.DIM} Examples:{Colors.RESET}")
    print(f"{Colors.CYAN}│   • {Colors.GREEN}192.168.1.1{Colors.RESET}")
    print(f"{Colors.CYAN}│   • {Colors.GREEN}192.168.1.1, 8.8.8.8{Colors.RESET}")
    print(f"{Colors.CYAN}│   • {Colors.GREEN}192.168.1.0/24{Colors.RESET}")
    print(f"{Colors.CYAN}│   • {Colors.GREEN}192.168.1.1-20{Colors.RESET}")
    print(f"{Colors.CYAN}└──{Colors.RESET}")
    
    ip_input = input(f"\n{Colors.GREEN}╼${Colors.RESET} Enter target{Colors.YELLOW}(s){Colors.RESET}: ").strip()
    
    if not ip_input:
        print(f"{Colors.RED}[✗]{Colors.RESET} No input provided")
        sys.exit(1)
    
    print(f"\n{Colors.BLUE}[*]{Colors.RESET} Resolving targets...\n")
    ips_to_scan = validate_ips(ip_input)
    
    if not ips_to_scan:
        print(f"{Colors.RED}[✗]{Colors.RESET} No valid targets found")
        sys.exit(1)
    
    # Get port range
    start_port, end_port = get_port_range()
    
    # Calculate total ports to scan
    total_ports_to_scan = len(ips_to_scan) * (end_port - start_port + 1)
    
    print(f"\n{Colors.CYAN}[i]{Colors.RESET} Targets: {Colors.YELLOW}{len(ips_to_scan)}{Colors.RESET} | Ports: {Colors.YELLOW}{start_port}-{end_port}{Colors.RESET} | Total probes: {Colors.YELLOW}{total_ports_to_scan:,}{Colors.RESET}")
    
    confirm = input(f"\n{Colors.YELLOW}[?]{Colors.RESET} Start scan? {Colors.GREEN}(y/n){Colors.RESET}: ").lower().strip()
    if confirm != 'y':
        print(f"{Colors.RED}[!]{Colors.RESET} Cancelled")
        sys.exit(0)
    
    # Start scanning
    start_time = datetime.now()
    print(f"\n{Colors.GREEN}[*]{Colors.RESET} Started at {Colors.CYAN}{start_time.strftime('%H:%M:%S')}{Colors.RESET}")
    print(f"{Colors.BLUE}{'='*50}{Colors.RESET}\n")
    
    results = {}
    
    # Scan each IP
    for ip in ips_to_scan:
        scan_ip_range(ip, start_port, end_port, results)
    
    # Summary
    end_time = datetime.now()
    total_time = end_time - start_time
    
    print(f"\n{Colors.BLUE}{'='*50}{Colors.RESET}")
    print(f"{Colors.GREEN}{Colors.BOLD}✓ SCAN COMPLETE{Colors.RESET}")
    print(f"{Colors.BLUE}{'='*50}{Colors.RESET}")
    
    total_open_ports = sum(len(ports) for ports in results.values())
    
    print(f"\n{Colors.CYAN}📊 Results:{Colors.RESET}")
    print(f"   {Colors.GREEN}•{Colors.RESET} Targets: {Colors.BOLD}{len(ips_to_scan)}{Colors.RESET}")
    print(f"   {Colors.GREEN}•{Colors.RESET} Open ports: {Colors.BOLD}{total_open_ports}{Colors.RESET}")
    print(f"   {Colors.GREEN}•{Colors.RESET} Time: {Colors.BOLD}{total_time}{Colors.RESET}")
    
    # Show open ports
    if total_open_ports > 0:
        print(f"\n{Colors.YELLOW}Open ports:{Colors.RESET}")
        for ip, open_ports in results.items():
            if open_ports:
                ports_str = ", ".join([f"{Colors.GREEN}{p}{Colors.RESET}" for p, _, _ in open_ports])
                print(f"   {Colors.CYAN}→{Colors.RESET} {ip}: {ports_str}")
    
    # Save results
    save_results(results, start_time.strftime('%Y-%m-%d %H:%M:%S'), len(ips_to_scan), total_open_ports)
    
    print(f"\n{Colors.GREEN}{Colors.BOLD}✨ Done!{Colors.RESET}\n")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n\n{Colors.RED}[!]{Colors.RESET} Interrupted\n")
        sys.exit(0)
    except Exception as e:
        print(f"\n{Colors.RED}[✗]{Colors.RESET} Error: {e}")
        sys.exit(1)

import socket
import subprocess
import concurrent.futures
import json
from datetime import datetime
def get_eigene_ip():
    hostname = socket.gethostname()
    ip = socket.gethostbyname(hostname)
    return ip

def ping_host(ip):
    try:
        result = subprocess.run(
            ["ping", "-n", "1", "-w", "500", ip],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        if result.returncode == 0:
            return ip
    except:
        pass
    return None

BEKANNTE_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    443: "HTTPS",
    3306: "MySQL",
    3389: "RDP",
    8080: "HTTP-Alt"
}

def scan_port(ip, port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.5)
        result = s.connect_ex((ip, port))
        s.close()
        if result == 0:
            service = BEKANNTE_PORTS.get(port, "Unbekannt")
            return port, service
    except:
        pass
    return None

def scan_ports(ip):
    print(f"\nScanne Ports auf {ip}...")
    offene_ports = []
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
        futures = {executor.submit(scan_port, ip, port): port 
                   for port in BEKANNTE_PORTS.keys()}
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result:
                port, service = result
                offene_ports.append((port, service))
                print(f"  Port {port} offen → {service}")
    
    return offene_ports

if __name__ == "__main__":
    eigene_ip = get_eigene_ip()
    print(f"Meine IP: {eigene_ip}")
    
    basis = ".".join(eigene_ip.split(".")[:3])
    
    # Host scan
    print(f"\nScanne Netzwerk {basis}.0/24...")
    ips = [f"{basis}.{i}" for i in range(1, 255)]
    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
        hosts = [ip for ip in executor.map(ping_host, ips) if ip]
    
    # Port scan auf jeden aktiven Host
    report = {
        "scan_datum": datetime.now().strftime("%Y-%m-%d %H:%M"),
        "eigene_ip": eigene_ip,
        "hosts": []
    }
    
    for host in hosts:
        ports = scan_ports(host)
        host_data = {
            "ip": host,
            "offene_ports": [
                {"port": p, "service": s} for p, s in ports
            ]
        }
        report["hosts"].append(host_data)
    
    # JSON speichern
    with open("report.json", "w") as f:
        json.dump(report, f, indent=4)
    
    print(f"\nReport gespeichert in report.json")
    print(f"Hosts gefunden: {len(hosts)}")
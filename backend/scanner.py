"""
Nmap scanning module.
Wraps python-nmap to perform port/service/OS detection scans.
"""

import nmap
from models import NmapResult, PortInfo
from dotenv import load_dotenv
load_dotenv()
# Ports commonly associated with known CVEs or risky services
DANGEROUS_PORTS = {
    21: "FTP - unencrypted file transfer",
    22: "SSH - brute-force target",
    23: "Telnet - cleartext protocol",
    25: "SMTP - mail relay abuse",
    80: "HTTP - unencrypted web",
    110: "POP3 - cleartext mail",
    135: "MS-RPC - lateral movement vector",
    139: "NetBIOS - SMB vulnerability surface",
    143: "IMAP - cleartext mail",
    443: "HTTPS",
    445: "SMB - EternalBlue target",
    1433: "MSSQL",
    1521: "Oracle DB",
    3306: "MySQL",
    3389: "RDP - brute-force / BlueKeep target",
    4444: "Metasploit default listener",
    5432: "PostgreSQL",
    5900: "VNC - remote access",
    6379: "Redis - often unauthenticated",
    8080: "HTTP alt - dev/proxy exposure",
    8443: "HTTPS alt",
    27017: "MongoDB - often unauthenticated",
}

SCAN_PROFILES = {
    "basic": "-sV --open -T4",            # Version detection, open ports only
    "full": "-sV -O --open -T4 -p-",     # + OS detection, all ports
    "stealth": "-sS -sV --open -T2",      # SYN stealth scan
}


def run_nmap_scan(target: str, scan_type: str = "basic") -> NmapResult:
    """
    Run an Nmap scan against the target.
    Returns structured port, service, and OS information.
    """
    nm = nmap.PortScanner()
    args = SCAN_PROFILES.get(scan_type, SCAN_PROFILES["basic"])

    try:
        nm.scan(hosts=target, arguments=args)
    except nmap.PortScannerError as e:
        raise RuntimeError(f"Nmap failed: {e}")

    # Resolve first live host from results
    hosts = nm.all_hosts()
    if not hosts:
        raise RuntimeError(f"No hosts found for target: {target}")

    host = hosts[0]
    host_data = nm[host]

    hostname = ""
    if host_data.get("hostnames"):
        hostname = host_data["hostnames"][0].get("name", "")

    state = host_data.get("status", {}).get("state", "unknown")

    # OS detection (only available in full scan with sudo)
    os_guess = ""
    if "osmatch" in host_data and host_data["osmatch"]:
        os_guess = host_data["osmatch"][0].get("name", "")

    ports: list[PortInfo] = []
    for proto in host_data.all_protocols():
        for port in sorted(host_data[proto].keys()):
            port_data = host_data[proto][port]
            service_name = port_data.get("name", "")
            version = f"{port_data.get('product', '')} {port_data.get('version', '')}".strip()
            state_val = port_data.get("state", "")

            # Flag known dangerous ports
            cve_hints = []
            if port in DANGEROUS_PORTS:
                cve_hints.append(DANGEROUS_PORTS[port])

            ports.append(PortInfo(
                port=port,
                protocol=proto,
                state=state_val,
                service=service_name,
                version=version,
                cve_hints=cve_hints,
            ))

    scan_stats = nm.scanstats()
    duration = float(scan_stats.get("elapsed", 0))

    return NmapResult(
        host=host,
        hostname=hostname,
        state=state,
        os_guess=os_guess,
        ports=ports,
        scan_duration=duration,
    )

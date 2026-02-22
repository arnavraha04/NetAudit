import subprocess
import re
import ipaddress
import socket

# ==============================
# Expanded Port Risk Database
# ==============================

port_risks = {
    20: ("FTP Data", "High", "FTP data transfer port, unencrypted."),
    21: ("FTP", "High", "FTP command port, unencrypted authentication."),
    22: ("SSH", "Low", "Secure remote login service."),
    23: ("Telnet", "Critical", "Telnet sends credentials in plain text."),
    25: ("SMTP", "Medium", "Mail sending service; can be exploited for spam."),
    53: ("DNS", "Medium", "Domain name resolution service."),
    67: ("DHCP", "Medium", "Dynamic host configuration service."),
    69: ("TFTP", "High", "Trivial file transfer; unencrypted."),
    80: ("HTTP", "Medium", "Standard web service; unencrypted."),
    110: ("POP3", "Medium", "Mail retrieval; may send passwords in plain text."),
    143: ("IMAP", "Medium", "Mail retrieval service."),
    161: ("SNMP", "High", "Device management; default community strings risky."),
    443: ("HTTPS", "Low", "Secure web service."),
    445: ("SMB", "High", "Windows file sharing; ransomware target."),
    3389: ("RDP", "High", "Remote desktop service."),
    3306: ("MySQL", "High", "Database service; often targeted."),
    5432: ("PostgreSQL", "High", "Database service."),
    5900: ("VNC", "High", "Remote desktop service."),
}

# ==============================
# CVE Intelligence Mapping
# ==============================
port_cves = {
    21: [
        ("CVE-2011-2523", "vsFTPd 2.3.4 Backdoor RCE"),
        ("CVE-1999-0497", "Anonymous FTP Misconfiguration"),
    ],
    22: [
        ("CVE-2018-15473", "OpenSSH Username Enumeration"),
        ("CVE-2016-0777", "OpenSSH Information Leak"),
    ],
    23: [
        ("CVE-2016-0772", "Telnet Buffer Overflow"),
    ],
    25: [
        ("CVE-2010-4344", "Exim SMTP Remote Code Execution"),
    ],
    53: [
        ("CVE-2015-5477", "BIND DNS TKEY Assertion Failure DoS"),
    ],
    80: [
        ("CVE-2021-41773", "Apache HTTP Server Path Traversal"),
        ("CVE-2017-5638", "Apache Struts RCE"),
    ],
    110: [
        ("CVE-2018-19518", "POP3 Server Overflow"),
    ],
    139: [
        ("CVE-2017-0144", "SMBv1 EternalBlue"),
    ],
    443: [
        ("CVE-2014-0160", "Heartbleed - OpenSSL"),
        ("CVE-2021-34473", "Microsoft Exchange ProxyShell"),
    ],
    445: [
        ("CVE-2017-0144", "EternalBlue - SMBv1 RCE"),
        ("CVE-2020-0796", "SMBGhost - SMBv3 RCE"),
    ],
    3389: [
        ("CVE-2019-0708", "BlueKeep - RDP RCE"),
    ]
}
# ==============================
# Target Validation
# ==============================

def validate_target(target):
    target = target.strip()

    if not target:
        return False

    try:
        ipaddress.ip_address(target)
        return True
    except ValueError:
        pass

    try:
        socket.gethostbyname(target)
        return True
    except socket.error:
        return False


def is_host_reachable(target):
    try:
        socket.create_connection((target, 80), timeout=3)
        return True
    except:
        return False


# ==============================
# Scan Menu
# ==============================

def get_scan_type():
    print("\nSelect Scan Type:")
    print("1. SYN Scan (Stealth)")
    print("2. TCP Connect Scan")
    print("3. UDP Scan")
    print("4. Ping Scan")

    choice = input("Enter choice (1-4): ")

    if choice == "1":
        return "-sS"
    elif choice == "2":
        return "-sT"
    elif choice == "3":
        return "-sU"
    elif choice == "4":
        return "-sn"
    else:
        print("Invalid choice. Using TCP Connect scan by default.")
        return "-sT"


# ==============================
# Clean Ping Scan
# ==============================

def clean_ping_output(target):
    try:
        output = subprocess.check_output(
            ["nmap", "-sn", target],
            stderr=subprocess.DEVNULL
        ).decode()

        print("\n========== PING SCAN RESULT ==========")
        print(f"Target        : {target}")

        if "Host is up" in output:
            print("Status        : UP")

            latency_match = re.search(r"\((.*?) latency\)", output)
            if latency_match:
                print(f"Latency       : {latency_match.group(1)}")

        else:
            print("Status        : DOWN")

        print("=======================================\n")

    except Exception as e:
        print("Ping scan failed:", e)


# ==============================
# Port Risk + CVE Analysis
# ==============================

def analyze_ports(scan_output):
    print("\n========== PORT RISK ANALYSIS ==========")
    print("-" * 50)

    lines = scan_output.split("\n")
    found = False

    for line in lines:
        if "/tcp" in line and "open" in line:
            found = True
            port_number = int(line.split("/")[0])

            if port_number in port_risks:
                service, risk, description = port_risks[port_number]
            else:
                service = "Unknown"
                risk = "Unknown"
                description = "No information available."

            print(f"\nPort: {port_number}")
            print(f"Service: {service}")
            print(f"Risk Level: {risk}")
            print(f"Description: {description}")

            # Show CVEs if available
            if port_number in port_cves:
                print("Known Associated CVEs:")
                for cve_id, cve_desc in port_cves[port_number]:
                    print(f"- {cve_id} ({cve_desc})")

            print("-" * 40)

    if not found:
        print("No open TCP ports detected.")


# ==============================
# Run Scan
# ==============================

def scan_target(target, scan_type):

    if scan_type == "-sn":
        clean_ping_output(target)
        return

    print(f"\nRunning Nmap scan on: {target}")
    print("Scan type:", scan_type)
    print("=" * 50)

    try:
        output = subprocess.check_output(
            ["nmap", scan_type, target],
            text=True
        )

        analyze_ports(output)

    except Exception as e:
        print("Scan failed:", e)


# ==============================
# Main
# ==============================

if __name__ == "__main__":

    target = input("Enter target IP or domain: ").strip()

    if not validate_target(target):
        print("Invalid IP address or hostname.")
        exit()

    if not is_host_reachable(target):
        print("Warning: Target resolved but may not be reachable on port 80.")

    scan_type = get_scan_type()
    scan_target(target, scan_type)

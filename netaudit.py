import subprocess
import re

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

            ip_match = re.search(r"Nmap scan report for .* \((.*?)\)", output)
            if ip_match:
                print(f"Resolved IP   : {ip_match.group(1)}")

        else:
            print("Status        : DOWN")

        print("=======================================\n")

    except Exception as e:
        print("Ping scan failed:", e)

# ==============================
# Port Risk Analysis
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

    target = input("Enter target IP or domain: ")
    scan_type = get_scan_type()
    scan_target(target, scan_type)

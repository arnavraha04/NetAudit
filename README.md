**NetAudit**

 NetAudit is a network auditing and monitoring tool designed to analyze network security, detect vulnerabilities, and provide detailed insights into connected devices. This project demonstrates hands-on knowledge  of network scanning, auditing, and security best practices.

## Project Features

  -Comprehensive Network Scanning – Scan IPs or domains for availability.
  
  -IP Validation – Only valid IPs are processed to prevent errors.
  
  -Multiple Scan Techniques – Supports SYN, TCP Connect, UDP, and Ping scans.
  
  -Port & Service Identification – Detects open ports and running services.
  
  -CVE-Based Risk Assessment – Highlights known vulnerabilities for detected services.
  
  -Interactive CLI – User-friendly command-line interface for efficient auditing.

## Installation

   1) Clone the repository:
    
            git clone https://github.com/arnavraha04/NetAudit.git
            cd NetAudit
    
    
2) Install required dependencies:
    
        pip install -r requirements.txt
   Make sure you have Python 3.x installed.

## Usage
    
   1)Run the main script:
    
        python netaudit.py
    
   2)Follow the interactive prompts to scan a network or perform risk analysis.

## Technologies Used

-Python 3.x

-Socket programming

-Network protocols (TCP/UDP)

-Libraries: scapy, python-nmap

## Future Improvements

  -NetAudit will continue to enhance automation and functionality. Planned improvements include automated vulnerability detection for newly discovered CVEs, the bility to schedule scans and maintain detailed logs, and optional email notifications for critical network events. Exportable reports in HTML format will also be added to make sharing and reviewing scan results easier.

## Contributing

  Contributions are welcome! Please fork the repository and create a pull request with your improvements.

## License

 This project is open-source and available under the MIT License.

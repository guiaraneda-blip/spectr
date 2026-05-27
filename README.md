# SPECTR
### Scan Parser & Exploit Recon Tool

SPECTR is a CLI cybersecurity tool that parses Nmap and Masscan output files and automatically searches for CVEs and public exploits for each discovered service, providing guided next steps for penetration testing.

---

## Features

- Parses Nmap and Masscan output files
- Searches CVEs via NVD API (NIST) with retry logic
- Searches public exploits via Exploit-DB (searchsploit)
- Detects available Metasploit modules
- Maps nmap service names for better CVE/exploit results
- Suggests post-exploitation next steps per service
- Bilingual interface: Spanish / English
- Saves reports to .txt with --report flag

---

## Compatibility

| Component        | Requirement                        |
|------------------|------------------------------------|
| OS               | Kali Linux / Debian-based distro   |
| Python           | 3.11+                              |
| searchsploit     | sudo apt install exploitdb         |
| masscan          | sudo apt install masscan           |
| Internet         | Required for NVD API               |

---

## Installation

    git clone https://github.com/guiaraneda-blip/spectr.git
    cd spectr
    python3 -m venv venv
    source venv/bin/activate
    pip install -r requirements.txt

---

## Usage

    # Basic scan (nmap)
    python spectr.py scan.txt

    # Parse masscan output
    python spectr.py scan.txt --masscan

    # Spanish interface (default)
    python spectr.py scan.txt --lang es

    # English interface
    python spectr.py scan.txt --lang en

    # Save report
    python spectr.py scan.txt --report

    # Custom filename
    python spectr.py scan.txt --report --output my_report.txt

---

## Workflow (Nmap)

    nmap -sV <target> -oN scan.txt
    python spectr.py scan.txt --lang en --report

## Workflow (Masscan)

    masscan <target> -p1-65535 --rate=1000 > scan.txt
    python spectr.py scan.txt --masscan --lang en --report

---

## Disclaimer

SPECTR is intended for educational purposes and authorized penetration testing only. Never use this tool against systems you do not own or have explicit permission to test. The author is not responsible for any misuse.

---

## Author

Ignacio Araneda — Cybersecurity student @ Duoc UC, Chile

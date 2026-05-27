from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich import box
from datetime import datetime

console = Console()

SEVERITY_COLOR = {
    "CRITICAL": "bold red",
    "HIGH":     "bold orange_red1",
    "MEDIUM":   "bold yellow",
    "LOW":      "bold green",
    "NONE":     "white",
}

def print_banner(lang):
    banner = Text()
    banner.append("  SPECTR\n", style="bold cyan")
    banner.append("  " + lang["app_name"] + "\n", style="dim cyan")
    banner.append("  " + lang["author"] + "  |  " + lang["version"] + "\n", style="dim white")
    banner.append("  " + lang["language"] + "\n", style="dim white")
    console.print(Panel(banner, border_style="cyan", padding=(0, 2)))

def print_host(host, lang):
    console.print("\n[bold cyan]► " + lang["target"] + ":[/bold cyan] " + host["target"])
    console.print("  [bold cyan]" + lang["ip"] + ":[/bold cyan] " + host["ip"])
    table = Table(box=box.SIMPLE_HEAD, border_style="cyan", header_style="bold cyan", show_lines=False)
    table.add_column(lang["port"],    style="bold white", width=8)
    table.add_column(lang["service"], style="cyan",       width=12)
    table.add_column(lang["version"], style="dim white",  width=35)
    table.add_column(lang["state"],   style="green",      width=10)
    for port in host["ports"]:
        table.add_row(
            port["port"] + "/" + port["protocol"],
            port["service"],
            port["version"] or "-",
            port["state"],
        )
    console.print(table)

def print_vulns(port, cves, lang):
    if not cves:
        console.print("  [dim]" + lang["no_vulns"] + "[/dim]")
        return
    console.print("\n  [bold red]>> " + lang["vuln_found"] + " -- " + port["port"] + "/" + port["service"] + "[/bold red]")
    for cve in cves:
        severity = cve.get("severity", "NONE")
        color = SEVERITY_COLOR.get(severity, "white")
        score = str(cve.get("score", 0.0))
        console.print("\n  [" + color + "]* " + cve["cve_id"] + "[/" + color + "]  [" + color + "]" + severity + " " + score + "[/" + color + "]  [dim]" + cve["published"] + "[/dim]")
        desc = cve.get("description_es") or cve.get("description", "")
        console.print("  [white]" + desc[:200] + "...[/white]")
        

def print_exploits(port, exploits, lang):
    if not exploits:
        console.print("  [dim]" + lang["no_exploits"] + "[/dim]")
        return
    console.print("\n  [bold magenta]>> " + lang["exploit_found"] + "[/bold magenta]")
    table = Table(box=box.SIMPLE_HEAD, border_style="magenta", header_style="bold magenta", show_lines=False)
    table.add_column(lang["exploit_id"],    style="magenta", width=8)
    table.add_column(lang["exploit_title"], style="white",   width=45)
    table.add_column(lang["exploit_type"],  style="dim",     width=12)
    table.add_column(lang["msf_module"],    style="cyan",    width=30)
    for exp in exploits[:5]:
        table.add_row(
            exp["edb_id"],
            exp["title"],
            exp["type"],
            exp["msf"] or "-",
        )
    console.print(table)

def print_next_steps(port, cves, lang):
    if not cves:
        return
    severities = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"]
    max_severity = "NONE"
    for sev in severities:
        if any(c["severity"] == sev for c in cves):
            max_severity = sev
            break
    steps = _get_steps(port["service"], max_severity, lang)
    console.print("\n  [bold yellow]>> " + lang["next_steps"] + "[/bold yellow]")
    for i, step in enumerate(steps, 1):
        console.print("  [yellow]" + str(i) + ".[/yellow] " + step)

def _get_steps(service, severity, lang):
    service = service.lower()
    BASE_STEPS = {
        "ftp": [
            "Check anonymous FTP login: ftp <target>",
            "Brute force: hydra -l admin -P wordlist.txt ftp://<target>",
            lang["post_exploit"] + ": buscar archivos sensibles en directorios FTP",
            lang["escalation"] + ": revisar permisos de archivos descargados",
            lang["cleanup"] + ": /var/log/vsftpd.log",
        ],
        "ssh": [
            "Enumerar version exacta para CVEs especificos",
            "Brute force: hydra -l root -P wordlist.txt ssh://<target>",
            lang["post_exploit"] + ": backdoor en ~/.ssh/authorized_keys",
            lang["escalation"] + ": sudo -l, SUID binaries, crontabs",
            lang["cleanup"] + ": /var/log/auth.log",
        ],
        "http": [
            "Directory enumeration: gobuster dir -u http://<target> -w /usr/share/wordlists/dirb/common.txt",
            "Buscar paneles admin: /admin, /wp-admin, /phpmyadmin",
            "Nikto scan: nikto -h <target>",
            lang["post_exploit"] + ": webshell upload si hay file upload vulnerable",
            lang["cleanup"] + ": /var/log/apache2/access.log",
        ],
        "smb": [
            "Enumerar shares: smbclient -L //<target>",
            "Check EternalBlue: nmap --script smb-vuln-ms17-010 <target>",
            "Metasploit: use exploit/windows/smb/ms17_010_eternalblue",
            lang["post_exploit"] + ": hashdump, mimikatz",
            lang["cleanup"] + ": Windows Event Logs",
        ],
        "https": [
            "SSL scan: sslscan <target>",
            "Check Heartbleed: nmap --script ssl-heartbleed <target>",
            "Directory enumeration: gobuster dir -u https://<target> -k -w wordlist.txt",
            lang["post_exploit"] + ": extraer certificados y credenciales",
            lang["cleanup"] + ": /var/log/nginx/access.log",
        ],
    }
    for key in BASE_STEPS:
        if key in service:
            return BASE_STEPS[key]
    return [
        "Investigar CVEs encontrados en " + service,
        "Buscar exploits: searchsploit " + service,
        lang["post_exploit"] + ": enumerar sistema, usuarios, archivos sensibles",
        lang["escalation"] + ": linpeas.sh / winpeas.exe",
        lang["lateral"] + ": escanear red interna desde este host",
    ]

def print_report_hint(lang):
    console.print("\n[dim cyan]" + lang["report_flag"] + "[/dim cyan]\n")

def save_report(hosts_data, lang, filename=None):
    if not filename:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = "spectr_report_" + timestamp + ".txt"
    with open(filename, "w") as f:
        f.write("=" * 60 + "\n")
        f.write("  " + lang["app_name"] + "\n")
        f.write("  " + lang["author"] + "  |  " + lang["version"] + "\n")
        f.write("  Generated: " + datetime.now().strftime("%Y-%m-%d %H:%M:%S") + "\n")
        f.write("=" * 60 + "\n\n")
        for entry in hosts_data:
            host = entry["host"]
            f.write(lang["target"] + ": " + host["target"] + "\n")
            f.write(lang["ip"] + ": " + host["ip"] + "\n\n")
            for port_data in entry["ports"]:
                port = port_data["port"]
                f.write("  Port: " + port["port"] + "/" + port["protocol"] + " -- " + port["service"] + " " + port["version"] + "\n")
                for cve in port_data.get("cves", []):
                    f.write("    [" + cve["severity"] + "] " + cve["cve_id"] + " (Score: " + str(cve["score"]) + ")\n")
                    desc = cve.get("description_es") or cve.get("description", "")
                    f.write("    " + desc[:150] + "...\n")
                    
                for exp in port_data.get("exploits", []):
                    f.write("    EDB-" + exp["edb_id"] + ": " + exp["title"] + "\n")
                    if exp["msf"]:
                        f.write("    MSF: " + exp["msf"] + "\n")
                f.write("\n")
    console.print("\n[bold green]>> " + lang["report_saved"] + ": " + filename + "[/bold green]")
    return filename


def print_default_creds(port, default_creds, lang):
    """Muestra credenciales por defecto conocidas para el servicio."""
    if not default_creds:
        return
    console.print(f"  [bold yellow]⚠ Default Credentials ({port['service']}):[/bold yellow]")
    for user, passwd in default_creds:
        passwd_display = passwd if passwd else "(empty)"
        console.print(f"    [yellow]→ {user} / {passwd_display}[/yellow]")

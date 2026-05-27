import argparse
import sys
from parser.nmap_parser import NmapParser
from parser.masscan_parser import MasscanParser
from recon.nvd import search_cves
from recon.service_mapper import map_service
from recon.default_creds import get_default_creds
from recon.exploitdb import search_exploits
from output.reporter import (
    console,
    print_banner,
    print_host,
    print_vulns,
    print_exploits,
    print_next_steps,
    print_default_creds,
    print_report_hint,
    save_report,
)

def load_lang(lang_code: str) -> dict:
    if lang_code == "es":
        from lang.es import STRINGS
    elif lang_code == "en":
        from lang.en import STRINGS
    else:
        print(f"[ERROR] Unsupported language: {lang_code}. Use --lang es | --lang en")
        sys.exit(1)
    return STRINGS


def main():
    parser = argparse.ArgumentParser(
        prog="spectr",
        description="SPECTR — Scan Parser & Exploit Recon Tool",
        epilog="Example: python spectr.py scan.txt --lang es --report"
    )
    parser.add_argument(
        "file",
        help="Nmap output file (.txt)"
    )
    parser.add_argument(
        "--lang",
        default="es",
        choices=["es", "en"],
        help="Interface language (default: es)"
    )
    parser.add_argument(
        "--report",
        action="store_true",
        help="Save report to .txt file"
    )
    parser.add_argument(
        "--output",
        default=None,
        help="Custom report filename (default: spectr_report_<timestamp>.txt)"
    )

    parser.add_argument(
        "--masscan",
        action="store_true",
        help="Parse masscan output instead of nmap"
    )
    args = parser.parse_args()
    lang = load_lang(args.lang)

    # Banner
    print_banner(lang)

    # Parsear nmap output
    console.print(f"\n[dim]{lang['loading']}[/dim]")
    if args.masscan:
        parser_tool = MasscanParser(args.file)
    else:
        parser_tool = NmapParser(args.file)
    hosts = parser_tool.parse()

    if not hosts:
        console.print(f"[bold red]{lang['no_hosts']}[/bold red]")
        sys.exit(0)

    # Estructura para reporte
    report_data = []

    for host in hosts:
        print_host(host, lang)

        host_entry = {"host": host, "ports": []}

        for port in host["ports"]:
            service = port["service"]
            service = map_service(service)
            version = port["version"]

            console.print(
                f"\n[bold cyan]┌─ Port {port['port']}/{port['protocol']} "
                f"— {service} {version}[/bold cyan]"
            )

            # Buscar CVEs
            console.print(f"[dim]  Searching CVEs for {service} {version}...[/dim]")
            cves = search_cves(service, version)

            # Buscar exploits
            console.print(f"[dim]  Searching exploits for {service} {version}...[/dim]")
            exploits = search_exploits(service, version)
            default_creds = get_default_creds(service)

            # Mostrar resultados
            print_vulns(port, cves, lang)
            print_exploits(port, exploits, lang)
            print_next_steps(port, cves, lang)
            print_default_creds(port, default_creds, lang)

            host_entry["ports"].append({
                "port":          port,
                "cves":          cves,
                "exploits":      exploits,
                "default_creds": default_creds,
            })

            console.print(f"[bold cyan]└{'─'*55}[/bold cyan]")

        report_data.append(host_entry)

    # Done
    console.print(f"\n[bold green]✓ {lang['done']}[/bold green]")

    # Reporte
    if args.report:
        save_report(report_data, lang, args.output)
    else:
        print_report_hint(lang)


if __name__ == "__main__":
    main()

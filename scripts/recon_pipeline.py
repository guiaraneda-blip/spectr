#!/usr/bin/env python3
"""
SPECTR v1.2 — Automated Recon Pipeline
Encadena: masscan → nmap → SPECTR
Uso: python scripts/recon_pipeline.py --target <IP/CIDR> [--lang es|en] [--report]
"""

import argparse
import subprocess
import sys
import os
import tempfile
import re
from datetime import datetime

# ── Colores ANSI simples para no depender de rich antes de importar SPECTR ──
CYAN  = "\033[96m"
GREEN = "\033[92m"
RED   = "\033[91m"
DIM   = "\033[2m"
RESET = "\033[0m"
BOLD  = "\033[1m"

def log(msg, color=CYAN):
    ts = datetime.now().strftime("%H:%M:%S")
    print(f"{DIM}[{ts}]{RESET} {color}{msg}{RESET}")

def error(msg):
    print(f"{RED}[ERROR] {msg}{RESET}")
    sys.exit(1)

def run_masscan(target: str, rate: int, output_file: str):
    log(f"[1/3] Lanzando masscan contra {target} (rate={rate})...")
    cmd = [
        "masscan", target,
        "-p", "1-65535",
        "--rate", str(rate),
        "-oG", output_file
    ]
    log(f"CMD: {' '.join(cmd)}", DIM)
    try:
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            error(f"masscan falló:\n{result.stderr}")
    except FileNotFoundError:
        error("masscan no encontrado. Instala con: sudo apt install masscan")

def parse_masscan_ports(output_file: str) -> dict:
    """Retorna {ip: [puerto, ...]} desde output masscan grepable."""
    hosts = {}
    try:
        with open(output_file, "r") as f:
            for line in f:
                match = re.match(
                    r"Discovered open port (\d+)/(tcp|udp) on (\d+\.\d+\.\d+\.\d+)",
                    line.strip()
                )
                if match:
                    port, _, ip = match.group(1), match.group(2), match.group(3)
                    hosts.setdefault(ip, []).append(port)
    except FileNotFoundError:
        error(f"No se encontró output de masscan: {output_file}")
    return hosts

def run_nmap(hosts: dict, output_file: str):
    log(f"[2/3] Lanzando nmap con service detection...")
    if not hosts:
        error("masscan no encontró puertos abiertos. Verifica el target.")

    # Construir targets y puertos para nmap
    targets = list(hosts.keys())
    all_ports = set()
    for ports in hosts.values():
        all_ports.update(ports)

    ports_arg = ",".join(sorted(all_ports, key=int))
    log(f"Hosts: {', '.join(targets)}", DIM)
    log(f"Puertos: {ports_arg}", DIM)

    cmd = [
        "nmap",
        "-sV",          # service version detection
        "-sC",          # default scripts
        "-p", ports_arg,
        "-oN", output_file,
    ] + targets

    log(f"CMD: {' '.join(cmd)}", DIM)
    try:
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            error(f"nmap falló:\n{result.stderr}")
    except FileNotFoundError:
        error("nmap no encontrado. Instala con: sudo apt install nmap")

def run_spectr(nmap_file: str, lang: str, report: bool, output: str):
    log(f"[3/3] Lanzando SPECTR sobre output de nmap...")
    # Construir comando SPECTR
    spectr_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    spectr_py   = os.path.join(spectr_root, "spectr.py")

    cmd = [sys.executable, spectr_py, nmap_file, "--lang", lang]
    if report:
        cmd.append("--report")
    if output:
        cmd += ["--output", output]

    log(f"CMD: {' '.join(cmd)}", DIM)
    result = subprocess.run(cmd)
    sys.exit(result.returncode)

def main():
    parser = argparse.ArgumentParser(
        prog="recon_pipeline",
        description="SPECTR Recon Pipeline — masscan → nmap → SPECTR",
        epilog="Ejemplo: python scripts/recon_pipeline.py --target 192.168.1.0/24 --lang es --report"
    )
    parser.add_argument("--target",  required=True, help="IP o CIDR a escanear")
    parser.add_argument("--lang",    default="es", choices=["es", "en"])
    parser.add_argument("--report",  action="store_true", help="Guardar reporte")
    parser.add_argument("--output",  default=None, help="Nombre custom del reporte")
    parser.add_argument("--rate",    default=1000, type=int, help="Rate masscan (default: 1000)")
    parser.add_argument("--keep",    action="store_true", help="Conservar archivos temporales")
    args = parser.parse_args()

    print(f"\n{BOLD}{CYAN}▓▒░ SPECTR RECON PIPELINE v1.2 ░▒▓{RESET}")
    print(f"{DIM}Target: {args.target} | Lang: {args.lang} | Rate: {args.rate}{RESET}\n")

    # Archivos temporales
    tmp_dir      = tempfile.mkdtemp(prefix="spectr_")
    masscan_out  = os.path.join(tmp_dir, "masscan.txt")
    nmap_out     = os.path.join(tmp_dir, "nmap.txt")

    log(f"Directorio temporal: {tmp_dir}", DIM)

    try:
        run_masscan(args.target, args.rate, masscan_out)
        hosts = parse_masscan_ports(masscan_out)
        log(f"Hosts con puertos abiertos: {len(hosts)}", GREEN)
        run_nmap(hosts, nmap_out)
        run_spectr(nmap_out, args.lang, args.report, args.output)
    finally:
        if not args.keep:
            import shutil
            shutil.rmtree(tmp_dir, ignore_errors=True)
            log("Archivos temporales eliminados.", DIM)
        else:
            log(f"Archivos conservados en: {tmp_dir}", DIM)

if __name__ == "__main__":
    main()

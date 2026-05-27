import re

class MasscanParser:
    def __init__(self, filepath: str):
        self.filepath = filepath

    def parse(self) -> list:
        try:
            with open(self.filepath, "r") as f:
                lines = f.readlines()
        except FileNotFoundError:
            print(f"[ERROR] File not found: {self.filepath}")
            return []

        hosts = {}

        for line in lines:
            # Formato: Discovered open port 22/tcp on 10.28.101.84
            match = re.match(
                r"Discovered open port (\d+)/(tcp|udp) on (\d+\.\d+\.\d+\.\d+)",
                line.strip()
            )
            if not match:
                continue

            port, protocol, ip = match.group(1), match.group(2), match.group(3)

            if ip not in hosts:
                hosts[ip] = {"target": ip, "ip": ip, "ports": []}

            hosts[ip]["ports"].append({
                "port":     port,
                "protocol": protocol,
                "state":    "open",
                "service":  "unknown",
                "version":  ""
            })

        return list(hosts.values())

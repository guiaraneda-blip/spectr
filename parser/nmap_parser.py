import re

class NmapParser:
    def __init__(self, filepath: str):
        self.filepath = filepath
        self.hosts = []

    def parse(self) -> list:
        try:
            with open(self.filepath, "r") as f:
                content = f.read()
        except FileNotFoundError:
            print(f"[ERROR] File not found: {self.filepath}")
            return []

        # Extraer bloques por host
        host_blocks = re.split(r"Nmap scan report for", content)

        for block in host_blocks[1:]:
            host_data = self._parse_host(block)
            if host_data:
                self.hosts.append(host_data)

        return self.hosts

    def _parse_host(self, block: str) -> dict:
        lines = block.strip().split("\n")

        # Extraer IP o hostname
        target = lines[0].strip()
        ip_match = re.search(r"\((\d+\.\d+\.\d+\.\d+)\)", target)
        ip = ip_match.group(1) if ip_match else target

        ports = []

        for line in lines:
            # Buscar líneas de puertos abiertos
            # Formato nmap: 22/tcp   open  ssh     OpenSSH 8.9p1
            port_match = re.match(
                r"(\d+)/(tcp|udp)\s+(open|filtered)\s+(\S+)\s*(.*)",
                line.strip()
            )
            if port_match:
                ports.append({
                    "port":     port_match.group(1),
                    "protocol": port_match.group(2),
                    "state":    port_match.group(3),
                    "service":  port_match.group(4),
                    "version":  port_match.group(5).strip()
                })

        if not ports:
            return None

        return {
            "target": target.strip(),
            "ip":     ip,
            "ports":  ports
        }

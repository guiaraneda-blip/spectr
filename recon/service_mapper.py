SERVICE_MAP = {
    "domain":           "dns",
    "ms-wbt-server":    "rdp",
    "http-alt":         "http",
    "netbios-ssn":      "smb",
    "microsoft-ds":     "smb",
    "msrpc":            "rpc",
    "epmap":            "rpc",
    "tcpwrapped":       "",
    "unknown":          "",
    "ssl/http":         "https",
    "ssl/https":        "https",
    "ftp-data":         "ftp",
}

def map_service(service: str) -> str:
    """
    Traduce nombres de servicio de nmap a nombres
    reconocibles por NVD y searchsploit.
    """
    normalized = service.lower().strip()
    return SERVICE_MAP.get(normalized, normalized)

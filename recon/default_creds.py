"""
SPECTR v1.2 — Default Credentials Database
Consulta credenciales por defecto conocidas por servicio.
"""

DEFAULT_CREDS = {
    "ftp": [
        ("anonymous", "anonymous"),
        ("admin",     "admin"),
        ("admin",     ""),
        ("root",      "root"),
        ("ftp",       "ftp"),
    ],
    "ssh": [
        ("root",  "root"),
        ("root",  "toor"),
        ("admin", "admin"),
        ("admin", "password"),
        ("pi",    "raspberry"),
        ("ubuntu","ubuntu"),
    ],
    "telnet": [
        ("admin", "admin"),
        ("admin", ""),
        ("root",  "root"),
        ("root",  ""),
        ("user",  "user"),
    ],
    "http": [
        ("admin", "admin"),
        ("admin", "password"),
        ("admin", "1234"),
        ("admin", ""),
        ("root",  "root"),
        ("user",  "user"),
    ],
    "https": [
        ("admin", "admin"),
        ("admin", "password"),
        ("admin", "1234"),
        ("root",  "root"),
    ],
    "smb": [
        ("administrator", ""),
        ("administrator", "password"),
        ("guest",         ""),
        ("admin",         "admin"),
    ],
    "mysql": [
        ("root",  ""),
        ("root",  "root"),
        ("root",  "mysql"),
        ("admin", "admin"),
    ],
    "rdp": [
        ("administrator", ""),
        ("administrator", "password"),
        ("admin",         "admin"),
    ],
    "snmp": [
        ("public",  ""),
        ("private", ""),
        ("admin",   ""),
    ],
    "dns": [
        ("admin", "admin"),
    ],
}

def get_default_creds(service: str) -> list:
    """
    Retorna lista de (usuario, password) conocidas para el servicio.
    Retorna lista vacía si el servicio no tiene creds registradas.
    """
    return DEFAULT_CREDS.get(service.lower().strip(), [])

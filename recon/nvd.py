import requests
import time
from deep_translator import GoogleTranslator

def translate(text: str, lang: str) -> str:
	if lang == "en":
	   return text
	try:
	    return GoogleTranslator(source="en", target="es").translate(text[:500])
	except Exception:
	    return text	

NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

SEVERITY_COLOR = {
    "CRITICAL": "red",
    "HIGH":     "orange_red1",
    "MEDIUM":   "yellow",
    "LOW":      "green",
    "NONE":     "white",
}

MAX_RETRIES = 3
RETRY_DELAY = 2  # segundos base, se duplica cada intento

def search_cves(service: str, version: str = "") -> list:
    """
    Busca CVEs en NVD por servicio y versión.
    Retorna lista de CVEs relevantes.
    Incluye retry logic con backoff exponencial.
    """
    SKIP_SERVICES = {"tcpwrapped", "unknown", "filtered", "closed", ""}
    if not service or service.lower() in SKIP_SERVICES:
        return []

    query = f"{service} {version}".strip()

    params = {
        "keywordSearch":  query,
        "resultsPerPage": 10,
    }

    response = None
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            response = requests.get(
                NVD_BASE_URL,
                params=params,
                timeout=10,
                headers={"User-Agent": "SPECTR/1.0"}
            )
            response.raise_for_status()
            break  # éxito, salimos del loop

        except requests.exceptions.Timeout:
            print(f"[ERROR] NVD timeout (intento {attempt}/{MAX_RETRIES})")
        except requests.exceptions.RequestException as e:
            print(f"[ERROR] NVD request failed (intento {attempt}/{MAX_RETRIES}): {e}")

        if attempt < MAX_RETRIES:
            wait = RETRY_DELAY * (2 ** (attempt - 1))  # 2s, 4s, 8s
            print(f"[INFO] Reintentando en {wait}s...")
            time.sleep(wait)
        else:
            print("[ERROR] NVD no disponible tras varios intentos.")
            return []

    data = response.json()
    
   
    vulnerabilities = data.get("vulnerabilities", [])

    results = []
    for item in vulnerabilities:
        cve = item.get("cve", {})
        cve_id = cve.get("id", "N/A")

        # Descripción en inglés
        descriptions = cve.get("descriptions", [])
        description = next(
            (d["value"] for d in descriptions if d["lang"] == "en"),
            "No description available."
        )

        # Severidad
        severity, score = _extract_severity(cve)

        # Fecha de publicación
        published = cve.get("published", "N/A")[:10]

        results.append({
            "cve_id":      cve_id,
            "description": description,
	    "description_es": translate(description, "es"),	
            "severity":    severity,
            "score":       score,
            "published":   published,
            "color":       SEVERITY_COLOR.get(severity, "white"),
        })

        # Respetar rate limit de NVD — max 5 requests por 30s sin API key
        time.sleep(0.6)

    return results


def _extract_severity(cve: dict) -> tuple:
    """
    Extrae severidad y score CVSS del CVE.
    Prioriza CVSSv3, fallback a CVSSv2.
    """
    metrics = cve.get("metrics", {})

    # CVSSv3
    cvss_v3 = metrics.get("cvssMetricV31", []) or metrics.get("cvssMetricV30", [])
    if cvss_v3:
        data = cvss_v3[0].get("cvssData", {})
        return data.get("baseSeverity", "NONE"), data.get("baseScore", 0.0)

    # Fallback CVSSv2
    cvss_v2 = metrics.get("cvssMetricV2", [])
    if cvss_v2:
        data = cvss_v2[0].get("cvssData", {})
        score = data.get("baseScore", 0.0)
        # CVSSv2 no tiene severity label, lo calculamos
        if score >= 7.0:
            severity = "HIGH"
        elif score >= 4.0:
            severity = "MEDIUM"
        else:
            severity = "LOW"
        return severity, score

    return "NONE", 0.0

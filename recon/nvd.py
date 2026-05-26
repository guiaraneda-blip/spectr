import requests
import time

NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

SEVERITY_COLOR = {
    "CRITICAL": "red",
    "HIGH":     "orange_red1",
    "MEDIUM":   "yellow",
    "LOW":      "green",
    "NONE":     "white",
}

def search_cves(service: str, version: str = "") -> list:
    """
    Busca CVEs en NVD por servicio y versión.
    Retorna lista de CVEs relevantes.
    """
    query = service
    if version:
        query = f"{service} {version}"

    params = {
        "keywordSearch":  query,
        "resultsPerPage": 10,
    }

    try:
        response = requests.get(
            NVD_BASE_URL,
            params=params,
            timeout=10,
            headers={"User-Agent": "SPECTR/1.0"}
        )
        response.raise_for_status()

    except requests.exceptions.Timeout:
        print("[ERROR] NVD API timeout.")
        return []
    except requests.exceptions.RequestException as e:
        print(f"[ERROR] NVD API request failed: {e}")
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

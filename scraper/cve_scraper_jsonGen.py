import requests
import json
from datetime import datetime
from cve_scraper import fetch_cve_details as fcd

def fetch_cve_details(cve_id):
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
    response = requests.get(url)
    if response.status_code == 200:
        return response.json()
    else:
        raise Exception(f"Error fetching data for {cve_id}: {response.status_code}")

def normalize_cve_data(raw_data):
    try:
        cve = raw_data["vulnerabilities"][0]["cve"]
        metrics = cve.get("metrics", {}).get("cvssMetricV31", [{}])[0].get("cvssData", {})
        weaknesses = cve.get("weaknesses", [{}])[0].get("description", [{}])[0].get("value", "")
        references = [ref["url"] for ref in cve.get("references", [])]
        tags = [tag for ref in cve.get("references", []) for tag in ref.get("tags", [])]
        products = []

        for node in cve.get("configurations", [{}])[0].get("nodes", []):
            for match in node.get("cpeMatch", []):
                cpe = match.get("criteria", "")
                if "sharepoint_server" in cpe:
                    parts = cpe.split(":")
                    products.append(f"{parts[4].capitalize()} {parts[5] if parts[5] != '*' else ''}".strip())

        return {
            "cve_id": cve["id"],
            "title": cve.get("cisaVulnerabilityName", ""),
            "description": cve["descriptions"][0]["value"],
            "published_date": cve.get("published", ""),
            "last_modified": cve.get("lastModified", ""),
            "severity": cve.get("metrics", {}).get("cvssMetricV31", [{}])[0].get("cvssData", {}).get("baseSeverity", ""),
            "cvss_score": metrics.get("baseScore", ""),
            "vector": metrics.get("vectorString", ""),
            "weakness": weaknesses,
            "affected_products": list(set(products)),
            "references": references,
            "exploited": "Exploit" in tags,
            "exploit_sources": list(set(tags)),
        }

    except Exception as e:
        print(f"Error parsing data: {e}")
        return {}

def save_to_json(data, filename):
    with open(filename, 'w') as f:
        json.dump(data, f, indent=2)

# Run example
if __name__ == "__main__":
    cve_id = "CVE-2025-53770"
    raw_data = fetch_cve_details(cve_id)
    normalized_data = normalize_cve_data(raw_data)
    print(fcd(cve_id))
    save_to_json(normalized_data, f"{cve_id}_normalized.json")
    print(f"✅ Normalized data saved to {cve_id}_normalized.json")

import requests
import sys

def fetch_cve_details(cve_id):
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
    headers = {"User-Agent": "CVEye-Security-Intel-Scanner"}
    
    response = requests.get(url, headers=headers)
    
    if response.status_code != 200:
        print(f"[!] Failed to fetch data for {cve_id}. Status code: {response.status_code}")
        return
    
    data = response.json()
    if not data.get("vulnerabilities"):
        print(f"[!] No data found for {cve_id}")
        return

    cve_data = data["vulnerabilities"][0]["cve"]
    
    print("=" * 80)
    print(f"🔎 CVE ID: {cve_data.get('id')}")
    print(f"📅 Published: {cve_data.get('published')}")
    print(f"🛠️  Last Modified: {cve_data.get('lastModified')}")
    print("=" * 80)
    
    # Descriptions
    print("\n📄 Description:")
    for desc in cve_data.get("descriptions", []):
        if desc["lang"] == "en":
            print(f" - {desc['value']}")
    
    # CVSS Score
    print("\n🎯 CVSS v3.1 Metrics:")
    metrics = cve_data.get("metrics", {}).get("cvssMetricV31", [])
    for m in metrics:
        cvss = m.get("cvssData", {})
        print(f" - Base Score: {cvss.get('baseScore')} ({cvss.get('baseSeverity')})")
        print(f" - Vector: {cvss.get('vectorString')}")
    
    # CWE
    print("\n🧱 Weaknesses (CWE):")
    weaknesses = cve_data.get("weaknesses", [])
    for w in weaknesses:
        for desc in w.get("description", []):
            print(f" - {desc['value']}")
    
    # Affected Configurations
    print("\n📦 Affected Products:")
    configurations = cve_data.get("configurations", [])
    for config in configurations:
        for node in config.get("nodes", []):
            for match in node.get("cpeMatch", []):
                print(f" - {match.get('criteria')}")

    # References
    print("\n🔗 References:")
    for ref in cve_data.get("references", []):
        print(f" - {ref['url']}")

    print("\n✅ Done.")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python cve_scraper.py <CVE-ID>")
    else:
        fetch_cve_details(sys.argv[1])

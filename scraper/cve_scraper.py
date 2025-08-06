import requests
import sys

def get_cve_metadata(cve_id):
    url = f"https://services.nvd.nist.gov/rest/json/cve/1.0/{cve_id}"
    resp = requests.get(url)
    if resp.status_code == 200:
        data = resp.json()
        print(f"✅ CVE Data for {cve_id}:
")
        print(data.get("result", {}).get("CVE_Items", [{}])[0].get("cve", {}).get("description", {}).get("description_data", [{}])[0].get("value"))
    else:
        print(f"❌ Failed to fetch CVE data. Status Code: {resp.status_code}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python cve_scraper.py <CVE-ID>")
    else:
        get_cve_metadata(sys.argv[1])

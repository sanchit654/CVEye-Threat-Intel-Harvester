import os
import time
import requests
from cve_scraper_jsonGen import fetch_cve_details, normalize_cve_data, save_to_json
from cve_scraper import fetch_cve_details as fcd

NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"

def get_user_mode():
    print("Choose input mode:")
    print("1. Manual CVE ID list")
    print("2. Fetch by published date range")
    return input("Enter 1 or 2: ").strip()

def get_manual_ids():
    raw = input("Enter CVE IDs separated by commas (e.g., CVE-2025-53770,CVE-2025-54321): ")
    return [cve.strip().upper() for cve in raw.split(",") if cve.strip()]

def get_cves_by_date_range():
    from_date = input("Enter start date (YYYY-MM-DD): ").strip()
    to_date = input("Enter end date (YYYY-MM-DD): ").strip()

    params = {
        "pubStartDate": f"{from_date}T00:00:00.000Z",
        "pubEndDate": f"{to_date}T23:59:59.999Z"
    }

    print(f"\n🔎 Querying CVEs from {from_date} to {to_date}...\n")
    response = requests.get(NVD_API_BASE, params=params)
    response.raise_for_status()

    results = response.json().get("vulnerabilities", [])
    return [entry["cve"]["id"] for entry in results]

def batch_process(cve_ids, output_dir="output"):
    os.makedirs(output_dir, exist_ok=True)

    for cve_id in cve_ids:
        print(f"📥 Fetching {cve_id}...")
        try:
            raw = fetch_cve_details(cve_id)
            data = normalize_cve_data(raw)
            print(fcd(cve_id))
            output_file = os.path.join(output_dir, f"{cve_id}_normalized.json")
            save_to_json(data, output_file)
            print(f"✅ Saved to {output_file}\n")
            time.sleep(1.2)
        except Exception as e:
            print(f"❌ Failed to process {cve_id}: {e}\n")

def main():
    mode = get_user_mode()

    if mode == "1":
        cve_ids = get_manual_ids()
    elif mode == "2":
        cve_ids = get_cves_by_date_range()
    else:
        print("Invalid option. Exiting.")
        return

    if not cve_ids:
        print("⚠️ No CVE IDs found.")
        return

    print(f"\n🚀 Processing {len(cve_ids)} CVE(s)...\n")
    batch_process(cve_ids)

if __name__ == "__main__":
    main()

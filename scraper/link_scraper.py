import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse
import re
import time

from aggregator_module import aggregate_cve_data
from cve_scraper_jsonGen import fetch_cve_details
from cve_scraper_jsonGen import normalize_cve_data
from github_poc_scraper import search_github_for_cve
from news_scraper import search_cve_news


def clean_text(text):
    # Basic cleaning: remove multiple spaces, newlines, tabs, etc.
    text = re.sub(r'\s+', ' ', text)
    return text.strip()


def fetch_text_from_url(url, timeout=10):
    try:
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        }
        response = requests.get(url, headers=headers, timeout=timeout)
        if response.status_code != 200:
            print(f"[!] Failed to fetch {url} - Status code: {response.status_code}")
            return ""

        soup = BeautifulSoup(response.content, "html.parser")

        # Remove script, style, and irrelevant tags
        for tag in soup(["script", "style", "noscript", "footer", "header", "form"]):
            tag.decompose()

        visible_text = soup.get_text(separator=' ')
        return clean_text(visible_text)

    except Exception as e:
        print(f"[!] Error fetching {url}: {e}")
        return ""


def scrape_all_links(cve_id, urls, delay=1):
    scraped_data = {}
    for url in urls:
        print(f"[*] Scraping: {url}")
        text = fetch_text_from_url(url)
        if text:
            scraped_data[url] = text
        time.sleep(delay)  # to avoid rate-limiting

    return scraped_data


# Example usage:
if __name__ == "__main__":
    print("🔍 CVEye: Link Scraper")
    cve_id = input("Enter CVE ID (e.g. CVE-2025-53770): ").strip()
    github_token = input("Enter your github token: ").strip()
    serpapi_key = input("Enter your SerpAPI Key: ").strip()

    cve_data = aggregate_cve_data(cve_id, github_token, serpapi_key)
    all_links = cve_data["github_pocs"] + cve_data["combined_links"]
    unique_links = list(set(all_links))

    output = scrape_all_links(cve_id, unique_links)
    for link, content in output.items():
        print(f"\n=== {link} ===\n{content[:1000]}\n...")

# aggregator.py

import json
import sys
from cve_scraper_jsonGen import fetch_cve_details
from cve_scraper_jsonGen import normalize_cve_data
from github_poc_scraper import search_github_for_cve
from news_scraper import search_cve_news


def aggregate_cve_data(cve_id, github_token, serpapi_key):
    print(f"\n🔎 Fetching data for {cve_id}...\n")

    raw_data = fetch_cve_details(cve_id)
    cve_data = normalize_cve_data(raw_data)
    github_data = search_github_for_cve(cve_id, github_token)
    news_data = search_cve_news(cve_id, serpapi_key)

    news_links = []
    for pointer in news_data:
        news_links.append(pointer["link"])

    github_links = []
    for pointer in github_data:
        github_links.append(pointer["url"])

    combined = cve_data["references"] + news_links
    unique_list = list(set(combined))

    # Aggregate all into one dictionary
    final_output = {
        "cve_data": cve_data,
        "github_pocs": github_links,
        "news_articles": news_links,
        "combined_links": unique_list
    }

    return final_output


if __name__ == "__main__":
    if len(sys.argv) < 4:
        print("Usage: python aggregator.py <CVE_ID> <GITHUB_TOKEN> <SERPAPI_KEY>")
        sys.exit(1)

    cve_id = sys.argv[1]
    github_token = sys.argv[2]
    serpapi_key = sys.argv[3]

    result = aggregate_cve_data(cve_id, github_token, serpapi_key)
    print(json.dumps(result, indent=4))

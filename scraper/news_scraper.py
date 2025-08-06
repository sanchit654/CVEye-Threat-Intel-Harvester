import requests
import json

def search_cve_news(cve_id, serpapi_key, num_results=30):
    url = "https://serpapi.com/search"
    params = {
        "q": cve_id,
        "tbm": "nws",  # News tab
        "api_key": serpapi_key,
        "num": num_results
    }

    response = requests.get(url, params=params)
    if response.status_code != 200:
        print(f"[!] Failed to fetch news for {cve_id}")
        print(response.text)
        return []

    data = response.json()
    news_results = data.get("news_results", [])
    parsed_results = []

    for article in news_results[:num_results]:
        parsed_results.append({
            "title": article.get("title"),
            "link": article.get("link"),
            "snippet": article.get("snippet"),
            "published": article.get("date")
        })

    return parsed_results

if __name__ == "__main__":
    print("🔍 CVEye: CVE News Aggregator")
    cve_id = input("Enter CVE ID (e.g. CVE-2025-53770): ").strip()
    serpapi_key = input("Enter your SerpAPI Key: ").strip()

    articles = search_cve_news(cve_id, serpapi_key)

    if articles:
        print(f"\n📰 Top {len(articles)} news articles for {cve_id}:\n")
        for idx, article in enumerate(articles, 1):
            print(f"{idx}. {article['title']}")
            print(f"   🕒 {article['published']}")
            print(f"   🔗 {article['link']}")
            print(f"   📄 {article['snippet']}\n")
    else:
        print(f"❌ No news found for {cve_id}")

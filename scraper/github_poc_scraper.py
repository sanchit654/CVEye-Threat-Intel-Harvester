import requests
import sys

def search_github_for_cve(cve_id, github_token, per_page=5):
    headers = {
        "Authorization": f"token {github_token}",
        "Accept": "application/vnd.github+json"
    }

    query = f"{cve_id} in:name,description,readme"
    url = f"https://api.github.com/search/repositories?q={query}&sort=stars&order=desc&per_page={per_page}"

    response = requests.get(url, headers=headers)
    if response.status_code != 200:
        print(f"GitHub API Error: {response.status_code}")
        print(response.text)
        return []

    data = response.json()
    results = []
    for item in data.get("items", []):
        repo_info = {
            "name": item["full_name"],
            "url": item["html_url"],
            "description": item["description"],
            "stars": item["stargazers_count"],
            "forks": item["forks_count"],
            "language": item["language"]
        }
        results.append(repo_info)

    print("\nThe total GitHub PoCs are: ", len(results))

    return results

def print_results(results, cve_id):
    if not results:
        print(f"No results found for {cve_id}")
        return

    print(f"\nGitHub PoCs for {cve_id}:\n")
    for repo in results:
        print(f"- 🔗 {repo['name']} - {repo['url']}")
        print(f"  🌟 Stars: {repo['stars']} | 🍴 Forks: {repo['forks']} | 📝 Language: {repo['language']}")
        print(f"  📄 {repo['description']}\n")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python github_poc_scraper.py CVE-XXXX-XXXX")
        sys.exit(1)

    cve_id = sys.argv[1].strip()
    github_token = input("🔐 Enter your GitHub Personal Access Token (PAT): ").strip()

    results = search_github_for_cve(cve_id, github_token)
    print_results(results, cve_id)

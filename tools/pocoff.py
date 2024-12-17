import os
import requests
import json
import argparse
from datetime import datetime

API_KEY = os.environ.get("GOOGLE_API_KEY")
CX = os.environ.get("SEARCH_ENGINE_ID")
DISCORD_WEBHOOK_URL = os.environ.get("DISCORD_WEBHOOK_URL")

def validate_env():
    if not API_KEY or not CX or not DISCORD_WEBHOOK_URL:
        raise ValueError("[ERROR] Missing required environment variables: GOOGLE_API_KEY, SEARCH_ENGINE_ID, or DISCORD_WEBHOOK_URL.")

def parse_arguments():
    parser = argparse.ArgumentParser(description="Seach Google Custom GitHub Search Engine for POCs")
    parser.add_argument("search_term", help="The search term (CVE)to look for.")
    parser.add_argument("--results", type=int, default=5, help="Number of results to fetch (default: 5).")
    return parser.parse_args()

def google_search(search_term, num_results=5):
    """Search Google Custom Search JSON API"""
    endpoint = "https://www.googleapis.com/customsearch/v1"
    results = []
    start_index = 1

    while len(results) < num_results:
        params = {
            "key": API_KEY,
            "cx": CX,
            "q": search_term,
            "num": min(10, num_results - len(results)),  # Fetch up to 10 at a time
            "start": start_index,
        }
        response = requests.get(endpoint, params=params)
        if response.status_code != 200:
            print(f"[ERROR] Google API Error: {response.json()}")
            break

        search_results = response.json()
        for item in search_results.get("items", []):
            results.append({
                "title": item.get("title"),
                "link": item.get("link"),
                "description": item.get("snippet", "No description provided."),
            })

        start_index += 10
        if "items" not in search_results or not search_results["items"]:
            break

    return results

def display_results(results):
    if not results:
        print("[INFO] No results found.")
        return

    print("\n **Search Results:**\n")
    for idx, result in enumerate(results, start=1):
        print(f"{idx}. \033[1m{result['title']}\033[0m")
        print(f"   URL: {result['link']}")
        print(f"   Description: {result['description'][:200]}...\n")

def main():
    try:
        validate_env()
        args = parse_arguments()

        results = google_search(args.search_term, args.results)

        display_results(results)

    except ValueError as e:
        print(e)
    except Exception as e:
        print(f"[ERROR] An unexpected error occurred: {e}")

if __name__ == "__main__":
    main()

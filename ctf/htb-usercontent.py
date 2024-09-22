import argparse
import os
import requests

def fetch_user_profile_content(user_id, use_proxy=False, verify_ssl=True):
    htb_token = os.environ.get('HTB_TOKEN')
    if not htb_token:
        raise ValueError("HTB_TOKEN environment variable is not set.")
    
    profile_api_url = f"https://www.hackthebox.com/api/v4/profile/content/{user_id}"
    headers = {
        'Authorization': f'Bearer {htb_token}',
        'User-Agent': 'htb-cli'
    }
    
    proxies = {
        'http': 'http://127.0.0.1:8080',
        'https': 'http://127.0.0.1:8080',
    } if use_proxy else None
    
    response = requests.get(profile_api_url, headers=headers, proxies=proxies, verify=verify_ssl)
    if response.status_code == 200:
        return response.json()
    else:
        raise Exception(f"Failed to fetch profile content: {response.status_code}, {response.text}")

def print_section(profile_content, section):
    if profile_content.get('profile', {}).get('content', {}).get(section):
        print(f"\n{section.capitalize()}:")
        for item in profile_content['profile']['content'][section]:
            if section == 'machines':
                machine_url = f"https://app.hackthebox.com/machines/{item['name']}"
                print(f"  ID: {item['id']}, Name: {item['name']}, OS: {item['os']}, Difficulty: {item['difficulty']}, Rating: {item['rating']}, URL: {machine_url}")
            elif section == 'writeups':
                print(f"  ID: {item['id']}, Machine ID: {item['machine_id']}, Machine Name: {item['machine_name']}, URL: {item['url']}, Likes: {item['likes']}, Dislikes: {item['dislikes']}")
            elif section == 'challenges':
                challenge_name_normalized = item['name'].replace(' ', '-').lower()  # doesent work for all challnges - meh
                challenge_url = f"https://app.hackthebox.com/challenges/{challenge_name_normalized}"
                print(f"  ID: {item.get('id')}, Name: {item.get('name', 'N/A')}, Difficulty: {item.get('difficulty', 'N/A')}, Category: {item.get('category', 'N/A')}, URL: {challenge_url}")
    else:
        print(f"\n{section.capitalize()}: None")



if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Fetch HTB user profile content.")
    parser.add_argument("user_id", type=int, help="User ID to query.")
    parser.add_argument("--proxy", action="store_true", help="Route requests through a proxy server.")
    parser.add_argument("--ignore-ssl", action="store_false", help="Ignore SSL certificate verification.")
    parser.add_argument("--machines", action="store_true", help="Print only the machines information.")
    parser.add_argument("--challenges", action="store_true", help="Print only the challenges information.")
    parser.add_argument("--writeups", action="store_true", help="Print only the writeups information.")
    args = parser.parse_args()
    
    try:
        profile_content = fetch_user_profile_content(args.user_id, args.proxy, args.ignore_ssl)

        sections_to_print = []
        if args.machines:
            sections_to_print.append('machines')
        if args.challenges:
            sections_to_print.append('challenges')
        if args.writeups:
            sections_to_print.append('writeups')

        if sections_to_print:
            for section in sections_to_print:
                print_section(profile_content, section)
        else:
            for section in ['machines', 'challenges', 'writeups']:
                print_section(profile_content, section)
    except Exception as e:
        print(e)

import os
import sys

import requests
from dotenv import load_dotenv

load_dotenv()

DO_API_TOKEN = os.getenv("DO_API_TOKEN")
BASE_URL = "https://api.digitalocean.com/v2"


def get_all_droplets():
    """Retrieve all droplets from DigitalOcean account."""
    url = f"{BASE_URL}/droplets"
    headers = {
        "Authorization": f"Bearer {DO_API_TOKEN}",
        "Content-Type": "application/json",
    }

    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        return response.json().get("droplets", [])
    except requests.exceptions.RequestException as e:
        print(f"[-] Error fetching droplets: {str(e)}")
        return []


def find_proxy_droplets():
    """Find all droplets with 'proxy' in their name."""
    droplets = get_all_droplets()
    return [d for d in droplets if "proxy" in d["name"].lower()]


def delete_droplet(droplet_id):
    """Delete a droplet by its ID."""
    if not droplet_id:
        return False

    url = f"{BASE_URL}/droplets/{droplet_id}"
    headers = {
        "Authorization": f"Bearer {DO_API_TOKEN}",
        "Content-Type": "application/json",
    }

    try:
        response = requests.delete(url, headers=headers)
        if response.status_code == 204:
            print(f"[+] Droplet {droplet_id} has been deleted")
            return True
        else:
            print(f"[-] Failed to delete droplet {droplet_id}")
            print(f"Status code: {response.status_code}")
            print(f"Response: {response.text}")
            return False
    except requests.exceptions.RequestException as e:
        print(f"[-] Error deleting droplet {droplet_id}: {str(e)}")
        return False


def delete_all_proxy_droplets():
    """Find and delete all proxy droplets."""
    proxy_droplets = find_proxy_droplets()
    if not proxy_droplets:
        print("[*] No proxy droplets found")
        return

    print(f"[+] Found {len(proxy_droplets)} proxy droplet(s)")
    for droplet in proxy_droplets:
        print(f"[+] Deleting droplet {droplet['id']} ({droplet['name']})")
        delete_droplet(droplet["id"])


if __name__ == "__main__":
    if len(sys.argv) > 1:
        # Delete specific droplet if ID is provided
        droplet_id = sys.argv[1]
        if droplet_id.lower() == "all":
            delete_all_proxy_droplets()
        else:
            delete_droplet(droplet_id)
    else:
        # Find and delete all proxy droplets if no ID is provided
        delete_all_proxy_droplets()

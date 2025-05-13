# api_clients.py

import requests

def call_virustotal(indicator, api_key):
    headers = {
        "x-apikey": api_key
    }
    url = f"https://www.virustotal.com/api/v3/search?query={indicator}"
    resp = requests.get(url, headers=headers)
    if resp.status_code == 200:
        json_data = resp.json()
        if "data" in json_data and json_data["data"]:
            return {
                "name": "VirusTotal",
                "hit": True,
                "url": f"https://www.virustotal.com/gui/search/{indicator}"
            }
    return {
        "name": "VirusTotal",
        "hit": False,
        "url": f"https://www.virustotal.com/gui/search/{indicator}"
    }

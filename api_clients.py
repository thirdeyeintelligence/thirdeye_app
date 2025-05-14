import requests

def call_virustotal_detailed(indicator, api_key):
    if not api_key:
        return None
    headers = {"x-apikey": api_key}
    url = f"https://www.virustotal.com/api/v3/files/{indicator}"
    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            data = response.json()
            return {
                "malicious_count": data["data"]["attributes"]["last_analysis_stats"]["malicious"],
                "tags": data["data"]["attributes"].get("tags", []),
                "rule_categories": list({r["rule_category"] for r in data["data"]["attributes"].get("crowdsourced_ids_results", [])}),
                "popular_threat": data["data"]["attributes"].get("popular_threat_classification", {}).get("suggested_threat_label", ""),
                "link": f"https://www.virustotal.com/gui/file/{indicator}/detection",
                "sandbox_verdicts": data["data"]["attributes"].get("sandbox_verdicts", {})
            }
    except Exception as e:
        print("VT error:", e)
    return None

def call_abusech(indicator, api_key):
    # Mock scoring logic (Abuse.ch doesn’t require auth for many endpoints)
    if indicator.startswith("1.") or "exe" in indicator:
        return {"score": 1}
    return None

def call_opencti(indicator, api_key):
    if not api_key:
        return None
    # Mocked OpenCTI score
    return {"score": 1 if "mal" in indicator else 0}

def call_anyrun(indicator, api_key):
    if not api_key:
        return None
    # Mock AnyRun logic
    return {"score": 1 if "stealer" in indicator else 0}

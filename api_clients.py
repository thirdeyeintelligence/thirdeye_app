import requests

def call_virustotal_detailed(indicator, api_key):
    headers = {"x-apikey": api_key}
    print("[DEBUG] Headers:", headers)
    url = f"https://www.virustotal.com/api/v3/files/{indicator}"

    try:
        res = requests.get(url, headers=headers)
        if res.status_code == 404:
            print(f"[VT] File not found for: {indicator}")
            return {
                "malicious_count": 0,
                "tags": [],
                "rule_categories": [],
                "popular_threat": None,
                "sandbox_verdicts": {},
                "link": f"https://www.virustotal.com/gui/file/{indicator}"
            }

        if res.status_code != 200:
            print(f"[VT] Error {res.status_code}: {res.text}")
            return None

        data = res.json()
        attributes = data.get("data", {}).get("attributes", {})

        vt_result = {
            "malicious_count": attributes.get("last_analysis_stats", {}).get("malicious", 0),
            "tags": attributes.get("tags", []),
            "rule_categories": list({r.get("rule_category", "") for r in attributes.get("crowdsourced_yara_results", [])}),
            "popular_threat": attributes.get("popular_threat_classification", {}).get("suggested_threat_label"),
            "sandbox_verdicts": {},
            "link": f"https://www.virustotal.com/gui/file/{indicator}"
        }

        # Optional: sandbox verdicts if present
        sandbox = attributes.get("sandbox_verdicts", {})
        for vendor, detail in sandbox.items():
            vt_result["sandbox_verdicts"][vendor] = {
                "category": detail.get("category", "unknown"),
                "malware_names": detail.get("malware_names", []),
                "malware_classification": detail.get("malware_classification", [])
            }

        return vt_result

    except Exception as e:
        print(f"[VT Exception] {e}")
        return None

        print("DEBUG VT Result for", indicator, vt_data)

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

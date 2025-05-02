import requests
import json
from datetime import datetime, timedelta
import os
from dotenv import load_dotenv
load_dotenv()

# Ensure data/ folder exists
os.makedirs("data", exist_ok=True)
API_KEY = os.getenv("NVD_API_KEY")

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

def fetch_recent_cves(days_back=7):
    start_date = (datetime.now() - timedelta(days=days_back)).isoformat() + "Z"
    end_date = datetime.now().isoformat() + "Z"

    headers = {
        "apiKey": API_KEY
    }

    params = {
        "pubStartDate": start_date,
        "pubEndDate": end_date,
        "resultsPerPage": 100
    }

    response = requests.get(NVD_URL, headers=headers, params=params)
    data = response.json()

    os.makedirs("data", exist_ok=True)
    with open("data/cves.json", "w") as f:
        json.dump(data, f, indent=4)

    print(f"Fetched {len(data.get('vulnerabilities', []))} CVEs.")
    
    return data   # <---- THIS LINE is the missing piece





import sqlite3

def insert_into_db(cve_data):
    conn = sqlite3.connect("data/cves.db")
    cursor = conn.cursor()

    for item in cve_data.get("vulnerabilities", []):
        try:
            cve = item["cve"]
            cve_id = cve["id"]
            published = cve["published"]
            modified = cve["lastModified"]
            description = cve["descriptions"][0]["value"] if cve["descriptions"] else ""
            severity = cve.get("metrics", {}).get("cvssMetricV31", [{}])[0].get("cvssData", {}).get("baseSeverity", "UNKNOWN")
            score = cve.get("metrics", {}).get("cvssMetricV31", [{}])[0].get("cvssData", {}).get("baseScore", None)

            cursor.execute('''
                INSERT OR REPLACE INTO cves (cve_id, published_date, last_modified_date, description, severity, cvss_score)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (cve_id, published, modified, description, severity, score))
        except Exception as e:
            print(f"Error inserting CVE {cve_id}: {e}")

    conn.commit()
    conn.close()
    print("Inserted CVEs into database.")

if __name__ == "__main__":
    data = fetch_recent_cves()
    insert_into_db(data)

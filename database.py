import requests
import sqlite3
import json
import time
from datetime import datetime

def create_database():
    with sqlite3.connect('cve_database.db') as conn:
        conn.execute('''
            CREATE TABLE IF NOT EXISTS cves (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                cve_id TEXT UNIQUE,
                published TEXT,
                last_modified TEXT,
                description TEXT,
                cvss_v2_score REAL,
                cvss_v3_score REAL,
                severity TEXT,
                vector_string TEXT,
                status TEXT
            )
        ''')
        print("Database created successfully")

def fetch_cves(start_index=0, results_per_page=2000):
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {
        "startIndex": start_index,
        "resultsPerPage": results_per_page
    }
    
    try:
        response = requests.get(url, params=params)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"Error fetching CVEs: {e}")
        return None

def populate_database(limit=None):
    create_database()
    start_index = 0
    total_processed = 0
    
    with sqlite3.connect('cve_database.db') as conn:
        cursor = conn.cursor()
        
        while True:
            print(f"Fetching CVEs starting from index {start_index}")
            data = fetch_cves(start_index)
            
            if not data or 'vulnerabilities' not in data:
                break

            vulnerabilities = data['vulnerabilities']
            if not vulnerabilities:
                break

            for vuln in vulnerabilities:
                try:
                    cve = vuln['cve']
                    
                    # Extract CVSS scores
                    metrics = cve.get('metrics', {})
                    cvss_v2 = metrics.get('cvssMetricV2', [{}])[0] if 'cvssMetricV2' in metrics else {}
                    cvss_v3 = metrics.get('cvssMetricV3', [{}])[0] if 'cvssMetricV3' in metrics else {}
                    
                    cvss_v2_score = cvss_v2.get('cvssData', {}).get('baseScore')
                    cvss_v3_score = cvss_v3.get('cvssData', {}).get('baseScore')
                    severity = cvss_v3.get('severity') or cvss_v2.get('severity')
                    vector_string = (cvss_v3.get('cvssData', {}).get('vectorString') or 
                                   cvss_v2.get('cvssData', {}).get('vectorString'))

                    cursor.execute('''
                        INSERT OR REPLACE INTO cves (
                            cve_id, published, last_modified, description,
                            cvss_v2_score, cvss_v3_score, severity,
                            vector_string, status
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ''', (
                        cve['id'],
                        cve.get('published'),
                        cve.get('lastModified'),
                        cve.get('descriptions', [{}])[0].get('value'),
                        cvss_v2_score,
                        cvss_v3_score,
                        severity,
                        vector_string,
                        'analyzed'
                    ))
                    
                    total_processed += 1
                    if total_processed % 100 == 0:
                        print(f"Processed {total_processed} CVEs")
                        conn.commit()

                    if limit and total_processed >= limit:
                        print(f"Reached limit of {limit} CVEs")
                        return
                        
                except sqlite3.Error as e:
                    print(f"Database error for CVE {cve['id']}: {e}")
                except Exception as e:
                    print(f"Error processing CVE: {e}")

            start_index += len(vulnerabilities)
            print(f"Total CVEs processed: {total_processed}")
            time.sleep(6)  
            conn.commit()

if __name__ == "__main__":
    import sys
    limit = int(sys.argv[1]) if len(sys.argv) > 1 else None
    populate_database(limit)
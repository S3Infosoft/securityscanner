CVE Integration Guide for ASV Scanner
=====================================

1\. Understand CVE Data Sources
-------------------------------

The main source of CVE data is the **National Vulnerability Database (NVD)**:

*   **NVD API**: Provides a REST API to access CVE details, severity scores, and related metadata. [NVD API Documentation](https://nvd.nist.gov/developers/vulnerabilities)
*   **CVE JSON Feeds**: Download full datasets or filtered feeds for offline analysis. [NVD JSON Feeds](https://nvd.nist.gov/vuln/data-feeds)

2\. Set Up NVD API Integration
------------------------------

### A. API Access

No authentication is required for the NVD API. Query specific CVEs using their ID or search by keywords, CPEs, or severity.

### B. Fetching CVE Data

    import requests
    
    def fetch_cve_data(cve_id):
        base_url = f"https://services.nvd.nist.gov/rest/json/cve/1.0/{cve_id}"
        try:
            response = requests.get(base_url, timeout=10)
            if response.status_code == 200:
                data = response.json()
                cve_info = data.get('result', {}).get('CVE_Items', [])[0]
                description = cve_info.get('cve', {}).get('description', {}).get('description_data', [])[0].get('value', "No description available.")
                cvss_v3 = cve_info.get('impact', {}).get('baseMetricV3', {}).get('cvssV3', {})
                severity = cvss_v3.get('baseSeverity', "Unknown")
                score = cvss_v3.get('baseScore', "N/A")
                print(f"CVE ID: {cve_id}")
                print(f"Description: {description}")
                print(f"Severity: {severity}")
                print(f"CVSS Score: {score}")
            else:
                print(f"Error: Unable to fetch data for {cve_id}. HTTP Status: {response.status_code}")
        except requests.exceptions.RequestException as e:
            print(f"Error: {e}")

3\. Match Detected Services with Vulnerabilities
------------------------------------------------

### A. CPE Matching

CPE (Common Platform Enumeration) is a standardized method of identifying software and hardware.

    def fetch_cves_by_cpe(cpe_name):
        base_url = f"https://services.nvd.nist.gov/rest/json/cves/1.0?cpeMatchString={cpe_name}"
        try:
            response = requests.get(base_url, timeout=10)
            if response.status_code == 200:
                data = response.json()
                results = data.get('result', {}).get('CVE_Items', [])
                for item in results:
                    cve_id = item.get('cve', {}).get('CVE_data_meta', {}).get('ID', "Unknown")
                    description = item.get('cve', {}).get('description', {}).get('description_data', [])[0].get('value', "No description available.")
                    print(f"\nCVE ID: {cve_id}")
                    print(f"Description: {description}")
            else:
                print(f"Error: Unable to fetch CVEs for {cpe_name}. HTTP Status: {response.status_code}")
        except requests.exceptions.RequestException as e:
            print(f"Error: {e}")

### Example Input

For a detected service:

    # Example Input
    fetch_cves_by_cpe("cpe:2.3:a:apache:http_server:2.4.49")

4\. Automate CVE Correlation
----------------------------

Extract service details and correlate them with vulnerabilities:

    def parse_nmap_results(scan_data):
        for host in scan_data.all_hosts():
            for proto in scan_data[host].all_protocols():
                for port in scan_data[host][proto].keys():
                    service = scan_data[host][proto][port]['name']
                    version = scan_data[host][proto][port].get('version', 'Unknown')
                    print(f"Service: {service}, Version: {version}")
                    # Generate CPE from service and version (simplified example)
                    cpe = f"cpe:2.3:a:{service}:{version}"
                    fetch_cves_by_cpe(cpe)

5\. Local CVE Database (Optional)
---------------------------------

For better performance and offline capabilities, download and store NVD JSON feeds in a local database:

    import sqlite3
    import json
    
    def load_cve_data_to_db(json_file, db_file):
        conn = sqlite3.connect(db_file)
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS cve_data (id TEXT, description TEXT, severity TEXT, score REAL)''')
        
        with open(json_file, 'r') as file:
            data = json.load(file)
            for item in data['CVE_Items']:
                cve_id = item['cve']['CVE_data_meta']['ID']
                description = item['cve']['description']['description_data'][0]['value']
                severity = item.get('impact', {}).get('baseMetricV3', {}).get('cvssV3', {}).get('baseSeverity', "Unknown")
                score = item.get('impact', {}).get('baseMetricV3', {}).get('cvssV3', {}).get('baseScore', 0)
                c.execute("INSERT INTO cve_data (id, description, severity, score) VALUES (?, ?, ?, ?)", (cve_id, description, severity, score))
        conn.commit()
        conn.close()

6\. Generate CVE Reports
------------------------

Integrate CVE data into your scanner’s final report, categorizing vulnerabilities by severity and adding remediation steps:

    Target: 192.168.1.1
    ----------------------------------------
    CVE ID: CVE-2023-12345
    Description: Buffer overflow in XYZ software.
    Severity: Critical
    CVSS Score: 9.8
    Remediation: Update to version 2.1.3 or later.
    ----------------------------------------


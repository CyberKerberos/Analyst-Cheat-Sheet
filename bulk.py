import requests
import time
import json
from requests.auth import HTTPBasicAuth

# ----------------------- Configuration -----------------------

# InsightVM API configuration
API_BASE_URL = "https://<your-insightvm-server>/api/3"  # Replace with your InsightVM console URL

# Load credentials from config.json
with open("config.json", 'r') as json_file:
    config_data = json.load(json_file)

USER_API = config_data['USER_API']
USER_PASS = config_data['USER_PASS']

# Site and Scan Configuration
SITE_NAME = "OCD-AMER"
SCAN_TEMPLATE_NAME = "full audit without web spider"
SCAN_ENGINE_NAME = "usad00001"

# List of IP addresses to scan
IP_ADDRESSES = [
    "10.152.160.4",
    "10.152.160.5",
    "10.152.22.153",
    "10.152.22.141",
    "10.152.18.136",
    "10.152.18.173",
    "10.152.22.164",
    "10.152.22.138",
    "10.152.18.161",
    "10.152.22.135",
    "10.152.22.137",
    "10.255.193.53",
    "10.152.22.132",
    "10.255.193.50",
    "10.255.193.55",
    "10.255.193.46",
    "10.255.193.58",
    "10.255.193.79",
    "10.254.57.10",
    "10.249.201.10",
    "10.254.57.12",
    "10.152.14.11",
    "10.152.14.72",
    "10.152.15.152",
    "10.152.21.13",
    "10.152.129.138",
    "10.254.89.19",
    "10.22.141.102",
    "10.254.97.9",
    "10.152.129.141",
    "10.152.129.141",
    "10.254.89.55",
    "10.152.129.141",
    "10.254.97.10",
    "10.254.97.11",
    "10.152.44.75",
    "10.152.44.70",
    "10.254.97.27",
    "10.254.89.18",
    "10.254.89.10",
    "10.254.89.52",
    "10.253.65.31",
    "10.248.4.27",
    "10.152.31.14"
]

# Time (in seconds) between status checks
STATUS_CHECK_INTERVAL = 60  # e.g., 60 seconds

# ----------------------- Helper Functions -----------------------

def get_headers():
    """
    Returns the headers required for API requests.
    """
    return {
        "Content-Type": "application/json",
        "Accept": "application/json"
    }

def get_site_id(site_name):
    """
    Retrieves the Site ID for the given site name.
    """
    url = f"{API_BASE_URL}/sites"
    params = {"filter": f"name:{site_name}"}
    response = requests.get(url, headers=get_headers(), params=params, auth=HTTPBasicAuth(USER_API, USER_PASS), verify=False)

    if response.status_code == 200:
        sites = response.json().get('resources', [])
        if sites:
            return sites[0]['id']
        else:
            print(f"Site '{site_name}' not found.")
            return None
    else:
        print(f"Error fetching sites: {response.status_code} - {response.text}")
        return None

def get_scan_template_id(template_name):
    """
    Retrieves the Scan Template ID for the given template name.
    """
    url = f"{API_BASE_URL}/scan_templates"
    params = {"filter": f"name:{template_name}"}
    response = requests.get(url, headers=get_headers(), params=params, auth=HTTPBasicAuth(USER_API, USER_PASS), verify=False)

    if response.status_code == 200:
        templates = response.json().get('resources', [])
        if templates:
            return templates[0]['id']
        else:
            print(f"Scan Template '{template_name}' not found.")
            return None
    else:
        print(f"Error fetching scan templates: {response.status_code} - {response.text}")
        return None

def get_scan_engine_id(engine_name):
    """
    Retrieves the Scan Engine ID for the given engine name.
    """
    url = f"{API_BASE_URL}/scan_engines"
    params = {"filter": f"name:{engine_name}"}
    response = requests.get(url, headers=get_headers(), params=params, auth=HTTPBasicAuth(USER_API, USER_PASS), verify=False)

    if response.status_code == 200:
        engines = response.json().get('resources', [])
        if engines:
            return engines[0]['id']
        else:
            print(f"Scan Engine '{engine_name}' not found.")
            return None
    else:
        print(f"Error fetching scan engines: {response.status_code} - {response.text}")
        return None

def assign_assets_to_site(site_id, ip_list):
    """
    Assigns a list of IP addresses as assets to the specified site.
    """
    url = f"{API_BASE_URL}/sites/{site_id}/assets"
    payload = {
        "resources": [{"ip": ip} for ip in ip_list]
    }
    response = requests.put(url, headers=get_headers(), json=payload, auth=HTTPBasicAuth(USER_API, USER_PASS), verify=False)

    if response.status_code in [200, 201, 204]:
        print(f"Successfully assigned {len(ip_list)} IPs to Site ID {site_id}.")
        return True
    else:
        print(f"Error assigning assets: {response.status_code} - {response.text}")
        return False

def initiate_scan(site_id, template_id, engine_id):
    """
    Initiates a scan for the specified site using the given template and engine.
    """
    url = f"{API_BASE_URL}/scans"
    payload = {
        "name": f"Automated Scan {site_id} - {time.strftime('%Y-%m-%d %H:%M:%S')}",
        "description": "Scan initiated by automated script",
        "type": "Vulnerability",
        "site": {"id": site_id},
        "scan_template": {"id": template_id},
        "scan_engine": {"id": engine_id}
    }
    response = requests.post(url, headers=get_headers(), json=payload, auth=HTTPBasicAuth(USER_API, USER_PASS), verify=False)

    if response.status_code in [200, 201]:
        scan = response.json()
        print(f"Scan initiated successfully. Scan ID: {scan['id']}")
        return scan['id']
    else:
        print(f"Error initiating scan: {response.status_code} - {response.text}")
        return None

def check_scan_status(scan_id):
    """
    Checks the current status of the scan.
    """
    url = f"{API_BASE_URL}/scans/{scan_id}"
    response = requests.get(url, headers=get_headers(), auth=HTTPBasicAuth(USER_API, USER_PASS), verify=False)

    if response.status_code == 200:
        scan = response.json()
        status = scan.get('status', 'Unknown')
        print(f"Scan ID {scan_id} Status: {status}")
        return status
    else:
        print(f"Error checking scan status: {response.status_code} - {response.text}")
        return None

def retrieve_scan_results(scan_id):
    """
    Retrieves the scan results, such as vulnerabilities found.
    """
    # Fetch vulnerabilities found in the scan
    vulnerabilities = []
    url = f"{API_BASE_URL}/scans/{scan_id}/vulnerabilities"
    params = {"limit": 1000}  # Adjust limit as needed

    while url:
        response = requests.get(url, headers=get_headers(), params=params, auth=HTTPBasicAuth(USER_API, USER_PASS), verify=False)
        if response.status_code == 200:
            data = response.json()
            vulnerabilities.extend(data.get('resources', []))
            url = data.get('pagination', {}).get('next', None)
        else:
            print(f"Error retrieving vulnerabilities: {response.status_code} - {response.text}")
            break

    print(f"Total Vulnerabilities Found: {len(vulnerabilities)}")
    return vulnerabilities

def save_results_to_file(vulnerabilities, filename="scan_results.json"):
    """
    Saves the scan results to a JSON file.
    """
    with open(filename, 'w') as f:
        json.dump(vulnerabilities, f, indent=4)
    print(f"Scan results saved to {filename}")

# ----------------------- Main Execution -----------------------

def main():
    # Step 1: Get Site ID
    site_id = get_site_id(SITE_NAME)
    if not site_id:
        return

    # Step 2: Assign IPs to Site
    assignment_success = assign_assets_to_site(site_id, IP_ADDRESSES)
    if not assignment_success:
        return

    # Step 3: Get Scan Template ID
    template_id = get_scan_template_id(SCAN_TEMPLATE_NAME)
    if not template_id:
        return

    # Step 4: Get Scan Engine ID
    engine_id = get_scan_engine_id(SCAN_ENGINE_NAME)
    if not engine_id:
        return

    # Step 5: Initiate Scan
    scan_id = initiate_scan(site_id, template_id, engine_id)
    if not scan_id:
        return

    # Step 6: Monitor Scan Status
    print("Monitoring scan status...")
    while True:
        status = check_scan_status(scan_id)
        if status is None:
            print("Unable to retrieve scan status. Exiting.")
            return
        elif status.lower() in ['completed', 'success']:
            print("Scan completed successfully.")
            break
        elif status.lower() in ['running', 'queued', 'started']:
            print(f"Scan is still in progress. Checking again in {STATUS_CHECK_INTERVAL} seconds...")
            time.sleep(STATUS_CHECK_INTERVAL)
        else:
            print(f"Scan ended with status: {status}. Exiting.")
            return

    # Step 7: Retrieve Scan Results
    print("Retrieving scan results...")
    vulnerabilities = retrieve_scan_results(scan_id)
    if vulnerabilities:
        # Step 8: Save Results to a File
        save_results_to_file(vulnerabilities, "scan_results.json")
    else:
        print("No vulnerabilities found or failed to retrieve vulnerabilities.")

if __name__ == "__main__":
    # Suppress SSL warnings if using verify=False (Not recommended for production)
    requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)
    main()

import re
import requests

# Set variables
abuseipdb_api_key = "YOUR_ABUSEIPDB_API_KEY"
virustotal_api_key = "YOUR_VIRUSTOTAL_API_KEY"

# Regular expression for IP addresses
ip_regex = r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"

# Read log files and extract IP addresses
ip_addresses = set()
for filename in ["log1.txt", "log2.txt"]:
    with open(filename, "r") as f:
        for line in f:
            match = re.search(ip_regex, line)
            if match:
                ip_addresses.add(match.group())

# Check AbuseIPDB, VirusTotal, and DB-IP for each IP address
for ip_address in ip_addresses:
    # Check AbuseIPDB
    print(f"Checking AbuseIPDB for {ip_address}...")
    abuseipdb_response = requests.get(f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip_address}",
                                      headers={"Key": abuseipdb_api_key, "Accept": "application/json"})
    abuseipdb_result = abuseipdb_response.json()
    print("AbuseIPDB result:")
    print(abuseipdb_result)

    # Check VirusTotal
    print(f"Checking VirusTotal for {ip_address}...")
    virustotal_response = requests.get(f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}",
                                       headers={"x-apikey": virustotal_api_key, "Accept": "application/json"})
    virustotal_result = virustotal_response.json()
    print("VirusTotal result:")
    print(virustotal_result)

    # Check DB-IP
    print(f"Checking DB-IP for {ip_address}...")
    dbip_response = requests.get(f"https://db-ip.com/{ip_address}/json", headers={"Accept": "application/json"})
    dbip_result = dbip_response.json()
    print("DB-IP result:")
    print(dbip_result)

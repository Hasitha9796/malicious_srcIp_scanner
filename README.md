# malicious_srcip_scanner
Python script that reads log files and checks the source IP addresses against the AbuseIPDB, VirusTotal, and DB-IP databases

To use this script, replace YOUR_ABUSEIPDB_API_KEY and YOUR_VIRUSTOTAL_API_KEY with your actual API keys for those services. Note that the AbuseIPDB API requires 
a free account to access the API key.

Save the script as a file (e.g., check_logs.py) and put the log files in the same directory as the script. Then, you can run the script from the command line 
with python check_logs.py. The script reads the log files and extracts IP addresses using a regular expression. The script checks the AbuseIPDB, VirusTotal, 
and DB-IP databases for each IP address and prints the JSON response from each database. You can modify the script to extract specific information from the 
response, depending on your needs.

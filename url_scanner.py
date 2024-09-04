import sys
import subprocess
import time

def open_ips_in_chromium(ip_list, url_list):
    chrome_path = "/usr/bin/google-chrome"
    for ip in ip_list:
        subprocess.run([chrome_path, "--new-window", ""], check=True)
        for url in url_list:
            url = url.replace("%s", ip)
            subprocess.run([chrome_path, url], check=True)
        time.sleep(2)
        

def virustotal_scan():
    url_list = ["https://www.virustotal.com/gui/ip-address/%s"]
    ip_list = sys.argv[2:]
    open_ips_in_chromium(ip_list, url_list)
    print("Scanning Virustotal")

def abuseipdb_scan():
    url_list = ["https://www.abuseipdb.com/check/%s"]
    ip_list = sys.argv[2:]
    open_ips_in_chromium(ip_list, url_list)
    print("Scanning AbuseIPDB")

def alienvault_scan():
    url_list = ["https://otx.alienvault.com/indicator/ip/%s"]
    ip_list = sys.argv[2:]
    open_ips_in_chromium(ip_list, url_list)
    print("Scanning Alienvault")

def scan_all():
    url_list = ["https://www.virustotal.com/gui/ip-address/%s", "https://www.abuseipdb.com/check/%s", "https://otx.alienvault.com/indicator/ip/%s"]
    ip_list = sys.argv[2:]
    open_ips_in_chromium(ip_list, url_list)
    print("Scanning all sources")

def main():
    if len(sys.argv) <= 2:
        print("Usage: python3 script.py [ARG] [ip_list delimited by spaces]")
        print("1 - Virus Total Only")
        print("2 - IPDB Only")
        print("3 - OTX Only")
        print("4 - All")
        sys.exit(1)
    
    function_number = int(sys.argv[1])
    
    if function_number == 1:
        virustotal_scan()
    elif function_number == 2:
        abuseipdb_scan()
    elif function_number == 3:
        alienvault_scan()
    elif function_number == 4:
        scan_all()
    else:
        print("Invalid function number")

if __name__ == "__main__":
    main()

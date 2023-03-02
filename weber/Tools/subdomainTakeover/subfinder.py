import requests
import sys
from datetime import datetime

def subdomain_finder(domain):
    with open("sub.txt","r") as f:
        for i in f:
            sub_domain = i.strip()
            new_url = sub_domain + "." + domain
            try:
                res = requests.get("http://"+new_url)
                print("Discovered Subdomain :",new_url)
            except:
                pass

if __name__ == "__main__":
    subdomain_finder("mollie.com")
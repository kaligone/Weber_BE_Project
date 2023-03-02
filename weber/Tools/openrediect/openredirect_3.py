import requests
from bs4 import BeautifulSoup as bs
from urllib.parse import urljoin
from pprint import pprint
from urllib.parse import * 
from Crawler.parameterCrawl import crawl
import requests
import numpy as np



def filter_potential_openredirect_urls(url_list):
    openredirect_url_list = []
    for url in url_list:
        if "=http" in url:
            openredirect_url_list.append(url)
    return openredirect_url_list

def replace_param_value(url, newParamValue, keywordInTargetParam):


    parsed = urlparse(url)
    querys = parsed.query.split("&")

    result = []
    for param in querys:
        if keywordInTargetParam in param:
            new_param = list(param)
            required_char = []
            
            for char in new_param:
                if char != "=":
                    required_char.append(char)
                elif char == "=":
                    break
                    
            new_param_str = ""
            for char in required_char:
                new_param_str += char
                
            result.append(new_param_str + "=" + newParamValue)
        else:
            result.append(param)
            
    new_query = "&".join(["{}".format(params) for params in result])
    parsed = parsed._replace(query=new_query)
    final_url = urlunparse(parsed)
    return final_url

def scan_urls_for_open_redirect(url_list, domainNameOfTarget):
    vulnerable_urls=[]
    total_error_encountered=0
    total_urls_scanned=0
    for url in url_list:
        try:
            r = requests.get(str(url), allow_redirects=False, verify=False)
            if r.status_code in [301, 302, 303, 304, 305, 306, 307, 308]:
                if ("evil.com" in r.headers["Location"]) and ("=http://evil.com" not in r.headers["Location"]) and (domainNameOfTarget not in r.headers["Location"]):
                    vulnerable_urls.append(url)
        except:
            total_error_encountered += 1

        total_urls_scanned += 1
        print(f"[>>] [Total URLs Scanned] : {total_urls_scanned}/{unique_potential_urls} | [>>] [Total Error Encountered] : {total_error_encountered}", end="\r")
    return vulnerable_urls

# url = "www.testphp.vulnweb.com"
# parse_url = urlparse(url)
# print(parse_url)
# print(parse_url.netloc)
# abc=parse_url.netloc
# print(abc)
# if abc.startswith('www.'):
#     abc = abc[4:]
# print(abc)
domain="www.testphp.vulnweb.com"
parametered_url_list = crawl("testphp.vulnweb.com")

openredirect_url_list=filter_potential_openredirect_urls(parametered_url_list)


final_openredirect_url_list = []
for url in openredirect_url_list:
    try:
        final_openredirect_url_list.append(replace_param_value(url, "http://evil.com", "http"))
    except:
        print("Warning")




final_openredirect_url_list = list(dict.fromkeys(final_openredirect_url_list))
unique_potential_urls = len(final_openredirect_url_list)


print("[>>] [Unique Potentially Vulnerable URLs Count] : ", len(final_openredirect_url_list))   
print("[>>] [Unique Potentially Vulnerable URLs] : ",) 
for url in final_openredirect_url_list:
    print(url)

try:
    scan = scan_urls_for_open_redirect(final_openredirect_url_list,domain)
except:
    print("Warning")


if len(scan)>=1:
    print("Open Redirect Found On\n")
    print("\n=========================================================================")
    for urls in scan:
        print(urls)
    print("\n[>>] [Total Confirmed URLs] : ", len(scan))
else:
    print("Domain "+domain+" is Safe From Open Redirection")
    print("\n[>>] [Total Confirmed URLs] : ", len(scan))
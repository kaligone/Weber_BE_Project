from Tools.xss.util.checker import *
from Tools.xss.util.parameterCrawl import *
from Tools.xss.util.urlparser import *


def check_XSS(domain):
    filtered_urls = []# contains the urls which contains the token from the above check_token list

    try:
        find_parameterized_url = crawl(domain).split("\n")
    except ValueError as err:
        print(err)
        return False
    
    check_token = ['?cat=', '?s=','/?s=', '?s=', '?search', '?id=', '?p=', '?id=', '/search?q=', '/index.php?lang=', '/search?query=', '?categoryid=', '/?eventSearch=', '/?startTime=', '/?q=', '/index.php?pn=', '/?lang=', '/index.php?id=', '/search.php?q=', '/login?redirect_uri=', '/index.php?action=', '/search/?search=', '/videos?tag=', '/videos?place=', '/videos?search=', '/?cat=', '/?email=','/?page=', '/search/?s=', '/?keywords=', '/search/?keywords=', '/?name=', '/?sort=', '/search-results?q=', '/?price=', 'title=', '/?title=', '/titile=']


    for url in find_parameterized_url:
        for token in check_token:
            if token in url:
                filtered_urls.append(url)

    # for x in filtered_urls:
    #     print(x+"\n")

    vulnerable_urls = []

    for input in filtered_urls:
        with open('D:/Work Folder/project/Weber_Final_Year_Project/Tools/xss/payload.txt', 'r') as file:
            f = file.read().splitlines()
            for payload in f:
                base_url = parse(input, payload)

                status = xssChecker(base_url,payload)

                if status:
                    vulnerable_urls.append(base_url)
                    # with open("xssVuln_url.txt", "a") as vulnerable_url_file:
                    #     vulnerable_url_file.write(base_url +"-"+payload+ "\n")

                    # vulnerable_url_file.close()
                else:
                    pass
                # if status:
                #     print(f"Found RXSS vulnerability !!! \n Vulnerable url --> {base_url}\n Payload used --> {payload}\n")
                # else:
                #     print(f"Not vulnerable url --> {base_url} ,  Status : {status}\n ,  Payload : {payload}")

        file.close()
    vulnerable_urls = list(dict.fromkeys(vulnerable_urls))
    return vulnerable_urls
        # removeDuplicate()
        

# def removeDuplicate():
#     with open('xssVuln_url.txt', 'r') as file:
#         lines =file.readlines()

#     unique_urls = set()

#     for line in lines:
#         unique_urls.add(line)

#     with open('xssVuln_url.txt', 'w') as outfile:
#         for line in unique_urls:
#             outfile.write(line)


if __name__ == "__main__":
    print(check_XSS("www.testphp.vulnweb.com"))
# #     # removeDuplicate()

    # domain = "http://testphp.vulnweb.com/listproducts.php?cat=%3Cscript%3Ealert%281%29%3C%2Fscript%3E%0A"
    # print(xssChecker(domain,"<script>alert(1)</script>"))
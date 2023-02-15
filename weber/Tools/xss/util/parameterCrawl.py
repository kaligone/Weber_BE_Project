"""
Workflow :
1. Get the url
2. Find the all parameters of the URL
3. Filter the responses according to the need
"""
# from core import requester

def crawl(url):
    try:
        if url:
            print("URL found ! ")
            print("Crawling all parameters of URL : ", url)
            url = f"https://web.archive.org/cdx/search/cdx?url=*.{url}/*&output=txt&fl=original&collapse=urlkey&page=/"
            response, retry = requester.connector(url)
            return response
    # else:
    #     return False
    except ConnectionAbortedError:
        print("Failed to connect to server")


#  example input urls : example.com
if __name__ == "__main__":
    print(crawl("cito.nl"))

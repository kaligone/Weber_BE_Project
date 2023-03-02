"""
Workflow :
1. Get the url
2. Find the all parameters of the URL
3. Filter the responses according to the need
"""
from Crawler.core import requester


def crawl(url):
    try:
        if url:
            print("URL found ! ")
            print("Crawling all parameters of URL : ", url)
            url = f"https://web.archive.org/cdx/search/cdx?url=*.{url}/*&output=txt&fl=original&collapse=urlkey&page=/"
            response, retry = requester.connector(url)
            # return response
            param_list= response.split('\n')
            return param_list
    # else:
    #     return False
    except ConnectionAbortedError:
        print("Failed to connect to the server")

# if __name__ == "__main__":
#     url="testphp.vulnweb.com"
#     response = crawl(url)
#     print(response)
#     param_list= response.split('\n')
#     print(param_list)
#     print(type(param_list))
    


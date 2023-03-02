# import
from urllib.parse import *

# parse the urls
def parse(url, payload):
    # input will be the urls and the payload
    # divide the urls into the parts like
    # [scheme=http/https, netloc=main_domain_name, path=file_pat, params=parameters, query, fragment]
    url_parts = list(urlparse(url))

    # in the parts of url at 4th position it contains the query parameters
    # we convert it into the dictionary
    url_parts[4] = dict(parse_qsl(url_parts[4]))

    # now iterate over each urls and change the value of the parameters to the payloads value
    for parameter,value in url_parts[4].items():
        url_parts[4][parameter] = payload

    # converting the query back to list
    url_parts[4] = list(url_parts[4].items())

    # converting the above query list to the encoded string of query
    url_parts[4] = urlencode(url_parts[4])

    # joining the urls
    # example --> http://testphp.vulnweb.com/listproducts.php?cat=%3Cscript%3Ealert%281%29%3C%2Fscript%3E
    base_url = urlunparse(url_parts)
    return base_url

# if __name__ == '__main__':
#     parse("http://testphp.vulnweb.com/listproducts.php?cat=1", "<script>alert(1)</script>")
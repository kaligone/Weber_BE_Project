import requests as r

def xssChecker(base_url, payload):
    if not base_url and not payload:
        return ValueError

    global response_data
    response = r.get(base_url)

    if response.status_code == 200:
        try:
            response_data = response.text
        except ValueError:
            print("EMPTY !! No data in response")

        if payload in response_data:
            return True
        else:
            return False

    else:
        print('Error ! Status code :{}'.format(response.status_code))
        return False


if __name__ == '__main__':
    print(xssChecker("http://testphp.vulnweb.com/listproducts.php?cat=%3Cscript%3Ealert%281%29%3C%2Fscript%3E%0A", "<script>alert(1)</script>"))

        # # print("Site is reachable ....")
        # # check if the content type is test or json
        # header = response.headers
        # if header['Content-Type'] == 'application/json':
        #     data = response.text
        #     data_flag = 1
        # else:
        #     data = response.text
        #
        # # now according the content type of response we will check and then check for RXSS
        # if data_flag: # true when data_flag=1 i.e. application/json content type of the response
        #     if payload in data:
        #         return True  # return true if found the payload reflected in the response i.e. vulnerable
        #     return False   # else return false if not found reflected i.e. may not be vulnerable
        # else: # true when the data_flag=0 i.e. application/text content type of the response
        #     if payload in data:
        #         return True  # return true if found the payload reflected in the response i.e. vulnerable
        #     return False   # else return false if not found reflected i.e. may not be vulnerable
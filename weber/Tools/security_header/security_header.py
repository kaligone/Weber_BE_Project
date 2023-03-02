import requests

class ScanHeaders:

    def __init__(self, url):
        self.url = url
        response = requests.get(self.url)
        self.headers = response.headers
        self.cookies = response.cookies

    def scan_xxss(self):
        """config failure if X-XSS-Protection header is not present"""
        try:
            if self.headers["X-XSS-Protection"]:
                print("[+]", "X-XSS-Protection", ':', "pass")
                return True
            else:
                return False
        except KeyError:
            print("[-]", "X-XSS-Protection header not present", ':', "fail!")
            return False

    def scan_nosniff(self):
        """X-Content-Type-Options should be set to 'nosniff' """
        try:
            if self.headers["X-Content-Type-Options"].lower() == "nosniff":
                print("[+]", "X-Content-Type-Options", ':', "pass")
                return True
            else:
                print("[-]", "X-Content-Type-Options header not set correctly", ':', "fail!")
                return False
        except KeyError:
            print("[-]", "X-Content-Type-Options header not present", ':', "fail!")  
            return False       

    def scan_xframe(self):
        """X-Frame-Options should be set to DENY or SAMEORIGIN"""
        try:
            if "deny" in self.headers["X-Frame-Options"].lower():
                print("[+]", "X-Frame-Options", ':', "pass")
                return True
            elif "sameorigin" in self.headers["X-Frame-Options"].lower():
                print("[+]", "X-Frame-Options", ':', "pass")
                return True
            else:
                print("[-]", "X-Frame-Options header not set correctly", ':', "fail!")
                return False
        except KeyError:
            print("[-]", "X-Frame-Options header not present", ':', "fail!")
            return False

    def scan_hsts(self):
        """config failure if HSTS header is not present"""
        try:
            if self.headers["Strict-Transport-Security"]:
                print("[+]", "Strict-Transport-Security", ':', "pass")
                return True
            else:
                return False
        except KeyError:
            print("[-]", "Strict-Transport-Security header not present", ':', "fail!")
            return False

    def scan_policy(self):
        """config failure if Security Policy header is not present"""
        try:
            if self.headers["Content-Security-Policy"]:
                print("[+]", "Content-Security-Policy", ':', "pass")
                return True
            else:
                return False
        except KeyError:
            print("[-]", "Content-Security-Policy header not present", ':', "fail!")
            return False

    # def scan_secure(self, cookie):
    #     """Set-Cookie header should have the secure attribute set"""
    #     if cookie.secure:
    #         print("[+]", "Secure", ':', "pass")
    #         return True
    #     else:
    #         print("[-]", "Secure attribute not set", ':', "fail!")
    #         return False

    # def scan_httponly(self, cookie):
    #     """Set-Cookie header should have the HttpOnly attribute set"""
    #     if cookie.has_nonstandard_attr('httponly') or cookie.has_nonstandard_attr('HttpOnly'):
    #         print("[+]", "HttpOnly", ':', "pass")
    #         return True
    #     else:
    #         print("[-]", "HttpOnly attribute not set", ':', "fail!")
    #         return False

def security_header_main(url):
    target = ScanHeaders(url)
    try:
        xss=target.scan_xxss()
        nosniff=target.scan_nosniff()
        xframe=target.scan_xframe()
        hsts=target.scan_hsts()
        policy=target.scan_policy()
        data_info = {
            "X-XSS-Protection": xss,
            "X-Content-Type-Options": nosniff,
            "X-Frame-Options":xframe,
            "Strict-Transport-Security":hsts,
            "Content-Security-Policy":policy
        }

        return data_info
    except:
        pass
    # for cookie in target.cookies:
    #   print("Set-Cookie:")
    #   target.scan_secure(cookie)
    #   target.scan_httponly(cookie)

# url="https://www.pce.ac.in"
# data=security_header_main(url)
# print(data)
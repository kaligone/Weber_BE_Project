import requests
from bs4 import BeautifulSoup
from bs4 import BeautifulSoup

url = "https://trip.uber.com/www.google.com/%2F.."




def detect_js_redirection(url):
    response = requests.get(url)
    soup = BeautifulSoup(response.content, "html.parser")
    scripts = soup.find_all("script")
    for script in scripts:
        if "window.location"  or "windows.open" in script.text:
            return True
    return False


def detect_meta_refresh(url):
    response = requests.get(url)
    soup = BeautifulSoup(response.text, 'html.parser')
    meta = soup.find("meta", attrs={"http-equiv": "refresh"})
    if meta:
        return True
    return False


def detect_http_redirection(url):
    response = requests.head(url, allow_redirects=True)
    if response.status_code in [301, 302, 303, 304, 305, 306, 307, 308]:
        return True
    return False


def detect_frame_redirection(url):
    response = requests.get(url)
    soup = BeautifulSoup(response.text, 'html.parser')
    frame = soup.find("frame", attrs={"src": True})
    if frame:
        return True
    return False

def open_redirect(url):
    # loop for find the trace of all requests (303 is an open redirect) see the final destination
    try:
        # response = requests.get(url, verify=True)
        response = requests.get(url, allow_redirects=True) 
        # for resp in response.history:
        #     print(resp.url)
        try:
            if response.status_code in (301,302,307,308):                             
                print ("Request was redirected")                             
                for resp in response.history:
                    print( "|")
                    print (resp.status_code, resp.url)
                print ("Final destination:")
                print( "+")
                print (response.status_code, response.url)
            else:
                print( "Request was not redirected")
        except:
            print ("connection error :(")
    except:
        print ("quiting..")

def results_vulnerability():
    if detect_js_redirection(url):
        print("This page contains JavaScript-based redirection.")
        return 
    else:
        print("This page does not contain JavaScript-based redirection.")

    if detect_meta_refresh(url):
        print("This page is being redirected using HTML meta refresh.")
    else:
        print("This page is not being redirected using HTML meta refresh.")

    if detect_http_redirection(url):
        print("This page is being redirected using HTTP.")
    else:
        print("This page is not being redirected using HTTP.")

    if detect_frame_redirection(url):
        print("This page is being redirected using frame-based redirection.")
    else:
        print("This page is not being redirected using frame-based redirection.")
    open_redirect(url)

results_vulnerability()



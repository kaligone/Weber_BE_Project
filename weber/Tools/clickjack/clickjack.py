# Automation script for clickjacking vulnerability identification
from urllib.request import urlopen
from sys import argv, exit
from flask import Flask,request
__author__ = "W!vOL3r"

# Function to check if URL contains necessary headers
'''
Clickjacking occurs to absence X-Frame-Option header
Now we have to check if this header is present in the headers of the website
If its absent then the website is vulnerable for Clickjacking
'''
def clickjack_Check(url):
    """ Check if the URL is vulnerable is not """
    # url=request.args.get('url')
    # print(url)
    try:
        print("Starting with the scanning.......\n")

        # Append http or https if not presemt already...
        if "http" or "https" not in url:
            url = "http://" + url

        # open url and access the data
        data = urlopen(url)
        # check if url is opened and data is accessible or not
        if data:
            print("Accessing the url headers")
        else:
            print("No able to access the urls")

        # accessing the headers...
        headers = data.info()
        # check if headers are accessible...
        if headers:
            print("All available headers found ....")
        else:
            print("Not able to fetch headers ...")

        # Check if the X-Frame-Option is present or not
        # if not present then return true...
        
        if not "X-Frame-Options" in headers:
            return True
        else:
            return False
    except:
        return False

# if __name__ == '__main__':
#     if clickjack_Check("pce.ac.in"):
#         print("Vulnerable")
#     else:
#         print("Not Vulnerable")
    # print("Welcome to Clickjacking identifier tool...\n")
    # url = input("Enter the url to be checked : ")
    # print("Starting the scanner ....")
    # print("Given url {}".format(url))
    # if Check_URL():
    #     print("\nClickjacking found !!")
    # else:
    #     print("\nGiven URL is not vulnerable !!!")
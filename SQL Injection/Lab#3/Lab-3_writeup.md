\+ Lab #3    : SQL injection UNION attack, determining the number of columns returned by the query\
\+ Lab Level : Practitioner\
\+ Link      : https://portswigger.net/web-security/sql-injection/union-attacks/lab-determine-number-of-columns \


## About:
This lab contains a [SQL injection](https://portswigger.net/web-security/sql-injection) vulnerability in the product category filter. The results from the query are returned in the application's response, so you can use a UNION attack to retrieve data from other tables. The first step of such an attack is to determine the number of columns that are being returned by the query. You will then use this technique in subsequent labs to construct the full attack.

## End Goal: 
Determine the number of columns returned by the query by performing a [SQL injection UNION attack](https://portswigger.net/web-security/sql-injection/union-attacks)

## Detection: 
* Submit a single quotation mark ```'``` in ```/filter?category=Gifts``` to break out the original SQL query quotation marks and cause an internal error,
* The resulting query sent by the App to the back-end databases should look to something like:
```SQL
SELECT * FROM products WHERE category = 'Gifts''
```
* The App should return a ```500 Internal Server Error```, which means that an error has occured in the back-end database while processing the query.
* The ```category``` parameter is vulnerable to SQL injection.

## Exploitation: 
> :memo: **Note:** The goal of this lab is to figure out the number of columns returned by the query by perfoming a SQL Injection UNION attack. To do so, we will incrementally inject a series of ```UNION SELECT``` payloads specifiying different number of ```NULL``` values until we no longer get an ```Internal Server Error```. 
1. Intercept the request with Burp Suite proxy
2. Send the request to repeater
3. Start by injecting the category parameter with ```Gifts'+UNION+SELECT+NULL--``` which will return an error
4. And then ```'UNION+SELECT+NULL,NULL--``` which will also return an error
5. And finally ```'UNION+SELECT+NULL,NULL,NULL--``` which will output the results of the original query <br/>
```SELECT * FROM products WHERE category = 'Gifts'```
7. The number of columns is then ```3```

### Automated:
* Refer to https://github.com/YounesTasra-R4z3rSw0rd/Web-Security-Academy/blob/main/SQL%20Injection/Lab%233/Lab-3.py
* Requirements:
```bash
pip3 install -m requirements.txt
```
* Help Menu: 
```bash
$ python3 Lab-3.py --help
usage: Lab-1.py [-h] -u URL [-n]

Usage Example: python3 Lab-3.py --url https://0a2100.web-security-academy.net/ --no-proxy

options:
  -h, --help         show this help message and exit
  -u URL, --url URL  Enter the Lab URL
  -n, --no-proxy     Do not use proxy                               
```

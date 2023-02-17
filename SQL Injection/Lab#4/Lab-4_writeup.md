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
> :memo: **Note:** The goal of this lab is to figure out the number of columns returned by the query and then probing each column to test whether it can hold a specific string data, given in the Lab.<br/>
> To do so, we will incrementally submit a series of ```UNION SELECT``` payloads that place the string value into each column in turn until we no longer get an ```Internal Server Error```. 

#### Determining the number of columns: 
1. Intercept the request with Burp Suite proxy,
2. Send the request to repeater,
3. Start by injecting the category parameter with ```Gifts'+UNION+SELECT+NULL--``` which will return an error
4. And then ```'UNION+SELECT+NULL,NULL--``` which will also return an error
5. And finally ```'UNION+SELECT+NULL,NULL,NULL--``` which will output the results of the original query <br/>
```SELECT * FROM products WHERE category = 'Gifts'```
6. The number of columns is then ```3```

#### Finding a columns containing text:
1. Copy the string given in the Lab:




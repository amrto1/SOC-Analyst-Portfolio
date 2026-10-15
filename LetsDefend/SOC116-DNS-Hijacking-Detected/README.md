# SOC116 – DNS Hijacking Detected — Event ID 49

## 1. Alert Overview

| Field | Value |
|---|---|
| Event ID | `49` |
| Alert Time | `2021-02-06 12:42:07 +03:00` |
| Alert Rule | `SOC116 – DNS Hijacking Detected` |
| Alert Type | Malware |
| Hostname | `WilsonPRD` |
| Source IP | `172.16.17.34` |
| Suspicious IP | `49.233.160.217` |
| File | `update.py` |
| File MD5 | `307b47d1217f267a47cee8dd86c2f191` |
| File Size | `1.28 KB` |
| Device Action | **Allowed** |

## 2. Investigation Findings

### 2.1. Initial VirusTotal Check

The MD5 hash lookup on VirusTotal appeared clean and did not provide a clear malicious verdict. Since a clean hash-reputation result does not prove that a file is harmless, we continued with behavioral and endpoint investigation.

![VirusTotal hash lookup](screenshots/virustotal-hash.png)

### 2.2. Source Code Analysis

Reviewing `update.py` revealed that it appends this mapping to the Windows hosts file:

```python
f = open("C:\Windows\System32\drivers\etc\hosts", "a")
f.write("49.233.160.217 github.com")
```

This maps `github.com` to `49.233.160.217` through local name resolution. Consequently, visits to GitHub from the affected system could be redirected to the unexpected IP address without changing the public DNS records.

![update.py source code](screenshots/update-source_code.png)

### 2.3. Network Investigation

Log Management recorded traffic from `172.16.17.34` to `49.233.160.217:443`:

| Log Source | Timestamp | Source Port | Destination |
|---|---|---:|---|
| Firewall | `11:42:21` | `23512` | `49.233.160.217:443` |
| Proxy | `11:43:38` | `53211` | `49.233.160.217:443` |

The records associate the traffic with `https://github.com`. Endpoint Network Action also records connections to the same IP at 12:42, 12:43, and 12:44. Together, these logs confirm communication with the suspicious destination and are consistent with the redirection described in the script.

![Log Management records](screenshots/logs.png)

![Endpoint Network Actions](screenshots/net-action.png)

### 2.4. Endpoint and Browser Correlation

Terminal History shows `whoami` at 12:42, `python` at 12:43, and execution of `update.py` at 12:44. Browser History shows visits to GitHub's homepage, login page, and pull requests page between 12:42 and 12:44.

The execution record links the script to the endpoint, while the browser history is consistent with GitHub activity during the network events. Browser history alone does not establish that credentials were entered or stolen.

![Terminal History](screenshots/terminal-history.png)

![Browser History](screenshots/browser-history.png)

### 2.5. Timestamp Discrepancy

Log Management timestamps are approximately one hour earlier than the Endpoint Network Action, Terminal History, and Browser History records. The available evidence does not establish the cause, so the discrepancy is noted rather than assuming a specific time-zone or logging issue.

## 3. Playbook Investigation

### 3.1. Define Threat Indicator

**Answer: Unknown or unexpected outgoing internet traffic**

The endpoint communicated with the unexpected destination `49.233.160.217`, which was associated with the suspected GitHub redirection.

### 3.2. Check Whether the Malware Was Quarantined/Cleaned

**Answer: Not Quarantined**

The alert shows `Device Action: Allowed`. The evidence reviewed does not show a subsequent successful quarantine or cleanup action.

### 3.3. Analyze Malware

**Answer: Malicious**

The script modifies the Windows hosts file to map `github.com` to an unexpected IP address, supporting the DNS-hijacking finding despite the initially clean VirusTotal hash result.

### 3.4. Check If Someone Requested the C2

**Answer: Accessed**

The network records show the endpoint connecting to `49.233.160.217:443`. This supports that the destination was accessed; the supplied logs alone do not prove that it functioned as a command-and-control server.

## 4. Final Assessment

**Final Verdict: True Positive.**

The initially clean VirusTotal result did not reveal the script's behavior. Source-code analysis identified a hosts-file mapping that redirects `github.com` to `49.233.160.217`; endpoint and network records then showed script execution and communication with that destination alongside GitHub browsing activity.

The alert's device action was **Allowed**. The available evidence does not confirm successful containment or cleanup, credential theft, or that the destination served as a C2 server.

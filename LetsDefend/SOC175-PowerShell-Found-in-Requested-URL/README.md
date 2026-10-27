# SOC175 – PowerShell Found in Requested URL – Possible CVE-2022-41082 Exploitation

## 1. Alert Overview

| Field | Value |
|---|---|
| Alert ID | SOC175 |
| Event ID | 125 |
| Severity | High |
| Alert Type | Web Attack |
| Event Time | 2022-09-30 07:19:10 +03:00 |
| Source IP | `58.237.200.6` |
| Destination IP | `172.16.20.8` |
| Destination Host | Exchange Server 2 |
| Log Source | IIS |
| HTTP Method | GET |
| User-Agent | `Mozilla/5.0 zgrab/0.x` |
| Device Action | Blocked |
| MITRE ATT&CK | T1190 – Exploit Public-Facing Application |
| Final Verdict | True Positive – Unsuccessful Attack |

## 2. Investigation

### Step 1: Analyze the Alert Trigger

The alert was triggered because the HTTP request URL contained the word `PowerShell`.

The request targeted the Exchange Autodiscover endpoint. Its query string contained unusual routing-like text and a parameter named `FooProtocol` with the value `Powershell`.

This pattern raised suspicion of a potential Microsoft Exchange exploitation attempt associated with CVE-2022-41082 and ProxyNotShell. The URL alone does not prove that PowerShell commands were executed.

### Step 2: Analyze the Source IP

The source IP address `58.237.200.6` was checked using threat-intelligence sources, including VirusTotal and AbuseIPDB.

According to the lab's investigation notes, the IP was associated with malicious activity and had been reported by other users on AbuseIPDB. This supported treating the request as suspicious rather than as a legitimate or authorized scan.

### Step 3: Check for a Planned Test

No evidence of an authorized test was identified in the provided investigation results. The reported threat-intelligence findings also supported treating the activity as unplanned.

**Outcome:** Not Planned.

### Step 4: Review Related Activity

The source IP was searched in Endpoint Security and Mailbox, but no results were found.

Log Management showed three HTTP GET requests from `58.237.200.6` to Exchange Server `172.16.20.8` over HTTPS.

| Timestamp | Request summary | Device Action |
|---|---|---|
| 2022-09-30 06:17:23 | Request to the Exchange Autodiscover endpoint | Blocked |
| 2022-09-30 06:18:07 | Autodiscover request containing an EWS path | Blocked |
| 2022-09-30 06:19:10 | Autodiscover request containing a PowerShell-related parameter | Blocked |

All three requests were recorded as blocked, including the request that triggered SOC175.

No related Endpoint Security or Mailbox results were found during the investigation.

### Step 5: Determine Whether the Attack Succeeded

The alert details and corresponding Log Management records showed that the requests were blocked.

No evidence of successful PowerShell execution or subsequent compromise was identified in the available investigation results.

The lack of related Endpoint Security events alone does not prove that exploitation failed. However, the recorded blocking actions across all three requests support the conclusion that the observed attack attempt was unsuccessful.

**Outcome:** Attack Unsuccessful.

### Step 6: Determine the Traffic Direction and Attack Type

The traffic originated from an external IP address and targeted an internal Exchange server.

- **Traffic Direction:** Internet → Company Network
- **Planned Test:** No
- **Traffic Classification:** Malicious
- **Attack Type:** Other
- **Tier 2 Escalation:** No, according to the playbook answers

## 3. Final Verdict

**True Positive – Malicious Exchange Exploitation Attempt, Blocked.**

The suspicious Autodiscover request contained a PowerShell indicator and a URL structure consistent with a potential Exchange exploitation attempt. Threat-intelligence findings supported classifying the source IP as malicious, and Log Management showed that all three observed requests were blocked.

The available evidence supports a true-positive classification for malicious activity, while the recorded blocking actions and absence of identified compromise evidence support the conclusion that the attack was unsuccessful.

The investigation did not establish that CVE-2022-41082 exploitation or PowerShell execution occurred successfully.

## 4. Evidence

Screenshots referenced in this case:

- `screenshots/log-management.png` — Overview of the three requests and their timestamps.
- `screenshots/raw-log1.png` — Raw log for the first Autodiscover request.
- `screenshots/raw-log2.png` — Raw log for the request containing the EWS path.
- `screenshots/raw-log3.png` — Raw log for the request containing the PowerShell-related parameter and the recorded blocked action.

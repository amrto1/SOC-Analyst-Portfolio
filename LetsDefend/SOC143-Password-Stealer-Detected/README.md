# SOC143 - Password Stealer Detected

## 1. Alert Overview

| Field | Details |
|---|---|
| Event ID | 90 |
| Alert Name | SOC143 - Password Stealer Detected |
| Event Time | 2021-04-26 23:03:14 +03:00 |
| Alert Type | Exchange |
| Difficulty | Beginner |
| Source Address | `bill@microsoft.com` |
| Destination Address | `ellie@letsdefend.io` |
| Sender IP | `180.76.101.229` |
| Email Subject | `.` |
| Device Action | Allowed |
| Attachment | `svgbd05664f01205fa90774f42468a8743a` |
| Attachment MD5 | `bd05664f01205fa90774f42468a8743a` |

## 2. Executive Summary

An email claiming to originate from `bill@microsoft.com` was sent to `ellie@letsdefend.io` with an HTML attachment associated with the MD5 hash `bd05664f01205fa90774f42468a8743a`.

File analysis associated the attachment with a credential-phishing scenario involving a deceptive Microsoft sign-in page and a suspicious submission endpoint hosted under `tecyardit.com`.

The email was delivered to the recipient, and the attachment and associated URL were classified as malicious. No access to `tecyardit.com` was found in the available raw logs. The evidence supports classifying the email as malicious, but does not confirm successful credential submission or theft.

## 3. Evidence Collection

### 3.1. Email Security

The email-security record contained the following details:

- **Sender:** `bill@microsoft.com`
- **Recipient:** `ellie@letsdefend.io`
- **Sender IP:** `180.76.101.229`
- **Subject:** `.`
- **Final Action:** `Unknown`

The alert recorded the device action as `Allowed`, while the email-security table showed the final action as `Unknown`. The message was recorded as delivered to the recipient.

![Email Security Evidence](screenshots/email-security.png)

### 3.2. File Reputation

The attachment was identified by the MD5 hash:

```
bd05664f01205fa90774f42468a8743a
```

The analyzed file was associated with an HTML page imitating a Microsoft sign-in experience. This behavior is consistent with credential phishing, in which a user is deceived into entering account credentials into a fraudulent page.

![File Reputation Evidence](screenshots/file-repu.png)

### 3.3. URL Reputation

The suspicious URL associated with the suspected credential-submission endpoint was:

`https://tecyardit.com/wp-content/card/2/post.php`

The URL was identified as malicious during the investigation. Its presence supports the assessment that the attachment was designed to direct users to suspicious infrastructure. URL reputation alone does not establish that credentials were successfully transmitted.

![URL Reputation Evidence](screenshots/URL-repu.png)

## 4. ANY.RUN Sandbox Analysis

### 4.1. Dropbox User Content Domain

- **Process:** `msedge.exe`
- **Process ID:** `3016`
- **Classification:** `Misc activity`
- **Detection:** `ET INFO DropBox User Content Domain (dl.dropboxusercontent.com in TLS SNI)`

This detection indicates that `dl.dropboxusercontent.com` appeared in the TLS Server Name Indication (SNI). It identifies a hostname associated with a TLS connection but does not, by itself, prove that a file was downloaded or that the connection was malicious.

### 4.2. Microsoft Dr. Watson User-Agent

- **Process:** `svchost.exe`
- **Process ID:** `7984`
- **Classification:** `Unknown Traffic`
- **Detection:** `ET USER_AGENTS Microsoft Dr Watson User-Agent (MSDW)`

This signature identifies an HTTP User-Agent pattern associated with Microsoft Dr. Watson. It does not independently prove that a crash occurred or that the process performed credential theft.

![ANY.RUN Network Threats](screenshots/any-run.png)

### 4.3. Browser Activity and Suspicious Endpoint

The sandbox screenshot shows Microsoft Edge displaying:

`https://tecyardit.com/wp-content/card/2/post.php`

The browser displayed `DNS_PROBE_FINISHED_NXDOMAIN`, indicating that the hostname could not be resolved at the time shown.

![ANY.RUN Browser Activity](screenshots/any-run2.png)

This screenshot documents a browser navigation attempt to the suspicious endpoint within the sandbox. The DNS error does not establish whether an earlier HTTP POST request succeeded or whether credentials reached the server.

The Dr. Watson User-Agent detection and the DNS error are separate observations. The available evidence does not establish that they were directly related; the detections refer to different processes, and additional connection details and timestamp correlation would be required to link them.

## 5. Investigation Findings

| Finding | Assessment |
|---|---|
| Email containing a suspicious attachment | Observed |
| Email delivered to the intended recipient | Confirmed in the email investigation |
| Attachment associated with an HTML credential-phishing page | Supported by file analysis |
| Microsoft sign-in impersonation | Supported by the analyzed page |
| Suspicious credential-submission endpoint | Identified |
| Dropbox hostname in TLS SNI | Observed; purpose not established |
| Dr. Watson User-Agent signature | Observed; significance not established |
| Access to `tecyardit.com` in the available raw logs | Not found |
| Successful credential submission | Not confirmed |
| Successful credential theft or exfiltration | Not confirmed |

## 6. Playbook Execution

### Step 1: Check If Someone Opened the Malicious File/URL

**Result:** Not Opened

No access to `tecyardit.com` was found in the available raw logs.

![Log Management Evidence](screenshots/log-management.png)

The absence of requests to the suspicious domain in the reviewed logs supports the conclusion that no access was observed in those logs. It does not independently prove that the attachment was never opened, because opening a local HTML file may not generate a request to the suspected endpoint.

### Step 2: Check If Mail Delivered to User

**Result:** Delivered

The email was delivered to the intended recipient, `ellie@letsdefend.io`.

### Step 3: Analyze URL/Attachment

**Result:** Malicious

The attachment and associated URL were classified as malicious. The analyzed HTML page was associated with a credential-phishing scenario involving a deceptive Microsoft sign-in page and a suspicious submission endpoint.

### Step 4: Check for Attachments or URLs in the Email

**Result:** Yes

The email contained an HTML attachment associated with the MD5 hash `bd05664f01205fa90774f42468a8743a`.

## 7. Final Verdict

**True Positive — Malicious credential-phishing email.**

The email was delivered to the intended recipient and contained an attachment associated with a deceptive Microsoft sign-in page and a suspicious credential-submission endpoint. File and URL analysis support the malicious classification.

No access to `tecyardit.com` was found in the available raw logs, and successful credential submission or theft was not confirmed. The Dropbox SNI and Microsoft Dr. Watson User-Agent detections provide additional sandbox context but are not independent proof of credential theft.

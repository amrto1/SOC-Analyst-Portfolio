# SOC101 – Phishing Mail Detected

## 1. Alert Overview

| Field | Value |
|---|---|
| Alert | SOC101 – Phishing Mail Detected |
| Event ID | `41` |
| Alert time | `2021-01-02 15:39:43 +03:00` |
| Alert type | Exchange |
| MITRE ATT&CK shown in alert | `T1053.005` |
| Sender | `david@cashbank.com` |
| Recipient | `mark@letsdefend.io` |
| Subject | `Credit Card Statement` |
| Sender IP / SMTP address | `104.140.188.46` |
| Device action | **Blocked** |

## 2. Email Investigation

Email Security showed a message from `david@cashbank.com` to `mark@letsdefend.io` with the subject **Credit Card Statement** and body text: “Your credit card statement is attached.”

The Email Security screenshot shows the attachment label as `9ed9ad87a1564fbb5e1b652b3e7148c8`. The lab download URL refers to `9ed9ad87a1564fbb5e1b652b3e7148c8.zip`; the archive password provided by the lab was `infected`. Earlier notes used the label `svg9ed9ad87a1564fbb5e1b652b3e7148c8`, so the exact attachment display name is not fully consistent across the available records.

### Sender reputation

The walkthrough reports that the sender IP had poor email reputation in Cisco Talos. Its checks for `cashbank.com` also reported no MX record and no visible SPF/DNS or DMARC record. These are the results described by the walkthrough and should not be treated as a current DNS assessment.

![Email Security record for the Credit Card Statement message](screenshots/02-email-details.png)

Email Security also showed an older message using the same sender address, sent to another recipient in September 2020 from a different IP. This is relevant context, but by itself does not prove the two emails belonged to the same campaign.

## 3. VirusTotal Analysis

The supplied VirusTotal screenshot shows **47/71 security vendors** flagging an executable whose displayed filename is `3cc33ce58536242bc9b2029cd9475a287351a379ccbd12da6b8b7bf2cc68be89.exe`. The page labels the sample with `trojan.bitsaloa/phoenixminer` and the categories `trojan`, `downloader`, and `miner`.

![VirusTotal detection summary for the executable sample](screenshots/03-virustotal-file.png)

**Evidence limitation:** this screenshot is for an executable sample, not an identifiable hash for the email attachment itself. The reviewed evidence does not establish that this executable is identical to the attached ZIP/sample. Therefore, the 47/71 result supports the malicious classification of the displayed executable, but is not represented as a direct hash verdict for the email attachment. 

## 4. Network Log Correlation

Log Management recorded the following Exchange event:

| Field | Value |
|---|---|
| Log time as displayed | `2021-01-02 14:39:53` |
| Type | Exchange |
| Source IP | `104.140.188.46` |
| Source port | `53918` |
| Destination IP | `172.16.20.3` |
| Destination port | `25` |
| Raw log | `Sender Mail: david@cashbank.com Destination Mail: mark@letsdefend.io` |

The source IP and email addresses correspond to the alerted message. Destination port 25 is consistent with SMTP. The log records `172.16.20.3` as the destination; available evidence does not identify it as Mark's workstation.

![Exchange log row for the message](screenshots/04-smtp-logs.png)

The raw log expands the row's mail fields and confirms the sender and destination email addresses:

![Raw Exchange log fields](screenshots/05-raw-exchange-log.png)

**Timestamp note:** The alert shows `15:39:43 +03:00`, while Email Security and Log Management show approximately `14:39:43` and `14:39:53`. The records do not explain this one-hour difference, so the displayed times are preserved as supplied.

## 5. Delivery Status

The alert's `Device Action` was **Blocked**. The lab walkthrough's playbook check also interprets this as the email not being delivered to Mark.

This supports that the message was blocked at the mail-security stage. It does not prove the file was never opened or executed anywhere else, nor does it establish endpoint compromise. No endpoint execution evidence for Mark was established in the reviewed material.

## 6. Indicators and Observables

| Type | Value | Context |
|---|---|---|
| Sender email | `david@cashbank.com` | Displayed sender |
| Recipient email | `mark@letsdefend.io` | Intended recipient |
| Sender IP | `104.140.188.46` | Correlated across alert and logs |
| Subject | `Credit Card Statement` | Alerted message |
| Attachment label | `9ed9ad87a1564fbb5e1b652b3e7148c8` | As visible in the supplied Email Security screenshot |
| Alternate attachment label | `svg9ed9ad87a1564fbb5e1b652b3e7148c8` | Present in earlier lab notes; exact display label is inconsistent |
| ZIP archive basename | `9ed9ad87a1564fbb5e1b652b3e7148c8.zip` | Lab download URL |
| SHA-256 of VirusTotal executable | `3cc33ce58536242bc9b2029cd9475a287351a379ccbd12da6b8b7bf2cc68be89` | Executable sample shown in VirusTotal; not confirmed as the attachment's hash |

The lab's sample-download host is recorded as sample provenance, not automatically classified as attacker-controlled infrastructure.

## 7. Final Assessment

**True Positive – phishing email blocked before delivery to the intended recipient, with an associated executable sample flagged as malicious in VirusTotal.**

The sender-reputation observations, the email context, the malicious executable sample shown in VirusTotal, and the lab's final verdict support classifying this alert as a true positive. The VirusTotal screenshot does not establish that the displayed executable is the same file as the email attachment. Successful execution, persistence, or compromise of Mark's endpoint was **not established**.

## 8. ATT&CK Mapping Note

The alert displays `T1053.005`; this value is preserved exactly as shown. Because this is an email-phishing alert, validate the technique mapping against the source rule rather than assuming it describes the activity observed. No replacement technique is asserted here.

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

The displayed attachment name was `svg9ed9ad87a1564fbb5e1b652b3e7148c8`. The lab sample was provided inside a ZIP archive whose URL basename was `9ed9ad87a1564fbb5e1b652b3e7148c8.zip`; the lab-provided archive password was `infected`.

### Sender reputation

The walkthrough reports that the sender IP had poor email reputation in Cisco Talos. Its checks for `cashbank.com` also reported no MX record and no visible SPF/DNS or DMARC record. These are the results described by the walkthrough and should not be treated as a current DNS assessment.

Email Security also showed an older message using the same sender address, sent to another recipient in September 2020 from a different IP. This is relevant context, but by itself does not prove the two emails belonged to the same campaign.

## 3. Attachment Analysis

The attachment was assessed as malicious during the lab. The walkthrough reports a VirusTotal result of **50/70** detections; this number is attributed to the walkthrough and was not independently re-verified here.

The walkthrough's sandbox analysis described suspicious downloader behavior and referenced `certutil`, PowerShell, `phoenixminer.exe`, Quasar RAT, evasion-related behavior, and GitHub-hosted URLs. These are sample-analysis observations reported by the walkthrough. They do **not** prove that the attachment executed on Mark's endpoint. A sandbox screenshot showed an error while opening the file, which must not be mistaken for evidence of successful execution on the recipient's workstation.

No file hash or exact GitHub URL was available in the reviewed records, so neither is fabricated in this report.

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
| Attachment display name | `svg9ed9ad87a1564fbb5e1b652b3e7148c8` | As displayed in Email Security |
| ZIP archive basename | `9ed9ad87a1564fbb5e1b652b3e7148c8.zip` | Lab download URL |

The lab's sample-download host is recorded as sample provenance, not automatically classified as attacker-controlled infrastructure.

## 7. Playbook Result

According to the lab walkthrough:

1. The attachment/URL assessment was **malicious**.
2. The email was **not delivered**, as indicated by the blocked action.
3. The final playbook verdict was **True Positive**.

## 8. Final Assessment

**True Positive – phishing email containing a malicious attachment, blocked before delivery to the intended recipient.**

The sender-reputation observations, malicious sample assessment, and lab playbook result support the alert classification. However, successful execution, persistence, or compromise of Mark's endpoint was **not established**. Sandbox behavior is kept separate from endpoint evidence.

## 9. Recommended Response Actions

- Retain the message and sample in a controlled analysis environment.
- Review mail telemetry for other messages using the same sender, IP, subject, or attachment identifier.
- Block or quarantine the confirmed malicious sample and use the observed sender indicators in appropriate mail-security controls.
- Review sender authentication and suspicious messages claiming to originate from `cashbank.com`.
- If later evidence indicates delivery or execution, investigate the relevant endpoint separately for process, network, and persistence activity.

## 10. ATT&CK Mapping Note

The alert displays `T1053.005`; this value is preserved exactly as shown. Because this is an email-phishing alert, validate the technique mapping against the source rule rather than assuming it describes the activity observed. No replacement technique is asserted here.

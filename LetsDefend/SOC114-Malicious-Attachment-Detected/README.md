# SOC114 – Malicious Attachment Detected

## Alert Details

| Field | Value |
|---|---|
| Event ID / Time | `45` / `2021-01-31 15:48:30 +03:00` |
| Severity / Type | High / Exchange |
| Sender | `accounting@cmail.carleton.ca` |
| Recipient | `richard@letsdefend.io` |
| Subject | Invoice |
| Sender IP | `49.234.43.39` |
| Device Action | Allowed |
| Final Result | True Positive |

## Investigation

Email Security showed an invoice-themed message with an attachment. The playbook confirmed that the email was **Delivered** and that the recipient **Opened** the malicious file or URL.

![Email Security record](screenshots/01-email-details.webp)

VirusTotal showed **37/62 detections** for the analyzed spreadsheet sample, with phishing/downloader labels and a `CVE-2017-11882` tag.

![VirusTotal spreadsheet report](screenshots/02-virustotal-attachment.webp)

Endpoint Security browser history on `RichardPRD` (`172.16.17.45`) recorded access to `andaluciabeach.net/image/network.exe` at `2021-01-31 16:15`. The supplied VirusTotal URL report showed **10/91 detections** and resolved the domain to `70.38.21.234`. This report was generated years after the incident, so it is not treated as a reputation snapshot from the event date.

![Endpoint browser history](screenshots/03-browser-history.webp)

![VirusTotal URL report](screenshots/04-virustotal-url.webp)

A process record on `RichardPRD` showed `JuicyPotato.exe` at `C:/User/Public/JuicyPotato.exe`, running as `NT Authority/System` at `2021-01-31 16:20`. Its VirusTotal report showed **58/71 detections** and a JuicyPotato-related label.

![Endpoint process evidence](screenshots/05-endpoint-process.webp)

![VirusTotal JuicyPotato report](screenshots/06-virustotal-juicypotato.webp)

The screenshots do not establish that the spreadsheet, the downloaded executable, and the later process are the same file or prove a complete execution chain. The process record lacks a PID, parent process, and command line.

## Playbook Results

| Check | Result |
|---|---|
| Attachments or URLs present | **Yes** |
| Analyze URL/Attachment | **Malicious** |
| Mail delivered | **Delivered** |
| Malicious file/URL opened | **Opened** |
| Playbook score | **20/20 (100%)** |
| Final verdict | **True Positive** |

## Final Assessment

**True Positive — phishing email delivered and opened, with malicious attachment/URL findings and suspicious endpoint activity.** The supplied evidence supports the lab verdict, but does not independently establish the full relationship between the email attachment, URL access, and later SYSTEM-level process.

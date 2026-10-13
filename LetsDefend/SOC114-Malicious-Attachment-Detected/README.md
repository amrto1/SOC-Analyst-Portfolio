# SOC114 – Malicious Attachment Detected

## Alert Details

| Field | Value |
|---|---|
| Event ID / Time | `45` / `2021-01-31 15:48:30 +03:00` |
| Severity / Type | High / Exchange |
| Sender / Recipient | `accounting@cmail.carleton.ca` → `richard@letsdefend.io` |
| Subject | Invoice |
| Sender IP | `49.234.43.39` |
| Device Action | **Allowed** |
| MITRE ATT&CK shown in alert | `T1598.001` |

## Investigation

- **Email:** Invoice-themed message with an attachment. The playbook confirmed it was **Delivered** and the malicious file/URL was **Opened**.
- **Attachment analysis:** VirusTotal showed **37/62 detections** for the analyzed spreadsheet sample, tagged with phishing/downloader indicators and `CVE-2017-11882`.
- **URL access:** Browser history on `RichardPRD` (`172.16.17.45`) showed `andaluciabeach.net/image/network.exe` at `2021-01-31 16:15`. The supplied VirusTotal URL report showed **10/91 detections** and resolved the domain to `70.38.21.234`. This report dates from 2026, so it is not a reputation snapshot from the incident date.
- **Endpoint process:** At `2021-01-31 16:20`, `JuicyPotato.exe` was listed at `C:/User/Public/JuicyPotato.exe` running as `NT Authority/System`. Its VirusTotal report showed **58/71 detections** and a JuicyPotato-related label.

The screenshots do not establish that the email attachment, the downloaded executable, and the later process are the same file or prove a complete execution chain. The process record lacks a PID, parent process, and command line.

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

**True Positive — phishing email delivered and opened, with malicious attachment/URL findings and suspicious endpoint activity.** The lab evidence supports the verdict, but does not independently prove the full relationship between the attachment, URL access, and later SYSTEM-level process.

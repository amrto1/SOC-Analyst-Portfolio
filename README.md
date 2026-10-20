# SOC Analyst Portfolio

A collection of hands-on SOC investigations and blue-team labs.

## LetsDefend

| Event ID | Alert | Focus | Verdict | Write-up |
|---:|---|---|---|---|
| 74 | SOC136 – Data Leak via Mailbox Forwarding Detected | Email security review, credential disclosure, external recipient, threat-intelligence context | True Positive | [Read case study](LetsDefend/SOC136-Data-Leak-via-Mailbox-Forwarding-Detected/README.md) |\n| 72 | SOC135 – Multiple FTP Connection Attempt | FTP authentication log review, password-guessing behavior, playbook assessment | True Positive | [Read case study](LetsDefend/SOC135-Multiple-FTP-Connection-Attempt/README.md) |
| 71 | SOC134 – Suspicious WMI Activity | WMI command analysis, endpoint process review, historical Proxy/C2 evidence, playbook assessment | True Positive | [Read case study](LetsDefend/SOC134-Suspicious-WMI-Activity/README.md) |
| 69 | SOC133 – Suspicious Request to New Registered Domain | Firewall/Proxy log review, URL/IP reputation, WHOIS registration context, playbook assessment | False Positive | [Read case study](LetsDefend/SOC133-Suspicious-Request-to-New-Registered-Domain/README.md) |
| 67 | SOC131 – Reverse TCP Backdoor Detected | Extracted-string analysis, Python reverse shell, C2 assessment, PowerShell downloader hypothesis | True Positive | [Read case study](LetsDefend/SOC131-Reverse-TCP-Backdoor-Detected/README.md) |
| 66 | SOC102 – Proxy: Suspicious URL Detected | Proxy log review, URL/IP reputation, endpoint review, playbook assessment | False Positive | [Read case study](LetsDefend/SOC102-Proxy-Suspicious-URL-Detected/README.md) |
| 64 | SOC130 – Event Log Cleared | PowerShell process review, file hash reputation, ANY.RUN behavior analysis, Event Log clearing playbook | False Positive | [Read case study](LetsDefend/SOC130-Event-Log-Cleared/README.md) |
| 63 | SOC129 – Successful Local File Inclusion | LFI/path traversal, Proxy log analysis, HTTP 404 investigation, playbook assessment | True Positive | [Read case study](LetsDefend/SOC129-Successful-Local-File-Inclusion/README.md) |
| 62 | SOC128 – Malicious File Upload Attempt | PHP web shell analysis, Filescan/YARA findings, Proxy-to-endpoint command correlation | True Positive | [Read case study](LetsDefend/SOC128-Malicious-File-Upload-Attempt/README.md) |
| 61 | SOC126 – Suspicious New Autorun Value Detected | Quasar RAT analysis, autorun persistence, Registry tracing settings, process/file and network activity | True Positive | [Read case study](LetsDefend/SOC126-Suspicious-New-Autorun-Value-Detected/README.md) |
| 60 | SOC127 – SQL Injection Detected | Proxy log analysis, SQL injection payload review, playbook investigation | False Positive | [Read case study](LetsDefend/SOC127-SQL-Injection-Detected/README.md) |
| 58 | SOC125 – Suspicious Rundll32 Activity | Suspicious rundll32 command, proxy log analysis, Emotet sandbox investigation, Registry proxy-setting modification | True Positive | [Read case study](LetsDefend/SOC125-Suspicious-Rundll32-Activity/README.md) |
| 57 | SOC124 – Scheduled Task Created | Scheduled task review, file hash reputation, endpoint terminal history, historical log review | False Positive | [Read case study](LetsDefend/SOC124-Scheduled-Task-Created/README.md) |
| 56 | SOC123 – Enumeration Tool Detected | Proxy log analysis, Linux enumeration script review, terminal-history correlation, sandbox analysis | True Positive | [Read case study](LetsDefend/SOC123%E2%80%93Enumeration-Tool-Detected/README.md) |
| 54 | SOC108 – Malicious Remote Access Software Detected (TeamViewer Website Access) | Proxy logs, URL and IP reputation, legitimate remote-access website review | False Positive | [Read case study](LetsDefend/SOC108-TeamViewer-Website-Access/README.md) |
| 53 | SOC121 – Proxy: Malicious Executable File Detected | Proxy log triage, URL/IP reputation, file relationships, sandbox analysis | True Positive | [Read case study](LetsDefend/SOC121-Proxy-Malicious-Executable-File-Detected/README.md) |
| 51 | SOC118 – Internal Port Scan Activity | File reputation, endpoint process review, internal firewall port-scan correlation | True Positive | [Read case study](LetsDefend/SOC118-Internal-Port-Scan-Activity/README.md) |
| 49 | SOC116 – DNS Hijacking Detected | VirusTotal triage, Python source analysis, hosts-file redirection, network correlation | True Positive | [Read case study](LetsDefend/SOC116-DNS-Hijacking-Detected/README.md) |
| 48 | SOC107 – Privilege Escalation Detected (JuicyPotato) | Suspicious download, URL reputation, SYSTEM-level process analysis | True Positive | [Read case study](LetsDefend/SOC107-Privilege-Escalation-Detected/README.md) |
| 47 | SOC115 – Wscript.exe Usage as Dropper | Script analysis and endpoint investigation | True Positive | [Read case study](LetsDefend/SOC115-Wscript.exe-Usage-as-Dropper/README.md) |
| 45 | SOC114 – Malicious Attachment Detected | Phishing email review, malicious attachment/URL analysis, browser and endpoint evidence | True Positive | [Read case study](LetsDefend/SOC114-Malicious-Attachment-Detected/README.md) |
| 44 | SOC113 – Suspicious hh.exe Usage | CHM file analysis, process investigation, file reputation, historical log review | False Positive | [Read case study](LetsDefend/SOC113-Suspicious-hh.exe-Usage/README.md) |
| 43 | SOC112 – Traffic to Blacklisted IP | Proxy log analysis, URL reputation, threat intelligence, containment | True Positive | [Read case study](LetsDefend/SOC112-Traffic-to-Blacklisted-IP/README.md) |
| 41 | SOC101 – Phishing Mail Detected | Email analysis, sender reputation, malicious attachment triage, SMTP log correlation | True Positive | [Read case study](LetsDefend/SOC101-Phishing-Mail-Detected/README.md) |
| 39 | SOC109 – Emotet Malware Detected | Malware triage, PowerShell decoding and deobfuscation, network IOC analysis | True Positive | [Read case study](LetsDefend/SOC109-Emotet-Malware-Detected/README.md) |
| 38 | SOC108 – Malicious Remote Access Software Detected | Process review, network analysis, threat intelligence, playbook | False Positive | [Read case study](LetsDefend/SOC108-Malicious-Remote-Access-Software-Detected/README.md) |
| 31 | SOC104 – Malware Detected | Process and file analysis, VirusTotal, network-log correlation | True Positive | [Read case study](LetsDefend/SOC104-Malware-Detected/README.md) |
| 19 | SOC107 – Privilege Escalation Detected (creditcard) | Process timeline, malware reputation, privilege-escalation investigation | True Positive | [Read case study](LetsDefend/SOC107-Privilege-Escalation-Detected/README.md) |

All findings reflect the evidence available in each lab. Successful execution or containment is not claimed unless confirmed.

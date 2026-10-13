# SOC109 – Emotet Malware Detected

## 1. Alert Information

- **Alert:** Emotet Malware Detected
- **Severity:** Medium
- **Affected host:** `172.16.17.83`
- **User:** Maxim
- **Event ID:** `39`
- **Initial device action:** `Allowed`

![VirusTotal file detection](screenshots/01-virustotal-file.png)

## 2. File Analysis

- **Filename:** `MES 2020_12_31 S632974.doc`
- **MD5:** `eee99e6d8ade9463dd206dfbad3485ea`
- **SHA-1:** `204f560829a6d70f93ef6ce396d74f61423c13d7`
- **SHA-256:** `70450709057b656283751c362a7b72b9b0232ddd86f8482016ee85947392e27c`

VirusTotal flagged the document as malicious, with **51/63 security vendors** detecting it.

## 3. Process Analysis

The document was associated with a suspicious command launched through `cmd.exe`. The command displayed a fake Word error message and launched PowerShell in hidden mode using `-w hidden -ENCOD`.

### Command decoding

The Base64 payload was decoded to reveal the PowerShell script. Decoding exposed the script content, but the script remained obfuscated using string concatenation, character codes, format operators, and mixed casing.

![Process history](screenshots/02-process-tree.png)

### PowerShell deobfuscation and behavior

Reviewing the decoded script revealed that it:

- Dynamically reconstructed directory paths and external URLs.
- Set `$ErrorActionPreference` to `SilentlyContinue`, suppressing many visible errors.
- Used `System.Net.WebClient.DownloadFile` to **attempt** downloading a file.
- Checked whether the file was at least `39,163` bytes before **attempting** execution through `rundll32.exe`.

![Encoded command](screenshots/03-encoded-command.png)

![Decoded PowerShell](screenshots/04-decoded-powershell.png)

The code supports an intended download-and-execution chain, but the available evidence does not prove that the download or execution completed successfully.

## 4. Network Analysis

Proxy logs recorded HTTP GET requests from `172.16.17.83` to:

- `190.247.139.101`
- `152.170.79.100`

Both IPs were reported as malicious by VirusTotal. The logs confirm requests were made, but do not independently confirm successful downloads.

![Network connection history](screenshots/05-network-connections.png)

*Note: Add separate screenshots of the raw proxy GET requests and VirusTotal IP reputation if you captured them during the lab.*

## 5. Indicators of Compromise (IOCs)

| Type | Indicator |
|---|---|
| SHA-256 | `70450709057b656283751c362a7b72b9b0232ddd86f8482016ee85947392e27c` |
| IP address | `190.247.139.101` |
| IP address | `152.170.79.100` |
| Filename | `MES 2020_12_31 S632974.doc` |

## 6. Playbook Execution

1. **Threat indicator:** Unknown or unexpected outgoing internet traffic.
2. **Quarantine status:** **Not Quarantined**. The initial alert showed `Device Action: Allowed`.
3. **Malware analysis:** **Malicious** — VirusTotal detections and PowerShell behavior supported the finding.
4. **C2 access check:** **Accessed** — proxy logs recorded HTTP GET requests to the suspicious destinations.
5. **Containment:** The playbook directed the analyst to contain the host through EDR, but the recorded result was **Not Quarantined**. Successful containment is therefore not confirmed.

## 7. Final Verdict

**True Positive – Emotet-related malicious activity.**

The malicious document, obfuscated PowerShell behavior, and suspicious outbound requests support the alert classification. The malware was recorded as **Not Quarantined**, so containment should not be reported as successful.

## Investigation Notes

- A recorded outbound request does not by itself prove that a file was successfully downloaded.
- VirusTotal relation entries may include artifacts from other analyses; they should not automatically be treated as confirmed connections from this host.
- This write-up reflects the evidence available in the lab and avoids claiming successful execution or containment without confirmation.

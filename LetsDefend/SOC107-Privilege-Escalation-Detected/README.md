# SOC107 – Privilege Escalation Detected

## Alert Details

| Field | Value |
|---|---|
| Event ID | `19` |
| Time | `2020-09-22 15:40:22 +03:00` |
| Source host / IP | `KatharinePRD` / `172.16.15.78` |
| File | `creditcard` |
| File MD5 | `7299c49dd85069e47d6514ab5e10c264` |
| Size | `17 KB` |
| Device action | **Allowed** |
| MITRE ATT&CK shown in alert | `T1204` |

## Investigation

### Process timeline

Endpoint Security showed these two relevant processes:

| Time | Process | User | Path |
|---|---|---|---|
| 15:11 | `xfce4-terminal` | `katharine` | `/usr/bin/xfce4-terminal` |
| 15:12 | `creditcard` | `root` | `/home/katharine/Documents/creditcard` |

The terminal was running as `katharine`, then about a minute later `creditcard` appeared under `root`. This sequence is suspicious and consistent with a possible privilege-escalation attempt. However, neither process had a PID, parent process, or command line in the available record, so a direct parent-child relationship was not established.

![Endpoint Security process list](screenshots/02-processes.webp)

### File reputation

The VirusTotal screenshot for `creditcard` showed **40/63 detections**. The sample was tagged with `exploit` and `CVE-2017-16995`, supporting the malicious classification.

![VirusTotal file report](screenshots/01-virustotal.webp)

The alert's MD5 is `7299c49dd85069e47d6514ab5e10c264`. The VirusTotal page displayed a 64-character hash for the same `creditcard` filename and a size of 17.46 KB; the report records the values as shown rather than treating the displayed hash as the MD5.

## Playbook Results

| Check | Result |
|---|---|
| Threat indicator | **Other** |
| Malware quarantined/cleaned | **Not Quarantined** |
| Malware analysis | **Malicious** |
| C2 access check | **Accessed** |
| Containment | **Contained** |

The C2 check was marked **Accessed** in the completed lab playbook. The currently available evidence does not include the specific C2 address, so no address is inferred or added here.

## Final Verdict

**True Positive – malicious activity consistent with privilege escalation.** The key evidence is the `creditcard` process appearing under `root` shortly after `xfce4-terminal` was recorded under `katharine`, together with the malicious VirusTotal result. The missing process IDs, parent process, and command line limit how precisely the execution chain can be reconstructed.

# SOC107 – Privilege Escalation Detected (creditcard) — Event ID 19

## Alert Details

| Field | Value |
|---|---|
| Event ID / Time | `19` / `2020-09-22 15:40:22 +03:00` |
| Host / IP | `KatharinePRD` / `172.16.15.78` |
| File | `creditcard` |
| MD5 | `7299c49dd85069e47d6514ab5e10c264` |
| Size | `17 KB` |
| Device Action | **Allowed** |
| MITRE ATT&CK shown in alert | `T1204` |

## Key Process Evidence

| Time | Process | User |
|---|---|---|
| 15:11 | `xfce4-terminal` | `katharine` |
| 15:12 | `creditcard` | `root` |

**The important clue:** `xfce4-terminal` appeared under `katharine`; about a minute later, `creditcard` appeared under `root`. This is consistent with a possible privilege-escalation attempt. However, the records show no PID, parent process, or command line, so the direct execution chain is not confirmed.

The file path was `/home/katharine/Documents/creditcard`. VirusTotal showed **40/63 detections** and tagged the sample with `exploit` and `CVE-2017-16995`, supporting the malicious assessment.

## Playbook Results

| Check | Result |
|---|---|
| Threat indicator | **Other** |
| Quarantined/cleaned | **Not Quarantined** |
| Malware analysis | **Malicious** |
| C2 access | **Accessed** |
| Containment | **Contained** |
| Final verdict | **True Positive** |

The playbook recorded C2 access and successful containment. The specific C2 address was not included in the evidence available for this write-up, so no address is inferred.

## Final Assessment

**True Positive – malicious activity consistent with privilege escalation.** The strongest evidence is the change from a process recorded under `katharine` to `creditcard` recorded under `root`, alongside the malicious VirusTotal result. Because process IDs, parent process, and command line are missing, the exact escalation mechanism remains unconfirmed.

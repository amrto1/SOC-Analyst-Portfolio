# SOC126 - Suspicious New Autorun Value Detected

## Alert Overview

| Field | Details |
|---|---|
| Event ID | 61 |
| Alert Rule | SOC126 - Suspicious New Autorun Value Detected |
| Event Time | `2021-02-14 18:40:35 (UTC+03:00)` |
| Role | Security Analyst |
| Alert Type | Malware |
| Difficulty | Easy |
| MITRE ATT&CK | T1204 - User Execution |
| Source Host | `KatharinePRD` |
| Source IP | `172.16.15.78` |
| File Name | `OliwciaPrivInstaller.exe` |
| File Size | 348 KB |
| MD5 | `436fa243bbfed63a99b8e9f866cd80e5` |
| Device Action | **Cleaned** |
| Final Verdict | **True Positive** |

## 1. Investigation

The alert concerns `OliwciaPrivInstaller.exe`, identified in the [ANY.RUN public report](https://any.run/report/7a1ad31508f2ea1d7abc2907977eaf32537f09994d1622b3e2e733649905c861/efff3fb8-1641-41ba-b58e-f9d78cfd8f02) as a Quasar RAT sample.

The Log Management and Endpoint Security records available in the lab were not used as supporting evidence because their timestamps were too far from the alert time.

### 1.1. Behavior Activities

The ANY.RUN report recorded the following behaviors:

**Malicious**
- Changes the autorun value in the registry.
- Quasar was detected.
- Drops/copies Quasar RAT executable.

**Suspicious**
- Creates files in the user directory.
- Executable content was dropped or overwritten.
- Starts itself from another location.
- Checks for external IP.

These indicators show persistence-related activity, executable copying, and external IP checking. The report's behavior classifications are considered together with the process, registry, and network findings below.

### 1.2. Processes

| Process | PID | Finding |
|---|---:|---|
| `OliwciaPrivInstaller.exe` | 2608 | Original Quasar RAT sample |
| `cmd.exe` | 1448 | Copy of the sample running from another location |

The sample copied itself to:

```text
C:\Users\admin\AppData\Roaming\Microsoft\cmd.exe
```

The copied file had the same MD5 as the original sample. Despite the familiar `cmd.exe` name, the matching hash indicates that it was a copy of the malware, not the legitimate Windows Command Prompt.

### 1.3. Registry Activity

#### Autorun Persistence

**Registry key:**

```text
HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run
```

**Value name:** `Windows`

The report associated autorun modifications with both processes:

- `OliwciaPrivInstaller.exe` (PID 2608), pointing to:
  `C:\Users\admin\AppData\Local\Temp\OliwciaPrivInstaller.exe`
- `cmd.exe` (PID 1448), pointing to:
  `C:\Users\admin\AppData\Roaming\Microsoft\cmd.exe`

Values under the `Run` key are used to launch programs automatically when the user logs in. These entries therefore represent a persistence mechanism for the original sample and its copy.

#### Windows Tracing Configuration

The report also recorded changes under these keys:

```text
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Tracing\OliwciaPrivInstaller_RASAPI32
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Tracing\OliwciaPrivInstaller_RASMANCS
```

The relevant values included:

| Value name | Data | Meaning |
|---|---:|---|
| `EnableFileTracing` | `0` | File tracing disabled for the relevant component |
| `EnableConsoleTracing` | `0` | Console tracing disabled for the relevant component |

These settings affect specific diagnostic tracing mechanisms. They do **not** by themselves show that all Windows Event Logs or the EDR were disabled.

### 1.4. Files Activity

No additional significant file findings were identified beyond the copy of the sample described above. The copied executable used the name `cmd.exe` under the user's roaming profile, while its MD5 matched the original `OliwciaPrivInstaller.exe`.

### 1.5. Network Activity

The ANY.RUN analysis showed these destinations:

| Destination | Associated service/hostname | Observation |
|---|---|---|
| `208.95.112.1` | `ip-api.com` | External IP lookup |
| `193.161.193.99` | `jebacdisaskurwysyna-33409.portmap.io` | Potential C2-related endpoint |

The request to `ip-api.com` is consistent with checking the system's public IP address, which may be reconnaissance.

The second destination was treated as a potential Command and Control (C2) endpoint in the analysis. However, the presence of this endpoint in the sandbox report does not by itself establish successful C2 access in the LetsDefend alert scenario.

## 2. Playbook Investigation

### 2.1. Define Threat Indicator

**Answer:** Unknown or unexpected services and applications configured to launch automatically.

The unexpected autorun value indicates a potential persistence mechanism.

### 2.2. Check if the Malware Is Quarantined/Cleaned

**Answer:** Quarantined

The playbook result was `Quarantined`, and the alert's Device Action was `Cleaned`.

### 2.3. Analyze Malware

**Answer:** Malicious

The ANY.RUN report identified the sample as Quasar RAT and recorded autorun modifications, executable copying, and external IP checking.

### 2.4. Check If Someone Requested the C2

**Answer:** Not Accessed

The playbook result was `Not Accessed`. The potential C2 endpoint appears in the sandbox analysis, but the available LetsDefend resources did not indicate that it was accessed in the alert scenario.

## 3. Final Assessment

**Verdict: True Positive**

The alert is supported by the Quasar RAT classification, autorun persistence changes, and the creation of a second executable copy under a legitimate-looking name. The sample also changed specific tracing settings and checked the public IP, while the playbook indicated that the potential C2 was not accessed. The recorded device action was `Cleaned`.

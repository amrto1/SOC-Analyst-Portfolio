# SOC145 – Ransomware Detected

## 1. Alert Overview

| Field | Details |
|---|---|
| Event ID | 92 |
| Event Time | May 23, 2021 — 19:32:16 (UTC+3) |
| Rule Name | SOC145 – Ransomware Detected |
| Severity | Critical |
| Alert Type | Malware |
| Difficulty | Medium |
| Source Hostname | `MarkPRD` |
| Source IP | `172.16.17.88` |
| File Name | `ab.exe` |
| File Size | 775.50 KB |
| MD5 | `0b486fe0503524cfe4726a4022fa6a68` |
| Device Action | Allowed |
| MITRE ATT&CK | T1204 |
| Final Verdict | True Positive |

## 2. Malware Analysis

The sample `ab.exe` was identified as ransomware based on its matching MD5 hash and the available sandbox analysis.

**ANY.RUN report:**  
[View the malware analysis](https://any.run/report/1228d0f04f0ba82569fc1c0609f9fd6c377a91b9ea44c1e7f9f84b2b90552da2/6e248b54-37e4-410f-ae97-1f783248eb5b)

The analysis identified ransomware-related behavior, including file-renaming activity and attempts to interfere with recovery mechanisms. It also showed execution of the sample from a temporary directory and a further copy in a user roaming directory.

The observed behaviors support classifying the alert as a True Positive.

## 3. Processes – Backup Deletion and Recovery Disabling

### 3.1 `wbadmin.exe` – Targeting System State Backups

The following commands were observed:

```cmd
wbadmin DELETE SYSTEMSTATEBACKUP -deleteOldest
```

```cmd
wbadmin DELETE SYSTEMSTATEBACKUP -keepVersions:0
```

`wbadmin.exe` is a Windows backup management utility.

- `DELETE SYSTEMSTATEBACKUP` targets System State backups.
- `-deleteOldest` requests deletion of the oldest System State backup.
- `-keepVersions:0` requests deletion of all System State backup versions.

These commands indicate an attempt to remove backup copies that could help restore the system after a destructive attack. However, the available evidence does not establish that every deletion attempt succeeded.

### 3.2 `vssadmin.exe` – Targeting Shadow Copies

The report recorded the following command:

```cmd
vssadmin Delete Shadows /All /Quiet
```

`vssadmin.exe` manages Volume Shadow Copies, which can support recovery of previous versions of files and volumes.

Shadow Copies can help users recover files after accidental changes or destructive activity. Ransomware may attempt to delete them to make recovery more difficult.

The observed command indicates an attempt to delete all Shadow Copies quietly. A successful deletion should not be claimed unless the available execution results confirm it.

### 3.3 `bcdedit.exe` – Disabling Windows Recovery

The following command was recorded:

```cmd
bcdedit /set {default} recoveryenabled No
```

`bcdedit.exe` is a Windows utility used to modify Boot Configuration Data (BCD), which stores boot application settings.

This command does not delete backup files. It changes a boot configuration setting associated with Windows recovery.

The command is consistent with an attempt to make recovery more difficult following a ransomware incident.

## 4. Registry Activity – Correlating BCD Changes

The Registry activity included writes under the following path:

```text
HKLM\BCD00000000\Objects\{...}\Elements\...
```

A write under a path such as:

```text
HKLM\BCD00000000\Objects\{...}\Elements\16000009\Element
```

is consistent with activity involving the Boot Configuration Data store.

When correlated with the `bcdedit.exe` command, these Registry writes support the conclusion that the boot configuration was being modified. The path alone, however, does not independently prove which specific setting was changed; that conclusion depends on correlating the Registry events with the recorded command and its execution details.

## 5. Files Activity – Interpreting the Evidence

The report showed files such as:

```text
C:\Windows\Logs\WindowsBackup\Wbadmin.1.etl
C:\Windows\Logs\WindowsBackup\Wbadmin.2.etl
C:\Windows\Logs\WindowsBackup\Wbadmin.3.etl
```

These `.etl` files were associated with Windows Backup activity during the sandbox run. Their presence does not prove that the malware deleted Windows Event Logs.

The file activity also included suspicious files consistent with ransomware behavior. The malware analysis showed file-renaming activity and files resembling ransomware instructions.

The available evidence supports attempted deletion of System State backups and Shadow Copies, along with a modification to the Windows recovery configuration. It does **not** independently confirm that the Windows Security or System Event Logs were cleared.

## 6. Log Management and Endpoint Visibility

No relevant Log Management events were available around the alert time, and no relevant Endpoint Security logs were available for additional correlation.

This limited the ability to reconstruct the full execution timeline and determine how the file initially reached the host.

The missing logs do not, by themselves, prove that the malware deleted or disabled Windows logging. The `.etl` files found under `C:\Windows\Logs\WindowsBackup\` are associated with Windows Backup activity and are not sufficient evidence of Event Log clearing.

## 7. Playbook Results

| Playbook Check | Result |
|---|---|
| Define Threat Indicator | Other |
| Check if the malware was quarantined or cleaned | Not Quarantined |
| Analyze Malware | Malicious |
| Check if someone requested the C2 | Not Accessed |
| Final Classification | True Positive |

The device action was recorded as **Allowed**, and the playbook indicated that the malware was **not quarantined**. These findings support treating the host as potentially compromised and requiring containment and remediation.

## 8. Assessment

The process, Registry, file, and sandbox evidence indicates ransomware activity with attempts to interfere with recovery mechanisms:

- `wbadmin.exe` commands targeted System State backups.
- `vssadmin.exe` attempted to delete Shadow Copies; successful deletion was not confirmed by the available evidence.
- `bcdedit.exe` was used to change the default boot entry's recovery setting.
- Registry writes under `HKLM\BCD00000000` were consistent with modification of the BCD configuration.
- The `.etl` files documented Windows Backup activity and were not proof of Event Log deletion.
- The sandbox showed ransomware-related file activity.
- The endpoint action was Allowed, and the playbook reported that the malware was not quarantined.

**Final Verdict: True Positive — Ransomware Detected.**

The evidence supports treating `MarkPRD` as a potentially compromised host. Containment, verification of the malware's removal, assessment of file impact, and recovery from trusted backups are appropriate response priorities.

The available evidence does not establish that every backup deletion attempt succeeded, that Windows Event Logs were cleared, or how the malware was initially delivered.

# Ramnit – Blue Team Lab

## Overview

This case study documents a Windows memory-forensics investigation using **Volatility 3** and **VirusTotal**. The objective was to identify the suspicious process in the memory image, trace its network activity, recover the executable from memory, and collect related threat-intelligence indicators.

The investigation focused on the process **ChromeSetup.exe** (PID **4628**). Although its name resembles a legitimate Google Chrome installer, its observed outbound connection and VirusTotal relationships warranted further investigation.

## What is Volatility 3?

**Volatility 3** is an open-source memory forensics framework used to analyze memory images (RAM dumps). It helps investigators recover information about running processes, network connections, loaded modules, command-line arguments, handles, and file objects from a captured memory image.

### Useful Volatility 3 plugins

| Plugin | Purpose |
|---|---|
| `windows.pslist` | Lists processes present in memory |
| `windows.pstree` | Displays processes as a tree, showing parent-child relationships |
| `windows.cmdline` | Displays command-line arguments used to launch processes |
| `windows.netscan` | Recovers network connections and their associated processes |
| `windows.dlllist` | Lists DLLs loaded by a process |
| `windows.malfind` | Searches memory regions that may indicate injected or suspicious code |
| `windows.dumpfiles` | Extracts file objects and file-backed data from memory |
| `windows.handles` | Lists handles opened by processes |

## Investigation Findings

### Q1. What is the name of the process responsible for the suspicious activity?

**Answer: `ChromeSetup.exe`**

**Analysis:**

The process tree (`windows.pstree`) identified a process named `ChromeSetup.exe` with PID **4628**. Its name alone does not establish that it is malicious, so its execution details and network activity were examined next.

### Q2. What is the exact path of the executable for the malicious process?

**Answer: `C:\Users\alex\Downloads\ChromeSetup.exe`**

**Analysis:**

The `windows.cmdline` output showed the command line used to launch PID 4628:

```text
"C:\Users\alex\Downloads\ChromeSetup.exe"
```

This established the executable path reported for the process in the memory image.

**Evidence:**

![Volatility command-line output showing ChromeSetup.exe and its path](screenshots/cmdline.png)

### Q3. What IP address did the malware attempt to connect to?

**Answer: `58.64.204.181`**

**Analysis:**

The `windows.netscan` output associated PID **4628** (`ChromeSetup.exe`) with a TCP connection attempt to **58.64.204.181** on destination port **5202**.

The output included entries in the `CLOSED` and `SYN_SENT` states. The `SYN_SENT` state indicates that a TCP connection attempt had been initiated, but the captured evidence does not show a completed handshake. Therefore, this is best described as an attempted outbound connection, not proof that a session was established.

**Evidence:**

![Volatility netscan output showing ChromeSetup.exe connecting to 58.64.204.181 on port 5202](screenshots/netscan.png)

### Q4. Which city is associated with the IP address the malware communicated with?

**Answer: `Hong Kong`**

**Analysis:**

The IP address **58.64.204.181** was searched on VirusTotal. The IP report displayed **Hong Kong** as its geographic location and identified the network as **AS17444 – HKBN Enterprise Solutions Limited**.

Geolocation identifies the location associated with the IP address; it does not establish the physical location or identity of the attacker.

**Evidence:**

![VirusTotal IP report showing the Hong Kong geolocation](screenshots/IP-VT.png)

### Q5. What is the SHA1 hash of the malware executable?

**Answer: `280c9d36039f9432433893dee6126d72b9112ad2`**

**Analysis:**

To recover the executable-related data from the process, the following command was used:

```powershell
vol -f "C:\Users\AMR MOHAMED\Downloads\159-Ramnit\temp_extract_dir\memory.dmp" -o "C:\Tools\Volatility3" windows.dumpfiles --pid 4628
```

**Command breakdown:**

- `-f`: specifies the memory image to analyze.
- `-o`: specifies the directory where extracted files will be written.
- `windows.dumpfiles`: extracts file objects and file-backed data available in the memory image.
- `--pid 4628`: limits the extraction to file objects associated with process ID 4628.

The plugin extracted multiple files, including DLLs and two file-backed objects associated with `ChromeSetup.exe`. The executable-related image was identified as:

```text
file.0xca82b85325a0.0xca82b7e06c80.ImageSectionObject.ChromeSetup.exe.img
```

The DLLs in the output are not automatically suspicious; they can be normal modules mapped by the process. The extracted image was then used as the artifact for hash identification.

To calculate the SHA1 hash in PowerShell:

```powershell
Get-FileHash ".\file.0xca82b85325a0.0xca82b7e06c80.ImageSectionObject.ChromeSetup.exe.img" -Algorithm SHA1
```

> **Hash algorithm note:** SHA1 is required for this lab question. Using `-Algorithm SHA256` calculates a different hash and will not produce the requested SHA1 value. A memory-extracted image may also differ from the original on-disk file if some data was not present in the captured memory.

**Evidence:**

![Extracted ChromeSetup.exe memory image](screenshots/file.png)

### Q6. What is the compilation timestamp for the malware?

**Answer: `2019-12-01 08:36 UTC`**

**Analysis:**

The file's VirusTotal report was reviewed, and the **Creation Time** value displayed under the file's history/details was **2019-12-01 08:36:04 UTC**. This timestamp was used for the lab answer.

Timestamps embedded in executable metadata can be altered and should be treated as supporting metadata rather than independently verified proof of when the malware was actually compiled.

**Evidence:**

![VirusTotal file report showing the creation timestamp](screenshots/VT-creationDate.png)

### Q7. What domain is associated with the malware?

**Answer: `dnsnb8.net`**

**Analysis:**

The file's VirusTotal **Relations** tab was examined. Under **Contacted Domains**, the domain **dnsnb8.net** appeared with malicious detections in the VirusTotal report. The related contacted URLs included subdomains such as `ddos.dnsnb8.net`.

This relationship makes the domain a useful threat-intelligence lead for further hunting. A VirusTotal relationship by itself does not prove that the domain was contacted during this specific memory-capture session.

**Evidence:**

![VirusTotal relations showing dnsnb8.net under Contacted Domains](screenshots/VT-domain.png)

## Indicators of Compromise (IOCs)

| Indicator | Type | Context |
|---|---|---|
| `ChromeSetup.exe` | Process / filename | Suspicious process identified in memory (PID 4628) |
| `C:\Users\alex\Downloads\ChromeSetup.exe` | File path | Executable path reported by `windows.cmdline` |
| `58.64.204.181` | IPv4 address | Remote address in the process's TCP connection attempt |
| `5202/TCP` | Destination port | Remote port associated with the connection attempt |
| `dnsnb8.net` | Domain | Domain listed in the sample's VirusTotal relations |
| `280c9d36039f9432433893dee6126d72b9112ad2` | SHA1 | Lab-provided SHA1 identifier for the executable |

## Conclusion

The memory investigation identified **ChromeSetup.exe** (PID 4628), running from the user's Downloads directory. Volatility 3's `windows.netscan` plugin associated the process with an attempted outbound TCP connection to **58.64.204.181:5202**. VirusTotal associated that IP with **Hong Kong**.

The executable-related image was recovered using `windows.dumpfiles`, and VirusTotal was used to review its metadata and relationships. The investigation recorded the SHA1 **280c9d36039f9432433893dee6126d72b9112ad2**, the reported timestamp **2019-12-01 08:36 UTC**, and the related domain **dnsnb8.net**.

The findings demonstrate how memory forensics and threat-intelligence pivots can be combined to investigate a suspicious process. Individual indicators—such as a filename, IP geolocation, or timestamp—should be interpreted in context and corroborated with additional evidence.

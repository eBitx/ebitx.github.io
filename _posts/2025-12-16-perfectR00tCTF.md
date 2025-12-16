---
title: "PerfectR00t CTF"
date: 2025-12-16 8:40:00 +0300
categories: [CTF]
tags: [lab , malware-analysis, CTF]
---
![IMG](assets/lib/perfectR00t/per.png)

---

## Introduction

After a period of absence focused on studying and sharpening my skills, I’m back.

I recently competed in a cybersecurity CTF and proudly secured 2nd place. It was a great experience, and I’m really happy with the result and the teamwork behind it.

In this write-up, I’ll be sharing my Malware challenge solution, and more solutions will follow soon.

Special thanks to my friends and teammates from Al Qabilah — their support and collaboration played a big role in reaching this result.

![IMG](assets/lib/perfectR00t/1.jpg)

---
## CashNight1403 malware series ##

In this write-up, I will solve the CashNight1403 malware series.

The challenge involves a suspicious file delivered through an unusual communication channel. Endpoint telemetry flagged abnormal process behavior, unusual registry interactions, and outbound network activity associated with the sample.

The objective is to determine whether the file is malicious or a false positive, understand its behavior, and identify its malware family.
![IMG](assets/lib/perfectR00t/2.jpg)

---
Malware analysis?

Step 1: Upload to VirusTotal

Step 2: Pretend it’s advanced malware analysis

![IMG](assets/lib/perfectR00t/images.jpg)

---
### Q1 - What is the malware family?

![IMG](assets/lib/perfectR00t/3.jpg)

A lookup of the sample across public threat-intelligence platforms revealed a matching entry in the VirusTotal community, linked to a corresponding MalwareBazaar submission.

The file was classified as a DLL belonging to the Adware.Techsnab family, as identified by community signatures and prior analysis.

Malware Family: `Adware.Techsnab`
![IMG](assets/lib/perfectR00t/4.jpg)

So The Flag is : 
```
r00t{Adware.Techsnab}
```

---
### Q2 - What is the humanhash of the malware you identified?

Humanhash is a human-readable representation of a cryptographic hash. It maps a hash value to a deterministic sequence of words, making it easier to visually compare and communicate hashes while preserving uniqueness and collision resistance.

Threat-intelligence platforms such as MalwareBazaar use humanhash to simplify sample identification and cross-reference related files without manually comparing long hexadecimal hashes.

![IMG](assets/lib/perfectR00t/5.jpg)

So The Flag is : 
```
r00t{arkansas-yankee-beryllium-jupiter}
```
---
### Q3 - When was the malware first compiled?

The compilation time of the malware was identified by inspecting the Portable Executable (PE) header metadata available in the VirusTotal file details.

Specifically, the Compilation Timestamp field indicates the time at which the binary was compiled by the developer’s toolchain.

First Compilation Time:

![IMG](assets/lib/perfectR00t/6.jpg)

So The Flag is : 
```
r00t{2025-11-21 17:11:40 UTC}
```

#### About the Compilation Timestamp

The Compilation Timestamp is a metadata field stored in the Portable Executable (PE) header. It represents the time when the binary was compiled by the developer’s toolchain.

This field is commonly used during malware analysis to build a basic timeline and estimate when a sample was created or first built. Platforms like VirusTotal extract and display this value directly from the PE header for quick reference.

It is worth noting that while this timestamp is useful for contextual analysis, it can be manually modified by malware authors. However, it still provides valuable insight when correlated with other indicators.

---
### Q4 - What is the first dll created when the malware is executed at first time?

Upon executing the malware for the first time in an isolated sandbox environment, a new DLL file was immediately dropped to disk.

This behavior was visually confirmed during runtime, where a newly created DLL appeared on the desktop, as shown in the execution screenshot.

The first DLL created was:
`_787cb98047d59432462618f4f93162dacc240ef5d1937632408d28f32b621d2c.dll`

![IMG](assets/lib/perfectR00t/7.jpg)
So The Flag is : 
```
r00t{_787cb98047d59432462618f4f93162dacc240ef5d1937632408d28f32b621d2c.dll}
```
#### Infection Flow Overview

The diagram illustrates the natural execution flow of the malware.

The infection begins with a web download, which delivers a compressed archive. This archive contains a loader associated with ACRStealer, which then extracts and drops the final DLL payload.
The final stage shown represents the analyzed sample, confirming its position within the overall infection chain.

![IMG](assets/lib/perfectR00t/8.jpg)

---
### Q5 - What is the process capability of the malware: mention three.

Understanding a malware’s capabilities is critical for predicting its runtime behavior during sandbox execution. These capabilities can be derived through static analysis, reverse engineering, or by correlating the sample with publicly available threat intelligence.

In this challenge, the required process capabilities were documented and could be confirmed without deep reversing.

![IMG](assets/lib/perfectR00t/9.jpg)

So The Flag is : 
```
r00t{terminate_process,create_thread,suspend_thread}
```

----
### Q6 - What is the malware MIME type?
The malware’s MIME type was identified by reviewing the sample’s metadata on MalwareBazaar, where file content is classified based on its binary format rather than file extension alone.

This classification confirms the executable nature of the sample. 

![IMG](assets/lib/perfectR00t/10.jpg)

So The Flag is : 
```
r00t{application/x-dosexec}
```

#### About MIME Type

A MIME type (Multipurpose Internet Mail Extensions) is a standardized identifier used to describe the actual content type of a file, independent of its filename or extension. It allows systems and security tools to determine how a file should be handled or interpreted.

In malware analysis, the MIME type is useful for confirming the real nature of a sample, such as whether it is an executable, script, or document, even if it is disguised with a misleading extension.

----
### Q7 - One of the registry is responsible for emulator stuffs what is it?

Certain registry keys in Windows are associated with execution compatibility and emulation mechanisms, particularly those related to WOW64, which enables 32-bit binaries to run on 64-bit systems.

Among the observed registry entries, the following key is directly related to x86 emulation and binary translation, as indicated by its location under the WOW64 subsystem and its association with JIT execution:

![IMG](assets/lib/perfectR00t/11.jpg)

So The Flag is : 
```
r00t{HKEY_LOCAL_MACHINE\Software\Microsoft\Wow64\x86\xtajit}
```
---
### Q8 - A malware developer forgot to string debugging path, can you identify the full path?

During development, malware authors may unintentionally leave behind debugging artifacts. In Windows malware built using Visual Studio, this commonly includes references to Program Database (PDB) files, which store debugging symbols and paths.

By performing static analysis on the sample and inspecting embedded strings, a hardcoded PDB path was identified. This path reveals the original build environment used by the developer.

Identified Debugging Path:
![IMG](assets/lib/perfectR00t/12.jpg)

So The Flag is : 
```
r00t{C:\Users\Administrator\Desktop\Debug\privates\bin\Debug\CrashRpt1403.pdb}
```
---
### Q9 - What is the child process created when the malware is executed?

Dynamic analysis shows that, after initial execution, the malware spawns a delayed child process during runtime.

The created child process is:
![IMG](assets/lib/perfectR00t/13.jpg)

So The Flag is : 
```
r00t{C:\Windows\Microsoft.NET\Framework\v4.0.30319\RegAsm.exe}
```
---
### Q10 - After some time when the malware is being executed there is an embedded COM process created attached with the command, what is the cmd command you observed?

During dynamic execution, the malware was observed invoking a legitimate Windows binary with COM embedding parameters after a short runtime delay.

The command executed was:

![IMG](assets/lib/perfectR00t/14.jpg)

So The Flag is : 
```
r00t{C:\WINDOWS\System32\slui.exe -Embedding}
```

---
## IDAT Loader series ##
---
#### Scenario Overview

During routine security monitoring, the SOC detected suspicious activity originating from within the environment. What initially appeared to be normal system behavior quickly escalated into something far more concerning.

Telemetry revealed WMI-spawned PowerShell execution, followed by multiple instances of legitimate Windows binaries initiating unexpected outbound network connections. The activity pattern suggested deliberate abuse of native system components to evade detection and blend in with normal operations.

Further investigation led to the recovery of the initial infection vector, indicating the presence of an active loader operating as part of a real-world campaign. The behavior observed raises serious concerns about execution evasion, process masquerading, and attacker tradecraft.

This challenge places you in the role of a SOC analyst tasked with understanding how the loader operates, how it achieves execution, and what techniques are being leveraged to bypass traditional detection mechanisms.

---

### Q1 - The initial file uses WMI instead of direct powershell.exe execution. Which MITRE ATT&CK technique ID describes this process creation evasion?

As shown in the sandbox execution timeline, the initial sample does not invoke powershell.exe directly. Instead, it leverages Windows Management Instrumentation (WMI) to spawn PowerShell in a hidden and indirect manner.

This technique allows the malware to:

Evade direct process creation detection

Blend execution within legitimate WMI activity

Bypass basic command-line–based monitoring

According to the MITRE ATT&CK framework, this behavior maps to the following technique:

MITRE ATT&CK Technique ID: [Windows Management Instrumentation - T1047](https://attack.mitre.org/techniques/T1047/)

![IMG](assets/lib/perfectR00t/15.jpg)

So The Flag is : 
```
r00t{T1047}
```
---
### Further Execution Analysis - PowerShell Payload Deobfuscation & Stage Analysis

During further dynamic analysis, the spawned PowerShell process was inspected more closely. The command line revealed that the malware executes PowerShell in hidden window mode and relies on Base64-encoded content that is decoded and executed at runtime using Invoke-Expression.

This confirms that the loader uses runtime deobfuscation to conceal its real functionality and evade static inspection.

*1 - Initial Observation – Encoded PowerShell Execution*

![IMG](assets/lib/perfectR00t/16.jpg)

At this stage, the PowerShell command contained a long Base64 string passed directly to the execution pipeline. This indicates that the actual payload is not visible in plaintext and must be decoded to understand the next execution stage.

*2- Base64 Decoding – Revealing the Script Logic*

![IMG](assets/lib/perfectR00t/17.jpg)

After decoding the Base64 content, the script revealed the following behaviors:

Creation of a System.Net.WebClient object

Custom HTTP headers to mimic a legitimate browser

Downloading remote content from an external URL

Parsing downloaded data to extract an embedded payload

This confirms that the PowerShell code acts as a downloader and loader, retrieving the next stage dynamically.

*3- Reversed Base64 Content – Extracting the Remote Resource*

![IMG](assets/lib/perfectR00t/18.jpg)

Further analysis showed that part of the downloaded content itself was Base64-encoded in reverse order, requiring an additional decoding step.

![IMG](assets/lib/perfectR00t/19.jpg)

Once reversed and decoded, the final resource URL was revealed:

`https://cutec.co.za/arquivo_20251126065850.txt`

This demonstrates a multi-layer obfuscation strategy, where encoding and reversing techniques are combined to hinder automated detection and analysis.
 
 lets go and solve the other Q

 ---
### Q2 - The PNG was originally hosted on clearnet but also mirrored on Tor. What is the .onion URL hosting the exact same malicious image? .

 While analyzing the decoded PowerShell payload, the embedded download logic revealed a reference to a PNG file hosted on the Internet Archive. Further inspection of the Base64-decoded content showed that the same resource was also accessible through the Internet Archive’s official Tor v3 hidden service.

This confirms that the .onion address was not discovered externally, but directly extracted from the decoded Base64 payload, indicating that the malware explicitly references both clearnet and Tor-based mirrors for payload availability.

The extracted Tor mirror is:

![IMG](assets/lib/perfectR00t/20.jpg)

So The Flag is : 
```
r00t{archivep75mbjuhnx6x4j5mwjmomyxb573v42balldqu56ruli2oiad.onion}
```

---
### Q3 - Extract the .NET DLL embedded inside the PNG. What is the creation timestamp of this DLL?.

To answer this question, the malicious PNG file was uploaded to VirusTotal for relationship and behavior analysis.

By inspecting the Relations tab, VirusTotal shows that the PNG file is associated with the dropping of a Win32 .NET DLL during sandbox execution. This indicates that the image is leveraged as part of the malware delivery chain to stage or deploy an executable payload.

It is important to note that this conclusion is based on observed runtime behavior correlation within VirusTotal’s sandbox environment, rather than static confirmation of steganographic or polyglot file structure within the PNG itself.

![IMG](assets/lib/perfectR00t/21.jpg)

The dropped DLL was identified as:

`fbe9cbd20b1447fbc3005d05db5b969b50926ca8b1fe3c385506815d650aa.dll`

Further inspection of the DLL’s details page on VirusTotal reveals the Creation Time under the History section. This timestamp corresponds to the compilation time embedded within the Portable Executable (PE) metadata of the extracted .NET assembly.

The creation timestamp of the embedded DLL is:

![IMG](assets/lib/perfectR00t/22.jpg)

So The Flag is : 
```
r00t{2025-11-24 17:56:13 UTC}
```
---
### Q4 - The .NET assembly is loaded directly from Base64 without ever touching disk. What is the exact MITRE technique and sub-technique?

The .NET assembly is loaded directly from Base64 without touching disk

The decoded PowerShell payload uses the .NET Reflection.Assembly::Load() method to load a Base64-encoded assembly directly into memory. This allows the malware to execute managed code without writing the payload to disk, effectively bypassing file-based detection mechanisms.

This behavior maps directly to the following MITRE ATT&CK technique: [Reflective Code Loading - T1620](https://attack.mitre.org/techniques/T1620/)

![IMG](assets/lib/perfectR00t/23.jpg)

---
### Q5 - The loaded .NET assembly calls a method. What is the exact decoded URL used to download the final stage payload?

During analysis of the decoded PowerShell payload, the Base64-encoded content was reversed and decoded, revealing the exact URL used by the loaded .NET assembly to retrieve the final stage payload.

The decoded URL is:
![IMG](assets/lib/perfectR00t/19.jpg)

So The Flag is : 
```
r00t{hxxps://cutec.co.za/arquivo_20251126065850.txt}
```
---
### Q6 - Download the payload from the URL above. What is the TLSH hash of the resulting executable?

Payload Extraction and TLSH Calculation

To solve this question, the payload was first downloaded from the decoded URL:

```bash
wget https://cutec.co.za/arquivo_20251126065850.txt -O stage.txt
```

Initial inspection of the downloaded file showed that it was **ASCII text with a single very long line**, indicating that the content was not a raw binary but an encoded payload:

```bash
file stage.txt
```

Attempts to directly decode the content using Base64 failed, even after removing whitespace, confirming that the data was not standard Base64:

```bash
base64 -d stage.txt
```

```bash
cat stage.txt | tr -d '\n\r\t ' > clean.txt
base64 -d clean.txt
```

Based on earlier analysis, the payload was suspected to be **Base64-encoded in reverse order**. The content was therefore reversed before decoding:

```bash
rev stage.txt > reversed.txt
cat reversed.txt | tr -d '\n\r\t ' > clean_rev.txt
base64 -d clean_rev.txt > stage.bin
```

After reversing and decoding, the resulting file was identified as a **Windows PE executable**:

```bash
file stage.bin
```

```
PE32 executable (GUI) Intel 80386, for MS Windows
```

With the final executable successfully extracted, the **TLSH hash** was calculated using the `tlsh` utility:

```bash
tlsh stage.bin
```

The resulting TLSH value represents the fuzzy hash of the final stage payload and was used as the answer for this challenge.

So The Flag is : 
```
r00t{T10BB4AE01B6D2C1B2D57654300D26E775DEBCBD2028369A7BB3DA0D57F970180AB39BB2}
```

---
### Q7 - Execute sample.js file in a sandbox environment. What is the primary C2 domain and port the malware beacons to?

By executing `sample.js` inside a sandbox (ANY.RUN) and reviewing the **network indicators / IOC panel**, the malware was observed beaconing to a single primary command-and-control endpoint.

The sandbox explicitly reports the C2 as:

* **Domain:** `agrifeed.com`
* **Port:** `2044`

![IMG](assets/lib/perfectR00t/24.jpg)

This is corroborated by:

* The **ANY.RUN verdict panel** showing `C2: agrifeed.com:2044`
* DNS request telemetry resolving `agrifeed.com`
* Outbound connection attempts over TCP port **2044**

![IMG](assets/lib/perfectR00t/25.jpg)
**Final Answer (Flag):**

```
r00t{agrifeed.com:2044}
```

---

### 8- What is the exact Mutex created by this malware build to prevent multiple instances? (lower case)

The malware configuration extracted during dynamic analysis confirms the exact mutex used by this build.

By inspecting the **Malware Configuration** section associated with the Remcos RAT sample, the mutex value is explicitly defined under the `Mutex_name` field.

![IMG](assets/lib/perfectR00t/26.jpg)

The mutex is created to ensure that only a single instance of the malware runs on the infected system, a common technique used by RAT families to prevent duplicate execution and multiple C2 sessions.

The identified mutex value is:

```
Rmc-57BGQ7
```

As required by the challenge, the mutex is provided in lowercase:

```
r00t{rmc-57bgq7}
```


---

## Closing Thoughts

And that wraps up this malware adventure 

From *“looks like a normal file”* to **WMI abuse, in-memory .NET loading, reversed Base64, hidden PowerShell, and a classic RAT C2**, this challenge was a great reminder that malware rarely does anything “direct”.

No files written when they shouldn’t be, legit Windows binaries doing very illegit things, and payloads hiding where no one expects them — business as usual in malware land.

CTF challenges like this perfectly simulate real SOC investigations, where the job isn’t just to find *what* is malicious, but **how**, **why**, and **what comes next**.

If you made it this far, congrats — you survived another loader chain 
More write-ups coming soon… stay curious, stay paranoid, and never trust a PNG. 

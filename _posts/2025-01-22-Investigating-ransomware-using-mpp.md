# Investigating a ransomware on a Windows machine using Maximum Plaso Parser


Usefull links:
* MPP is available [here](https://github.com/youhgo/maximumPlasoTimelineParser)
* DOPP is available [here](https://github.com/youhgo/DOPP)


In this article we will proceed to the investigation of a Windows machine infected with a ransomware, using Maximum Plaso Parser.




## What is MPP ?


MPP or MaximumPlasoParser is a python script that will parse a [plaso - Log2Timeline](https://github.com/log2timeline/plaso)  Json timeline file.
The goal is to regroup artefacts by categories in some easily readable and straight forward results.
MPP produces extremely simple and readable results, allowing analysts to find the information they need directly.




# Start the investigation


## Vocabulary


**VMDK** : Virtual Machine Disk : VMDK is a file format that describes containers for virtual hard disk drives to be used in virtual machines like VMware Workstation or VirtualBox.

**MFT** : Master File Table : The Master File Table (MFT) is a system file in the NTFS file system (having the name $MFT) that stores metadata information about all files and directories on an NTFS volume. The MFT acts as an index to all the files and directories on the volume, providing quick access to the information needed to retrieve a file.

**USNJRNL** : Update Sequence Number Journal : The USN Journal (Update Sequence Number Journal), or Change Journal, is a feature of the Windows NT file system (NTFS) which maintains a record of changes made to the volume.

**Amcache** : AmCache is a component of the Application Compatibility Framework in Windows. it stores metadata about executables and other files that have been run or interacted with on the system. This includes information about when files were first executed.

**Shimcache** : ShimCache, also known as the Application Compatibility Cache, is a feature in Windows that helps maintain compatibility for older applications running on newer operating systems.

**VT** : Virus Total : Virus Total is an online service that analyzes suspicious files and URLs to detect types of malware and malicious content using antivirus engines and website scanners.


## Context
You are a forensic analyst and you have been contacted to investigate a windows machine that has been infected with a ransomware. The client only provided the Virtual Machine DisK (VMDK) of the machine.




## Parsing the evidences


In this article we are gonna use Log2Timeline and Maximim Plaso Parser to analyse the VMDK file provided.


To create the timeline with plaso :


```bash
psteal.py --source /home/hro/DFIR/BROCELIANDE_DC_Graal-disk1.vmdk -w full_timeline_graal.json -o json_line
```
Psteal.py  is tool which uses log2timeline and psort engines to parse all data in one go.
* – source is the path to the folder or file containing the data to be parsed
* -w is the result file
* -o json_line is the output format



MPP needs a jsonline output format, that's why we use -o json_line and not csv. 


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
There are multiple ways to find this information. We will first explore the MFT and look for a lot of file creation/modification having the same extension.


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




By looking on the MFT, we can find the ransomware at : C/Users/arthur/Documents/Bytelocker.exe with md5 : b8ef6e365a55a0ec96c19c61f1bce476.


From his name and info on VT, the ransomware is Bytelocker.


To find the time when the ransomware was executed we can check for the first file containing the ".byt" extension,




```bash
rg -i "\.byt" mft.csv | head -1
2021-01-07|04:03:12|USNJRNL|N/A|USN_REASON_FILE_CREATE|arrivée-dun-chaton-à-la-maison.jpg.byt
```


Keep in mind that the MFT is sometimes inaccurate regarding file modification.


If the date of the first encrypted file doesn't seem right you can look for the first ransom note left by the ransomware as they are neither modified nor encrypted.


Here it would give us a timeframe around 4 AM on January 07 2021.




Lot of ransom notes are labeled "readmexx", after searching for that we can find it :
```bash
rg -i "README" mft.csv  | head -1
2021-01-07|04:20:59|USNJRNL|N/A|USN_REASON_FILE_CREATE|#README_CTRM#.rtf
```


(Note:  we'll see more later about CRTM )


After extracting the ransom note from the disk, we can get it's content:


```crtf
Аll yоur vаluаblе dаtа hаs bееn еnсryptеd!
Hеllо!
Sоrry, but wе hаvе tо infоrm yоu thаt duе tо sесurity issuеs, yоur sеrvеr wаs hасkеd. Plеаsе bе surе thаt yоur dаtа is nоt brоkеn. All yоur vаluаblе filеs wеrе еnсryptеd with strоng сryptо аlgоrithms AES-256+RSA-2048 аnd rеnаmеd. Yоu саn rеаd аbоut thеsе аlgоrithms in Gооglе. Yоur uniquе dесryptiоn kеy is sесurеly stоrеd оn оur sеrvеr аnd yоur dаtа саn bе dесryptеd fаst аnd sаfеly.
[...]
```


The Date-Time of the creation of the first encrypted file / ransom note gives us a good time window to look for.


## Getting the ransomware
Lets search in the MFT what happened during the first 3 minutes after 4am on the 2021-01-07.


(In our case, we could search directly for Bytelocker.exe, but in some other situations we have no garanties to know the name of the ransomware.)

```bash
rg -iN "2021-01-07.04:0[1-3]:.." mft.csv  | head
2021-01-07|04:01:33|USNJRNL|N/A|USN_REASON_DATA_EXTEND USN_REASON_DATA_TRUNCATION|lastalive0.dat
2021-01-07|04:02:33|USNJRNL|N/A|USN_REASON_DATA_TRUNCATION|lastalive1.dat
[...]
2021-01-07|04:02:53|USNJRNL|N/A|USN_REASON_FILE_DELETE USN_REASON_CLOSE|Bytelocker.exe
2021-01-07|04:02:57|FILESTAT|file|Content Modification Time|\Users\arthur\Documents\confidentiel\Bytelocker.exe
2021-01-07|04:02:57|FILESTAT|file|Last Access Time|\Users\arthur\Documents\confidentiel\Bytelocker.exe
2021-01-07|04:02:57|USNJRNL|N/A|USN_REASON_DATA_EXTEND USN_REASON_FILE_CREATE|Bytelocker.exe
```

We have a hit on an file name:  "Bytelocker.exe", lets search that file :


```bash
rg -iN "Bytelocker.exe" mft.csv 
2021-01-07|03:56:55|USNJRNL|N/A|USN_REASON_FILE_CREATE|Bytelocker.exe
2021-01-07|03:59:47|USNJRNL|N/A|USN_REASON_FILE_DELETE USN_REASON_CLOSE|Bytelocker.exe
[...]
2021-01-07|04:00:11|USNJRNL|N/A|USN_REASON_DATA_EXTEND USN_REASON_FILE_CREATE USN_REASON_CLOSE|Bytelocker.exe
2021-01-07|04:00:11|FILESTAT|file|Creation Time|\Users\arthur\Documents\confidentiel\Bytelocker.exe
2021-01-07|04:00:11|USNJRNL|N/A|USN_REASON_FILE_CREATE|Bytelocker.exe
2021-01-07|04:02:53|USNJRNL|N/A|USN_REASON_FILE_DELETE USN_REASON_CLOSE|Bytelocker.exe
[...]
2021-01-07|04:02:57|FILESTAT|file|Content Modification Time|\Users\arthur\Documents\confidentiel\Bytelocker.exe
2021-01-07|04:02:57|USNJRNL|N/A|USN_REASON_FILE_CREATE|Bytelocker.exe
[...]
2021-01-07|04:05:41|FILESTAT|file|Creation Time|\Users\arthur\Documents\Bytelocker.exe
2021-01-07|04:05:41|USNJRNL|N/A|USN_REASON_FILE_CREATE|Bytelocker.exe
[...]
2021-01-07|04:26:41|USNJRNL|N/A|USN_REASON_BASIC_INFO_CHANGE|Bytelocker.exe
2021-01-07|04:26:41|USNJRNL|N/A|USN_REASON_SECURITY_CHANGE|Bytelocker.exe
2021-01-07|04:26:46|FILESTAT|file|Metadata Modification Time|\Users\arthur\Documents\Bytelocker.exe
[...]
2021-01-07|04:27:15|USNJRNL|N/A|USN_REASON_BASIC_INFO_CHANGE|Bytelocker.exe
2021-01-07|04:27:15|USNJRNL|N/A|USN_REASON_SECURITY_CHANGE|Bytelocker.exe
2021-01-07|04:27:16|FILESTAT|file|Metadata Modification Time|\Users\arthur\Documents\confidentiel\Bytelocker.exe
```

With the info of the MFT combine with the one from the USN Journal, we can see that the ransomware was dropped at multiple places:
* \Users\arthur\Documents\confidentiel\Bytelocker.exe
* \Users\arthur\Documents\Bytelocker.exe


Now that we know what to look for and at what time, let's search for all executed programs.
There is several way to do that, the first one is the amcache, the second the shimcash or appcompat cash and we can also have information in the user experience/assist:


```bash
rg -iN "bytelocker.exe" amcache.csv app_compat_cache.csv user_assist.csv
user_assist.csv
2021-01-07|03:58:58|C:\Users\Public\Bytelocker.exe|0|0
2021-01-07|04:00:50|C:\Users\arthur\Documents\confidentiel\Bytelocker.exe|0|0


app_compat_cache.csv
2021-01-07|03:56:55|Bytelocker.exe|C:\Users\Public\Bytelocker.exe|e55e5b02ad40e9846a3cd83b00eec225fb98781c6f58a19697bf66a586f77672
2021-01-07|04:02:57|Bytelocker.exe|C:\Users\Arthur\Documents\confidentiel\Bytelocker.exe|e55e5b02ad40e9846a3cd83b00eec225fb98781c6f58a19697bf66a586f77672
2021-01-07|04:05:41|Bytelocker.exe|C:\Users\Arthur\Documents\Bytelocker.exe|e55e5b02ad40e9846a3cd83b00eec225fb98781c6f58a19697bf66a586f77672


amcache.csv
2040-01-05|12:07:17|bytelocker.exe|c:\users\public\bytelocker.exe|0006325d14a30ff7987e661f1b3bcca4b51100000000|d5006bbcc79d52882acac909e7e9d9a4141af938d9f942981f5e0ae3bba5a62b
2040-01-05|12:07:17|bytelocker.exe|c:\users\arthur\documents\confidentiel\bytelocker.exe|0006325d14a30ff7987e661f1b3bcca4b51100000000|d5006bbcc79d52882acac909e7e9d9a4141af938d9f942981f5e0ae3bba5a62b
2041-01-28|23:31:00|bytelocker.exe|c:\users\arthur\documents\bytelocker.exe|0006325d14a30ff7987e661f1b3bcca4b51100000000|d5006bbcc79d52882acac909e7e9d9a4141af938d9f942981f5e0ae3bba5a62b
```




We have hits in all of these files, the dateTime in the amcache is obviously wrong but it means that the binary was executed (we obviously knew because of all the encrypted files).
Contrary to the amcache, an entry in the shimcache doesn't mean the program was executed.
But if we correlate the dateTime of the shimcache entry, the user assist entry and the date of the first file encryption, we can assume that the entries in the shimcache are pretty much correct.


We have a total of 3 entries in the amcache with a location that wasn't in the MFT "c:\users\public\bytelocker.exe".




While looking at the USN_journal (see above) we can see that the binary was deleted and created again in another directory. That would explain why some ransom notes are encrypted I guess ?


```bash
rg -i "#README_CTRM#.rtf.byt" mft.csv | head -1
2021-01-07|04:21:00|USNJRNL|N/A|USN_REASON_FILE_CREATE|#README_CTRM#.rtf.byt
```


OK, we have our ransomware execution, the file location and the execution time. Let's continue to investigate.


## Identifying malicious Users


Lets check what users were connected at that time. The time window is in the middle of the night so results might not get polluted by legit connections.


Security event 4624 registers all connections to the machine. Let search at ~3 am:


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


We can see multiple services accounts as well as computers accounts. But we can see that the accounts "Administrator" and "arthur" were connected.


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
It's good practice to check with the client wherever those connections are legit or not. Sometimes, clients can be in another timezone and therefore work during our night time, so a connection at 3am could be legit.


The first malicious connection identified on this machine was made on the "2021-01-07" at "03:28:22" by the account "Administrator".


As you will see below the account "arthur" is also compromised.




## Identifying malicious Actions


Because the connections we saw above are in SMB, an action should be linked.


Let’s see what happens in the next 10 seconds following the connection:


```bash
rg -iN "2021-01-07\|03:28:2." *.csv
windefender.csv
2021-01-07|03:28:23|1116 - Detection|VirTool:Win32/MSFPsExecCommand|Severe|NT AUTHORITY\SYSTEM|Unknown|CmdLine:_C:\Windows\System32\cmd.exe /Q /c echo cd ^> \\127.0.0.1\C$\__output 2^>^&1 > C:\Windows\TEMP\execute.bat & C:\Windows\system32\cmd.exe /Q /c C:\Windows\TEMP\execute.bat & del C:\Windows\TEMP\execute.bat|Not Applicable


user_special_logon_id4672.csv
2021-01-07|03:28:22|4672|Administrator|-|-|-|-
2021-01-07|03:28:23|4672|SYSTEM|-|-|-|-


new_service_id7045.csv
2021-01-07|03:28:22|7045|LocalSystem|%COMSPEC% /Q /c echo cd  ^> \\127.0.0.1\C$\__output 2^>^&1 > %TEMP%\execute.bat & %COMSPEC% /Q /c %TEMP%\execute.bat & del %TEMP%\execute.bat|BTOBTO


user_logon_id4624.csv
2021-01-07|03:28:22|4624|-|Administrator|192.168.88.137|53942|3
2021-01-07|03:28:23|4624|GRAAL$|SYSTEM|-|-|5
```


We have interesting things going on here; let’s explain:


#### Connections
```
user_logon_id4624.csv
2021-01-07|03:28:22|4624|-|Administrator|192.168.88.137|53942|3
2021-01-07|03:28:23|4624|GRAAL$|SYSTEM|-|-|5


user_special_logon_id4672.csv
2021-01-07|03:28:22|4672|Administrator|-|-|-|-
2021-01-07|03:28:23|4672|SYSTEM|-|-|-|-


```


We can see that the account "Administrator" was connected using SMB. We can also see that the SYSTEM account is connected using type 5, meaning that a service starts and the service account logs into the local system. SYSTEM and Administrator are privileged account, that why we have 4672 log entry paired with the 4624.


#### Services


A new service was created :


```bash
new_service_id7045.csv
2021-01-07|03:28:22|7045|LocalSystem|%COMSPEC% /Q /c echo cd  ^> \\127.0.0.1\C$\__output 2^>^&1 > %TEMP%\execute.bat & %COMSPEC% /Q /c %TEMP%\execute.bat & del %TEMP%\execute.bat|BTOBTO
```


Lets breakdown that command line :


The first part:
```bash
%COMSPEC% /Q /c echo cd  ^> \\127.0.0.1\C$\__output 2^>^&1 > %TEMP%\execute.bat
```


* %COMSPEC%: This environment variable typically points to the command interpreter (cmd.exe).
* /Q: Runs the command interpreter in quiet mode.
* /c: Executes the following command and then exits.
* "echo":  This command is used to output text to the console or a file.


```bash
cd ^> \\127.0.0.1\C$\__output 2^>^&1 > %TEMP%\execute.bat:
```


* "cd": This command changes the current directory.
* "^> \\127.0.0.1\C$\__output": This part specifies the new directory.
* "\\127.0.0.1": Represents the local machine.
* "C$"": This is an administrative share of the local C: drive. Accessing it requires elevated privileges.
* "__output": This is the target subdirectory within the C: drive.
* "2^>^&1": This redirects both standard error (2) and standard output (1) to the same location.
* "\> %TEMP%\execute.bat": This redirects the output of the echo command to a file named execute.bat within the temporary directory (%TEMP%). This effectively creates a batch file with the cd command.
* "cd ^> \\127.0.0.1\C$\__output": This is the command that will be written to the batch file.




**To Sum Up :**


This command will launch a terminal and create a batch file at location %TEMP%\execute.bat and write cmd to change location to the share folder of the machine inside of it.




The second part :


```bash
%COMSPEC% /Q /c %TEMP%\execute.bat & del %TEMP%\execute.bat|BTOBTO
```


* "%COMSPEC% /Q /c %TEMP%\execute.bat" : This cmd executes the execute.bat file that was just created.
* "del %TEMP%\execute.bat": This deletes the temporary execute.bat file after it has been executed.
* "BTOBTO" This part redirects the output of the entire command sequence to another process or file named "BTOBTO." The nature of "BTOBTO" is unknown from this command alone.


**To Sum Up :**


This cmd will execute then delete the batch file created previously.




#### Anti Virus hits
```bash
windefender.csv
2021-01-07|03:28:23|1116 - Detection|VirTool:Win32/MSFPsExecCommand|Severe|NT AUTHORITY\SYSTEM|Unknown|CmdLine:_C:\Windows\System32\cmd.exe /Q /c echo cd ^> \\127.0.0.1\C$\__output 2^>^&1 > C:\Windows\TEMP\execute.bat & C:\Windows\system32\cmd.exe /Q /c C:\Windows\TEMP\execute.bat & del C:\Windows\TEMP\execute.bat|Not Applicable
[...]
2021-01-07|03:28:38|1117 - Action|VirTool:Win32/MSFPsExecCommand|Severe|NT AUTHORITY\SYSTEM|Unknown|Remove
```


The windefer av identified that cmd line as a Severe threat and later removed it/blocked it.




By checking the timeline we can see that the attacker tried at least 4 times without success, he tried with user arthur and Administrator.


## Post exploitation:


As we continue to browse our timeline we can find :


```bash
amcache.csv
2021-01-07|03:24:40|mimikatz.exe|c:\users\public\mimikatz.exe|0006474843b18c8fcb1dda3a11ea33af7ed000000904|d5006bbcc79d52882acac909e7e9d9a4141af938d9f942981f5e0ae3bba5a62b
```


we have an entry name mimikatz.exe in the Amcache hive at 2021-01-07T03:24:40.


I can't find any other action related to it, no entry in the MFT, no type3 connection related, no av flag, nothing. We saw earlier that the amcache dateTime was not correct so it might be the case here but i doubt it as it's in the timeframe of the attack.


As we keep going, we can see more interestings things here :


```bash
mft.csv
2021-01-07|03:35:06|4624|-|arthur|192.168.88.137|45860|3


2021-01-07|03:35:43|USNJRNL|N/A|USN_REASON_DATA_EXTEND USN_REASON_FILE_CREATE|mimikatz.exe
2021-01-07|03:35:44|1116 - Detection|HackTool:Win32/Mimikatz.D|High|BROCELIANDE\arthur|C:\Users\Public\beacon.exe|file:_C:\Users\Public\mimikatz.exe|Not Applicable
2021-01-07|03:35:45|1116 - Detection|HackTool:Win64/Atosev.A|High|NT AUTHORITY\SYSTEM|C:\Users\Public\beacon.exe|file:_C:\Users\Public\beacon.exe|Not Applicable


2021-01-07|03:35:46|1116 - Detection|Behavior:Win32/Atosev.D!sms|Severe|-|C:\Users\Public\beacon.exe|behavior:_pid:5172:41451891338358; process:_pid:5172,ProcessStart:132544280605139768|Not Applicable
2021-01-07|03:35:46|1117 - Action|Behavior:Win32/Atosev.D!sms|Severe|-|C:\Users\Public\beacon.exe|Remove
2021-01-07|03:35:59|1117 - Action|HackTool:Win32/Mimikatz.D|High|BROCELIANDE\arthur|C:\Users\Public\beacon.exe|Quarantine
```


We have another connection from user arthur and multiple av hit with mimikatz and "beacon.exe".




Later on, a powershell cmd is executed:


```bash
powershell.csv
2021-01-07|03:37:03|600|powershell Set-MpPreference -DisableRealtimeMonitoring $true; Get-MpComputerStatus
```


This command disables the real time monitoring of the AV and checks the AV status.


Few seconds later we get a connection by Arthur and the creation of the file beacon.exe.


Shortly after it's flag by the AV:


```bash
2021-01-07|03:37:06.374663|4672usrSpeLogon|4672|arthur|-|-|-|-
2021-01-07|03:37:06.374766|4624usrLogon|4624|-|arthur|192.168.88.137|45990|3
[...]
2021-01-07|03:37:12.855915|mft|USNJRNL|N/A|USN_REASON_FILE_CREATE|beacon.exe
[...]
2021-01-07|03:37:24.672126|windefender|1116 - Detection|HackTool:Win64/Atosev.A|High|NT AUTHORITY\SYSTEM|Unknown|file:_C:\Users\Public\beacon.exe|Not Applicable
```
Note that this time we don't have any 1117 event id from  Av saying that the malware has been set to quarantine  !


The exe was still on the disk so i get more info about it :
```bash
md5sum beacon.exe
4f3df018ea5e4eb39c9cc5c55050a92b  beacon.exe
```


Info from VT indicates that it's a beacon from Cobalt Strike.


We can extract the config from the beacon with csce :
```json  "server": {
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




With the av down, we see the successful creation of mimikatz.exe :




```bash
2021-01-07|03:41:06.888806|4672usrSpeLogon|4672|arthur|-|-|-|-
2021-01-07|03:41:06.888956|4624usrLogon|4624|-|arthur|192.168.88.137|46108|3
[...]
2021-01-07|03:41:21.621575|mft|FILESTAT|file|Creation Time|\Users\Public\mimikatz.exe
[...]
2021-01-07|03:41:21.902393|shimcache|mimikatz.exe|C:\Users\Public\mimikatz.exe|e55e5b02ad40e9846a3cd83b00eec225fb98781c6f58a19697bf66a586f77672
```

As we go through the timeline we can see multiple connections from arthur, still in SMB.
```bash
2021-01-07|03:49:07.978986|4672usrSpeLogon|4672|arthur|-|-|-|-
2021-01-07|03:49:07.979144|4624usrLogon|4624|-|arthur|192.168.88.137|46302|3
2021-01-07|03:49:13.105779|mft|FILESTAT|file|Creation Time|\ProgramData\Microsoft\Diagnosis\DownloadedSettings\[Citrteam@hotmail.com].1LnNJAKH-WboL7pFq.CTRM
```

In the MFT, this file is created : [Citrteam[@]hotmail[.]com].1LnNJAKH-WboL7pFq.CTRM. It match 2 iocs, the first one is "Citrteam[@]hotmail[.]com" and the second one is the file extension : "CRTM. Both those iocs are linked to CRTM ransomware, himself belonging to Matrix ransomware families.


CTRM ransomware encrypts files and renames them. It also creates a ransom note, usually named "CTRM_INFO.rtf" in all folders that contain encrypted files. CTRM renames files by replacing their filenames with the citrteam@xxxx.com email address and random strings, file ext is  ".CTRM".


We have previously identified the ransomware as Bytelocker and now we have evidence of CRTM. Here we only have 1 file name CRTM, it was created and not modified. Maybe it was just a test by the attacker. Furthermore we don't have any evidence of any execution of a binary nor its creation in the MFT.


## Launching the Ransomware


After lot of failed connections from Arthur, we get an eventID 4648 and a success RDP connexion with a bytelocker.exe entry in the shimcache:


```Bash
timeline.csv
2021-01-07|03:55:16.043038|4648usrExpLogon|4648|GRAAL$|arthur|127.0.0.1|0|-
2021-01-07|03:55:16.043065|4624usrLogon|4624|GRAAL$|arthur|127.0.0.1|0|2
2021-01-07|03:55:16.043094|4672usrSpeLogon|4672|arthur|-|-|-|-
2021-01-07|03:55:16.301111|rdpLocal|21|BROCELIANDE\arthur|-|2|-|-|-|AuthSuccess
[...}
2021-01-07|03:56:17.120954|4672usrSpeLogon|4672|GRAAL$|-|-|-|-
2021-01-07|03:56:17.121054|4624usrLogon|4624|-|GRAAL$|192.168.88.135|56719|3
[...]
2021-01-07|03:56:55.101887|mft|USNJRNL|N/A|USN_REASON_FILE_CREATE|Bytelocker.exe
2021-01-07|03:56:55.101887|shimcache|Bytelocker.exe|C:\Users\Public\Bytelocker.exe|e55e5b02ad40e9846a3cd83b00eec225fb98781c6f58a19697bf66a586f77672
```

The ransomware execution might have failed as we see another tentative later on:

```bash
2021-01-07|04:01:09.520882|4672usrSpeLogon|4672|arthur|-|-|-|-
2021-01-07|04:01:09.521008|4624usrLogon|4624|-|arthur|192.168.88.137|46658|3
2021-01-07|04:02:57.273187|mft|USNJRNL|N/A|USN_REASON_FILE_CREATE|Bytelocker.exe
2021-01-07|04:02:57.273187|shimcache|Bytelocker.exe|C:\Users\Arthur\Documents\confidentiel\Bytelocker.exe|e55e5b02ad40e9846a3cd83b00eec225fb98781c6f58a19697bf66a586f77672
```

This tentative was successful as we can witness the encryption of many files few seconds later:

```bash
2021-01-07|04:03:18.460768|mft|USNJRNL|N/A|USN_REASON_DATA_EXTEND USN_REASON_FILE_CREATE|arrivée-dun-chaton-à-la-maison.jpg.byt
2021-01-07|04:03:18.570408|mft|USNJRNL|N/A|USN_REASON_DATA_EXTEND USN_REASON_FILE_CREATE USN_REASON_CLOSE|arrivée-dun-chaton-à-la-maison.jpg.byt
2021-01-07|04:03:18.570408|mft|USNJRNL|N/A|USN_REASON_FILE_DELETE USN_REASON_CLOSE|arrivée-dun-chaton-à-la-maison.jpg
2021-01-07|04:03:18.570408|mft|USNJRNL|N/A|USN_REASON_RENAME_NEW_NAME USN_REASON_OBJECT_ID_CHANGE USN_REASON_CLOSE|arrivée-dun-chaton-à-la-maison.jpg
2021-01-07|04:03:18.570408|mft|USNJRNL|N/A|USN_REASON_RENAME_NEW_NAME USN_REASON_OBJECT_ID_CHANGE|arrivée-dun-chaton-à-la-maison.jpg
2021-01-07|04:03:18.570408|mft|USNJRNL|N/A|USN_REASON_RENAME_OLD_NAME USN_REASON_OBJECT_ID_CHANGE|arrivée-dun-chaton-à-la-maison.jpg.byt
```

The ransomware added an entry to the runkey, probably for persistence :

```bash
2021-01-07|04:05:58.398303|runKey|Bytelocker: "C:\Users\arthur\AppData\Roaming\{86ff23e9-f09f-4ca4-ae3d-41fe11fbabcd}.exe"
```

Later on we spot the creation and execution of this binary : ATXO3fAc.exe.
```bash
2021-01-07|04:20:51.023841|shimcache|ATXO3fAc.exe|C:\Users\Administrator\Documents\ATXO3fAc.exe|e55e5b02ad40e9846a3cd83b00eec225fb98781c6f58a19697bf66a586f77672
```

By searching the md5 of ATXO3fAc64.exe we can find another name from it : VSSDestroy. It is associated with Matrix ransomwares.

It his launched by a bat script :
```bash
root@Sidious:/mnt/vmdk/Users/Administrator/Documents# cat CEp5f0ji.bat
cacls %1 /E /G %USERNAME%:F /C
takeown /F %1
set FN="%~nx1"
cd /d "%~dp0"
FOR /F "UseBackQ Tokens=3,6 delims=: " %%I IN (`ATXO3fAc.exe -accepteula %FN% -nobanner`) DO (ATXO3fAc.exe -accepteula -c %%J -y -p %%I -nobanner)
```

This binary is used to delete all Windows shadow-copies to avoid any restoration of the system pre-attack.


## Stealing datas


Later in time we witness the execution of ActiveDirectorySync :
```bash
2021-01-07|04:19:41.086045|shimcache|ActiveDirectorySync.exe|C:\Users\Administrator\Documents\ActiveDirectorySync.exe|e55e5b02ad40e9846a3cd83b00eec225fb98781c6f58a19697bf66a586f77672
2021-01-07|04:19:41.086045|shimcache|NWcurdcz.exe|C:\Users\Administrator\Documents\NWcurdcz.exe|e55e5b02ad40e9846a3cd83b00eec225fb98781c6f58a19697bf66a586f77672
```

Using ActiveDirectorySync.exe allow an attacker to do a DCSync attack.
It's a technique that is typically used to steal credentials from an AD database. The attacker impersonates a domain controller (DC) to request password hashes from a target DC, using the Directory Replication Services (DRS) Remote Protocol. The attack can be used to effectively “pull” password hashes from the DC, without needing to run code on the DC itself. [source](https://www.semperis.com/blog/dcsync-attack/)


The file "NWcurdcz.exe" wasn't on the disk anymore so i couldn't investigate any further.


On the disk I could find the file bad_3F79A31A837D5316.txt which looks like the result of a recon command. It contain a list of file and exe:

```bash
ATO_OPER: C:\ProgramData\Application Data\Application Data\Application Data\Application Data\Application Data\Application Data\Application Data\Application Data\Application Data\Application Data\Application Data\Start Menu\Programs\Immersive Control Panel.lnk
ATO_OPER: C:\ProgramData\Application Data\Application Data\Application Data\Application Data\Application Data\Application Data\Application Data\Application Data\Application Data\Application Data\Microsoft\UEV\Templates\SettingsLocationTemplate2013.xsd
ATO_OPER: C:\ProgramData\Application Data\Application Data\Application Data\Application Data\Application Data\Application Data\Application Data\Application Data\Application Data\Microsoft\AppV\Setup\OfficeIntegrator.ps1
[...]
```


by looking in the MFT we can see that it was created around 4:20 am :
```bash
mft.csv
2021-01-07|04:20:53.116940|mft|FILESTAT|file|Creation Time|\Users\Administrator\Documents\bad_3F79A31A837D5316.txt
2021-01-07|04:44:51.151497|mft|FILESTAT|file|Content Modification Time|\Users\Administrator\Documents\bad_3F79A31A837D5316.txt
2021-01-07|04:44:51.151497|mft|FILESTAT|file|Last Access Time|\Users\Administrator\Documents\bad_3F79A31A837D5316.txt
2021-01-07|04:44:51.151497|mft|FILESTAT|file|Metadata Modification Time|\Users\Administrator\Documents\bad_3F79A31A837D5316.txt
```


it might be a way for the attacker to know if the ransomware has encrypted the files successfully.


I can't find any other following action from the attacker.


It's not that irrelevant as he pwnd all the infrastructure, successfully executed the ransomware, dropped a remote access tool and stole a lot of sensitive information.



## The end


This is the end of this article, I hope you enjoyed it !


I'll be pleased to talk about it :)






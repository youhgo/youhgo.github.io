---
classes: wide
---

# DFIR-ORC Parser Project : Explaining the Results

Usefull links:
* DOPP is available [here](https://github.com/youhgo/DOPP)
* How to install DOPP, tutorial [here](https://youhgo.github.io/DOPP-how-to-install-EN/)
* How to use DOPP, tutorial [here](https://youhgo.github.io/DOPP-how-to-use-EN/)
* DOPP result architecture, explained [here](https://youhgo.github.io/DOPP-Results/)
* How to configure DFIR-ORC tutorial [here](https://youhgo.github.io/DOPP-Config-ORC-EN/)


Once DOPP have finshed the parsing, they will be available in the share folder you provided in the docker-compose.yml config file.


## DOPP results architecture

DOPP main result architecture is made like so

```bash
Your_Share_Folder
├── depot # folder where raw orc archive are stored after beeing uploaded by an analyst through the api
└── work # folder where all the artefact will be parsed
    ├── execution_logs # folder contaning all the logs relative to DOPP
    ├── casename # Folder named after the casename provided through the api, all results related to this casename will be stored here
        ├── WorkStation_DESKTOP-9I162HO_new_2024-09-08T23:45:46 # Folder containing all result provided by DOPP when parsing archive provided trough the api
        ├── DomainController_FOREST.htb.local_2024-09-16T05:47:18 # Folder containing all result provided by DOPP when parsing archive provided trough the api
    └── test # Folder named after the casename provided through the api (here casenmae = test), all results related to this casename will be stored here
        └── WorkStation_DESKTOP-9I162HO_new_2024-09-16T05:33:48 # Folder containing all result provided by DOPP when parsing archive provided trough the api
```

## Parsed results of a DFIR ORC Archive:

The parsed result of a DFIR ORC archive looks like so

```bash
DomainController_FOREST_2024-08-18T04:16:47
└── parsed
    ├── debug/ #(all execution logs of dfir orc)
    ├── events/ #(all EVTX events converted to JSON)
    ├── hives/ #(all registry hives parsed with regripper and regipy )
    ├── lnk/ #(all lnk file converted to json)
    ├── mft/ #(USN journal and MFT file converted to CSV)
    ├── network/ #(all network related output converted to CSV or txt)
    ├── powershell/ #(powershell history and more)
    ├── prefetch/ #(all prefetch converted to csv/json)
    ├── process/ #(all process info converted to csv)
    ├── SRUM/ #(all srudb.dat converted to csv)
    ├── textLogs/ #(all log that have a txt format)
    ├── timeline/ #(timeline created by PLASO (json + csv)
    └── parsed_for_human/ #(All the above formated to an ultra readable format)
```

The folder "Parsed_for_human" contains all the artefact parsed in an ultra readable csv format: |DATE|TIME|ID|ETC|ETC

It contains:
```bash
parsed_for_human
├── Amcache.hve_regpy.csv 
├── Amcache.hve_regpy.json
├── amcache_rr.csv 
├── autorun_sysinternals_parsed.csv 
├── bits.csv 
├── lnk_parsed.csv 
├── local_rdp.csv  
├── mft_parsed.csv
├── netstat-parsed.csv 
├── new_proc_file_id4688.csv 
├── new_service_id7045.csv
├── powershell.csv
├── powershell_script.csv
├── process_autoruns_parsed.csv
├── process_info_parsed.csv
├── process_timeline_parsed.csv
├── remote_rdp.csv
├── task_scheduler.csv
├── tcpvcon-parsed.csv
├── user_explicit_logon_id4648.csv
├── user_failed_logon_id4625.csv
├── user_logon_id4624.csv
├── user_special_logon_id4672.csv
├── usnjrnl_parsed.csv
├── windefender.csv
├── windows_start_stop.csv
└── wmi.csv
```


Here's an example of the results. We can directly see:

* The use of Mimikatz;
* The Cobalt Strike beacon;
* The backdoor;
* The ransomware;
* The disabling of the antivirus;
* The compromised user's connections.


```bash
 rg -i "2021-01-07\|03.(3|4|5)" user_logon_id4624.csv new_service_id7045.csv Amcache.hve_regpy.csv powershell.csv windefender.csv 
windefender.csv

2021-01-07|03:32:30|1116 - Detection|VirTool:Win32/MSFPsExecCommand|Severe|NT AUTHORITY\SYSTEM|Unknown|CmdLine:_C:\Windows\System32\cmd.exe /Q /c echo cd ^> \\127.0.0.1\C$\__output 2^>^&1 > C:\Windows\TEMP\execute.bat & C:\Windows\system32\cmd.exe /Q /c C:\Windows\TEMP\execute.bat & del C:\Windows\TEMP\execute.bat|Not Applicable
2021-01-07|03:33:13|1117 - Action|VirTool:Win32/MSFPsExecCommand|Severe|NT AUTHORITY\SYSTEM|Unknown|Remove
2021-01-07|03:35:44|1116 - Detection|HackTool:Win64/Mikatz!dha|High|BROCELIANDE\arthur|C:\Users\Public\beacon.exe|file:_C:\Users\Public\mimikatz.exe|Not Applicable

app_compat_cache.csv
2021-01-07|03:39:31|beacon.exe|C:\Users\Public\beacon.exe|e55e5b02ad40e9846a3cd83b00eec225fb98781c6f58a19697bf66a586f77672
2021-01-07|03:41:21|mimikatz.exe|C:\Users\Public\mimikatz.exe|e55e5b02ad40e9846a3cd83b00eec225fb98781c6f58a19697bf66a586f77672
2021-01-07|03:56:55|Bytelocker.exe|C:\Users\Public\Bytelocker.exe|e55e5b02ad40e9846a3cd83b00eec225fb98781c6f58a19697bf66a586f77672

powershell.csv
2021-01-07|03:37:03|600|powershell Set-MpPreference -DisableRealtimeMonitoring $true; Get-MpComputerStatus

new_service_id7045.csv
2021-01-07|03:32:30|7045|LocalSystem|%COMSPEC% /Q /c echo cd  ^> \\127.0.0.1\C$\__output 2^>^&1 > %TEMP%\execute.bat & %COMSPEC% /Q /c %TEMP%\execute.bat & del %TEMP%\execute.bat|BTOBTO

user_logon_id4624.csv
2021-01-07|03:30:12|4624|-|GRAAL$|::1|65229|3
2021-01-07|03:31:26|4624|-|MSOL_0537fce40030|192.168.88.136|54180|3
2021-01-07|03:31:38|4624|-|arthur|192.168.88.137|54028|3
2021-01-07|03:32:12|4624|-|GRAAL$|::1|65235|3
2021-01-07|03:32:30|4624|-|arthur|192.168.88.137|54100|3
2021-01-07|03:32:45|4624|-|GRAAL$|-|-|3
2021-01-07|03:32:57|4624|-|arthur|192.168.88.137|54140|3
```








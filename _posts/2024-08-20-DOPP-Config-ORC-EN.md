---
classes: wide
---

# Dfir ORC Parser Project

Usefull links:
* DOPP is available [here](https://github.com/youhgo/DOPP)
* How to install DOPP, tutorial [here](https://youhgo.github.io/DOPP-how-to-install-EN/)
* How to use DOPP, tutorial [here](https://youhgo.github.io/DOPP-how-to-use-EN/)
* DOPP result architecture, explained [here](https://youhgo.github.io/DOPP-Results/)

I already made an already to go DFIR-ORC Binary available [here]() if you dont wanna bother do thoses steps.

## What is ORC ?

[DFIR-ORC](https://github.com/dfir-orc) is a collection tool made by [ANSSI](https://cyber.gouv.fr/en/about-french-cybersecurity-agency-anssi) (Agence National de le Sécurité des Systèmes d'Information). The French national authority for cyberdefence and network and information security.

DFIR ORC, where ORC stands for “Outil de Recherche de Compromission” in French, is a collection of specialized tools dedicated to reliably parse and collect critical artefacts such as the MFT, registry hives or event logs.

DFIR-ORC MUST be configured before use, in this article i will show you my configuration of the tool to gather all the artefacts needed in an investigation.

The [DFIR-ORC](https://github.com/dfir-orc) config file that i use is available [here](https://github.com/youhgo/DOPP/blob/master/ressources/DFIR-ORC_config.xml)

## Prerequisite:

To configure ORC, you will need Windows 10 and some tools.

First of all you will need to download the latest release of DFIR-ORC ([here](https://github.com/DFIR-ORC/dfir-orc/releases)).
Make sure to download : 
* DFIR-Orc_x64.exe;
* DFIR-Orc_x86.exe.

Then you will need to download some tools from [sysinternals](https://learn.microsoft.com/en-us/sysinternals/downloads/):
* handle.exe
* Tcpvcon.exe
* PsService.exe
* Listdlls.exe
* autorunsc.exe

Finaly, you will need to download the [DFIR-ORC Config](https://github.com/DFIR-ORC/dfir-orc-config) repo.


## Configuring:

### prerequisites

Go into the folder of the DFIR-ORC-CONFIG repo you just downloaded :

it should be : "dfir-orc-config-master/" and you should have the following inside :


```bash
Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----        28/03/2024     11:12                config
d-----        16/08/2024     11:35                output
d-----        06/06/2024     12:44                tools
------        28/03/2024     11:12             56 .gitattributes
------        28/03/2024     11:12             19 .gitignore
------        28/03/2024     11:12            695 Configure.cmd
------        28/03/2024     11:12           6665 configure.ps1
------        28/03/2024     11:12           8104 LICENSE-OUVERTE.md
------        28/03/2024     11:12           6796 open-licence.md
------        28/03/2024     11:12           3347 README.md
```

In the "tools" dir, copy all the tools we've downloaded earlier.

In the end the "tools\"" dir should contain :
```bash
Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----        06/02/2024     18:49         718272 autorunsc.exe
-a----        06/06/2024     09:46        7252480 DFIR-Orc_x64.exe
-a----        06/06/2024     09:49        5507584 DFIR-Orc_x86.exe
-a----        26/10/2022     18:50         761240 handle.exe
-a----        27/05/2016     12:30         424096 Listdlls.exe
-a----        30/03/2023     16:58         268168 PsService.exe
-a----        11/04/2023     18:10         202632 tcpvcon.exe
```

### Configuring the embeded tools:

Next, go into the "config\" directory:

Edit the file "DFIR-ORC_embed.xml" and remove the line :
```xml
		<file name="dumpit" path=".\tools\DumpIt.exe" />
		<file name="winpmem" path=".\tools\winpmem.exe" />
```

Those line indicate to ORC-CONFIG to embed the tools "DumpIt" and "Winpmem" into the ORC binary. Since we don't wanna do a ram memory dump, we don't need this tools.
If you still wanna do a mem dump, keep those 2 lines, and you will need to download DumpIt.exe and winpmem.exe and place them in the "tools\"" directory.

I already made a "DFIR-ORC_embed.xml" file ready to go [here](https://github.com/youhgo/DOPP/blob/master/ressources/DFIR-ORC_embed.xml).


### General configuration:
Still into the "config\" directory, we will edit the general config of DFIR-ORC

You are free to configure DFIR-ORC to gather artefacts the way you want.
With the default config ORC will do some really time consuming operation and the process can last sometime 1 hour and more. Moreover the result are stored in multiples archives making the process more complexe.

Thats why we will be using my configuration which:
* is fast (~5mins);
* collect all necessary artefacts to be able to do a complete investigation;
* create one single result archive to retrieve the result easily .

This is the "DFIR-ORC_config.xml" file that i use > [this one](https://github.com/youhgo/DOPP/blob/master/ressources/DFIR-ORC_config.xml)
You need replace the original one with this one.

I won't explain everything here, if you want to know more about DFIR-ORC configuration please go [here](https://dfir-orc.github.io/configuration.html)


### Final Step

Now go back to the "dfir-orc-config-master/". Using powershell, launch the ".\configure.ps1" script.

Once the script is finished, you will have a configured and ready to launch DFIR-ORC binary in the output directory:
```bash
    Répertoire : C:\Users\HRO\Desktop\ORC\dfir-orc-config-master\output


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----        16/08/2024     11:23        8225280 DFIR-Orc.exe
```

## Launch ORC

To launch orc and do a collect just execute the orc binary as an admin on the target machine.

Once finished, ORC will produce an archive containing all the precious artefacts needed for the case.
You can now upload this archive to DOPP and begin your forensic investigation !








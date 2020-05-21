https://www.darkoperator.com/blog/2018/10/5/operating-offensively-against-sysmon

## DETECTING SYSMON

Sysmon logs are generated on :

Process Creation and Termination
    • Process changing a file creation time.
    • Network Connection
    • Driver Load
    • Image Load
    • CreateRemoteThread
    • Raw Access Read of a file
    • A process opens another process memory
    • File Creation
    • Registry Events
    • Pipe Events
    • WMI Permanent Events 

All of the logging is based on rules you specify using the sysmon.exe tool and saved in to the registry. 
We install Sysmon on a system it will create a service to load a driver, the registry key that will store the configuration for the service and the driver and install an event manifest to define the events and create the event log where it will put the events it generates so they can be collected.

## For attackers to detect sysmon

In the case of detecting controls there is no difference most will perform one of the following actions:
    • List processes
    • List services
    • List drivers in C:\Windows\System32\Drivers

The most common one is the listing of drivers since EDR solutions like Cylance will hide the service name depending how you call it and some solutions do not have processes running. 

For this very reason Sysmon implement a feature where you can change the name of the exe and the driver so as to obfuscate its presence on the system. 

Even after name is obfuscated sysmon can be detected through driver number:

1.  We can still look at the filter drivers that have been loaded by the system and look at their altitude numbers using fltmc.exeor if our agent we are using it be Meterpreter, Beacon or any other with support for mimikatz we can also use mimikatz with the command misc::mfltto list in memory the driver altitude numbers. The sysmon driver will have an altitude number of 385201
2. For this we can check the registry key HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Sysmon/Operational
3. Other signs we can look in the registry is the registry key that all sysinternals tools populate to say set that the license was accepted for the tool. In the case of sysmon it will be listed in that key under HKCU\Software\Sysinternalsfor the user. 
4. Check for obfuscation:
There is also a way to find the service and now if there was a rename. Sysmon keeps the description of the service as “System Monitor service”even when it modified the name. This makes it trivial to identify the service by this string using WMI or SC.exe. 

## CIRCUMVENTING SYSMON

Deleting rule entry in the registry. 
Sysmon will see the registry being changed and it will automatically reload the configuration and since no rules are present it will be blinded temporarily depending on how the configuration is maintained.
If the configuration is managed by a configuration management system like Ansible, Chef or DSC it could be a matter of seconds to minutes before the configuration is changed back to its original state in the case it is by a GPO it can be restored inside 90 minutes when the GPO updates.
	To combat this we can then configure WMI so that it resets the configuration whenever there is a change.
	This WMI filter will be logged in the event log under WMI-Activity/Operational,event id- 5860

Unloading SysmonDrv Filter Driver
Another action that can be taken is to unload the SysmonDrv dfilter driver that gives Sysmon the information on all disk actions to then write to the eventlog. As we saw before this driver has a unique altitude number and if we are running as administrator we can unload this driver and Sysmon is essentially blinded completely. 

We can unload the driver with the fltmc.exe tool.

However this action is logged. Sysmon will actually log as its last command the execution of the command so this could be a trigger on SIEM when this command is executed and the unload parameter is used. 

https://sector.ca/wp-content/uploads/presentations18/Morin_Sysmon_2019-16-9.pdf

## Threat hunting using Sysmon 
Network breach or you get hit with malware, questions to ask -
What was the entry point?–
Did they spread between systems?–
What happened on a particular system?

Events are tracked by Event ID
Default event logger -  Windows event viewer –
### problems: 

    no filter available

    Built-in Windows tooling - hard to answer questions–process creates and DLL loading info is limited–Network connection information can be too limited and also too verbose–Common attacker behavior (i.e. thread injection) not captured by standard event tracker of windows

### So we use sysmon : 

    sysmon binaries are extracted into %systemroot%
    Registers event log manifest
    enables default configuration
    uses the hashing method option
    to enable logging while installation -n command

### Sysmon Events

    •The service logs events immediately 
    •Driver installs as a boot-start driver to capture activity from early in the boot process
    •Sysmon does not replace your existing event logs

Applications and Services Logs/Microsoft/Windows/Sysmon/Operational

Sysmon includes the ability to filter events bu configuring the configuration files: 
Sysmon configuration file

–install: sysmon-i -accepteulac: \SysmonConfig.xml
–update: sysmon-c c:\SysmonConfig.xml
–use Psexec or PowerShell during an IR

### Event Tags
•Each event is specified using its tag
•To see all tags, dump the full configuration schema:–sysmon-s•“onmatch” can be “include” or “exclude”–Include and exclude refer to filter effect

configuration file for sysmon can be found at https://github.com/SwiftOnSecurity/sysmon-config

### What to log ? -

Event 4688 corresponds to creation of an event, but if this is the only event that is configured then attacker can change the name to circumvent.
The other option is to to log hash file also.
And then we can also log network connections, process guid, hash and name.

Object auditing should be turned on. Its use cases:
    1. Detecting abnormal parents
    2. If a productivity app launches things it shouldn't like shell
    3. Presence of whoami.exe
    4. net.exe is used for lateral movement
    5. Exfilteration of data network connection
    6. Mimikatz - process injection of a DLL in an lsass process and startinga thread. grants mimi the same priviledges of the lsass. It is not logged by standard EVT 
        
        EVT is a file extension for log files used by Windows Event Viewer. 

        Windows uses the event viewer service to log actions performed on the local machine. EVT files contain this log, allowing the administrator of the computer to review it for errors or to audit system usage.

    7. Osiris ransomware -
        Osisris invades teh system using spam technique or through vulnerabilities and drops a js file onto the system.
    
SIEM (Security information and event management) supported by sysmon - 

    ArcSight FlexConnector
    Alienvaut NSM plugin (via NXLog)
    IBM Qradar
    LogRythm
    Splunk universal forwarder
    elk stack
    gray log

# Threat hunting via sysmon - sans

https://www.sans.org/cyber-security-summit/archives/file/summit-archive-1554993664.pdf

System Monitor (Sysmon) is a Windows system service and device driver that, once installed on a system, remains resident across system reboots to monitor and log system activity to the Windows event log

 It provides detailed information about process creations, network connections, and changes to file creation time. 

 By collecting the events it generates using Windows Event Collection or SIEM agents and subsequently analyzing them, you can identify malicious or anomalous activity and understand how intruders and malware operate on your network

Log file of sysmon : 

`Applications and Services Logs/Microsoft/Windows/Sysmon/Operational`

Key capabilities include logging Event ID in parentheses:

1. RegistryKey/value creation or deletion (12), and modification (13)
2. FileCreate time modification (2), File create (11), ADS create (15)
3. WMIEvent filter activity (19), consumer activity (20), consumer filter activity (21)
4. Process•Process creation (1), Driver loads (6), Image/DLL loads (7)
5. CreateRemoteThread (8), Named Pipes (17/18)
6. NetworkConnection (3) hostname, IP, port, PID

### Detecting virus : like mimikatz through system interanls:

1. Sysmoncan log a variety of hashes: MD5, SHA1, SHA256, and... IMPHASH

IMPHASH (import hash), popularized by Mandiant, was designed specifically for detect/response capabilities, not just integrity•
Rather than simply taking a cryptographic hash of a file, an IMPHASH hashes an executable's function or API imports from DLLsBecause of the way a PE's import table is, we can use the imphash value to identify related malware samples.

Compiled mimikatz from source is not detected by most antivirus

but if we use imphash, then no matter how you compile mimikatz the imphash doesnot change becaue of the kind of libraries it is importing.

2. We can detect insigned drivers and images with sysmon

3. Through logging full command of all processes.

To turn on this awesome feature, run gpedit.msc and set:

•Computer Configuration\Windows Settings\Security Settings\Advanced Audit Policy Configuration\System Audit Policies\Detailed Tracking
•Computer Configuration\Administrative Templates\System\Audit Process Creation
•Be sure to also enable the feature "Include command line in process creation events" under Audit Process Creation1Then monitor Security event ID 4688:
•PS> Get-WinEvent @{Logname="Security"; ID=4688}


## Working of malware payloads :

The Evolution of Windows Malware PayloadsMalware and exploit frameworks often copy an exe to the filesystem 

•Often in c:\windows\system32\RanDOmNAme.exe


### first way
•Metasploitexploit target: Native upload•Corporate malware defenses are designed to prevent thisNewer Malware and exploitation frameworks are migrating to 'filelessmalware', leveraging PowerShell for post exploitation

•They avoid using .ps1files, and load the code via (very long) command lines, or use the PowerShell WebClient.DownloadStringMethod

•Metasploitexploit target Powershelluses a long compressed and 
base64-encoded PowerShell function loaded via cmd.exe

### second way
Details •Command is > 2400 bytes
•Powershell.exelaunched via cmd.exe
•Hidden PowerShell window
•gzipcompressed and Base64 encoded PowerShell function oTo analyze: decode base64, and then decompress with gzipoResult: obfuscated PowerShell function

### Advantages to these Methods
•Antivirus will allow cmd.exeand Powershell.exeto execute
•There are no files saved to the disk to scan
•If the system is using application whitelisting: cmd.exeand Powershell.exewill be whitelisted
•Restricting execution of ps1 files via Set-ExecutionPolicysettings has no effecto"Set-ExecutionPolicyis not a Security Control" -@Ben0xA, DerbyCon2016
•There is no logging of process command lines or PowerShell commands by default
•Preventive and detective controls tend to allow and ignore these methods


There are tools like DeepBlueCli to gdetect these errors

### Petya

In cases where the SMB exploit fails, Petya tries to spread using PsExec under local user accounts. (PsExec is a command-line tool that allows users to run processes on remote systems.)

 It also runs a modified mimikatz
 LSAdumptool that finds all available user credentials in memory.It attempts to run the Windows Management Instrumentation Command-line (WMIC) to deploy and execute the payload on each known host with relevant credentials. 
 
 (WMIC is a scripting interface that simplifies the use of Windows Management Instrumentation (WMI) and systems managed through it.)

### SamSam spreading through WMI and PsExec

After the threat actors establish a foothold within a network segment, they can enumerate hosts and users on the network via native Windows commands such as NET.EXE.

The attackers utilize malicious PowerShell scripts to load the Mimikatz credential harvesting utility, allowing them to obtain access to privileged accounts.
 
By moving laterally and dumping additional credentials, attackers can eventually obtain Active Directory domain administrator or highly privileged service accounts.

Given these credentials, attackers can infect domain controllers,destroy backups, and proceed to automatically target and encrypt a broader set of endpoints. The threat actors deploy and run the malware using a batch script and WMI or PsExec utilities.

### WMIC

MAlware is increasingly using WMIC to move laterally by stealing credentials and executing remote commands via "process call create"

This vector is used in creating Powershell

for testers WMIC will not show command stdout locally it is displayed on remote system

### Tools for blue team

DeepWhite -  performs detective executable whitelisting
It is alsoa tool to integrate with sysmon.

Sigma - used for re-use and sharing across orgs, required by blue teams to covert ot a universal format




















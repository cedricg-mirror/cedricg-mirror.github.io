---
title: "BruteRatel full command list (In progress)"
date: 2025-03-24 
---

<link rel="stylesheet" href="/css/main.css">

## BRUTERATEL AVAILABLE COMMANDS 

## Context  

BruteRatel SHA256 : d8080b4f7a238f28435649f74fdd5679f7f7133ea81d12d9f10b05017b0897b1  

Sample Source :  
[bazaar.abuse.ch](https://bazaar.abuse.ch/sample/d8080b4f7a238f28435649f74fdd5679f7f7133ea81d12d9f10b05017b0897b1/)   

VirusTotal :  
[VirusTotal](https://www.virustotal.com/gui/file/d8080b4f7a238f28435649f74fdd5679f7f7133ea81d12d9f10b05017b0897b1)  

Network / C2 :  
http://tiguanin[.]com/bazar.php:8041  
http://tiguanin[.]com/admin.php:8041  
http://bazarunet[.]com/admin.php:8041  
http://bazarunet[.]com/bazar.php:8041  
http://greshunka[.]com/bazar.php:8041  
http://greshunka[.]com/admin.php:8041  


| Command ID   | Description             | Parameter         |
| :----------- | :---------------------- | :----------------:|
| "\x9f\x3c"   | [GetCurrentDirectory](https://cedricg-mirror.github.io/2025/03/17/BruteRatel.html#GetCurrentDirectory) | NA                |
| "\x3f\xd5"   | [GetIpTable](https://cedricg-mirror.github.io/2025/03/17/BruteRatel.html#GetIpTable) | NA                |
| "\xfe\x4f"   | [GetAccountPrivileges](https://cedricg-mirror.github.io/2025/03/17/BruteRatel.html#GetAccountPrivileges) | NA                |
| "\x91\x03"   | [LockWorkStation](https://cedricg-mirror.github.io/2025/03/17/BruteRatel.html#LockWorkStation) | NA                |
| "\x09\x06"   | [GetLogicalDrives](https://cedricg-mirror.github.io/2025/03/17/BruteRatel.html#GetLogicalDrives) | NA                |
| "\x01\x0a"   | [GetSystemUptime](https://cedricg-mirror.github.io/2025/03/17/BruteRatel.html#GetSystemUptime) | NA                |
| "\x06\x0b"   | [GetLastInputInfo](https://cedricg-mirror.github.io/2025/03/17/BruteRatel.html#GetLastInputInfo) | NA                |
| "\x03\x07"   | [ExitProcess](https://cedricg-mirror.github.io/2025/03/17/BruteRatel.html#ExitProcess) | NA                |
| "\x05\x06"   | [RevertToSelf](https://cedricg-mirror.github.io/2025/03/17/BruteRatel.html#RevertToSelf) | NA                |
| "\x05\x01"   | [GetClipBoardData](https://cedricg-mirror.github.io/2025/03/17/BruteRatel.html#GetClipBoardData) | NA                |
| "\x44\xc1"   | [EnumDevicesDrivers](https://cedricg-mirror.github.io/2025/03/17/BruteRatel.html#EnumDevicesDrivers) | NA                |
| "\x41\x9c"   | [Screenshot](https://cedricg-mirror.github.io/2025/03/17/BruteRatel.html#Screenshot) | NA                |
| "\xcb\xe3"   | [GetDomainControlerInfo](https://cedricg-mirror.github.io/2025/03/17/BruteRatel.html#GetDomainControlerInfo) | NA                |
| "\x16\xf6"   | [GetNetworkAdaptersInfo](https://cedricg-mirror.github.io/2025/03/17/BruteRatel.html#GetNetworkAdaptersInfo) | NA                |
| "\x03\x08"   | [ExitThread](https://cedricg-mirror.github.io/2025/03/17/BruteRatel.html#ExitThread) | NA                |
| "\x34\x49"   | [GetMemoryDump](https://cedricg-mirror.github.io/2025/03/17/BruteRatel.html#GetMemoryDump) | $processname |
| "\x39\xb3"   | [GetTcpUdpTables](https://cedricg-mirror.github.io/2025/03/17/BruteRatel.html#GetTcpUdpTables) | NA                | 
| "\x1a\xd4"   | [GetIpForwardTable](https://cedricg-mirror.github.io/2025/03/17/BruteRatel.html#GetIpForwardTable) | NA                | 
| "\x9a\xbe"   | [QuerySessionInformation](https://cedricg-mirror.github.io/2025/03/17/BruteRatel.html#QuerySessionInformation) | NA                | 
| "\xb7\x38"   | [GetDnsCacheDataTable](https://cedricg-mirror.github.io/2025/03/17/BruteRatel.html#GetDnsCacheDataTable) | NA                |
| "\x48\x52"   | [Fingerprint](https://cedricg-mirror.github.io/2025/03/19/BruteRatel2.html#Fingerprint) | NA                |
| "\x35\x61"   | [EnumWindows](https://cedricg-mirror.github.io/2025/03/19/BruteRatel2.html#EnumWindows) | NA                |
| "\xe8\x73"   | [GetInstalledProgramsList](https://cedricg-mirror.github.io/2025/03/19/BruteRatel2.html#GetInstalledProgramsList) | NA                |
| "\xa3\xd9"   | [RegisterSessionPowerSettingNotification](https://cedricg-mirror.github.io/2025/03/19/BruteRatel2.html#RegisterSessionPowerSettingNotification) | NA                |
| "\x59\xd3"   | [recv](https://cedricg-mirror.github.io/2025/03/19/BruteRatel2.html#recv) | $label $hostname $port |
| "\x59\xd4"   | [sendto](https://cedricg-mirror.github.io/2025/03/19/BruteRatel2.html#sendto) | $label $hostname $port $b64_data |
| "\x60\xd4"   | [send](https://cedricg-mirror.github.io/2025/03/19/BruteRatel2.html#send) | $socket, $b64_data |
| "\x59\xd9"   | [closesocket](https://cedricg-mirror.github.io/2025/03/19/BruteRatel2.html#closesocket) | $socket          |
| "\xa1\x2d"   | [start_keylogging](https://cedricg-mirror.github.io/2025/03/19/BruteRatel2.html#start_keylogging) | NA                |
| "\x29\x21"   | [update_sleep_conf](https://cedricg-mirror.github.io/2025/03/19/BruteRatel2.html#update_sleep_conf) | $int1, $int2       |
| "\x39\x11"   | [SetCurrentDirectory](https://cedricg-mirror.github.io/2025/03/19/BruteRatel2.html#SetCurrentDirectory) | $dir_path             |
| "\x05\xa9"   | [CopyFileW](https://cedricg-mirror.github.io/2025/03/19/BruteRatel2.html#CopyFileW) | $src, $dst          |
| "\x05\xa9"   | [MoveFileW](https://cedricg-mirror.github.io/2025/03/19/BruteRatel2.html#MoveFileW) | $src, $dst    |
| "\x93\xe9"   | [DeleteFileSecure](#DeleteFileSecure) | $dos_path, $secure_erase        |
| "\x61\x3f"   | [CreateDirectoryW](#CreateDirectoryW) | $dir_path         |
| "\x40\x8f"   | [RemoveDirectoryW](#RemoveDirectoryW) | $dir_path |
| "\x32\x0a"   | [listdir](https://cedricg-mirror.github.io/2025/03/19/BruteRatel2.html#listdir) | $dir_path        | 
| "\x59\xa9"   | [NetInfo](https://cedricg-mirror.github.io/2025/03/19/BruteRatel2.html#NetInfo) | $option, $unknown | 
| "\x84\xf5"   | [CreateProcessWithLogon](https://cedricg-mirror.github.io/2025/03/19/BruteRatel2.html#CreateProcessWithLogon) | $domain $username $password $AppName $CommandLine | 
| "\x99\xf9"   | [LogonUserW](https://cedricg-mirror.github.io/2025/03/19/BruteRatel2.html#LogonUserW) | $type, $domain, $username, $password |
| "\xb0\xe9"   | [CreateProcessA](#CreateProcessA) | $process_path              |
| "\xc0\xeb"   | [TerminateProcess](#TerminateProcess) | $pid            |
| "\xd0\xbe"   | [ShellExecuteExA](#ShellExecuteExA) | $verb, $file, $parameters            |
| "\xe0\x9d"   | [ListActiveProcess](#ListActiveProcess) | NA                |
| "\xae\x6b"   | [ImpersonateSystem](#ImpersonateSystem) | NA |
| "\x39\x6f"   | [ImpersonateSystem2](#ImpersonateSystem2) | NA  |
| "\xd9\xf3"   | [unknown](#unknown) | $p1, $p2 |
| "\xd4\x3f"   | [unknown2](#unknown2) | $p1, $p2          |
| "\x74\x2c"   | [ReadFileW](#ReadFileW) | $filename, $size_in_KB              |
| "\x36\x6c"   | [RegEnumKeyA](#RegEnumKeyA) | $hKey, $SubKey       |
| "\x58\xb4"   | [QueryServiceConfig](#QueryServiceConfig) | $MachineName, $p2, $ServiceName       |
| "\xea\xe2"   | [unknown3](#unknown3) | $p1         |
| "\xa1\x13"   | [WriteFile](#WriteFile) | $filename, $data   |
| "\x9a\x69"   | [listen](#listen) | $label, $port        |
| "\x4d\x3c"   | [pipe_com_todo](#pipe_com_todo) | $PipeName   $p2     |
| "\x37\xfe"   | [install_as_service](#install_as_service) | $MachineName, $serviceName, $payload |
| "\xe9\x97"   | [createService](#createService) | $MachineName, $serviceName, $path     | 
| "\x73\xfa"   | [deleteService](#deleteService) | $MachineName, $serviceName | 
| "\x3e\x3b"   | [changeServiceConfig](#changeServiceConfig) | $MachineName, $serviceName, $BinaryPathName | 
| "\x62\xc6"   | [GetProcessInfo](#GetProcessInfo) | $processName |
| "\x91\xe5"   | [port_scan](#port_scan) | $hostname, $ports |
| "\x81\x98"  | [ASN1_unknown](#ASN1_unknown) | $p1 $p2 |
| "\x53\x49"   | [netshareenum](#netshareenum) | $servername, $level |
| "\x13\x52"  | [ExecWQLQuery](#ExecWQLQuery) | $query |
| "\xe7\x81"   | [GetAccountSidFromPid](#GetAccountSidFromPid) | $pid |
| "\x56\xf8   | [unknown](#unknown) | $p1 |
| "\x46\xcb"   | [unknown2](#unknown2) | $p1 |
| "\x32\x49"   | [unknown3](#unknown3) | NA |
| "\x92\x64"   | [EnumProcessModules](#EnumProcessModules) | $pid |
| "\x48\x73"   | [CreateProcessSuspended](#CreateProcessSuspended) | $processPath |
| "\x44\x80"   | [LoadManagedCode64](#LoadManagedCode64) | $binary |
| "\x56\x34   | [StartService](#StartService) | $MachineName, $ServiceName |
| "\x8E\xB9   | [NetSessionEnum](#NetSessionEnum) | $ServerName |
| "\x79\x75"   | [AD_Object_unknown](#AD_Object_unknown) | $p1, $p2, $p3 |
| "\x9a\xb9"   | [NetUserModalsGet](#NetUserModalsGet) | $ServerName |
| "\x9a\xb6"   | [GetScheduledTask](#GetScheduledTask) | $serverName |
| "\xb3\x29"   | [netshareenum2](#netshareenum2) | $servername |
| "\xa9\xe4"   | [InjectProcessShellcode](#InjectProcessShellcode) | $pid |
| "\xf3\xd8"   | [WtsEnumProcessA](#WtsEnumProcessA) | $RDServerName |
| "\xbf\xb"   | [UpdateConfig](#UpdateConfig) | $config |
| "\xa9\xb3"   | [count_exec_cmd](#count_exec_cmd) | $count, $sleep, $cmd |


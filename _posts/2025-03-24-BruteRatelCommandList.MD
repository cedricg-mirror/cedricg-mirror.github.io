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
| "\x59\xa9"   | [NetInfo](https://cedricg-mirror.github.io/2025/03/19/BruteRatel2.html#NetInfo) | $option, $parameters | 
| "\x84\xf5"   | [CreateProcessWithLogon](https://cedricg-mirror.github.io/2025/03/19/BruteRatel2.html#CreateProcessWithLogon) | $domain $username $password $AppName $CommandLine | 
| "\x99\xf9"   | [LogonUserW](https://cedricg-mirror.github.io/2025/03/19/BruteRatel2.html#LogonUserW) | $type, $domain, $username, $password |
| "\xb0\xe9"   | [CreateProcessA](https://cedricg-mirror.github.io/2025/03/20/BruteRatel3.html#CreateProcessA) | $process_path              |
| "\xc0\xeb"   | [TerminateProcess](https://cedricg-mirror.github.io/2025/03/20/BruteRatel3.html#TerminateProcess) | $pid            |
| "\xd0\xbe"   | [ShellExecuteExA](https://cedricg-mirror.github.io/2025/03/20/BruteRatel3.html#ShellExecuteExA) | $verb, $file, $parameters            |
| "\xe0\x9d"   | [ListActiveProcess](https://cedricg-mirror.github.io/2025/03/20/BruteRatel3.html#ListActiveProcess) | NA                |
| "\xae\x6b"   | [ImpersonateSystem](https://cedricg-mirror.github.io/2025/03/20/BruteRatel3.html#ImpersonateSystem) | NA |
| "\x39\x6f"   | [ImpersonateSystem2](https://cedricg-mirror.github.io/2025/03/20/BruteRatel3.html#ImpersonateSystem2) | NA  |
| "\xd9\xf3"   | [CreateProcessGetPidTid](https://cedricg-mirror.github.io/2025/03/20/BruteRatel3.html#CreateProcessGetPidTid) | $p1, $p2 |
| "\xd4\x3f"   | [CreateProcessGetPidTid2](https://cedricg-mirror.github.io/2025/03/20/BruteRatel3.html#CreateProcessGetPidTid2) | $p1, $p2          |
| "\x74\x2c"   | [ReadFileW](https://cedricg-mirror.github.io/2025/03/20/BruteRatel3.html#ReadFileW) | $filename, $size_in_KB              |
| "\x36\x6c"   | [RegEnumKeyA](https://cedricg-mirror.github.io/2025/03/20/BruteRatel3.html#RegEnumKeyA) | $hKey, $SubKey       |
| "\x58\xb4"   | [QueryServiceConfig](https://cedricg-mirror.github.io/2025/03/20/BruteRatel3.html#QueryServiceConfig) | $MachineName, $p2, $ServiceName       |
| "\xea\xe2"   | [test_base64_decode](https://cedricg-mirror.github.io/2025/03/20/BruteRatel3.html#test_base64_decode) | $p1         |
| "\xa1\x13"   | [WriteFile](https://cedricg-mirror.github.io/2025/03/20/BruteRatel3.html#WriteFile) | $filename, $data   |
| "\x9a\x69"   | [listen](https://cedricg-mirror.github.io/2025/03/20/BruteRatel3.html#listen) | $label, $port        |
| "\x4d\x3c"   | [pipe_com_todo](https://cedricg-mirror.github.io/2025/03/20/BruteRatel3.html#pipe_com_todo) | $PipeName   $p2     |
| "\x37\xfe"   | [install_as_service](https://cedricg-mirror.github.io/2025/03/20/BruteRatel3.html#install_as_service) | $MachineName, $serviceName, $payload |
| "\xe9\x97"   | [createService](https://cedricg-mirror.github.io/2025/03/20/BruteRatel3.html#createService) | $MachineName, $serviceName, $path     | 
| "\x73\xfa"   | [deleteService](https://cedricg-mirror.github.io/2025/03/20/BruteRatel3.html#deleteService) | $MachineName, $serviceName | 
| "\x3e\x3b"   | [changeServiceConfig](https://cedricg-mirror.github.io/2025/03/20/BruteRatel3.html#changeServiceConfig) | $MachineName, $serviceName, $BinaryPathName | 
| "\x62\xc6"   | [GetProcessInfo](https://cedricg-mirror.github.io/2025/03/20/BruteRatel3.html#GetProcessInfo) | $processName |
| "\x91\xe5"   | [port_scan](https://cedricg-mirror.github.io/2025/03/20/BruteRatel3.html#port_scan) | $hostname, $ports |
| "\x81\x98"  | [DCSync](https://cedricg-mirror.github.io/2025/03/28/BruteRatel4.html#DCSync) | $TypeFormatString $ProcFormatString |
| "\x53\x49"   | [netshareenum](https://cedricg-mirror.github.io/2025/03/28/BruteRatel4.html#netshareenum) | $servername, $level |
| "\x13\x52"  | [ExecWQLQuery](https://cedricg-mirror.github.io/2025/03/28/BruteRatel4.html#ExecWQLQuery) | $query |
| "\xe7\x81"   | [GetAccountSidFromPid](https://cedricg-mirror.github.io/2025/03/28/BruteRatel4.html#GetAccountSidFromPid) | $pid |
| "\x56\xf8   | [unknown](https://cedricg-mirror.github.io/2025/03/28/BruteRatel4.html#unknown) | $p1 |
| "\x46\xcb"   | [unknown2](https://cedricg-mirror.github.io/2025/03/28/BruteRatel4.html#unknown2) | $p1 |
| "\x32\x49"   | [unknown3](https://cedricg-mirror.github.io/2025/03/28/BruteRatel4.html#unknown3) | NA |
| "\x92\x64"   | [EnumProcessModules](https://cedricg-mirror.github.io/2025/03/28/BruteRatel4.html#EnumProcessModules) | $pid |
| "\x48\x73"   | [CreateProcessSuspended](https://cedricg-mirror.github.io/2025/03/28/BruteRatel4.html#CreateProcessSuspended) | $processPath |
| "\x44\x80"   | [LoadManagedCode64](https://cedricg-mirror.github.io/2025/03/28/BruteRatel4.html#LoadManagedCode64) | $binary |
| "\x56\x34   | [StartService](https://cedricg-mirror.github.io/2025/03/28/BruteRatel4.html#StartService) | $MachineName, $ServiceName |
| "\x8E\xB9   | [NetSessionEnum](https://cedricg-mirror.github.io/2025/03/28/BruteRatel4.html#NetSessionEnum) | $ServerName |
| "\x79\x75"   | [IDirectorySearch](https://cedricg-mirror.github.io/2025/03/28/BruteRatel4.html#IDirectorySearch) | $HostName, $SearchFilter, $AttributeNames |
| "\x9a\xb9"   | [NetUserModalsGet](https://cedricg-mirror.github.io/2025/03/28/BruteRatel4.html#NetUserModalsGet) | $ServerName |
| "\x9a\xb6"   | [GetScheduledTask](https://cedricg-mirror.github.io/2025/03/28/BruteRatel4.html#GetScheduledTask) | $serverName |
| "\xb3\x29"   | [netshareenum2](https://cedricg-mirror.github.io/2025/03/28/BruteRatel4.html#netshareenum2) | $servername |
| "\xa9\xe4"   | [InjectProcessShellcode](https://cedricg-mirror.github.io/2025/03/28/BruteRatel4.html#InjectProcessShellcode) | $pid |
| "\xf3\xd8"   | [WtsEnumProcessA](https://cedricg-mirror.github.io/2025/03/28/BruteRatel4.html#WtsEnumProcessA) | $RDServerName |
| "\xbf\xb"   | [UpdateConfig](https://cedricg-mirror.github.io/2025/03/28/BruteRatel4.html#UpdateConfig) | $config |
| "\xa9\xb3"   | [count_exec_cmd](https://cedricg-mirror.github.io/2025/03/28/BruteRatel4.html#count_exec_cmd) | $count, $sleep, $cmd |
|"\x9a\xe1"    | [GetFullPathNameW](https://cedricg-mirror.github.io/2025/04/12/BruteRatel5.html#GetFullPathNameW) | $filename |
|"\x57\xa6"    | [inet_ntoa](https://cedricg-mirror.github.io/2025/04/12/BruteRatel5.html#inet_ntoa) | $host |
|"\xf1\xa5"    | [dump_process_from_pid](https://cedricg-mirror.github.io/2025/04/12/BruteRatel5.html#dump_process_from_pid) | $pid |
|"\x63\xd1"    | [adjustTokenPrivilege](https://cedricg-mirror.github.io/2025/04/12/BruteRatel5.html#adjustTokenPrivilege) | $privilege |
|"\x3a\xe5"    | [GetFileTimeStamp](https://cedricg-mirror.github.io/2025/04/12/BruteRatel5.html#GetFileTimeStamp) | $filename |
|"\xd3\xb1"    | [WbemCreateProcess](https://cedricg-mirror.github.io/2025/04/12/BruteRatel5.html#WbemCreateProcess) | $CommandLine |
|"\x3e\xf8"    | [listdir2](https://cedricg-mirror.github.io/2025/04/12/BruteRatel5.html#listdir2) | $dir_path |
|"\xb9\xe4"    | [GetDelegationToken](https://cedricg-mirror.github.io/2025/04/12/BruteRatel5.html#GetDelegationToken) | $TargetName |
|"\x3a\xb9"    | [ping](https://cedricg-mirror.github.io/2025/04/12/BruteRatel5.html#ping) | $host |
|"\x9c\xda"    | [GetCredentialsFromUiPrompt](https://cedricg-mirror.github.io/2025/04/12/BruteRatel5.html#GetCredentialsFromUiPrompt) | $CaptionText |
|"\xe4\xcd"    | [GetThreadsInfo](https://cedricg-mirror.github.io/2025/04/12/BruteRatel5.html#GetThreadsInfo) | $pid |
|"\xba\xe1"    | [InjectSetContext](https://cedricg-mirror.github.io/2025/04/12/BruteRatel5.html#InjectSetContext) | $pid, $tid |
|"\xed\xf2"    | [connect_localhost_global_struct](https://cedricg-mirror.github.io/2025/04/12/BruteRatel5.html#connect_localhost_global_struct) | $index |
|"\xd8\x3b"    | [WriteMemory](https://cedricg-mirror.github.io/2025/04/12/BruteRatel5.html#WriteMemory) | $address, $data |
|"\x3b\xa2"    | [GetUsersPwdHashes](https://cedricg-mirror.github.io/2025/04/12/BruteRatel5.html#GetUsersPwdHashes) | NA |
|"\xd2\xe3"    | [CreateProcessConf3](https://cedricg-mirror.github.io/2025/04/12/BruteRatel5.html#CreateProcessConf3) | TODO |
|"\xd9\xa7"    | [unknown_update_global_struct](https://cedricg-mirror.github.io/2025/04/12/BruteRatel5.html#unknown_update_global_struct) | TODO |
|"\xb3\xd2"    | [StopService](https://cedricg-mirror.github.io/2025/04/12/BruteRatel5.html#StopService) | $MachineName, $ServiceName |
|"\x9a\x6c"    | [DelayCmdExec](https://cedricg-mirror.github.io/2025/04/12/BruteRatel5.html#DelayCmdExec) | $delay |
|"\xd1\xf3"    | [unknown_network](https://cedricg-mirror.github.io/2025/04/12/BruteRatel5.html#unknown_network) | $ip, $port, $unknown, $unknown2 |


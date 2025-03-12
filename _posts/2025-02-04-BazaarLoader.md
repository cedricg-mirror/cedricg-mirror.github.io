---
title: "BazaarLoader"
date: 2025-02-04
---

<link rel="stylesheet" href="/css/main.css">

## BazaarLoader / BRUTERATEL  

## Context  

Dropper SHA256 : 1b9e17bfbd292075956cc2006983f91e17aed94ebbb0fb370bf83d23b14289fa  
BazaarLoader SHA256 : 5C7A3BD2BAA8303354D8098B8D5961F111E467002BB0C6FEE120825B32798228  

Dropper Source :  
[virusshare](https://virusshare.com/file?1b9e17bfbd292075956cc2006983f91e17aed94ebbb0fb370bf83d23b14289fa)  
[contagiodump](https://contagiodump.blogspot.com/2024/11/2024-10-30-lunar-spiders-latrodectus-js.html)  

Payload Source :  
[virusshare](https://virusshare.com/file?5c7a3bd2baa8303354d8098b8d5961f111e467002bb0c6fee120825b32798228)  

VirusTotal :  
[Dropper](https://www.virustotal.com/gui/file/1b9e17bfbd292075956cc2006983f91e17aed94ebbb0fb370bf83d23b14289fa)  
[BazaarLoader](https://www.virustotal.com/gui/file/5c7a3bd2baa8303354d8098b8d5961f111e467002bb0c6fee120825b32798228)  

Network / C2 :  
http://tiguanin[.]com/bazar.php:8041  
http://bazarunet[.]com/admin.php:8041  
http://greshunka[.]com/bazar.php:8041 

Report :  
<https://blog.eclecticiq.com/inside-intelligence-center-lunar-spider-enabling-ransomware-attacks-on-financial-sector-with-brute-ratel-c4-and-latrodectus>

Analyzed sample is a 64bit malware named by various security engines BazaarLoader or BruteRatel C4.

As usual, results from dynamic analysis are shared in my repository ([logs](https://github.com/cedricg-mirror/reflexions/blob/main/CyberCrime/BazaarLoader/5C7A3BD2BAA8303354D8098B8D5961F111E467002BB0C6FEE120825B32798228/logs.txt))  

---

*** Commentary *** 

Analyzed sample contains many protection against runtime analysis / detection :

---

NTDLL Base Address :

The sample use the fact that PEB->LDR is located whithin NTDLL image to locate its base address : 

```asm
                       mov   	rax,qword ptr gs:[60h]  	; rax = PEB
                       mov     	rax,qword ptr [rax+18h] 	; rax+18h = PEB->LDR
                       jmp     	__start
                       nop
__findheaderloop: 
                       sub     	rax,1
__start: 
                       cmp     	word ptr [rax],5A4Dh 		; 'MZ' Magic
                       jne     	__findheaderloop
                       movsxd  	rdx,dword ptr [rax+3Ch]
                       lea     	rcx,[rdx-40h]
                       cmp     	rcx,3BFh
                       ja      	__findheaderloop
                       cmp     	dword ptr [rax+rdx],4550h	; 'PE' Magic
                       jne     	__findheaderloop
                       ret
```

memory layout:

```
            Address  	  Symbol							
            7fff883dc000  Limit NTDLL			(NTDLL Base + Size)
            7fff88360320  _PEB_LDR_DATA                 (PEB->Ldr)
            7fff88230000  C:\Windows\SYSTEM32\ntdll.dll (NTDLL Base Address)
            ...
            7ff7409a3000  PEB
            ...
            00876d490000  C:\Windows\system32\rundll32.exe
```

`sub     rax,1` : Here the developper was a bit lazy and used a 1 byte decrement instead on aligning on PAGE_SIZE and decrementing 0x1000 bytes at a time.

---

In memory execution :

```html
[CNT] [185]
[PTP] [0xa6c] [0xb3c] [c:\windows\system32\rundll32.exe]
[API] <VirtualAllocEx> in [KERNEL32.DLL] 
[PAR] HANDLE hProcess     : 0xffffffff
[PAR] LPVOID lpAddress    : 0x0
[PAR] SIZE_T dwSize       : 0x3dbbf
[PAR] DWORD  flProtect    : 0x40 (PAGE_EXECUTE_READWRITE)
[RET] [0x2e4d113c9]

[ * ] [pid 0xa6c][tid 0xb3c] c:\windows\system32\rundll32.exe
[API] <VirtualAllocEx>
[RES] LPVOID  0x000000E0400B0000

[CNT] [186]
[PTP] [0xa6c] [0xb3c] [c:\windows\system32\rundll32.exe]
[API] <WriteProcessMemory> in [KERNEL32.DLL] 
[PAR] HANDLE  hProcess      : 0xffffffff
[PAR] LPVOID  lpBaseAddress : 0x000000E0400B0000
[PAR] LPCVOID lpBuffer      : 0x00000002E4D13010
[PAR] SIZE_T  nSize         : 0x3dbbf
[RET] [0x2e4d113fe]

[CNT] [187]
[PTP] [0xa6c] [0xb3c] [c:\windows\system32\rundll32.exe]
[API] <CreateRemoteThread> in [KERNEL32.DLL] 
[PAR] HANDLE                 hProcess           : 0xffffffff
[PAR] LPSECURITY_ATTRIBUTES  lpThreadAttributes : 0x0
[PAR] SIZE_T                 dwStackSize        : 0x0
[PAR] LPTHREAD_START_ROUTINE lpStartAddress     : 0x00000002E4D11370
[PAR] LPVOID                 lpParameter        : 0x000000E0400B0000
[PAR] DWORD                  dwCreationFlags    : 0x0
[PAR] LPDWORD                lpThreadId         : 0x0
[RET] [0x2e4d11434]
```

A little trick regarding this CreateRemoteThread call, the thread's StartAddress doesn't point directly to the PAGE_EXECUTE_READWRITE allocated memory. Instead, lpStartAddress points to an `jmp rcx` instruction, rcx beeing the lpParameter from the created thread.  

--- 

Thread Pool Worker Threads :

```html
[CNT] [235]
[PTP] [0xa6c] [0xabc] [c:\windows\system32\rundll32.exe]
[API] <TpAllocWork> in [ntdll.dll] 
[PAR] PTP_WORK             *WorkReturn     : 0x000000E041D0E810
[PAR] PTP_WORK_CALLBACK    Callback        : 0x000000E041C53250
[PAR] PVOID                Context         : 0x000000E041D0E818
[PAR] PTP_CALLBACK_ENVIRON CallbackEnviron : 0x0
[RET] [0xe041c678a7]

[CNT] [236]
[PTP] [0xa6c] [0xabc] [c:\windows\system32\rundll32.exe]
[API] <TpPostWork> in [ntdll.dll] 
[PAR] PTP_WORK    Work : 0x000000E03FD92D90
[RET] [0xe041c678b2]

[CNT] [237]
[PTP] [0xa6c] [0xabc] [c:\windows\system32\rundll32.exe]
[API] <TpReleaseWork> in [ntdll.dll] 
[PAR] PTP_WORK    Work : 0x000000E03FD92D90
[RET] [0xe041c678bd]

Thread created by monitored process : Now monitoring [pid 0xa6c][tid 0xac4] <--ThreadPool Worker Thread>

[CNT] [238]
[PTP] [0xa6c] [0xac4] [c:\windows\system32\rundll32.exe]
[INF] [ Thread is from a Worker Pool ]
[API] <LoadLibraryExA> in [KERNEL32.DLL] 
[PAR] LPCTSTR lpFileName : 0x000000E041D0E893 ("iphlpapi.dll") <--DLL loaded by the worker thread>
[PAR] DWORD   dwFlags    : 0x0 (Same behavior as LoadLibrary)
[RET] 0x7ffa026353c7                                           <--return address in NTDLL>
```

The sample relies on the ThreadPool worker thread feature to execute various sensitives actions.  
MSDN : <https://learn.microsoft.com/en-us/windows/win32/procthread/thread-pool-api>  
Some POC : <https://github.com/mobdk/WinSpoof>  

Interestingly, the creation of a ThreadPool Worker thread doesn't seem to trigger any notification to the PsSetCreateThreadNotifyRoutine kernel callback interface...

--- 

Undocumented encryption routine :

```html
[ * ] [pid 0xa6c][tid 0xabc] c:\windows\system32\rundll32.exe
[API] <_vsnprintf>
[PAR] char_t   *buffer : 0x000000E03FD58240
[STR]          -> "{"cds":{"auth":"OV1T557KBIUECUM5"},"mtdt":{"h_name":"home","wver":"x64/6.3","ip":"169.254.143.85","arch":"x64","bld":"96"
[STR]             "00","p_name":"QwA6AFwAVwBpAG4AZABvAHcAcwBcAHMAeQBzAHQAZQBtADMAMgBcAHIAdQBuAGQAbABsADMAMgAuAGUAeABlAA==","uid":"user","pi"
[STR]             "d":"2668","tid":"2748"}}"
[RES] int 266

[CNT] [330]
[PTP] [0xa6c] [0xabc] [c:\windows\system32\rundll32.exe]
[API] <SystemFunction032> in [CRYPTSP.DLL] 
[INF] [ Undocumented RC4 implementation ]
[PAR] PBINARY_STRING buffer : 0x000000E041D0E780
[FLD]                -> Length    = 0x10a
[FLD]                -> MaxLength = 0x10a
[FLD]                -> Buffer    = 0x000000E03FD58900 
[PAR] PBINARY_STRING key    : 0x000000E041D0E770
[FLD]                -> Length    = 0x10
[FLD]                -> MaxLength = 0x10
[FLD]                -> Buffer    = 0x000000E03FD5CEE0 ("S47EFEUO3D2O6641")
[RET] [0xe041c54c35]

[...]

[CNT] [340]
[PTP] [0xa6c] [0xabc] [c:\windows\system32\rundll32.exe]
[API] <HttpSendRequestA> in [wininet.dll] 
[PAR] HINTERNET hRequest         : 0xcc000c
[PAR] LPCTSTR   lpszHeaders      : 0x0 (null)
[PAR] DWORD     dwHeadersLength  : 0x0
[PAR] LPVOID    lpOptional       : 0x000000E03FD561C0
[STR]           -> "88ea80d0a8145617084c1971a2e5f10dafc825dfa01aa9131c31eed2159e33380dff1f6c5b2b0f95bf9e3eccd60c1d280c96fa1f4acd82ac6739fad4"
[STR]              "6dc3ae39d58a579d7cbdc8dd1c967704a3b004fc992ed35b62fc6c335fdabf3d06f73d1be31cfa6e400611012495666f57da92a1ce53a79a2a8a3bd1"
[STR]              "a17fa2ed8fb54d132d80e926f544078052cf155d1dfb93137bf25aff3337a6e363e7a802c276d9ed4b0d03bdb4b22fc8ce5ecaa162f5cdca8f199770"
[STR]              "4a349921f9a0b1d11f2dd44af30628be98cea3f63a006f832b5468f7afaeb783ac1299062871d81cb499b6d15a4dbcc66ff0959fdaf1cd309dc790e0"
[STR]              "25725ea1c95ef9ef0283f09beef05c8dc375080d6f0c71cdb1da"
[PAR] DWORD     dwOptionalLength : 0x214
[RET] [0xe041c579dc]
```

Here the sample is relying on the undocumented SystemFunction032 function from CRYPTSP.DLL to encrypt through RC4 the initial fingerprint of the compromised host (RC4 Key : "S47EFEUO3D2O6641").

--- 

Encrypted in memory payload :

```html
[CNT] [350]
[PTP] [0xa6c] [0xabc] [c:\windows\system32\rundll32.exe]
[API] <SystemFunction036> in [CRYPTBASE.DLL] 
[INF] [ RtlGenRandom ]
[PAR] PVOID RandomBuffer       : 0x000000E041D0E8C0
[PAR] ULONG RandomBufferLength : 0x10       // generate a random 16byte key
[RET] [0xe041c68db2]

[...]

[CNT] [389]
[PTP] [0xa6c] [0xaac] [c:\windows\system32\rundll32.exe]
[/!\] [ Illegitimate call detected ! ]
[API] <SystemFunction032> in [CRYPTSP.DLL] 
[INF] [ Undocumented RC4 implementation ]
[PAR] PBINARY_STRING buffer : 0x000000E04227F698
[FLD]                -> Length    = 0x4c000
[FLD]                -> MaxLength = 0x4c000
[FLD]                -> Buffer    = 0x000000E041C50000 
[PAR] PBINARY_STRING key    : 0x000000E04227F6A8
[FLD]                -> Length    = 0x10
[FLD]                -> MaxLength = 0x10
[FLD]                -> Buffer    = 0x000000E04227F684 ([0x82,0x16,0x55,0x8a,0xe4,0xfa,0xff,0x7f,0xf3,0x71,0xf6,0xf8,0x61,0x82,0xcf,0xfa])
[RET] [0x7ffa03692600] in [ntdll.dll]
```

Here the malware ensure to be fully encrypted whenever possible, which prevents memory dumps as well as in memory signatures.
The key is changed  after each payload execution.
Setting a BreakPoint on this function call enable to dump the unencrypted payload from memory.


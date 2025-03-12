Dropper SHA256 : 1b9e17bfbd292075956cc2006983f91e17aed94ebbb0fb370bf83d23b14289fa  
BazaarLoader SHA256 : 5C7A3BD2BAA8303354D8098B8D5961F111E467002BB0C6FEE120825B32798228  

Dropper Source :  
https://virusshare.com/file?1b9e17bfbd292075956cc2006983f91e17aed94ebbb0fb370bf83d23b14289fa  
https://contagiodump.blogspot.com/2024/11/2024-10-30-lunar-spiders-latrodectus-js.html  

Payload Source :  
https://virusshare.com/file?5c7a3bd2baa8303354d8098b8d5961f111e467002bb0c6fee120825b32798228  


VT Dropper : https://www.virustotal.com/gui/file/1b9e17bfbd292075956cc2006983f91e17aed94ebbb0fb370bf83d23b14289fa  
VT BazaarLoader : https://www.virustotal.com/gui/file/5c7a3bd2baa8303354d8098b8d5961f111e467002bb0c6fee120825b32798228  

Network / C2 :  
http://tiguanin[.]com/bazar.php:8041  
http://bazarunet[.]com/admin.php:8041  
http://greshunka[.]com/bazar.php:8041 

Report :  
https://blog.eclecticiq.com/inside-intelligence-center-lunar-spider-enabling-ransomware-attacks-on-financial-sector-with-brute-ratel-c4-and-latrodectus

Analyzed sample is a 64bit malware named by various security engines BazaarLoader or BruteRatel C4.

Runtime analysis results are shared in logs.txt which contains an execution trace until the sample tries to reach a C2.

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

```python
Monitoring: [pid 0x9d8][tid 0xb00] c:\windows\system32\rundll32.exe
Monitoring: [API] <VirtualAllocEx> in [KERNEL32.DLL] 
Parameter : HANDLE hProcess     : 0xffffffff
Parameter : LPVOID lpAddress    : 0x0
Parameter : SIZE_T dwSize       : 0x3dbbf
Parameter : DWORD  flProtect    : 0x40 (PAGE_EXECUTE_READWRITE)
Return  @ : 0x2e4d113c9

Monitoring: [pid 0x9d8][tid 0xb00] c:\windows\system32\rundll32.exe
Monitoring: [RES]  <VirtualAllocEx>
Result    : LPVOID  0x000000FA94200000

Monitoring: [pid 0x9d8][tid 0xb00] c:\windows\system32\rundll32.exe
Monitoring: [API] <WriteProcessMemory> in [KERNEL32.DLL] 
Parameter : HANDLE  hProcess      : 0xffffffff
Parameter : LPVOID  lpBaseAddress : 0x000000FA94200000
Parameter : LPCVOID lpBuffer      : 0x00000002E4D13010
Parameter : SIZE_T  nSize         : 0x3dbbf
Return  @ : 0x2e4d113fe

Monitoring: [pid 0x9d8][tid 0xb00] c:\windows\system32\rundll32.exe
Monitoring: [API] <CreateRemoteThread> in [KERNEL32.DLL] 
Parameter : HANDLE                 hProcess           : 0xffffffff
Parameter : LPSECURITY_ATTRIBUTES  lpThreadAttributes : 0x0
Parameter : SIZE_T                 dwStackSize        : 0x0
Parameter : LPTHREAD_START_ROUTINE lpStartAddress     : 0x00000002E4D11370 // jmp rcx
Parameter : LPVOID                 lpParameter        : 0x000000FA94200000 // Allocated memory
Parameter : DWORD                  dwCreationFlags    : 0x0
Parameter : LPDWORD                lpThreadId         : 0x0
Return  @ : 0x2e4d11434
```

A little trick regarding this CreateRemoteThread call, the thread's StartAddress doesn't point directly to the PAGE_EXECUTE_READWRITE allocated memory. Instead, lpStartAddress points to an `jmp rcx` instruction, rcx beeing the lpParameter from the created thread.  

--- 

Thread Pool Worker Threads :

```html
Monitoring: [pid 0x9d8][tid 0xb04] c:\windows\system32\rundll32.exe
Monitoring: [API] <TpAllocWork> in [ntdll.dll] 
Parameter : PTP_WORK             *WorkReturn     : 0x000000FA9437E610
Parameter : PTP_WORK_CALLBACK    Callback        : 0x000000FA942C3250
Parameter : PVOID                Context         : 0x000000FA9437E618
Parameter : PTP_CALLBACK_ENVIRON CallbackEnviron : 0x0
Return  @ : 0xfa942d78a7

Monitoring: [pid 0x9d8][tid 0xb04] c:\windows\system32\rundll32.exe
Monitoring: [API] <TpPostWork> in [ntdll.dll] 
Parameter : PTP_WORK    Work : 0x000000FA92382D80
Return  @ : 0xfa942d78b2

Monitoring: [pid 0x9d8][tid 0xb04] c:\windows\system32\rundll32.exe
Monitoring: [API] <TpReleaseWork> in [ntdll.dll] 
Parameter : PTP_WORK    Work : 0x000000FA92382D80
Return  @ : 0xfa942d78bd

Thread created by monitored process : Now monitoring [pid 0x9d8][tid 0xb2c] // ThreadPool Worker Thread

Monitoring: [pid 0x9d8][tid 0xb2c] c:\windows\system32\rundll32.exe 
Monitoring: [API] <LoadLibraryExA> in [KERNEL32.DLL] 
Parameter : LPCTSTR lpFileName : 0x000000FA9437E693 ("iphlpapi.dll")        // DLL loaded by the worker thread
Parameter : DWORD   dwFlags    : 0x0 (Same behavior as LoadLibrary)
Return  @ : 0x7ff9b52e53c7                                                  // return address in NTDLL
```

The sample relies on the ThreadPool worker thread feature to execute various sensitives actions.  
MSDN : https://learn.microsoft.com/en-us/windows/win32/procthread/thread-pool-api  
Some POC : https://github.com/mobdk/WinSpoof  

Interestingly, the creation of a ThreadPool Worker thread doesn't seem to trigger any notification to the PsSetCreateThreadNotifyRoutine kernel callback interface...

--- 

Undocumented encryption routine :

```python
Monitoring: [pid 0x9d8][tid 0xb04] c:\windows\system32\rundll32.exe
Monitoring: [RES]  <_vsnprintf>
Parameter : char_t   *buffer : 0x000000FA9234AB10
String    :          -> "{"cds":{"auth":"OV1T557KBIUECUM5"},"mtdt":{"h_name":"home","wver":"x64/6.3","ip":"10.0.2.15","arch":"x64", "bld":"9600","p_name":"QwA6AFwAVwBpAG4AZABvAHcAcwBcAHMAeQBzAHQAZQBtADMAMgBcAHIAdQBuAGQAbABsADMAMgAuAGUAeABlAA==","uid":"user","pid":"2520","tid":"2820"}}"
Result    : int 261

Monitoring: [pid 0x9d8][tid 0xb04] c:\windows\system32\rundll32.exe
Monitoring: [API] <SystemFunction032> in [CRYPTSP.DLL] 
Monitoring: [ i ] [ Undocumented RC4 implementation ]
Parameter : PBINARY_STRING buffer : 0x000000FA9437E580
Field     :                -> Length    = 0x105
Field     :                -> MaxLength = 0x105
Field     :                -> Buffer    = 0x000000FA9234AA00 
Parameter : PBINARY_STRING key    : 0x000000FA9437E570
Field     :                -> Length    = 0x10
Field     :                -> MaxLength = 0x10
Field     :                -> Buffer    = 0x000000FA9234CBC0 ("S47EFEUO3D2O6641")
Return  @ : 0xfa942c4c35

[...]

Monitoring: [pid 0x9d8][tid 0xb04] c:\windows\system32\rundll32.exe
Monitoring: [API] <HttpSendRequestA> in [wininet.dll] 
Parameter : HINTERNET hRequest         : 0xcc000c
Parameter : LPCTSTR   lpszHeaders      : 0x0 (null)
Parameter : DWORD     dwHeadersLength  : 0x0
Parameter : LPVOID    lpOptional       : 0x000000FA923527B0
String    :           -> "88ea80d0a8145617084c1971a2e5f10dafc825dfa01aa9131c31eed2159e33380dff1f6c5b2b0f95bf9e3eccd60c1d280c96fa1f4acd82ac6739fad4"
String    :              "6dc3ae39d58a579d7cbdc8dd1c967704a3b004fc992ed35d75e2703445c5bb2b19fb645ca258fa35101d4f173c9b3c3b0f9c9cb98e06f588208a2ec5"
String    :              "e110eea0c0a030476ebcfb45f927108052af23591afb825078d85afa7137b4c160f29e08c276f2d7480b13b783b202c8cd7edaab47f5d3d68c20b176"
String    :              "64349c0ffaa7a1db232df74af01128bbbace85fa393e4986135462c5afbeb7869512bd7a573fb57ffccdf0df421aa0d128b895c68be4d67693dfc2bb"
String    :              "746254a1d74abbbe448de8cdb5ac4c87c33a42345d" // RC4 encrypted fingerprint
Parameter : DWORD     dwOptionalLength : 0x20a
Return  @ : 0xfa942c79dc
```

Here the sample is relying on the undocumented SystemFunction032 function from CRYPTSP.DLL to encrypt through RC4 the initial fingerprint of the compromised host (RC4 Key : "S47EFEUO3D2O6641").

--- 

Encrypted in memory payload :

```python
Monitoring: [pid 0x9d8][tid 0xb04] c:\windows\system32\rundll32.exe
Monitoring: [API] <SystemFunction036> in [CRYPTBASE.DLL] 
Monitoring: [ i ] [ RtlGenRandom ]
Parameter : PVOID RandomBuffer       : 0x000000FA94A7FC54
Parameter : ULONG RandomBufferLength : 0x10                 // generate a random 16byte key
Return  @ : 0xfa942d85a6

[...]

Monitoring: [pid 0x9d8][tid 0xf8] c:\windows\system32\rundll32.exe
Monitoring: [API] <SystemFunction032> in [CRYPTSP.DLL] 
Monitoring: [!] [Illegitimate call detected !]
Monitoring: [ i ] [ Undocumented RC4 implementation ]
Parameter : PBINARY_STRING buffer : 0x000000FA94A7FC68
Field     :                -> Length    = 0x4c000
Field     :                -> MaxLength = 0x4c000
Field     :                -> Buffer    = 0x000000FA942C0000 // memory allocated for the CreateRemoteThreadCall (see above)
Parameter : PBINARY_STRING key    : 0x000000FA94A7FC78
Field     :                -> Length    = 0x10
Field     :                -> MaxLength = 0x10
Field     :                -> Buffer    = 0x000000FA94A7FC54 ([0x3a,0xd,0x53,0xf4,0x17,0x47,0x50,0xe3,0x27,0x3d,0x4f,0x63,0x88,0xd,0xf4,0x50])
Return  @ : 0x7ff9b6342600
```

Here the malware ensure to be fully encrypted whenever possible, which prevents memory dumps as well as in memory signatures.
The key is changed  after each payload execution.
Setting a BreakPoint on this function call enable to dump the unencrypted payload from memory.


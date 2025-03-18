---
title: "BruteRatel full command analysis (2/X)"
date: 2025-03-19 
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

This article is the second part of my full analysis of BruteRatel commands : [First Part](https://cedricg-mirror.github.io/2025/03/17/BruteRatel.html)  

This detailed analysis will be split into several parts, I will be presenting in this post the next 20 commands that BruteRatel can respond to.  

# COMMAND LIST

Here is a short description of the 20 command codes and purpose :  

| Command ID   | Description             | Parameter         |
| :----------- | :---------------------- | :----------------:|
| "\x48\x52"   | [fingerprint](#fingerprint) | NA                |
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

# Command Syntax  

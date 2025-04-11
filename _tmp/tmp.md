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
|"\xd2\xe3"    | [CreateProcessConf3](#CreateProcessConf3) |  |
|""    | [](#) |  |
|"\xb3\xd2"    | [StopService](#StopService) | $MachineName, $ServiceName |
|"\x9a\x6c"    | [DelayCmdExec](#DelayCmdExec) | $delay |
|"\xd1\xf3"    | [unknown_network](#unknown_network) | $ip, $port, $unknown, $unknown2 |

In the following section, I share some dynamic analysis results from the aforementioned commands :  

<a id="GetFullPathNameW"></a>
# GetFullPathNameW  

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

<a id="inet_ntoa"></a>
# inet_ntoa  

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

<a id="dump_process_from_pid"></a>
# dump_process_from_pid  

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

<a id="adjustTokenPrivilege"></a>
# adjustTokenPrivilege  

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

<a id="GetFileTimeStamp"></a>
# GetFileTimeStamp  

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

<a id=""></a>
# 

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

---
title: "BruteRatel full command analysis (3/X)"
date: 2025-03-20 
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

This article is the third part of my full analysis of BruteRatel commands : [Previous Part](https://cedricg-mirror.github.io/2025/03/19/BruteRatel2.html)  

This detailed analysis will be split into several parts, I will be presenting in this post the next 20 commands that BruteRatel can respond to.  

# COMMAND LIST

Here is a short description of the next 20 command codes and purpose :  

| Command ID   | Description             | Parameter         |
| :----------- | :---------------------- | :----------------:|
| "\xb0\xe9"   | [CreateProcessA](#CreateProcessA) | $process_path              |
| "\xc0\xeb"   | [TerminateProcess](#TerminateProcess) | $pid            |
| "\xd0\xbe"   | [ShellExecuteExA](#ShellExecuteExA) | $verb, $file, $parameters            |
| "\xe0\x9d"   | [ListActiveProcess](#ListActiveProcess) | NA                |
| "\xae\x6b"   | [ImpersonateSystem](#ImpersonateSystem) | NA |
| "\x39\x6f"   | [ImpersonateSystem2](#ImpersonateSystem2) | NA  |
| "\xd9\xf3"   | [unknown](#unknown) | $p1, $p2 |
| "\xd4\x3f"   | [unknown2](#unknown2) | $p1, $p2          |
| "\x74\x2c"   | [ReadFileW](#ReadFileW) | $filename, $size_in_KB              |
| "\x36\x6c"   | [RegEnumKeyA](#RegEnumKeyA) | $hKey, $SubKey       |
| "\x58\xb4"   | [QueryServiceConfig](#QueryServiceConfig) | $dir_path             |
| "\xea\xe2"   | [maybe_push_cmd](#maybe_push_cmd) | $p1         |
| "\xa1\x13"   | [WriteFile](#WriteFile) | $src, $dst    |
| "\x9a\x69"   | [listen](#listen) | $label, $port        |
| "\x4d\x3c"   | [pipe_com_todo](#pipe_com_todo) | $PipeName        |
| "\x37\xfe"   | [install_as_service](#install_as_service) | $MachineName, $serviceName, $payload |
| "\xe9\x97"   | [createService](#createService) | $MachineName, $serviceName, $path     | 
| "\x73\xfa"   | [deleteService](#deleteService) | $MachineName, $serviceName | 
| "\x3e\x3b"   | [changeServiceConfig](#changeServiceConfig) | $MachineName, $serviceName, $BinaryPathName | 
| "\x62\xc6"   | [GetProcessInfo](#GetProcessInfo) | $processName |
| "\x91\xe5"   | [port_scan](#port_scan) | $hostname, $ports |

# Dynamic Analysis  

In the following section, I share some dynamic analysis results from the aforementioned commands :  

<a id="CreateProcessA"></a>
# CreateProcessA  

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

<a id="TerminateProcess"></a>
# TerminateProcess  

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
<a id="ShellExecuteExA"></a>
# ShellExecuteExA  

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

<a id="ListActiveProcess"></a>
# ListActiveProcess  

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

<a id="ImpersonateSystem"></a>
# ImpersonateSystem  

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

<a id="ImpersonateSystem2"></a>
# ImpersonateSystem2  

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

<a id="unknown"></a>
# unknown  

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

<a id="unknown2"></a>
# unknown2  

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

<a id="ReadFileW"></a>
# ReadFileW  

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

<a id="RegEnumKeyA"></a>
# RegEnumKeyA  

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

<a id="QueryServiceConfig"></a>
# QueryServiceConfig  

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

<a id="maybe_push_cmd"></a>
# maybe_push_cmd  

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

<a id="WriteFile"></a>
# WriteFile  

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

<a id="listen"></a>
# listen  

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

<a id="pipe_com_todo"></a>
# pipe_com_todo  

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

<a id="install_as_service"></a>
# install_as_service  

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

<a id="createService"></a>
# createService  

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

<a id="deleteService"></a>
# deleteService  

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

<a id="changeServiceConfig"></a>
# changeServiceConfig  

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

<a id="GetProcessInfo"></a>
# GetProcessInfo  

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

<a id="port_scan"></a>
# port_scan  

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

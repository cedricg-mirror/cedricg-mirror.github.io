---
title: "BruteRatel Comparative analysis using Reflexions Sandbox"
date: 2025-03-21 
---

<link rel="stylesheet" href="/css/main.css">

## BRUTERATEL  

## Context  

BruteRatel Sample 1 SHA256 : D8080B4F7A238F28435649F74FDD5679F7F7133EA81D12D9F10B05017B0897B1  
BruteRatel Sample 2 SHA256 : 83859ACDF4AC22927FA88F715666653807501DB6F1865A3657599B4C5D130BB2  

Sample Source :  
[bazaar.abuse.ch](https://bazaar.abuse.ch/sample/d8080b4f7a238f28435649f74fdd5679f7f7133ea81d12d9f10b05017b0897b1/)   
[bazaar.abuse.ch](https://bazaar.abuse.ch/sample/83859acdf4ac22927fa88f715666653807501db6f1865a3657599b4c5d130bb2/)   



# INTRO  

In this article I will demonstrate how simple it can be to spot code evolution between 2 versions of the same malware using dynamic analysis and Reflexionsn Sandbox.  
The 2 samples analysed here are from the BruteRatel Malware.  

Sold for 3000$ their authors claim that 'each release includes new evasion methods tested with more than 10 EDR software solutions', and their code is indeed packed with various countermesures that I partially described in a previous [post](https://cedricg-mirror.github.io/2025/02/04/BazaarLoader.html)   

The two samples I chose for this analysis vary a lot from the 'outside', first one is a 248KB DLL while the second one is a 3MB signed DLL.  

I ran the two samples in a controlled environment while redirecting their network communications to my own (basic) implementation of a BruteRatel C2.  
In this case the C2 simply reply to their beaconing with an 'ExitProcess' order.  
A list of all BrutelRatel commands is available [here](https://cedricg-mirror.github.io/2025/03/17/BruteRatel.html) (Ongoing process)  
Samples were supervised by the Reflexions Sandbox, results are available [here](https://github.com/cedricg-mirror/reflexions/tree/main/CyberCrime/BRUTERATEL)   

# Loader  

Manually comparing the excution trace clearly indicates that the two samples used a different 1st stage loader :  

![]()

The traces start to converge around API call 150 for the 1st sample and API call 302 for the second sample with some differences however :  

![2nd Loader](/docs/assets/images/BRUTERATEL_DIFF/diff_loader2.jpg)  

This indicate that the two samples used the same 2nd stage loader which was modified between the generation of sample 1 and 2.  

# BruteRatel Main Payload  

The excution traces then merge completly at API call 213 for the first sample and 355 for the second sample :  

![BruteRatel Payload](/docs/assets/images/BRUTERATEL_DIFF/bruteratel_start.jpg)  




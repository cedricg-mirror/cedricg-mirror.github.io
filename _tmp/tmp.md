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

This is when the final stage, the BruteRatel payload is reached.  
Notice how the Region size of each NtProtectVirtualMemory call is strictly identical.  

# C2  

A logical shift happens between the two samples at API call 212 and 414 for the simple reason that the 1st sample is relying on 3 different C2 while the 2nd sample on uses 2 :  

![BruteRatel Payload](/docs/assets/images/BRUTERATEL_DIFF/C2.jpg)  

# User-Agent  

Result from _vsnwprintf call 275 (1st sample) and 415 (2nd sample) shows that the harcoded user-agent was changed : 

Sample 1 :  
```html
[CNT] [275]
[PTP] [0xff8] [0x7dc] [c:\windows\system32\rundll32.exe]
[API] <_vsnwprintf> in [ntdll.dll] 
[PAR] wchar_t  *buffer : 0x000000097830CE10
[PAR] size_t   size    : 0x72
[PAR] wchar_t  *format : 0x000000097A278444
[PAR] va_list  argptr  : 0x000000097A2FEA50
[RET] [0x97a273d41]

[ * ] [pid 0xff8][tid 0x7dc] c:\windows\system32\rundll32.exe
[API] <_vsnwprintf>
[PAR] wchar_t  *buffer : 0x000000097830CE10
[STR]          -> "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.93 Safari/537.36"
[RES] int 114
```

Sample 2 :  
```html
[CNT] [415]
[PTP] [0x3e8] [0xe10] [c:\windows\system32\rundll32.exe]
[API] <_vsnwprintf> in [ntdll.dll] 
[PAR] wchar_t  *buffer : 0x000000CFD9B7A2A0
[PAR] size_t   size    : 0x6b
[PAR] wchar_t  *format : 0x000000CFDBD68444
[PAR] va_list  argptr  : 0x000000CFDBDEE820
[RET] [0xcfdbd63d41]

[ * ] [pid 0x3e8][tid 0xe10] c:\windows\system32\rundll32.exe
[API] <_vsnwprintf>
[PAR] wchar_t  *buffer : 0x000000CFD9B7A2A0
[STR]          -> "Mozilla/5.0 (X11; U; Linux i686; pt-BR) AppleWebKit/533.3 (KHTML, like Gecko) Navscape/Pre-0.2 Safari/533.3"
[RES] int 107
```

# Authorization-Token  

So did the Token :  

![Auth Token](/main/docs/assets/images/BRUTERATEL_DIFF/Auth.jpg)  


# Update in sample 2  

At this point in its loading procedure, BruteRatel normally start a simple fingerprinting of the infected host to send to the C2 upon its first beaconing.  

![Fingerprint Diff](/main/docs/assets/images/BRUTERATEL_DIFF/fingerprint.jpg)  

This fingerprint phase is visible in green for sample1, sample 2 however is doing something else :  

![Fingerprint Diff](/main/docs/assets/images/BRUTERATEL_DIFF/sample2_fingerprint.jpg)  

We can see that some instructions were added (orange) before the start of the fingerprinting (green)  

This change is related to the HTTP Header :  

![Fingerprint Diff](/docs/assets/images/BRUTERATEL_DIFF/new_header.jpg)  

BruteRatel was updated to include this new header (unclear for which purpose at this point)  

# RC4 Key  

Unsuprisingly the RC4 Key used to encrypt communication with C2 was also changed :  

![RC4](/docs/assets/images/BRUTERATEL_DIFF/Rc4.jpg)

# ExitProcess  

The execution between the 2 samples then goes on until executing the 'ExitProcess' Order :  

![RC4](/main/docs/assets/images/BRUTERATEL_DIFF/exit.jpg)  

# Conclusion :  

This short article illustrate a few keypoint :  

- It's much easier to change the packaging (loader) than the payload
- Changes to the loader, or changing the loader altogether, doesn't make much difference from a dynamic analysis point of view
- Behavior based signatures still prove to be a very efficient and reliable way not only to identify a specific malware but also to spot potentieal updates

Nonetheless, statical analysis remains the only option to get to specific changes, for instance if the 'ExitProcess' command ID was changed between the two samples generation it would have made my job much more tedious.  


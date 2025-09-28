---
title: "PacketMaze Writeup"
date: 2025-09-15 4:40:00 +0300
categories: [Network Forensics]
tags: [lab, network-forensics]
---

# PacketMaze Lab — Network Forensics Writeup


## Scenario
A company's internal server has been flagged for unusual network activity, with multiple outbound connections to an unknown external IP. Initial analysis suggests possible data exfiltration. Investigate the provided network logs to determine the source and method of compromise.
---
---
## link of the challenge : 
```
https://cyberdefenders.org/blueteam-ctf-challenges/packetmaze/
```
---
## important Note
 This lab does not include any malicious software The goal is entirely educational just as the name PacketMaze implies It’s about navigating through network packets learning to capture and analyze them with Wireshark, and gaining familiarity with various network protocols **(such as IP, TCP/UDP, and a few less common ones introduced in the exercise)** The focus is on improving packet analysis skills and protocol understanding, not on handling real malware.
---

## Q1) What is the FTP password?
To solve this question we will filter on FTP .

![PCAP Evidence](assets/lib/PacketMaze/p1.jpg)

so the answer is 
```
USER : kali
PASS : AfricaCTF2021
```
---

---
## Q2) What is the IPv6 address of the DNS server used by 192.168.1.26?

I started by applying a DNS filter in Wireshark (dns) and observed that the client ****192.168.1.26** was sending DNS queries to the server **192.168.1.10****.
The DNS packets themselves did not show the server’s IPv6 address.
To find it I compared the MAC address of 192.168.1.10 with other frames in the capture.
By matching that MAC address, I identified IPv6 packets from the same device and obtained its corresponding IPv6 address which is the DNS server’s IPv6 address used by 192.168.1.26.

![PCAP Evidence](assets/lib/PacketMaze/p2.jpg)

The Answer is :
```
fe80::c80b:adff:feaa:1db7
```
---

---
## Q3 ) What domain is the user looking up in packet 15174?

![PCAP Evidence](assets/lib/PacketMaze/P3.jpg)

The Answer is :
```
www.7-zip.org
```
---

---
## Q4 ) How many UDP packets were sent from 192.168.1.26 to 24.39.217.246?

I applied the following Wireshark filter to isolate the traffic:
```
ip.addr == 192.168.1.26 && ip.addr == 24.39.217.246 && udp
```
![PCAP Evidence](assets/lib/PacketMaze/p4.jpg)

This filter displays only UDP packets exchanged between **192.168.1.26** and **24.39.217.246**
The result immediately showed the total number of UDP packets sent from **192.168.1.26** to **24.39.217.246**.

The Answer is :
```
10 packets
```
---
---
## Q5 ) What is the MAC address of the system under investigation in the PCAP file?

The PCAP shows a single primary host consistently acting as the source of traffic.
All conversations originate from the same system **192.168.1.26** which communicates with every other device in the capture.

![PCAP Evidence](assets/lib/PacketMaze/p5.jpg)

if we opend and packet we can find the MAC

![PCAP Evidence](assets/lib/PacketMaze/p6.jpg)

The Answer is :
```
c8:09:a8:57:47:93
```
---
---
## Q6 ) What was the camera model name used to take picture 20210429_152157.jpg?

First, I extracted the file 20210429_152157.jpg from the PCAP to my local system.
To find the camera model, I noted that the EXIF metadata can be viewed in two ways:

Using a tool such as ExifTool – running exiftool 20210429_152157.jpg displays all embedded metadata, including the camera make and model.

Via the file’s Properties in Windows – right-click the image, choose Properties → Details tab, and check the “Camera Model” field (if the EXIF data hasn’t been stripped).

Either method reveals the camera model name if the EXIF information is still present.
![PCAP Evidence](assets/lib/PacketMaze/p7.jpg)

![PCAP Evidence](assets/lib/PacketMaze/p8.jpg)

The Answer is :
```
LM-Q725K
```
---
---
## Q7 ) What is the ephemeral public key provided by the server during the TLS handshake in the session with the session ID: da4a0000342e4b73459d7360b4bea971cc303ac18d29b99067e46d16cc07f4ff?

To locate it, I searched the using the filter:
```
tls.handshake.session_id == da4a0000342e4b73459d7360b4bea971cc303ac18d29b99067e46d16cc07f4f
```

![PCAP Evidence](assets/lib/PacketMaze/p9.jpg)

I then examined the Server Key Exchange portion of the TLS handshake and found the value in the Pubkey field.
The ephemeral public key provided by the server is:

```
04edcc123af7b13e90ce101a31c2f996f471a7c8f48a1b81d765085f548059a550f3f4f62ca1f0e8f74d727053074a37bceb2cbdc7ce2a8994dcd76dd6834eefc5438c3b6da929321f3a1366bd14c877cc83e5d0731b7f80a6b80916efd4a23a4d
```
---
---
## Q8 ) What is the first TLS 1.3 client random that was used to establish a connection with protonmail.com?

I applied the filter:
```
tls.record.content_type == 22 && tls.handshake.extensions_server_name == "protonmail.com"
```
![PCAP Evidence](assets/lib/PacketMaze/P10.jpg)

This displays all TLS handshake packets where the Server Name Indication (SNI) is protonmail.com.
I located the initial Client Hello packet and, inside the Handshake Protocol: Client Hello section, found the Client Random value.

The first TLS 1.3 client random is:
```
24e92513b97a0348f733d16996929a79be21b0b1400cd7e2862a732ce7775b70

```
---
---
## Q9 ) Which country is the manufacturer of the FTP server’s MAC address registered in?

First I identified the MAC address of the FTP server by inspecting the packets in Wireshark that show the server as the source/destination during the FTP session.

![PCAP Evidence](assets/lib/PacketMaze/p11.jpg)

After obtaining that MAC address I looked it up on a MAC-vendor database such as macvendors.com

![PCAP Evidence](assets/lib/PacketMaze/p12.jpg)

This lookup reveals the vendor/manufacturer name and the country of registration for that MAC address, which provides the answer to the question.

![PCAP Evidence](assets/lib/PacketMaze/p13.jpg)

The Answer is :
```
United States
```
---
---
## Q10 ) What time was a non-standard folder created on the FTP server on the 20th of April?

I first applied a Wireshark filter to display only FTP traffic
Then I looked for the packets where a LIST command was issued to view directory contents.
By following the TCP Stream of that session, I checked the server’s responses to identify which folder was created on 20 April and noted the exact timestamp from the packet capture for when that creation took place.

![PCAP Evidence](assets/lib/PacketMaze/p14.jpg)

The Answer is :
```
17:53
```
---
---
## Q11 ) What URL was visited by the user and connected to the IP address 104.21.89.171?
I applied this filter 
```
ip.addr == 104.21.89.171 && http
```
This shows all HTTP traffic between the client and that IP.
By examining the HTTP Host and Request URI fields in the GET request

![PCAP Evidence](assets/lib/PacketMaze/p15.jpg)

 I identified the full URL that the user visited.

 The Answer is :
```
http://dfir.science/
```


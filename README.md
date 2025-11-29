# Snort IDS Implementation Against session hijacking and Captcha bypass attacks

 My goal was to configure Snort to detect and block session hijacking and captcha bypass attempts. I documented every step so I could present a complete workflow.

---


## Step 1. 
I prepared my environment,updated my system and installed the required dependencies.

Command: 

sudo apt update
sudo apt install snort


I verified the installation.

Command: 
snort -V

<img width="1203" height="830" alt="image" src="https://github.com/user-attachments/assets/fb57d8c2-31e0-4d28-8e95-0fff8c55f631" />



<img width="937" height="347" alt="image" src="https://github.com/user-attachments/assets/7ae05d7b-49c7-432b-a161-b93db93db9b3" />


---
## Step 2. 
I configured the network interface and placed my interface in promiscuous mode so Snort could inspect all packets.


Command: 
sudo ip link set eth0 promisc on

I confirmed the status using the following command: ip link show eth0



<img width="1112" height="201" alt="image" src="https://github.com/user-attachments/assets/f51cb142-280d-456a-b2de-b5dc60923e26" />

---
## Step 3. 

I updated rule sets and pulled the latest community rules and loaded them into my configuration.

Command:
sudo snort -c /etc/snort/snort.conf -T (For Snort 2) OR  sudo snort -c /etc/snort/snort.lua -T (For snort 3) 


This test helped me confirm my rule paths and syntax.


<img width="1192" height="833" alt="image" src="https://github.com/user-attachments/assets/96fc369d-1322-41ad-b0fd-fc37b722aefd" />


<img width="968" height="602" alt="image" src="https://github.com/user-attachments/assets/f87be470-8af0-4c5f-8b60-dc56dc795e71" />

---

## Step 4. 
a. I created rules for session hijacking,I wanted to detect suspicious cookie behavior so I created a custom file called local.rules.

Command:
sudo nano /etc/snort/rules/local.rules

b. I added a rule that alerts whenever a packet contains a session cookie pattern.

Rule added:
alert tcp any any -> any 80 (msg:"Suspicious session cookie"; content:"Cookie"; nocase; content:"sessionid"; nocase; sid:100001;)

c. I reloaded Snort in IDS mode.

Command: 
sudo snort -A console -c /etc/snort/snort.conf -i eth0

d. Then I replayed a test capture with a forged cookie.

Command:
sudo tcpreplay -i eth0 test_session_hijack.pcap

















































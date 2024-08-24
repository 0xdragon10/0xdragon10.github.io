---
title: "Linux Privilege Escalation"
date: 2024-08-17 10:00:00 +0800
categories: [Linux, Security]
tags: [Privilege Escalation, Linux]
excerpt: "A detailed write-up on Linux privilege escalation techniques covered in the TCM Privilege Escalation course."
---
# Linux Privilege Escalation
**Introduction to the TCM Privilege Escalation Course for Linux**

The TCM Privilege Escalation Course for Linux is designed to equip cybersecurity enthusiasts with the skills and knowledge needed to elevate their access on Linux systems. Throughout this course, you will delve into various privilege escalation techniques, from exploiting misconfigurations to leveraging kernel vulnerabilities.

By the end of this course, you will have a deep understanding of how to identify and exploit weaknesses in Linux systems, making you proficient in the art of privilege escalation. This course is ideal for those looking to enhance their penetration testing skills or seeking to fortify their defenses against unauthorized access in Linux environments.
# System Enumeration :-

First thing i use this command   `hostname`   to display  the system's hostname. The hostname is a unique name assigned to a computer on a network, which helps identify it among other devices.

Second i use command `uname -a`  to display detailed information about the system's kernel and operating system i check if system have kernal exploit .

- Some command be useful to know version
    
    `cat /proc/version` 
    
    `lscpu` 
    
    `ps aux | grep root`
    

# User Enumeration :-

First we should know what is this user we write `whoami`  to display username and write `id` 

to know more info about user .

Second i want know user privilege we use `sudo -l`  we will see what user can access .

Third we check important files in system like `/etc/passwd`  and  `/etc/group` and `/etc/shadow` 

you can search about this files 

- some command be useful to see content in this files
    
    `cat /etc/passwd | cut -d : -f 1` 
    
    `cat /etc/shadow| cut -d : -f 2`
    

# Network Enumeration :-

### First Basic Network Information

View Network Interfaces and IP Addresses by this command `ifconfig` and `ip -a`

View Routing Table by this command `route -n` and `ip rout`

### Second Network Scanning and Enumeration

List Open Ports on the Local Machine by this command `netstat -tuln` and `ss -tuln` 

### Network Traffic and Connection Monitoring

Monitor Active Network Connections by this command  `netstat -antup` 

display detailed network connection information on a system, including the process IDs (PIDs) associated with each connection `netstat -ano`

View Traffic on a Specific Port by this command `tcpdump -i eth0 port 80`

### Network and Host Discovery

Discover Live Hosts on the Network  by this command `arp-scan -l` 

Ping Sweep (Check Live Hosts in a Subnet) by this bash script 

```bash
for ip in $(seq 1 254); do ping -c 1 192.168.1.$ip | grep "64 bytes"; done
```

### Service and Process Enumeration

List Running Services and Open Ports by this command  ****`lsof -i -P -n` 

Check Which Process is Using a Specific Port by this command `lsof -i :80` 

Display Listening Sockets by this command `ss -lnp` 

# Password Hunting :-

You just search about any password and search about **id_ras** you should crowl in system

- we can use this commands to search
    
    `grep --color=auto -rnw '/' -ie "PASS=" --color=always 2> /dev/null`
    
    `grep --color=auto -rnw '/' -ie "PASSWORD=" --color=always 2> /dev/null`
    
    `grep --color=auto -rnw '/' -ie "pass" --color=always 2> /dev/null`
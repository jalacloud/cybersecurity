# Detecting Evasive Techniques


### **1. Common Evasive Techniques & Detection Strategies**  
Adversaries use advanced methods to avoid detection, including **timestomping**, **fileless malware**, **rootkits**, **process injection**, and **log deletion**. Below is a breakdown of each, with detection and mitigation steps.  


#### **A. Timestomping (Timestamp Manipulation)**  
**Tactic**: Altering file timestamps to blend in with legitimate files (MITRE ID: **T1070.006**).  
- **Example**: Using `SetFileTime` (Windows API) or `touch -d` (Linux) to modify timestamps of malicious files.  

**Detection**:  
- Compare `$STANDARD_INFORMATION` vs. `$FILE_NAME` in NTFS MFT entries:  
  ```bash  
  # Using SleuthKit (tsk):  
  istat -f ntfs /dev/sda1 12345  
  # Look for discrepancies between "Modified" (SI) and "Entry Modified" (FN).  
  ```  
- **Autopsy**: Use the "Modified vs. Changed" filter to flag mismatched timestamps.  

**Defense**:  
- Deploy **EDR** tools (e.g., CrowdStrike) to monitor file timestamp changes.  


#### **B. Fileless Malware**  
**Tactic**: Executing malicious code in memory (MITRE ID: **T1055**).  
- **Examples**:  
  - **PowerShell**: `Invoke-Mimikatz` loaded via `ReflectivePEInjection`.  
  - **WMI Persistence**: `wmic process call create "notepad.exe"` with encoded payloads.  

**Detection**:  
- **Memory Analysis**: Use **Volatility** to hunt for malicious processes:  
  ```bash  
  volatility -f memory.dump --profile=Win10x64 malfind -p <PID>  
  ```  
- **PowerShell Logging**:  
  - Enable Module/ScriptBlock logging (Event ID 4103/4104):  
    ```powershell  
    New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell" -Name "ModuleLogging" -Value 1  
    ```  
  - Hunt for `Invoke-Expression` or `IEX` in logs.  

**Defense**:  
- Restrict PowerShell with **Constrained Language Mode**:  
  ```powershell  
  $ExecutionContext.SessionState.LanguageMode = "ConstrainedLanguage"  
  ```  


#### **C. Rootkits & Kernel Drivers**  
**Tactic**: Hiding processes/files via kernel-level hooks (MITRE ID: **T1014**).  
- **Example**: **FURootkit** hooking `NtQuerySystemInformation` to hide processes.  

**Detection**:  
- **Cross-View Analysis**:  
  - Compare process lists from user mode (`tasklist`) vs. kernel mode (RAM dump via **Volatility**):  
    ```bash  
    volatility -f memory.dump --profile=Win10x64 pslist  
    volatility -f memory.dump --profile=Win10x64 psscan  
    ```  
  - Look for discrepancies (e.g., `psscan` reveals hidden processes).  
- **Driver Signing Enforcement**:  
  - Use `signtool.exe` to verify kernel drivers:  
    ```powershell  
    signtool verify /v /kp C:\Windows\System32\drivers\malicious.sys  
    ```  

**Defense**:  
- Enable **Secure Boot** and **Driver Signature Enforcement** (UEFI settings).  


#### **D. Process Injection (DLL Hijacking, Process Hollowing)**  
**Tactic**: Injecting code into legitimate processes (MITRE ID: **T1055**).  
- **Example**: Injecting Beacon (Cobalt Strike) into `explorer.exe`.  

**Detection**:  
- **API Hooking Detection**:  
  - Use **Sysinternals Process Explorer** to spot hooked DLLs (red highlighting).  
- **YARA Memory Scanning**:  
  ```yara  
  rule cobalt_strike {  
    strings: $mz = "MZ" $cobalt = "cobaltstrike"  
    condition: $mz at 0 and $cobalt in (0..1000)  
  }  
  ```  
- **Velociraptor** artifact to detect hollowed processes:  
  ```sql  
  SELECT * FROM process_memory_map WHERE Protection = "EXECUTE_READWRITE"  
  ```  

**Defense**:  
- Enable **Attack Surface Reduction (ASR)** rules:  
  ```powershell  
  Add-MpPreference -AttackSurfaceReductionRules_Ids "56a863a9-875e-4185-98a7-b882c64b5ce5" -AttackSurfaceReductionRules_Action Enabled  
  ```  


#### **E. Log Deletion & Tampering**  
**Tactic**: Clearing event logs or disabling auditing (MITRE ID: **T1070.001**).  
- **Example**: `wevtutil cl Security` or deleting `/var/log/auth.log`.  

**Detection**:  
- **Event Log Gaps**:  
  - Check for missing log IDs in Splunk:  
    ```splunk  
    index=windows EventCode=4624 | timechart span=1h count | where count=0  
    ```  
- **Auditd Monitoring (Linux)**:  
  ```bash  
  auditctl -w /var/log/ -p wa -k log_tampering  
  ```  

**Defense**:  
- Forward logs to a **SIEM** (e.g., ELK Stack) in real time.  
- Use **immutable storage** (WORM) for critical logs.  



### **2. Advanced Evasion: Encrypted/Polymorphic Malware**  
**Tactic**: Encrypting payloads or using polymorphism to evade signature-based detection.  
- **Example**: **Emotet** using TLS + unique C2 domains per campaign.  

**Detection**:  
- **SSL/TLS Fingerprinting**:  
  - Use **JA3/S hashes** to detect malicious clients:  
    ```suricata  
    alert tls any any -> any any (msg:"Emotet JA3"; ja3.hash; content:"a0e9f5d64349fb13191bc781f81f42e1";)  
    ```  
- **Entropy Analysis**:  
  - High entropy in files (e.g., `binwalk -E malware.exe`).  

**Defense**:  
- Deploy **behavioral sandboxes** (e.g., Cuckoo Sandbox) to analyze encrypted payloads.  



### **3. Defensive Countermeasures**  
#### **A. Proactive Hunting**  
- **Threat Intelligence**: Hunt for IOCs (e.g., VirusTotal, MISP).  
- **Deception**: Deploy **canary files** (e.g., fake credentials in `passwords.txt`) to trigger alerts.  

#### **B. Hardening**  
- **Windows**: Enable **LSA Protection** to block credential dumping:  
  ```reg  
  [HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa]  
  "RunAsPPL"=dword:00000001  
  ```  
- **Linux**: Restrict `/proc` access to prevent memory inspection:  
  ```bash  
  mount -o remount,hidepid=2 /proc  
  ```  

#### **C. EDR Configuration**  
- Tune EDR tools to alert on:  
  - Process hollowing (`CreateRemoteThread` in non-child processes).  
  - Anomalous registry modifications (`HKLM\Software\Microsoft\Windows\CurrentVersion\Run`).  



### **4. Incident Response Playbook**  
**Scenario**: Suspected log deletion and hidden process.  
1. **Contain**:  
   - Isolate the host and enable **firewall logging** to capture ongoing traffic.  
2. **Investigate**:  
   - **Live Response**: Use **Velociraptor** to collect:  
     - Process list: `SELECT * FROM pslist()`  
     - Prefetch files: `SELECT * FROM prefetch()`  
   - **Memory Forensics**: Extract hidden processes with **Volatility**:  
     ```bash  
     volatility -f memory.dump --profile=Win10x64 psscan  
     ```  
3. **Eradicate**:  
   - Terminate malicious processes: `taskkill /PID 1337 /F`  
   - Restore logs from backups or SIEM.  



### **5. Lab Exercises**  
1. **Timestomping Detection**:  
   - Use `SetFileTime.py` (Python) to modify a file’s timestamp.  
   - Detect the change with `istat` in SleuthKit.  
2. **Fileless Attack Simulation**:  
   - Run `Invoke-Mimikatz` in memory and capture it with **Sysmon** (Event ID 8: CreateRemoteThread).  
3. **Rootkit Detection**:  
   - Use **GMER** or **RootkitRevealer** to scan for hidden processes.  

---

### **Key Takeaways**  
- Evasive techniques leave **subtle anomalies** (e.g., timestamp mismatches, high entropy, log gaps).  
- Combine **memory forensics**, **behavioral analysis**, and **threat intel** to uncover hidden threats.  
- **Proactive hardening** (e.g., LSA Protection, constrained PowerShell) disrupts attacker workflows.  

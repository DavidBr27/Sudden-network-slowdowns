
# **🎯Sudden Network Slowdowns Incident**

## 📚 **Scenario:**
I've observed a noticeable drop in network performance, particularly affecting some of the older devices within the 10.0.0.0/16 subnet. External DDoS attacks have been ruled out, and the security team now suspects that the issue may be originating from inside the network. Currently, all internal traffic is permitted by default across all hosts. Additionally, users have unrestricted access to PowerShell and other tools, which raises concerns. There’s a possibility that someone within the network is either downloading large volumes of data or conducting port scans against internal systems.

---

## 📊 **Incident Summary and Findings**

Goal: Gather relevant data from logs, network traffic, and endpoints.
Consider inspecting the logs for excessive successful/failed connections from any devices.  If discovered, pivot and inspect those devices for any suspicious file or process events.
Activity: Ensure data is available from all key sources for analysis.
Ensure the relevant tables contain recent logs:
DeviceNetworkEvents
DeviceFileEvents
DeviceProcessEvents

```kql
DeviceFileEvents
| order by Timestamp desc 
| take 10

DeviceNetworkEvents
| order by Timestamp desc 
| take 10

DeviceProcessEvents
| order by Timestamp desc 
| take 10
```

### **Timeline Overview**
1. **🔍 Windows-target-1 and test-vm-david were found failing multiple connection attempts to themselves and other hosts on the same network.**

   **Detection Query (KQL):**
   ```kql
   DeviceNetworkEvents
   | where ActionType == "ConnectionFailed"
   | summarize ConnectionCount = count() by DeviceName, ActionType, LocalIP
   | order by ConnectionCount
   ```

    <p align="center"> <img src="https://github.com/user-attachments/assets/30798316-4c7e-4de5-9f33-fd091469844b" alt="ConnectionFailed Summary Table" width="800"/> </p>


2. **⚙️ Process Analysis:**
   - **Observed Behavior:** After observing failed connection requests from the suspected hosts (`10.0.0.5` and `10.0.0.106`) in chronological order, I noticed that a port scan was taking place due to the sequential order of the targeted ports. There were several port scans being conducted.

   **Detection Query (KQL):**
   ```kql
    let SuspectedIPs = dynamic(["10.0.0.106","10.0.0.5"]);
    DeviceNetworkEvents
    | where ActionType == "ConnectionFailed"
    | where tostring(LocalIP) in (SuspectedIPs)
    | order by Timestamp desc
    | project Timestamp, DeviceName, ActionType, RemoteIP, RemotePort, LocalIP

   ```
 <div align="center">

`windows-target-1` 
<br>
<br>
<img src="https://github.com/user-attachments/assets/9fb969aa-e409-4d2b-aa2e-50132616366e" alt="windows-target-1 failed connections" width="800"/>

</div>

<div align="center">

`test-vm-david`  
<br>
<img src="https://github.com/user-attachments/assets/44eb09b8-8537-4cb3-b27a-12394cf7b01c" alt="test-vm-david failed connections" width="800"/>

</div>


   

3. **🌐 Network Check:**
   - **Observed Behavior:** I pivoted to the `DeviceProcessEvents` table to investigate any suspicious activity around the time the port scan began. I observed a PowerShell script named `portscan.ps1` launched on `windows-target-1` at `2025-03-20T00:37:33.6100498Z`, followed by the same script being executed on `test-vm-david` at `2025-03-20T00:38:13.8006082Z`.


   **Detection Query (KQL):**
   ```kql
   let SuspectedVMs = dynamic(["test-vm-david", "windows-target-1"]);
   let specificTime = datetime("2025-03-20T00:42:04.8377505Z");
   DeviceProcessEvents
   | where Timestamp between ((specificTime - 10m) .. (specificTime + 10m))
   | where tostring(DeviceName) in (SuspectedVMs)
   | order by Timestamp desc
   | project Timestamp, FileName, DeviceName, InitiatingProcessCommandLine, AccountName
   ```
<div align="center">

`windows-target-1` 
<br>
<br>
<img src="https://github.com/user-attachments/assets/8db93fd3-c449-4c2f-8c41-7531ab35777d" alt="windows-target-1 process events" width="800"/>

</div>

<div align="center">

`test-vm-david` 
<br>
<br>
<img src="https://github.com/user-attachments/assets/5c5a37df-d6a9-4180-832c-d5ddbf935a9b" alt="test-vm-david process events" width="800"/>

</div>



4. **📝 Response:**
   - I discovered that the port scanning script was executed by the `SYSTEM` account, which is unusual and not part of any authorized administrative setup. After isolating the affected device, I performed a malware scan that returned clean results. As a precautionary measure, I kept the device isolated and submitted a ticket to have it re-imaged. I also shared the findings with the manager, noting the automated archive creation, and am currently awaiting further guidance.

 
<div align="center">

`Preview of portscan.ps1` 
<br>  
<img src="https://github.com/user-attachments/assets/3895a3fb-83af-4e37-aa9b-4bc56e30f346" alt="Response Summary Screenshot" width="800"/>

</div>


---

# MITRE ATT&CK Techniques for Incident Notes

| **Tactic**                | **Technique**                                                                                       | **ID**       | **Description**                                                                                                                                 |
|---------------------------|---------------------------------------------------------------------------------------------------|-------------|-------------------------------------------------------------------------------------------------------------------------------------------------|
| **Initial Access**         | [Exploitation of Remote Services](https://attack.mitre.org/techniques/T1210/)                     | T1210        | Failed connection attempts may indicate an attacker probing for open ports or exploitable services.                                            |
| **Discovery**              | [Network Service Scanning](https://attack.mitre.org/techniques/T1046/)                           | T1046        | Sequential port scans performed using a script (`portscan.ps1`) align with service discovery activity.                                         |
| **Execution**              | [Command and Scripting Interpreter: PowerShell](https://attack.mitre.org/techniques/T1059/001/)  | T1059.001    | The use of PowerShell (`portscan.ps1`) for conducting network scanning demonstrates script-based execution.                                    |
| **Persistence**            | [Account Manipulation](https://attack.mitre.org/techniques/T1098/)                               | T1098        | Unauthorized use of the SYSTEM account to launch a script indicates potential persistence through credential manipulation.                     |
| **Privilege Escalation**   | [Valid Accounts](https://attack.mitre.org/techniques/T1078/)                                     | T1078        | SYSTEM account execution suggests privilege escalation by leveraging valid but unauthorized credentials.                                       |
| **Defense Evasion**        | [Obfuscated Files or Information](https://attack.mitre.org/techniques/T1027/)                    | T1027        | If `portscan.ps1` contained obfuscated commands, this technique may have been used to avoid detection.                                         |
| **Impact**                 | [Network Denial of Service](https://attack.mitre.org/techniques/T1498/)                          | T1498        | The significant network slowdown could be a side effect or an intentional impact of excessive scanning activity.                              |

---

## Steps to Reproduce:
1. Deploy a virtual machine with a public-facing IP address.
2. Confirm that the device is reachable from the internet (e.g., using ping or other connectivity tests).
3. Onboard the VM to Microsoft Defender for Endpoint.
4. Check that relevant logs (such as network traffic and exposure alerts) are being ingested by MDE.
5. Run the KQL query in Microsoft Defender for Endpoint's advanced hunting to validate detection.

---

## Created By:
- **Author Name**: David Brom
- **Author Contact**: https://www.linkedin.com/in/trevinoparker/
- **Date**: March 2025

---

## Revision History:
| **Version** | **Changes**                   | **Date**         | **Modified By**   |
|-------------|-------------------------------|------------------|-------------------|
| 1.0         | Initial draft                  | `March 2025`  | `David Brom`   

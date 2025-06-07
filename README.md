# Sentinel Detection: Misplugged Network Device Alert

## Overview

This project contains a low-noise detection rule for Microsoft Sentinel that identifies when a device is incorrectly connected to the wrong 802.1X network (e.g., a classified host on an unclassified VLAN), based on historical failed authentications. The alert only triggers when the device later successfully connects to its correct network, indicating a likely misplug or policy violation.

This detection logic works across segmented enterprise environments and is built using both:
- **KQL** for Microsoft Sentinel/Defender SIEM
- **SQL** for SIEMs or environments that log auth events to a structured database

---

## Use Case

> Detect devices that were ever connected to the wrong network, but only trigger an alert once they successfully connect to the correct one.

Ideal for environments with:
- Segregated classified/unclassified networks
- 802.1X network access control
- Insider threat, network hygiene, or misconfiguration detection needs

---

## 🔎 Detection Logic Summary

1. When a device attempts to connect to the wrong network, the 802.1X authentication fails.
2. That failure is logged, but no alert is raised immediately.
3. When the device later successfully connects to its authorized network, the detection queries historical failures.
4. If a previous failed attempt on an unauthorized network exists, an alert is triggered.

---

## 📊 Files

- [`detection.kql`](detection.kql): Azure Sentinel KQL rule using custom `AuthEvents_CL` table and an inline allowlist
- [`detection.sql`](detection.sql): SQL rule for traditional database environments

---

## Author

Brandon Johnson
Defensive Cyberspace Operator | SOC Analyst | Detection Engineer

📫 LinkedIn: www.linkedin.com/in/brandxon | 📧 johnsbrm@gmail.com

---

## Sample KQL Query (Sentinel)

```kql
let AuthorizedDevices = datatable(DeviceName:string, MACAddress:string, AuthorizedNetwork:string)
[
  "host1", "AA:BB:CC:DD:EE:FF", "ClassifiedNet",
  "host2", "11:22:33:44:55:66", "UnclassifiedNet"
];

let FailedWrongNetwork = AuthEvents_CL
| where AuthResult_s == "Failure"
| join kind=inner AuthorizedDevices on $left.DeviceName_s == $right.DeviceName
| where NetworkName_s != AuthorizedNetwork
| distinct DeviceName_s, MACAddress_s;

let CorrectSuccess = AuthEvents_CL
| where AuthResult_s == "Success"
| join kind=inner AuthorizedDevices on $left.DeviceName_s == $right.DeviceName
| where NetworkName_s == AuthorizedNetwork;

CorrectSuccess
| join kind=inner FailedWrongNetwork on DeviceName_s, MACAddress_s
| project 
    TimeGenerated,
    DeviceName = DeviceName_s, 
    MACAddress = MACAddress_s, 
    NetworkName = NetworkName_s,
    AlertType = "Device Previously Connected to Wrong Network"

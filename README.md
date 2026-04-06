# SOC Automation Lab

## Overview
A fully functional Security Operations Center (SOC) automation lab built 
on cloud and local infrastructure. This project simulates a real-world 
SOC workflow end-to-end — from threat detection and alert generation to 
automated enrichment, case management, and analyst notification — without 
any manual intervention.

## Architecture
| Component | Role | Location |
|---|---|---|
| Windows 11 VM | Monitored endpoint | VirtualBox (local) |
| Sysmon | Endpoint telemetry collection | Windows 11 VM |
| Wazuh Agent | Forwards Sysmon logs to Wazuh Manager | Windows 11 VM |
| Wazuh Manager | SIEM - ingests, parses, and alerts on logs | Vultr cloud VM |
| Shuffle | SOAR - orchestrates automated response | shuffler.io |
| TheHive | Case management - receives and tracks alerts | Vultr cloud VM |
| VirusTotal | IOC enrichment via API | Cloud |
| Kali Linux | SOC analyst workstation | Local host |

## Data Flow
Windows 11 VM (Sysmon)
↓
Wazuh Agent
↓
Wazuh Manager (SIEM) — custom detection rule fires
↓
Shuffle (SOAR webhook trigger)
↓
SHA256 hash extracted via Regex
↓
VirusTotal API (IOC enrichment)
↓
TheHive (alert/case created) + Email notification to analyst

## What This Lab Does
1. **Telemetry Collection** — Sysmon is installed on the Windows 11 VM 
   and configured to capture detailed process creation events (Event ID 1), 
   including original file names, hashes, and parent process information.

2. **Log Ingestion** — The Wazuh agent forwards Sysmon logs to the Wazuh 
   Manager over TCP ports 1514/1515. Archive logging and Filebeat are 
   configured to ensure all events are indexed and searchable.

3. **Threat Detection** — A custom Wazuh detection rule (ID 100002, 
   level 15) monitors for process creation events where the original 
   filename matches `mimikatz.exe` using a PCRe2 regex pattern. This 
   detects Mimikatz even if the binary is renamed.

4. **SOAR Automation** — When the rule fires, Wazuh sends a JSON-formatted 
   alert to a Shuffle webhook. Shuffle then:
   - Extracts the SHA256 hash of the malicious binary using regex
   - Queries the VirusTotal API for threat intelligence on the hash
   - Creates an alert in TheHive with full context (hostname, severity, 
     rule description, VirusTotal results)
   - Sends an email notification to the SOC analyst

5. **Case Management** — TheHive receives the enriched alert and creates 
   a structured case for analyst review and response.

## Detection Rule
```xml
<rule id="100002" level="15">
  <if_group>sysmon_event1</if_group>
  <field name="win.eventdata.originalFileName" type="pcre2">
    (?i)mimikatz\.exe
  </field>
  <description>Mimikatz usage detected</description>
  <mitre>
    <id>T1003</id>
  </mitre>
</rule>
```

## Key Configurations
- **Sysmon** configured to log process creation events
- **Wazuh ossec.conf** updated to ingest `Microsoft-Windows-Sysmon/Operational` 
  event channel
- **Archive logging** enabled (`logall` and `logall_json` set to yes)
- **Filebeat** configured to ship archive logs to Wazuh indexer
- **Shuffle integration** in ossec.conf targets rule ID 100002 only

## Skills Demonstrated
- SIEM configuration and custom rule development
- Endpoint telemetry collection with Sysmon
- SOAR workflow design and automation
- IOC enrichment using threat intelligence APIs
- Case management and alert triage
- Linux server administration (Ubuntu 24.04)
- Cloud infrastructure setup (Vultr)
- Network security (UFW firewall management)
- Credential tool detection (Mimikatz/T1003)

## References
- [Wazuh Documentation](https://documentation.wazuh.com)
- [TheHive Project](https://thehive-project.org)
- [Shuffle Documentation](https://shuffler.io/docs)
- [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
- [MITRE ATT&CK T1003](https://attack.mitre.org/techniques/T1003/)

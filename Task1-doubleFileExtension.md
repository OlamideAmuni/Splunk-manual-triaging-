## Task 1: Double Extension File Download / Creation Detection

Objective

Detect and alert on files with double extensions (e.g., invoice.pdf.exe) being created or downloaded. This is a common indicator of potential malware or masquerading attempts.

## Workflow / Steps:
Write YAML Detection Rule:
- Created a YAML detection rule to match double extension file events.
- Rule specifies log sources (Windows Security Logs, Sysmon Event ID 1) and event types (file creation).
Convert YAML to SPL:
- Used unicoder.IO to convert the YAML rule into Splunk SPL (Search Processing Language).

  [detection rule for double extension](doubleExtensionDetection.yml)
  
Upload & Test in Splunk Cloud
- Uploaded simulated CSV logs containing file creation events.
- Tested the SPL in Search & Reporting to confirm it filters only events matching the rule.

! [putting SPL queries to test](splunk1.jpeg)
  
Save SPL as Alert:
- Saved the SPL query as a Splunk alert.
Configured alert settings:
- Description: Detect double extension file creation/download.
- Schedule: Trigger after 1 hour, 0 minutes past the hour.
- Trigger Actions:
1. Send email whenever an event matches the rule.
2. Add to Triggered Alerts so details of each alert can be reviewed manually.

Alert Notification & Manual Triaging
- After one hour, Splunk emails me notifying that an event matched the alert.
- Open Triggered Alerts in Splunk Cloud.
- Manually triage each alert:
1. Assigned True Positive status.
2. Set severity level medium.
3. Add comments/notes for context and investigation.
  
This helps simulate real SOC analyst workflow while using Splunk Cloud without advanced apps.
## Question Answered
- Which user created this file: Alice
- What time: 2025-12-26 5:48:00
- What file: Invoice.pdf.exe
- which Directory: c:\user\alice\downloads\invoice.pdf.exe
- How: Alice might have downloaded invoice.pdf.exe after interacting with a phishing email masquerading a legitimate sender( maybe an internal sender), or drive-by download from malicious website
- severity: Medium (Alice have not executed the file)
- Status: True positive.
- Why is this suspicious?: double extension file is used by attackers to trick target user to something else while it hides malicious contents. Executing this file will leads to initial system compromise, persistence, credentials theft, lateral movement, data exfiltration...

## Action Taken As A SOC Level 1 Analyst 
- Classify the Alert:
1. Threat Type: Malware delivery attempt / Masquerading
2. MITRE ATT&CK MAPPING:
Tactic: Defense Evasion / Initial Access
Technique: Masquerading (T1036)

- Containment:
1. File deletion or quarantine
2. user awareness (analyst needsto let the user know to prevent manual execution)
3. monitor the endpoint closely
4. Documents the alert for proper investigation by level 2 analyst 

# Learning Outcomes
- Writing YAML detection rules for SOC alerts.
Converting detection rules into Splunk SPL using unicoder.io
- Testing and verifying rules against simulated log events.
- Configuring alerts in Splunk Cloud, including email notifications and adding to Triggered Alerts.
- Practicing manual triage, assigning severity, true/false positive status, and documenting notes for each alert by answering questions like "who", "when", "what", "where" and "how"
- Qiuck decision making to contain infected machine 

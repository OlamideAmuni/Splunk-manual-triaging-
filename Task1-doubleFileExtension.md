## Task 1: Double Extension File Download / Creation Detection

Objective

Detect and alert on files with double extensions (e.g., invoice.pdf.exe) being created or downloaded. This is a common indicator of potential malware or masquerading attempts.

## Workflow / Steps:
Write YAML Detection Rule:
- Created a YAML detection rule to match double extension file events.
- Rule specifies log sources (Windows Security Logs, Sysmon Event ID 1) and event types (file creation).
Convert YAML to SPL:
- Used unicoder.IO to convert the YAML rule into Splunk SPL (Search Processing Language).
  
Upload & Test in Splunk Cloud
- Uploaded simulated CSV logs containing file creation events.
- Tested the SPL in Search & Reporting to confirm it filters only events matching the rule.
  
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

# Learning Outcomes
- Writing YAML detection rules for SOC alerts.
Converting detection rules into Splunk SPL using unicoder.io
- Testing and verifying rules against simulated log events.
- Configuring alerts in Splunk Cloud, including email notifications and adding to Triggered Alerts.
- Practicing manual triage, assigning severity, true/false positive status, and documenting notes for each alert by answering questions like "who", "when", "what", "where" and "how"

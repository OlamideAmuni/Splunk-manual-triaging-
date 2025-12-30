## SOC Analyst Level 1 Practice Lab
Project Overview

This repository contains my hands-on practice for Level 1 SOC analyst tasks. The focus is on detection, alerting, and triaging simulated threats using Windows logs, Splunk, and MITRE ATT&CK mapping.

The goal is to gain practical experience in:

- Writing detection rules for suspicious activity using YAML

- Converting YAML rules into SPL for Splunk

- Uploading simulated logs and configuring alerts

- Manual triaging and analysis

## Tasks & Implementation

 # Task 1: Double Extension File Download Detection
  
- Description: Detect when a file with a double extension (e.g., invoice.pdf.exe) is created or downloaded.

- Log Source: Windows Security Logs, Sysmon Event ID 1 (process creation)
- Detection Rule:
 
 # Task 2: Suspicious Process Creation
- Description: Detect suspicious processes spawned from double extension files.

- Log Source: Windows Security Logs, Sysmon Event ID 1
- Detection Rule:


## Tools & Workflow
- Simulated CSV logs: Uploaded Windows log CSVs containing file creation and process creation events.
- YAML to SPL conversion: Detection rules written in YAML and converted to SPL using an online converter.
- Splunk Cloud: Alerts configured to trigger email notifications whenever matching events occur.
- Manual triaging: Because Splunk Cloud does not provide full triage apps, alerts were analyzed and documented manually using pen and paper.

## Learning Outcomes

- Practical experience writing SOC detection rules.

- Understanding how to map alerts to MITRE ATT&CK tactics and techniques.

- Familiarity with Splunk alert configuration and simulated log ingestion.

- Practicing manual triaging for events flagged by alerts.

## Future Improvements
- Deploying a full Splunk Enterprise setup for real-time triaging.

- Expanding rules to cover more attack types and scenarios.

- Integrating with SOAR apps for automated response workflows

## Task 2 – Suspicious Process Creation from Double Extension File Execution
Overview
This task focuses on detecting suspicious process creation that occurs after a user execute a double file extension.
unlike task 1(file downloaded/created), this scenerio assumes the file was executed, leading to process creation,which increase the severity and risk.
Objectives
- Detect execution of suspicious processes originating from double extension files
- Generate alerts in splunk cloud
- Perform manual triage due to non access to splunk enterprise security
- Document findings and determine escalation requirements

## Step 1 – Writing the Detection Rule
I wrote the detection rule in YAML format for suspicious process creation from any double extension file. The YAML included:

- Event category: process_creation
- Product: Windows
- Detection conditions to match .exe child processes
- Metatdata such as severity and MITRE ATT&CK mapping

I also added parent process detection, specifically looking for explorer.exe as the parent, to identify user-driven execution.

## Step 2 – Converting YAML to SPL
I converted the YAML rule into Splunk SPL using the online converter unicoder.io .This SPL query was then used to search within Splunk and validate the detection.

## Step 3 – Uploading Simulated Logs
I uploaded a CSV file containing simulated Windows logs, including:

- Double extension file creation
- Process creation (with explorer.exe as parent process)
- parent-child process relationships
The simulated logs represent a realistic attack flow where
- A user download a malicious double extension file
- The user executes the file
- A suspicious process is created on the system

## Step 4 – Testing the Rule
I ran the SPL query in splunk cloud search and reporting to confirm that query correctly filtered process creation events. The SPL correctly filtered out process creation events originating from double extension files.

## Step 5 – Configuring Alerts
I saved the SPL query as an alert in Splunk with the following settings:

- Alert triggered after one hour
- Email notification enabled to receive alerts for every matching event
- Added the alert to Triggered Alerts for deeper inspection
- Alert type: scheduled
- severity: High(due to confirmed execution)

## Step 6 – Manual Triage And Documentation
Since I do not have access to Splunk SOAR and splunk essential security (a splunk base app for triaging), I manually triaged the alert using pen and paper. During triage, I identified:

- Child Process: invoice.pdf.exe
- Parent Process: explorer.exe
- Execution: User-driven (user manually open the file)
- Verdict: True Positive
- Severity: High
- Escalation: Required for Level 2 investigation
- File path: c:/users/alice/download/invoice.pdf.exe
- file type: Double Extension Executable
- filename: invoice.pdf.exe
- time: 2025-12-26 6:50:00
- user: Alice
- Tactics: Intial Access
- Technique: User Execution
- Sub-Technique: Malicious File T1204.002
- why is it Suspicious: Malware execution can lead to system compromise, persistence and C2 communication which might lead to data exfiltration.
- incident Summary: A suspicious process creation alert was triggered following the execution of a double extension file by Alice(invoice.pdf.exe), the execution was confirmed to be user driven indicating malware execution via social engineering or phishing emails.

Level 1 Analyst Action:
- Alert reviewed and validated
- Event classified as True Positive
- Severity assigned as High due to malware execution
- Isolate endpoint (if policy allows)
- Block file (if policy allow)
- Escalate to level 2 Analyst
This step confirmed that the double extension file had been executed, and the parent process name (explorer.exe) validated that it was manually launched by the user.

## Tool Used
- Splunk Cloud (Search and Reporting)
- YAML detection rules
- unicoder.io
- Simulated Windows event logs(csv file)

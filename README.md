# -Cloud-SIEM-and-SOAR-Lab

## Cloud SIEM & SOAR Lab: Automated Identity Brute-Force Detection & Response with Microsoft Sentinel


## Executive Summary

This project demonstrates the end-to-end design, deployment, detection engineering, and automated incident response (SOAR) of a cloud-native Security Operations Center (SOC) pipeline using Microsoft Sentinel, Microsoft Entra ID, and Azure Logic Apps.

By ingesting real-time identity telemetry (SigninLogs and AuditLogs), authoring custom Kusto Query Language (KQL) analytics rules mapped to the MITRE ATT&CK framework, and orchestrating an automated email notification playbook, this lab reduces Mean Time to Detect (MTTD) and Mean Time to Respond (MTTR) for credential-based attacks.

## Architecture & Workflow

```
[Simulated Brute-Force Attack] 
       │ (Failed Logins: Error 50126 / 50053)
       ▼
[Microsoft Entra ID] ──(Diagnostic Settings)──► [Log Analytics Workspace: soc-lab-logs-01]
                                                               │
                                                               ▼
                                                     [Microsoft Sentinel SIEM]
                                                               │
                                   ┌───────────────────────────┴───────────────────────────┐
                                   ▼                                                       ▼
                     [Scheduled Analytics Rule (KQL)]                        [Entity Mapping & Triage]
                     • MITRE: Credential Access                              • Account: UserPrincipalName
                     • Threshold: >= 3 attempts / 5m                         • IP: IPAddress
                                   │
                                   ▼ (Triggers Incident)
                        [Sentinel Automation Rule]
                                   │
                                   ▼
                 [Azure Logic App SOAR Playbook]
                 • Trigger: Microsoft Sentinel Incident
                 • Action: SMTP Send Email (V3)
                                   │
                                   ▼
                 [SOC Analyst Inbox Notification]

```


## Tech Stack & Azure Resources

• SIEM / XDR Platform: Microsoft Sentinel & Microsoft Defender Portal
• Data Warehouse: Azure Log Analytics Workspace (soc-lab-logs-01)
• Identity Provider: Microsoft Entra ID (SigninLogs, AuditLogs)
• SOAR Orchestration: Azure Logic Apps (Playbook-BruteForce-Email)
• Query Language: Kusto Query Language (KQL)
• Framework Alignment: MITRE ATT&CK (T1110 – Brute Force / Credential Access)

## Implementation Walkthrough

## Phase 1: SIEM Deployment & Identity Log Ingestion

1. Provisioned Core Infrastructure: Deployed a dedicated Resource Group (SOC-Lab-RG) and Log Analytics Workspace (soc-lab-logs-01), then onboarded Microsoft Sentinel.
2. Configured Entra ID Telemetry Pipeline: Enabled Diagnostic Settings (Entra-to-Sentinel) in Microsoft Entra ID to stream SignInLogs and AuditLogs directly into the Sentinel workspace.
3. Provisioned Target Identity: Created a dedicated non-privileged test account (test.victim) to safely execute controlled adversarial simulations without impacting administrative accounts.

## Phase 2: Threat Simulation & KQL Hunting

To validate log ingestion and baseline normal versus malicious authentication behavior, a credential brute-force simulation was executed against test.victim from an isolated browser session.

## Threat Hunting Query (SigninLogs)

```
kql
SigninLogs
| where ResultType != "0"
| project TimeGenerated, UserPrincipalName, IPAddress, Location, ResultType, ResultDescription
| sort by TimeGenerated desc
```

• Key Findings: Confirmed ingestion of failed sign-in telemetry displaying source IP geolocation (NG), target account, and authentication error codes 50126 (Invalid username or password) and 50053 (Smart Lockout triggered due to repeated failed attempts).

## Account Creation & Privilege Audit Query (AuditLogs)

```
kql
AuditLogs
| where OperationName has_any ("Add user", "Add member to role", "Reset password")
| project TimeGenerated, OperationName, InitiatedBy, TargetResources
| sort by TimeGenerated desc
```

## Phase 3: Detection Engineering & Tuning

Initial detection logic focused solely on invalid password events (50126). During iterative red-team testing, Entra ID Smart Lockout (50053) intercepted subsequent rapid login attempts. The rule was tuned to capture both states to eliminate detection blind spots.

## Production Scheduled Analytics Rule (KQL)

```
kql
SigninLogs
| where ResultType in ("50126", "50053")
| summarize FailedAttempts = count() by UserPrincipalName, IPAddress, bin(TimeGenerated, 5m)
| where FailedAttempts >= 3
```

• Rule Frequency & Lookup: Scheduled to run every 5 minutes over a 5-minute sliding window.
• Severity & Tactics: Classified as Medium severity under Credential Access (MITRE ATT&CK).
• Entity Mapping: Mapped UserPrincipalName to Account (FullName) and IPAddress to IP (Address) to enable automated entity extraction during incident triage.

## Phase 4: SOAR Playbook Automation (Azure Logic Apps)

To eliminate manual queue polling and accelerate analyst response, an automated SOAR workflow was engineered:
1. Registered Sentinel Service Principal: Configured the Azure Security Insights enterprise service principal via Azure Cloud Shell (az ad sp create) to authorize Sentinel-to-Logic-App execution permissions.
2. Built Logic App Playbook (Playbook-BruteForce-Email):
	• Trigger: Microsoft Sentinel incident (fires immediately upon incident creation).
	• Action: SMTP - Send Email (V3) authenticated securely via TLS/SSL (Port 587) to dispatch structured incident telemetry (Incident Title, Severity, Status, Description, and direct Incident URL).
3. Linked via Sentinel Automation Rule: Created Auto-Email on Brute Force Incident to trigger Playbook-BruteForce-Email whenever the brute-force analytics rule generates a new incident.

## Incident Triage & Validation Results

Upon executing an end-to-end validation test (4 consecutive failed sign-in attempts):
1. Detection: Microsoft Sentinel generated a Medium-severity incident within the 5-minute evaluation window.
2. Entity Enrichment: Both the target user (test.victim) and source IP address were automatically populated under incident entities.
3. SOAR Execution: The Logic App playbook executed automatically and delivered a formatted alert email with a direct investigation link to the SOC analyst's inbox.
4. Closure Documentation: Verified via KQL that zero ResultType == "0" (successful) logins occurred during the attack window, documented findings, and closed the incident as Benign Positive – Security Testing.

## Key Takeaways & Lessons Learned

• Iterative Rule Tuning Matters: Testing detection rules against real platform defenses (such as Entra ID Smart Lockout) reveals edge-case error codes (50053) that must be included to prevent false negatives.
• Entity Mapping Accelerates Triage: Mapping KQL output fields to native Sentinel entities transforms raw log rows into actionable forensic artifacts.
• Automation Bridges Detection and Response: Integrating Logic Apps with Sentinel Automation Rules ensures critical identity alerts reach analysts immediately rather than sitting unnoticed in a queue.

## Suggested Screenshots to Upload to Your GitHub images/ Folder

1. 01-kql-signinlogs-hunt.png — Your KQL query output showing error 50126 and source IP details.
2. 02-analytics-rule-entity-mapping.png — Your scheduled query rule showing Account and IP entity mappings.
3. 03-logic-app-designer.png — Your Playbook-BruteForce-Email workflow showing the Sentinel trigger and SMTP action.
4. 04-defender-incident-queue.png — Your closed/triaged incidents in the Microsoft Defender portal.
5. 05-soar-alert-email.png — The automated SOC alert email delivered to your Gmail inbox.
You can copy and paste this entire Markdown report directly into your GitHub repository's README.md file! Let me know if you want to customize any section—or if you're ready to build Project C (Visual SOC Threat Hunting Workbook) so we can add dashboard screenshots to your repo too!

---

# Step By Step

## MIcrosoft Azure

### Step-by-Step Registration Process

1. Go to the Official Site
	• Visit the Microsoft Learn Azure Account Guide -https://learn.microsoft.com/en-us/dotnet/azure/create-azure-account or go directly to the Azure Free Account Page- https://azure.microsoft.com/en-us/pricing/purchase-options/azure-account?icid=get-started-portal.

<img width="1892" height="911" alt="image" src="https://github.com/user-attachments/assets/a4cd7b78-cef3-4b14-bcef-417a61c90684" />

* Click on **Get Started with Azure**

<img width="1913" height="906" alt="image" src="https://github.com/user-attachments/assets/36cde776-e31b-4d1e-991a-397323928dd4" />

* Click **Try Azure for Free**

<img width="1905" height="859" alt="image" src="https://github.com/user-attachments/assets/ff1e148a-5558-45e9-bfc0-00cf4d1bdea2" />

2. Sign In or Create a Microsoft Account
   • Log in with your existing Microsoft or GitHub account.
   • If you do not have one, click Create one and follow the prompts to register a new email address and password.

Since we are setting up a New Account
* Click **Create One**

This will take you to the sign up page, where you will input your email...as shown below:


<img width="1915" height="919" alt="image" src="https://github.com/user-attachments/assets/33392745-338a-4487-926d-996883b7e748" />

NB: Since I already have an account I will just skip this process and just give you a summary of what you might account.

1. Fill in Your Profile Details
	• Enter your country or region, first name, last name, email address, and job title.
	• Provide your contact phone number and select your preferred verification method (text message or phone call).
2. Verify Your Phone Number
	• Enter the verification code (OTP) sent to your phone via SMS and click verify.
3. Provide Identity Verification via Card
	• Enter your credit or debit card details (cardholder name, card number, expiration date, and CVV).
	• Confirm your billing address details.
4. Accept Terms and Sign Up
	• Check the box to accept the Microsoft Customer Agreement, subscription terms, and privacy statement.
	• Click Sign up to complete the registration.
5. Access the Azure Portal
	• Once finished, click Go to the portal to land on the Azure Portal, where you can start creating resources, managing subscriptions, and using your $200 free trial credit (if you signed up for the free tier).

<img width="1646" height="793" alt="Screenshot 2026-11-12 174208" src="https://github.com/user-attachments/assets/a4f4eae9-8f23-4297-bdd8-e3d01bab9830" />

<img width="1906" height="908" alt="image" src="https://github.com/user-attachments/assets/97855a59-693d-4c53-b7d9-3e2601d2212a" />

---

# Lab 1: 

## Cloud SIEM Deployment & Log Ingestion 


### Step 1: Create a Dedicated Resource Group (SOC-Lab-RG)

• Open Azure Portal: Log into https://azure.com with your Azure Free Trial account (josephatoyebi2020@gmail.com).

• Create Resource Group: Search for Resource groups in the top search bar, click + Create, name it SOC-Lab-RG, select (UK) UK South as the region, and click Review + create > Create.


### Step 2: Create a Dedicated Resource Group (SOC-Lab-RG)

A Resource Group acts as a logical container for all your SOC lab resources so you can easily manage, monitor, and clean them up later.

• Open Resource Groups: 
	* Click inside the top blue search bar, type Resource groups, and select Resource groups under Services.

• Start Creation: 
	* Click the + Create button at the top left of the screen.

• Fill Out the Basics Tab:
	
	• Subscription: Leave your active Azure subscription selected (Azure subscription 1 / Free Trial).
	
	• Resource group: Type SOC-Lab-RG.
	
	• Region: Select (UK) UK South from the dropdown menu.

• Validate & Deploy: Click Review + create at the bottom, wait a few seconds for the green Validation passed banner, and click Create.

<img width="1646" height="918" alt="image" src="https://github.com/user-attachments/assets/52dd9ca1-9667-452c-941f-e21fa1acdec5" />

<img width="1914" height="915" alt="image" src="https://github.com/user-attachments/assets/1781a940-ed5a-444d-8f6a-393dce36b412" />

### Step 3: Provision the Log Analytics Workspace (soc-lab-logs-01)

Microsoft Sentinel stores all ingested security logs inside an Azure Log Analytics workspace.
• Search Workspaces: Type Log Analytics workspaces in the top Azure search bar and click + Create.

• Configure Basics:
	
	• Resource group: Select SOC-Lab-RG.
	
	• Name: Type soc-lab-logs-01.
	
	• Region: Select (UK) UK South (matching your resource group).

• Deploy: Click Review + create, wait for validation to pass, and click Create.

<img width="1640" height="918" alt="image" src="https://github.com/user-attachments/assets/50ae77ed-6eaf-4867-a491-9bf204e8c02e" />

<img width="1911" height="912" alt="image" src="https://github.com/user-attachments/assets/6683369b-ec43-4e57-a0a4-fb3fc3779425" />

### Step 4: Onboard Microsoft Sentinel onto Your Workspace

• Open Sentinel: Search for Microsoft Sentinel in the top Azure search bar and click + Create.

• Attach Workspace: Select soc-lab-logs-01 from the list and click Add at the bottom.

• Verify Onboarding: Once deployment finishes, your workspace opens inside the Microsoft Sentinel dashboard (ready to receive telemetry).

<img width="1909" height="908" alt="image" src="https://github.com/user-attachments/assets/91f7ce35-aa2c-42dc-a75b-f653c60f12b1" />

---

Immediately after the Installation of the Microsoft Sentinel, the following error popped up:

<img width="1917" height="886" alt="Screenshot 2026-11-13 081920" src="https://github.com/user-attachments/assets/3c8ae89c-c21b-46cd-a854-b29f480dc90e" />

* To correct the error, we need to set up Step 5.

---

### Step 5: Stream Microsoft Entra ID Logs (SigninLogs & AuditLogs)

Because Free Trial tenants without a Microsoft Entra ID P1/P2 license block the one-click Sentinel data connector, you configured Diagnostic Settings directly inside Entra ID to stream live identity telemetry into your workspace:

• Open Microsoft Entra ID: Search for Microsoft Entra ID in the top Azure search bar and open it.

• Navigate to Diagnostic Settings: In the left-hand menu, expand Monitoring & health (or Monitoring) and click Diagnostic settings.

• Create Diagnostic Setting: Click + Add diagnostic setting and configure:

	• Diagnostic setting name: Type Entra-to-Sentinel.
	
	• Logs (Categories to Stream): Check SignInLogs (tracks every successful and failed login attempt) and AuditLogs (tracks user creation, password resets, and role changes). Also check NonInteractiveUserSignInLogs, if available.
	
	• Destination details: Check Send to Log Analytics workspace, select your subscription, and choose soc-lab-logs-01.

• Save Configuration: Click Save at the top left to start streaming live identity events into Microsoft Sentinel.

<img width="1919" height="914" alt="image" src="https://github.com/user-attachments/assets/c1a9c05d-8cee-4d23-890e-95cf9359ac66" />

<img width="1919" height="888" alt="image" src="https://github.com/user-attachments/assets/8d107a5e-96fa-4f7d-b97c-a6c292e8c344" />


### Step 6: Verify Log Ingestion in Microsoft Sentinel

• Open Logs: Return to Microsoft Sentinel > select soc-lab-logs-01 > click Logs in the left-hand menu.

• Confirm Tables Exist: Check the Tables pane on the left under LogManagement (or Microsoft Entra ID) to confirm SigninLogs and AuditLogs appear and populate within 10–15 minutes of activity.

<img width="1912" height="906" alt="image" src="https://github.com/user-attachments/assets/fbb7d7fb-8b56-4a1d-87d0-cbb67e3b2a01" />


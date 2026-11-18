# Cloud-SIEM-and-SOAR-Lab

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

---

# Step By Step

## Microsoft Azure

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

<img width="1913" height="917" alt="Screenshot 2026-11-13 091404" src="https://github.com/user-attachments/assets/ef59783d-a4b1-42c7-81de-117b3fa5603c" />

---

---

# Lab 2:

## Adversarial Brute-Force Simulation & KQL Threat Hunting

### Step 1: Provision a Non-Privileged Target Account (test.victim)

In a real SOC lab, you never run brute-force simulations against your primary Global Administrator account to avoid locking yourself out of your Azure tenant.

• Open Microsoft Entra ID: In the Azure Portal (https://azure.com), search for Microsoft Entra ID in the top search bar and open it.

• Go to Users: In the left-hand menu, expand Manage > click Users, then click + New user > Create new user at the top.

• Configure Identity Details:

	• User principal name: Type test.victim (your full login username automatically becomes test.victim@://onmicrosoft.com).
	
	• Display name: Type Test Victim.
	
	• Password: Uncheck Auto-generate password and set a temporary initial password (e.g., LabTest2026!).

• Deploy User: Click Review + create, then click Create.

<img width="1919" height="922" alt="image" src="https://github.com/user-attachments/assets/0a88bcba-7f12-4481-96af-850cc4a44800" />

<img width="1912" height="905" alt="image" src="https://github.com/user-attachments/assets/834cca54-486f-4c8a-a13b-608b4b2036c0" />


### Step 2: Simulate a Credential Brute-Force Attack

To generate realistic malicious telemetry without contaminating my active admin session, execute the failed logins from an isolated browser session.

• Open an Incognito Window: Open a new Incognito / Private browser window (Ctrl + Shift + N in Chrome/Edge) and navigate to https://azure.com.

<img width="1919" height="1000" alt="Screenshot 2026-11-14 120748" src="https://github.com/user-attachments/assets/1042c078-f8e8-4b07-b6e2-5e9fd54ef585" />

• Enter Target Username: In the Microsoft sign-in prompt, type test.victim@://onmicrosoft.com and click Next.

<img width="649" height="692" alt="image" src="https://github.com/user-attachments/assets/c9e50fd0-64f4-4e05-bed8-15b1066c3416" />

• Execute Failed Login Attempts: Type an incorrect password (such as WrongPass123!) and click Sign in 4 to 5 times in a row until Microsoft displays an invalid password or Smart Lockout warning.

<img width="582" height="518" alt="image" src="https://github.com/user-attachments/assets/1602a735-bb7f-4c40-a468-7941578a707d" />

• Close Session: Close the Incognito window and wait 5 to 10 minutes for Entra ID to stream the telemetry into your Log Analytics workspace.

Because this is the very first time Entra ID is streaming sign-in logs into your Log Analytics workspace, give Azure about 10 to 15 minutes to initialize the SigninLogs table and deliver your failed attempts.

### Step 3: Hunt Your Brute-Force Attempts in Microsoft Sentinel

1. Switch back to your Azure Portal tab, open Microsoft Sentinel, select your workspace (soc-lab-logs-01), and click Logs in the left menu.
2. Set the Time range next to the blue Run button to Last 1 hour (or Last 4 hours).
3. Paste this KQL query into the editor and click Run:

kql
```
SigninLogs
| where ResultType != "0"
| project TimeGenerated, UserPrincipalName, IPAddress, Location, ResultType, ResultDescription
| sort by TimeGenerated desc
```

<img width="1918" height="911" alt="Screenshot 2026-11-13 134401" src="https://github.com/user-attachments/assets/4066edf2-fab9-4611-9690-8494126e44d5" />

4. What to Look For:

You should see your failed login attempts for test.victim@://onmicrosoft.com with ResultType == 50126 ***("Error validating credentials due to invalid username or password")***, along with your **IPAddress** and **Location**. (If it says "No results found" right away, wait 5 more minutes and click Run again).

<img width="1918" height="911" alt="Screenshot 2026-11-13 134401" src="https://github.com/user-attachments/assets/aac353cf-7980-4607-a50d-d61821b93588" />

---

---

# Lab 3: 

## SIEM Detection Engineering & Rule Tuning, matching the exact KQL logic, MITRE ATT&CK mapping, entity mapping, and iterative tuning you performed in your project.

### Step 1: Open Microsoft Sentinel Analytics

• Navigate to Defender Portal: Open https://microsoft.com (or open Microsoft Sentinel in Azure and click Go to Microsoft Defender portal).

• Open Analytics: Expand the left-hand navigation menu, scroll down to Microsoft Sentinel > Configuration, and click Analytics.

• Start Rule Creation: Click + Create at the top left and select Scheduled query rule from the dropdown.

### Step 2: Configure Rule Metadata & MITRE ATT&CK Mapping (General Tab)

• Name: Type SOC Lab - Entra ID Brute Force Attempt.

• Description: Enter Detects 3 or more failed sign-in or Smart Lockout attempts against an Entra ID account from the same IP address within a 5-minute window.

• Severity: Select Medium.

• Tactics and Techniques (MITRE ATT&CK):

	• Click the Tactics and techniques dropdown and check Credential Access (aligns with T1110 – Brute Force).

• Status: Confirm the rule toggle is set to Enabled, then click Next : Set rule logic >.

<img width="1902" height="907" alt="image" src="https://github.com/user-attachments/assets/44958552-1dca-4980-9af7-2bc1516fb41d" />

### Step 3: Author & Tune the KQL Detection Logic (Set Rule Logic Tab)

Initially, detection rules filtering only for invalid passwords (ResultType == "50126") miss subsequent rapid attempts once Microsoft Entra ID Smart Lockout (ResultType == "50053") blocks the account. You tuned the KQL query to capture both states and prevent false negatives:

• Paste Tuned KQL Query into Rule Query:

```
SigninLogs
| where ResultType in ("50126", "50053")
| summarize FailedAttempts = count() by UserPrincipalName, IPAddress, bin(TimeGenerated, 5m)
| where FailedAttempts >= 3
```

<img width="1903" height="927" alt="Screenshot 2026-11-13 142643" src="https://github.com/user-attachments/assets/3295c24c-7f62-48db-b8d3-9fde770d4227" />

• Verify Simulation Preview: Check the Results simulation chart on the right side of the screen to confirm the query validates cleanly with zero syntax errors.

### Step 4: Configure Entity Mapping for Forensic Extraction

Mapping KQL output columns to native Sentinel entities tells the SIEM to automatically extract and display the target user and attacker IP inside the incident's Evidence / Entities tab.

• Expand Entity Mapping: Scroll down on the Set rule logic tab to Alert enhancement > Entity mapping and click to expand it.

• Map Target User Account:

	• Click + Add new entity.
	
	• Entity type: Select Account.
	
	• Identifier: Select FullName.
	
	• Value: Select UserPrincipalName from the dropdown.

• Map Attacker Source IP:
	
	• Click + Add new entity again.
	
	• Entity type: Select IP.
	
	• Identifier: Select Address.
	
	• Value: Select IPAddress from the dropdown.

<img width="827" height="476" alt="Screenshot 2026-11-13 165647" src="https://github.com/user-attachments/assets/e4f206a3-0707-4532-a84b-3f2deaaf67b0" />

### Step 5: Set Query Scheduling & Alert Threshold

• Query Scheduling:
	
	• Run query every: Set to 5 Minutes.
	
	• Lookup data from the last: Set to 5 Minutes.

• Alert Threshold: Leave Generate alert when number of query results set to Is greater than 0.

• Event Grouping: Keep Group all events into a single alert selected so multiple failed attempts from the same IP and user generate one clean alert rather than flooding the queue.

### Step 6: Configure Incident Settings & Deploy Rule

• Incident Settings Tab: Click Next : Incident settings > and confirm Create incidents from alerts triggered by this analytics rule is Enabled.

• Automated Response Tab: Click Next : Automated response > (left blank initially until linking the SOAR playbook in Lab 4).

• Review + Create Tab: Click Next : Review + create >, wait for the green Validation passed banner, and click Save to activate your detection rule.


<img width="1912" height="913" alt="image" src="https://github.com/user-attachments/assets/250c20c2-2801-4eb3-b582-8a127a365565" />
	
Results:

• Incident ID 3: SOC Lab - Entra ID Brute...

• Status: New

• Severity: Medium (orange badge)

We have officially built a working Cloud Identity Threat Detection Pipeline in Microsoft Sentinel—capturing live failed login telemetry (SigninLogs), detecting a credential-access brute-force pattern with KQL, and raising a Medium-severity security incident.


---

---

# Lab 4: 

## SOAR Playbook Automation (Azure Logic Apps)

Building an Automated SOAR Playbook using Azure Logic Apps is one of the best resume builders for a SOC Analyst. In a real SOC, analysts use SOAR (Security Orchestration, Automation, and Response) so that the moment a high-risk brute-force alert triggers, an automated workflow instantly emails the on-call analyst with the incident title, severity, and attacker details.

Here is my step-by-step guide to building and connecting my first Sentinel SOAR Playbook:

### Step 1: Register the Microsoft Sentinel Service Principal via Azure Cloud Shell

On new Azure Free Trial tenants, the built-in Azure Security Insights enterprise service principal must be registered before Microsoft Sentinel can be granted permissions to trigger Azure Logic Apps.
• Open Cloud Shell: In the Azure Portal (https://azure.com), click the >_ (Cloud Shell) icon in the top blue navigation bar and select Bash.
• Skip Storage Mounting: When prompted for storage, select No storage account required, choose your subscription, and click Apply.
• Register Service Principal: Run the following Azure CLI command in the terminal:

```
bash
az ad sp create --id 58131f34-bef7-4935-999e-0c16b96a1de9
```

<img width="1918" height="953" alt="image" src="https://github.com/user-attachments/assets/18c3f87a-75e4-4c1f-9429-9a74de4b7a23" />

• Verify Output: Confirm JSON output returns showing "displayName": "Azure Security Insights", then close the Cloud Shell pane.

### Step 2: Generate a Google App Password for Authenticated SMTP

To avoid third-party OAuth blocks on personal @gmail.com accounts, you configured authenticated SMTP over TLS/SSL using a dedicated Google App Password.

• Enable 2-Step Verification: Navigate to https://google.com > 2-Step Verification and ensure it is turned On.

• Generate App Password: Search for App passwords in the top Google Account search bar, create a new app named Azure Sentinel, and copy the 16-character password generated by Google.

<img width="1896" height="895" alt="image" src="https://github.com/user-attachments/assets/5d6cb8d8-cd38-456a-beb5-31e367f3e7ef" />
<img width="1904" height="903" alt="image" src="https://github.com/user-attachments/assets/435963dd-2f66-4d07-84c7-e1867c2c1767" />

### Step 3: Deploy the Azure Logic App (Playbook-BruteForce-Email)

• Create Logic App: In the Azure Portal, search for Logic apps, click + Add / + Create, and select the serverless Consumption (Multi-tenant) plan.

<img width="1903" height="909" alt="Screenshot 2026-11-13 174014" src="https://github.com/user-attachments/assets/2c9e3393-ff9b-43d7-b24a-719cc7ccfac5" />

• Configure Basics:

	• Resource group: Select SOC-Lab-RG.
	• Logic app name: Type Playbook-BruteForce-Email.
	• Region: Select (UK) UK South (matching your Sentinel workspace).

<img width="1114" height="740" alt="Screenshot 2026-11-13 175352" src="https://github.com/user-attachments/assets/34faea14-da8d-40a8-ae97-129652088482" />

• Deploy: Click Review + create, then click Create, and click Go to resource once deployment finishes.

<img width="911" height="622" alt="Screenshot 2026-11-13 174927" src="https://github.com/user-attachments/assets/1fe70597-a8ae-48f2-9311-7d6076b2001d" />

<img width="1907" height="895" alt="Screenshot 2026-11-13 175709" src="https://github.com/user-attachments/assets/faf49585-3ca8-40e1-847a-67d2190d206d" />

### Step 4: Build & Publish the SOAR Workflow in Logic App Designer

• Open Designer: On the Playbook-BruteForce-Email page, click Edit (or Development Tools > Logic app designer).

• Configure Sentinel Trigger:

	• Click + Add trigger, search for Microsoft Sentinel, and select Microsoft Sentinel incident (When a response to an Azure Sentinel incident is triggered).
	
	• Sign in with your Azure account (josephatoyebi2020@gmail.com) to authorize the connection.

<img width="1909" height="895" alt="Screenshot 2026-11-13 180557" src="https://github.com/user-attachments/assets/a15ea8c9-f2f2-4f3b-94c9-d30690446fbf" />

• Configure Authenticated SMTP Action:

	• Click the + icon directly beneath the trigger > Add an action, search for SMTP, and select Send Email (V3).
	
	• Enter the SMTP connection details:
		
		• Connection Name: Gmail-SMTP-SOC
		
		• SMTP Server Address: ://gmail.com
		
		• User Name: josephatoyebi2020@gmail.com
		
		• Password: Paste your 16-character Google App Password
		
		• SMTP Server Port: 587
		
		• Enable SSL?: Checked (Yes)
	
	• Click Create new.

<img width="783" height="609" alt="Screenshot 2026-11-13 194037" src="https://github.com/user-attachments/assets/43f69b6a-c7eb-498e-9cd0-fae38e4dc30d" />

• Design Dynamic Alert Template:
	
	• Click Show all under Advanced parameters to reveal all email fields.
	
	• From & To: Enter josephatoyebi2020@gmail.com in both fields.
	
	• Subject: Type SOC ALERT:  and insert Incident Title from the Dynamic content (lightning bolt) menu.
	
	• Body: Paste your structured SOC alert template and insert dynamic telemetry tags (Incident Title, Incident Severity, Incident Status, Incident Description, and Incident URL).

	
```
Hello SOC Analyst,

A new security incident has been triggered in Microsoft Sentinel.

- Incident ID: [Insert Dynamic Content: Incident number]
- Title: [Insert Dynamic Content: Incident title]
- Severity: [Insert Dynamic Content: Incident severity]
- Status: [Insert Dynamic Content: Incident status]
- Description: [Insert Dynamic Content: Incident description]

Please log into the Microsoft Defender portal to investigate immediately.

```

<img width="583" height="538" alt="Screenshot 2026-11-13 210029" src="https://github.com/user-attachments/assets/e60efe42-fe9d-4ca5-9e6a-3efe32c96f8c" />

• Publish Playbook: Click the blue Publish button at the top right of the Logic App Designer to activate the workflow.

### Step 5: Link the Playbook via a Sentinel Automation Rule

• Open Sentinel Automation: Navigate to the Microsoft Defender portal (https://microsoft.com), expand Microsoft Sentinel > Configuration, and click Automation.

<img width="1877" height="896" alt="Screenshot 2026-11-13 210719" src="https://github.com/user-attachments/assets/35fd4c57-b45b-46eb-adc9-c7faff6a183b" />

• Create Automation Rule: Click + Create > Automation rule and configure:

	• Automation rule name: Auto-Email on Brute Force Incident
	
	• Trigger: When incident is created
	
	• Conditions: Incident provider Equals Microsoft Sentinel AND Analytics rule name Contains SOC Lab - Entra ID Brute Force Attempt
	
	• Actions: Select Run playbook.

• Grant Playbook Permissions: Click Manage playbook permissions, check SOC-Lab-RG, and click Apply.

• Attach & Activate: Select Playbook-BruteForce-Email from the playbook dropdown and click Apply at the bottom to save and enable the rule.

<img width="1133" height="812" alt="Screenshot 2026-11-13 224637" src="https://github.com/user-attachments/assets/001fabc2-20ff-4bce-8f0d-c7aa40aeef59" />


---

To investigate the brute-force attack in my lab (or in a real SOC environment), follow a structured Tier-1 / Tier-2 SOC Incident Triage Workflow. This proves I can go beyond just seeing an alert and determine scope, impact, and containment.

### Step 1: Triage & Enrich the Incident in Microsoft Defender

<img width="1878" height="882" alt="image" src="https://github.com/user-attachments/assets/e8db206a-4ed3-44c4-a2e1-f3087e8b100b" />

• Assign Ownership: Open your brute-force incident under Incidents (://microsoft.com), assign it to yourself (Assign to me), and change the status from New to In progress / Active.

• Inspect Mapped Entities: Open the Evidence / Entities tab to identify the core forensic indicators extracted by your analytics rule.
	
	• Target Account: test.victim@://onmicrosoft.com
	
	• Attacker Source IP: 102.88.115.140

<img width="1889" height="905" alt="image" src="https://github.com/user-attachments/assets/3e2384b1-ad82-43f4-8c5d-a62ed581ba6f" />

<img width="1918" height="907" alt="image" src="https://github.com/user-attachments/assets/a415bb2c-865b-42d8-9331-e9abe30f57c2" />


### Step 2: Check for Account Compromise (Did the Attacker Get In?)

The most critical question in any brute-force investigation is whether any login attempt succeeded (ResultType == "0").

• Open Logs / Advanced Hunting: Navigate to Microsoft Sentinel > Logs (or Advanced hunting in Defender) and run this KQL query:

<img width="1912" height="861" alt="image" src="https://github.com/user-attachments/assets/52310074-f033-4558-aae4-56c9073da7b2" />

```
SigninLogs
| where UserPrincipalName == "test.victim@://onmicrosoft.com"
| where TimeGenerated >= ago(24h)
| project TimeGenerated, ResultType, ResultDescription, IPAddress, Location, ClientAppUsed, UserAgent
| sort by TimeGenerated desc
```

• Analyze the Results:
	
	• Containment Confirmed (ResultType is only 50126 or 50053): The attack was completely blocked by password validation and Entra ID Smart Lockout.
	
	• Compromise Detected (ResultType == "0" from the attacker IP): The attacker guessed the password, requiring immediate password reset, session revocation, and MFA enforcement.



### Step 3: Document Findings & Close the Incident

Once you confirm zero successful logins and zero unauthorized directory changes, close out the ticket with clear forensic documentation.

• Set Status & Classification: Change Status to Resolved / Closed and select Benign positive > Security testing (in a real attack where logins failed, you would classify it as True positive > Credential access and block the IP via Conditional Access).

• Add Closing Notes: Record the attack timeframe, target account, source IP, total failed attempts, confirmation of zero ResultType == "0" events, and final disposition.

<img width="1879" height="916" alt="image" src="https://github.com/user-attachments/assets/5c18fbf1-0c2a-45b8-8a86-0da16ba1fc7c" />


### Result

* Email

<img width="1903" height="845" alt="image" src="https://github.com/user-attachments/assets/22b92448-27b6-4b92-bd0d-008b8941dd38" />

* Click on the link in the mail
<img width="1912" height="906" alt="image" src="https://github.com/user-attachments/assets/2106f129-fadf-48b3-844f-19c607ef9c4c" />




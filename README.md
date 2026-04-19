SOC Analyst Lab – Microsoft Sentinel

- Overview
This project demonstrates hands-on experience with Microsoft Sentinel, focusing on log ingestion, threat detection, and incident investigation using Kusto Query Language (KQL).

Custom logs were generated and ingested into a Log Analytics workspace to simulate real-world security events.

Objectives
- Ingest custom security logs into Microsoft Sentinel
- Detect suspicious activity using KQL
- Investigate simulated security incidents
- Build practical SOC analyst skills

Data Simulated
- Failed login attempts
- Admin privilege assignments
- Password changes
- Possible brute force attacks

Tools & Technologies
- Microsoft Sentinel
- Azure Log Analytics
- Kusto Query Language (KQL)
- Azure CLI

Example Query

```kql
MyLogs_CL
| where Severity == "High"
| sort by TimeGenerated desc
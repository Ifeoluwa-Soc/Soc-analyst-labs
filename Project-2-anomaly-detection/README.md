# Project 2: Log Anomaly Detection

## Objective
Identify abnormal patterns in login activity using time-based analysis.

---

## Step 1: Establish baseline activity

```kql
MyLogs_CL
| summarize TotalEvents = count()

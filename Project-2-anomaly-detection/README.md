# Project 2: Log Anomaly Detection

## Objective
Identify abnormal patterns in login activity using time-based analysis.

## Data Source
Custom logs ingested into Microsoft Sentinel


---


## Step 1: Establish baseline activity

```kql
MyLogs_CL
| summarize TotalEvents = count()
```
---
## Output
Shows total number of log events in the dataset
---

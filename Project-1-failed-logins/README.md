Project 1: Failed Login Detection 

Objective
Detect repeated failed login attempts indicating potential brute force attacks. 

Data Source
Custom logs ingested into Microsoft Sentinel (MyLogs_CL)
---

## Step 1: Identify failed logins
```kql
MyLogs_CL
| Where Message contains "failed"
| sort by TimeGenerated desc
```
## Output
The query returns all failed login attempts
![Step 1 Results](1stquery.png)
---

## Step 2: Analyze frequency
```kql
MyLogs_CL
| where Message contains "failed"
| summarize FailedAttempts = count() by Message, Severity
```
## Output
This query shows the frequency of failed login attempts.
![Step 2 Results](2ndquery.png)
---

## Step 3: Detect suspicious activity
```kql
MyLogs_CL
| where Message contains "failed"
| summarize FailedAttempts = count() by Message, Severity
| Where FailedAttempts >= 2
```
## Output
Multiple failed attempts are identified, indicating potential brute foirce activity.
![Step 3 Results](3rdquery.png)
---

## Step 4: Timeline Analysis
```kql
MyLogs_CL
| where Message contains "failed"
| summarize FailedAttempts = count() by bin(TimeGenerated, 5m)
```
## Output
Login attempts are grouped into 5-minute intervals to visualize attack pattern.
![Step 4 Results](4thquery.png)
---

## Step 5: Timeline Chart
```kql
MyLogs_CL
| where Message contains "failed"
| summarize FailedAttempts = count() by bin(TimeGenerated, 5m)
```
## Output
Login attempts are grouped into 5-minute intervals to visualize attack pattern as a chart
![Step 5 Timeline chart](timelinequery.png)
---

## Conclusion
Suspicious login activity detected. Recommend monitoring and alert creation 

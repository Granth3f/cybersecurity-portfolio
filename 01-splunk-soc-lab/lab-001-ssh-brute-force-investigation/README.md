# Lab 001 — SSH Brute-Force Investigation

## Overview
- **Tool:** Splunk Enterprise
- **Category:** SOC Analysis
- **Log Source:** SSH authentication logs
- **Index:** main
- **Sourcetype:** secure-2
- **Dataset:** Splunk tutorial sample data
- **Status:** Completed

## 1. Objective
Investigate suspicious SSH authentication activity using Splunk. Identify the source IP, targeted server, attempted usernames, frequency of failed logins, and potential evidence of successful access.

## 2. Investigation Findings

| Finding | Result |
|---|---|
| Source IP | 87.194.216.51 |
| Target server | mailsv1 |
| Failed attempts | 948 |
| Peak hourly count | 223 |
| root attempts | 41 |
| operator attempts | 30 |
| admin attempts | 27 |
| Matching successful logins | 0 found |

## 3. Splunk Queries

### Identify failed attempts by IP

```spl
index=main sourcetype=secure-2 "Failed password"
| rex field=_raw "from (?<src_ip>\d{1,3}(?:\.\d{1,3}){3})"
| stats count as failed_attempts by src_ip
| sort - failed_attempts
```

### Identify targeted usernames

```spl
index=main sourcetype=secure-2 "Failed password"
|

# SOC127 – SQL Injection Detected (Event ID 60)

## 1. Alert Overview

| Field | Details |
|---|---|
| Event ID | 60 |
| Alert Rule | SOC127 – SQL Injection Detected |
| Event Time | `2021-02-14 13:05:12 UTC+03:00` |
| Alert Type | Proxy |
| Username | `kali` |
| Source Host | `PentestMachine` |
| Source IP | `172.16.20.5` |
| Destination Host | `gitServer` |
| Destination IP | `172.16.20.4` |
| User-Agent | `Penetration Test - Do not Contain` |
| Device Action | **Allowed** |
| Final Verdict | **False Positive** |

## 2. Investigation Findings

The Proxy detected an HTTP GET request containing a SQL injection payload in the `id` parameter.

**SQL Injection Payload:**

```sql
?id=1 and (1,2,3,4) = (SELECT * from db.users UNION SELECT 1,2,3,4 LIMIT 1)
```

The payload uses `UNION SELECT` and references the `db.users` table, indicating SQL injection testing or an attempted injection.

Log Management recorded traffic from `172.16.20.5` to `172.16.20.4` over port `443`. The Proxy action was **Allowed**. This shows that the request was permitted, but does not establish whether the SQL query executed successfully.

![Log Management records](screenshots/log-management.png)

*Log Management connection details for the source and destination.*

![Raw Proxy Log](screenshots/raw-log.png)

*Raw log showing the GET request, SQL injection payload, and Allowed action.*

No suspicious activity was found in endpoint security logs. The `PentestMachine` hostname and `Penetration Test - Do not Contain` User-Agent suggest that this was penetration-testing activity.

## 3. Playbook Investigation

### 3.1. Analyze URL Address

**Result: Malicious**

The requested URL contains a SQL injection payload.

### 3.2. Has Anyone Accessed IP/URL/Domain?

**Result: Accessed**

The Proxy log shows that the request was allowed.

## 4. Final Assessment

**Verdict: False Positive**

The source hostname and User-Agent suggest legitimate penetration testing. No additional suspicious activity was identified in endpoint security logs.

# AWS CloudTrail Investigation – Splunk

## Lab Overview

This investigation analyzes AWS CloudTrail activity in Splunk to identify a compromised IAM identity, trace the attacker's access to S3 objects, investigate bucket security configuration activity, and identify persistence through IAM user and group changes.

**Tools:** Splunk Enterprise, AWS CloudTrail  
**Data source:** `aws_cloudtrail` index

## 1. Identifying the Compromised User

I started by exploring the available fields in the `aws_cloudtrail` index. The `eventSource` field showed activity from several AWS services, including `signin.amazonaws.com`.

I pivoted to failed authentication events and counted them by username:

```spl
index="aws_cloudtrail" eventSource="signin.amazonaws.com" errorMessage="Failed authentication"
| stats count by userIdentity.userName
| sort -count
```

The results showed that `helpdesk.luke` had the highest number of failed authentication events (10), making it the primary account of interest. The lab identifies this account as compromised.

**Finding:** `helpdesk.luke`

![Compromised user identified from failed sign-in activity](screenshots/comromised-user.png)

## 2. Finding the First S3 Object Access

After identifying the compromised identity, I pivoted to its S3 data-access activity. I focused on `GetObject` events, which record requests to retrieve objects from S3.

```spl
index="aws_cloudtrail"
"userIdentity.userName"="helpdesk.luke"
eventSource="s3.amazonaws.com"
eventName=GetObject
```

The search returned eight events. I inspected the event details and identified the earliest relevant object-access event:

- **Event name:** `GetObject`
- **Event source:** `s3.amazonaws.com`
- **Event time:** `2023-11-02T09:55:53Z`
- **Source IP:** `185.192.70.71`

The `eventTime` field is in UTC.

**Finding:** `2023-11-02 09:55:53 UTC`

![GetObject search results](screenshots/GetObject-filter.png)

![First S3 GetObject event details](screenshots/GetObject-event.png)

## 3. Identifying the Bucket Containing a DWG File

I narrowed the S3 object-access search to events involving DWG files:

```spl
index="aws_cloudtrail"
"userIdentity.userName"="helpdesk.luke"
eventSource="s3.amazonaws.com"
eventName=GetObject
"*.dwg"
```

The matching event's `requestParameters` revealed the bucket name and object key:

- **Bucket:** `product-designs-repository31183937`
- **Object:** `Product2_CAD_Designs.dwg`

This confirms that the compromised identity accessed a CAD design file stored in that bucket.

**Finding:** `product-designs-repository31183937`

![DWG object search](screenshots/Q3.png)

![Bucket name and object key in the CloudTrail event](screenshots/Q3-bucket_name.png)

## 4. Investigating the Bucket with Public-Access Configuration Activity

I explored CloudTrail's available `eventName` values to identify S3 bucket security-related activity. The `GetBucketPublicAccessBlock` event stood out because it relates to a bucket's public-access-block configuration.

I used this as a pivot to inspect the associated bucket and the relevant configuration activity in the lab evidence.

**Finding:** `backup-and-restore98825501`

![S3 public-access configuration investigation](screenshots/Q4.png)

> **Evidence qualification:** `GetBucketPublicAccessBlock` is a read operation that retrieves the configuration; it does not itself change the setting. A configuration change should be confirmed with a write event such as `PutPublicAccessBlock` or `DeletePublicAccessBlock`. The bucket above is the answer identified by the lab evidence.

## 5. Identifying the IAM User Created by the Attacker

Next, I investigated whether the compromised identity was used to create another IAM user, which could provide an additional means of access.

```spl
index="aws_cloudtrail"
"userIdentity.userName"="helpdesk.luke"
"CreateUser"
```

The search returned one event. Inspecting its `requestParameters` revealed the username supplied in the account-creation request:

- **Event name:** `CreateUser`
- **Event source:** `iam.amazonaws.com`
- **Created username:** `marketing.mark`

**Finding:** `marketing.mark`

![IAM CreateUser event and requested username](screenshots/Q5.png)

## 6. Identifying the Group Assigned to the New User

To investigate the next persistence-related action, I searched for user-to-group membership operations performed by the compromised account:

```spl
index="aws_cloudtrail"
"userIdentity.userName"="helpdesk.luke"
"*AddUser*"
```

The resulting `AddUserToGroup` event contained the following values in `requestParameters`:

- **groupName:** `Admins`
- **userName:** `marketing.mark`

This confirms that the newly created IAM user was added to the `Admins` group.

**Finding:** `Admins`

![AddUserToGroup event showing the user and group](screenshots/Q6.png)

## 7. Investigation Summary

The CloudTrail evidence shows suspicious activity involving the compromised `helpdesk.luke` identity. The account was associated with repeated failed sign-in attempts, subsequent S3 object access, activity involving bucket public-access configuration, and IAM identity changes.

The creation of `marketing.mark` followed by its addition to the `Admins` group is particularly significant because it may provide the attacker with another identity and elevated access.

### Key Findings

| Question | Finding |
|---|---|
| Compromised user | `helpdesk.luke` |
| Failed authentication count | 10 |
| First S3 object access (UTC) | `2023-11-02 09:55:53` |
| Source IP in the first observed S3 event | `185.192.70.71` |
| DWG object | `Product2_CAD_Designs.dwg` |
| Bucket containing the DWG file | `product-designs-repository31183937` |
| Bucket identified in the public-access configuration investigation | `backup-and-restore98825501` |
| IAM user created | `marketing.mark` |
| Group assigned to the new user | `Admins` |

## Conclusion

This investigation demonstrates how CloudTrail can be used to reconstruct suspicious AWS activity by pivoting across identity, service, and event fields. Starting with failed authentication attempts helped identify the account of interest. Filtering for S3 `GetObject` events exposed object-access activity, while IAM `CreateUser` and `AddUserToGroup` events revealed actions consistent with persistence and privilege expansion.

From a defensive perspective, the affected identity should be contained and investigated, the newly created IAM user and its group membership should be reviewed, and S3 bucket policies and public-access settings should be validated. Relevant CloudTrail events should also be preserved for further investigation.

> Findings are based on the CloudTrail records and lab evidence reviewed. The presence of an event indicates the recorded API activity; conclusions about successful data exposure or configuration changes should be validated against the corresponding event details and response evidence.

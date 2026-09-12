export interface CloudTelemetryEvent {
  id: string;
  sourceType: 'AWS_CLOUDTRAIL' | 'AWS_S3_ACCESS';
  eventSource: string;
  eventName: string;
  awsRegion: string;
  timestamp: string;
  sourceIPAddress: string;
  userAgent: string;
  user: string;
  userIdentityType: string;
  userArn: string;
  accountId: string;
  requestParameters?: any;
  responseElements?: any;
  errorCode?: string;
  errorMessage?: string;
  severity: 'Critical' | 'High' | 'Medium' | 'Low' | 'Info';
  mitreTechnique: string;
  mitreTactic: string;
  summary: string;
  raw: string;
}

/**
 * Determine MITRE ATT&CK Cloud Matrix technique and severity based on CloudTrail event properties
 */
export function classifyCloudTrailEvent(record: any): {
  severity: 'Critical' | 'High' | 'Medium' | 'Low' | 'Info';
  mitreTechnique: string;
  mitreTactic: string;
  summary: string;
} {
  const eventName = record.eventName || '';
  const eventSource = record.eventSource || '';
  const user = record.userIdentity?.userName || record.userIdentity?.arn || record.userIdentity?.principalId || 'Unknown-IAM-Principal';
  const srcIp = record.sourceIPAddress || 'unknown-ip';
  const hasError = Boolean(record.errorCode || record.errorMessage);

  // 1. Defense Evasion: Impair Defenses — Disabling or tampering with CloudTrail
  if (
    eventName === 'StopLogging' ||
    eventName === 'DeleteTrail' ||
    eventName === 'UpdateTrail' ||
    eventName === 'PutEventSelectors'
  ) {
    return {
      severity: 'Critical',
      mitreTechnique: 'T1562.001 (Disable or Modify Cloud Logs)',
      mitreTactic: 'Defense Evasion',
      summary: `[CRITICAL CLOUD EVENT] Adversary attempted to disable/tamper with AWS CloudTrail (${eventName}) via IAM user '${user}' from IP ${srcIp}.`,
    };
  }

  // 2. Persistence & Privilege Escalation: IAM Account Manipulation
  if (
    eventName === 'CreateAccessKey' ||
    eventName === 'AttachUserPolicy' ||
    eventName === 'AttachRolePolicy' ||
    eventName === 'PutUserPolicy' ||
    eventName === 'CreateLoginProfile' ||
    eventName === 'UpdateAssumeRolePolicy'
  ) {
    const target = record.requestParameters?.userName || record.requestParameters?.roleName || 'IAM entity';
    return {
      severity: 'High',
      mitreTechnique: 'T1098 (Account Manipulation)',
      mitreTactic: 'Persistence',
      summary: `High privilege IAM mutation '${eventName}' applied to '${target}' by ${user} from IP ${srcIp}.`,
    };
  }

  // 3. Initial Access / Defense Evasion: Console Login & Account Compromise
  if (eventName === 'ConsoleLogin') {
    const isMfaUsed = record.additionalEventData?.MFAUsed === 'Yes';
    if (hasError) {
      return {
        severity: 'High',
        mitreTechnique: 'T1078.004 (Cloud Accounts: Failed Login)',
        mitreTactic: 'Credential Access',
        summary: `AWS Management Console authentication failed for user '${user}' from IP ${srcIp} (${record.errorMessage || 'Invalid credentials'}).`,
      };
    }
    if (!isMfaUsed) {
      return {
        severity: 'High',
        mitreTechnique: 'T1078.004 (Cloud Accounts: No MFA)',
        mitreTactic: 'Initial Access',
        summary: `AWS Management Console login without MFA enforced for IAM user '${user}' from IP ${srcIp}.`,
      };
    }
    return {
      severity: 'Low',
      mitreTechnique: 'T1078.004 (Cloud Accounts)',
      mitreTactic: 'Initial Access',
      summary: `Standard AWS Management Console login for user '${user}' from IP ${srcIp} with MFA.`,
    };
  }

  // 4. Collection / Exfiltration: S3 Cloud Object Access & Exfiltration
  if (
    eventSource === 's3.amazonaws.com' ||
    eventName === 'GetObject' ||
    eventName === 'PutBucketPolicy' ||
    eventName === 'PutBucketAcl' ||
    eventName === 'DeleteBucketPolicy' ||
    eventName === 'ListBuckets'
  ) {
    const bucket = record.requestParameters?.bucketName || 'S3 Bucket';
    const key = record.requestParameters?.key || '';
    const policyStr = typeof record.requestParameters?.bucketPolicy === 'object'
      ? JSON.stringify(record.requestParameters.bucketPolicy)
      : String(record.requestParameters?.bucketPolicy || '');
    const isPublicPolicy =
      /["']Principal["']\s*:\s*["']\*["']/i.test(policyStr) ||
      eventName === 'DeleteBucketPolicy';

    if (isPublicPolicy) {
      return {
        severity: 'Critical',
        mitreTechnique: 'T1530 (Data from Cloud Storage: Public Bucket Exposure)',
        mitreTactic: 'Exfiltration',
        summary: `S3 Bucket '${bucket}' policy modified to permit public or unauthenticated access by ${user}.`,
      };
    }

    if (eventName === 'GetObject') {
      return {
        severity: 'Medium',
        mitreTechnique: 'T1530 (Data from Cloud Storage Object)',
        mitreTactic: 'Collection',
        summary: `S3 GetObject retrieved object '${key}' from bucket '${bucket}' by ${user} from IP ${srcIp}.`,
      };
    }

    return {
      severity: 'Medium',
      mitreTechnique: 'T1530 (Data from Cloud Storage Object)',
      mitreTactic: 'Discovery',
      summary: `S3 storage operation '${eventName}' performed on bucket '${bucket}' by ${user}.`,
    };
  }

  // 5. Lateral Movement & Infrastructure Modification: Security Groups & VPC
  if (
    eventName === 'AuthorizeSecurityGroupIngress' ||
    eventName === 'AuthorizeSecurityGroupEgress' ||
    eventName === 'ModifySecurityGroupRules'
  ) {
    const ipPermissions = record.requestParameters?.ipPermissions?.items || [];
    const isOpenToWorld = JSON.stringify(ipPermissions).includes('0.0.0.0/0');

    if (isOpenToWorld) {
      return {
        severity: 'High',
        mitreTechnique: 'T1578.002 (Modify Cloud Compute Infrastructure: Open Ingress)',
        mitreTactic: 'Defense Evasion',
        summary: `AWS Security Group ingress rule opened to 0.0.0.0/0 (all internet) by user '${user}' from IP ${srcIp}.`,
      };
    }

    return {
      severity: 'Medium',
      mitreTechnique: 'T1578.002 (Modify Cloud Compute Infrastructure)',
      mitreTactic: 'Defense Evasion',
      summary: `AWS Security Group ingress/egress modification (${eventName}) executed by ${user}.`,
    };
  }

  // Default fallback for general CloudTrail API call
  return {
    severity: hasError ? 'Medium' : 'Info',
    mitreTechnique: 'T1078.004 (Cloud Accounts)',
    mitreTactic: 'Initial Access',
    summary: `CloudTrail API call ${eventSource}:${eventName} invoked by ${user} from ${srcIp}${hasError ? ` (Error: ${record.errorCode})` : ''}.`,
  };
}

/**
 * Parses AWS S3 Server Access Log format
 * Reference: https://docs.aws.amazon.com/AmazonS3/latest/userguide/LogFormat.html
 */
export function parseS3ServerAccessLog(logLine: string, index: number): CloudTelemetryEvent | null {
  const line = logLine.trim();
  if (!line || line.startsWith('#')) return null;

  // Pattern: [bucket-owner] bucket [time] remote-ip requester request-id operation key "request-uri" http-status ...
  const regex = /^\S+\s+(\S+)\s+\[([^\]]+)\]\s+(\S+)\s+\S+\s+\S+\s+(\S+)\s+(\S+)?\s+"([^"]+)"\s+(\d{3})\s+(\S+)\s+(\S+)/;
  const match = line.match(regex);

  if (!match) return null;

  const [, bucket, rawTime, remoteIp, operation, key, requestUri, httpStatus, errorCode, bytesSent] = match;
  const isDenied = httpStatus === '403';
  const isGetObject = operation === 'REST.GET.OBJECT' || requestUri.startsWith('GET');

  return {
    id: `S3-ACCESS-${Date.now()}-${index}`,
    sourceType: 'AWS_S3_ACCESS',
    eventSource: 's3.amazonaws.com',
    eventName: operation,
    awsRegion: 'us-east-1',
    timestamp: new Date(rawTime.replace(':', ' ')).toISOString() || new Date().toISOString(),
    sourceIPAddress: remoteIp,
    userAgent: 'S3-HTTP-Client',
    user: 'S3Requester',
    userIdentityType: 'AWSServiceOrAnonymous',
    userArn: `arn:aws:s3:::${bucket}`,
    accountId: 'AWS-S3-Bucket',
    requestParameters: { bucketName: bucket, key, requestUri, bytesSent },
    errorCode: errorCode !== '-' ? errorCode : undefined,
    severity: isDenied ? 'High' : isGetObject ? 'Medium' : 'Info',
    mitreTechnique: isDenied ? 'T1078.004 (Cloud Accounts: S3 403 Forbidden)' : 'T1530 (Data from Cloud Storage Object)',
    mitreTactic: isDenied ? 'Credential Access' : 'Collection',
    summary: `S3 Access Log: ${operation} on '${bucket}/${key || ''}' returned HTTP ${httpStatus} to IP ${remoteIp}`,
    raw: line,
  };
}

/**
 * Master parser for CloudTrail JSON, S3 Access Logs, or mixed cloud streams
 */
export function parseCloudTrailTelemetry(rawInput: string | object): CloudTelemetryEvent[] {
  const events: CloudTelemetryEvent[] = [];

  if (typeof rawInput === 'object' && rawInput !== null) {
    const rawObj = rawInput as any;
    const records = Array.isArray(rawObj.Records) ? rawObj.Records : [rawObj];
    records.forEach((rec: any, idx: number) => {
      const classification = classifyCloudTrailEvent(rec);
      events.push({
        id: `CLOUDTRAIL-${rec.eventID || Date.now() + '-' + idx}`,
        sourceType: 'AWS_CLOUDTRAIL',
        eventSource: rec.eventSource || 'aws.cloudtrail',
        eventName: rec.eventName || 'UnknownEvent',
        awsRegion: rec.awsRegion || 'us-east-1',
        timestamp: rec.eventTime || new Date().toISOString(),
        sourceIPAddress: rec.sourceIPAddress || '127.0.0.1',
        userAgent: rec.userAgent || 'aws-sdk',
        user: rec.userIdentity?.userName || rec.userIdentity?.arn || rec.userIdentity?.principalId || 'Unknown-User',
        userIdentityType: rec.userIdentity?.type || 'IAMUser',
        userArn: rec.userIdentity?.arn || 'N/A',
        accountId: rec.recipientAccountId || rec.userIdentity?.accountId || 'unknown-account',
        requestParameters: rec.requestParameters,
        responseElements: rec.responseElements,
        errorCode: rec.errorCode,
        errorMessage: rec.errorMessage,
        severity: classification.severity,
        mitreTechnique: classification.mitreTechnique,
        mitreTactic: classification.mitreTactic,
        summary: classification.summary,
        raw: typeof rec === 'string' ? rec : JSON.stringify(rec),
      });
    });
    return events;
  }

  const rawText = String(rawInput).trim();
  if (!rawText) return [];

  // Try parsing as single JSON or { "Records": [...] }
  try {
    const parsed = JSON.parse(rawText);
    return parseCloudTrailTelemetry(parsed);
  } catch {
    // If not a single valid JSON block, check line-by-line (e.g. JSON lines or S3 access logs)
    const lines = rawText.split('\n').map((l) => l.trim()).filter(Boolean);

    lines.forEach((line, idx) => {
      if (line.startsWith('{') && line.endsWith('}')) {
        try {
          const rec = JSON.parse(line);
          const classification = classifyCloudTrailEvent(rec);
          events.push({
            id: `CLOUDTRAIL-LINE-${Date.now()}-${idx}`,
            sourceType: 'AWS_CLOUDTRAIL',
            eventSource: rec.eventSource || 'aws.cloudtrail',
            eventName: rec.eventName || 'UnknownEvent',
            awsRegion: rec.awsRegion || 'us-east-1',
            timestamp: rec.eventTime || new Date().toISOString(),
            sourceIPAddress: rec.sourceIPAddress || '127.0.0.1',
            userAgent: rec.userAgent || 'aws-sdk',
            user: rec.userIdentity?.userName || rec.userIdentity?.arn || 'Unknown-User',
            userIdentityType: rec.userIdentity?.type || 'IAMUser',
            userArn: rec.userIdentity?.arn || 'N/A',
            accountId: rec.recipientAccountId || 'unknown-account',
            requestParameters: rec.requestParameters,
            responseElements: rec.responseElements,
            errorCode: rec.errorCode,
            errorMessage: rec.errorMessage,
            severity: classification.severity,
            mitreTechnique: classification.mitreTechnique,
            mitreTactic: classification.mitreTactic,
            summary: classification.summary,
            raw: line,
          });
          return;
        } catch {
          // Ignore JSON parse error, try S3 log regex
        }
      }

      // S3 Server Access Log check
      const s3Event = parseS3ServerAccessLog(line, idx);
      if (s3Event) {
        events.push(s3Event);
      }
    });
  }

  return events;
}

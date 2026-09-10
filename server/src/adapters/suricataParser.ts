export interface SuricataEveAlert {
  id: string;
  timestamp: string;
  eventType: string;
  srcIp: string;
  srcPort: number;
  destIp: string;
  destPort: number;
  proto: string;
  signature?: string;
  severity?: number;
  category?: string;
  mitreTechnique?: string;
  raw: any;
}

export function parseSuricataEveJson(rawContent: string): SuricataEveAlert[] {
  const alerts: SuricataEveAlert[] = [];
  const lines = rawContent.split('\n').filter(l => l.trim().length > 0);

  lines.forEach((line, idx) => {
    try {
      const obj = JSON.parse(line);
      const eventType = obj.event_type || 'alert';
      
      let signature = obj.alert?.signature || obj.dns?.type || obj.http?.url || 'Network Traffic Flow';
      let category = obj.alert?.category || 'Network Anomaly';
      let severity = obj.alert?.severity || 3;
      let mitre = 'T1071.001 (Application Layer Protocol)';

      if (category.toLowerCase().includes('trojan') || category.toLowerCase().includes('malware')) {
        mitre = 'T1071.001 (Command and Control Web Protocols)';
      } else if (category.toLowerCase().includes('attempted-admin') || category.toLowerCase().includes('brute')) {
        mitre = 'T1110.001 (Password Guessing)';
      } else if (category.toLowerCase().includes('exploit')) {
        mitre = 'T1190 (Exploit Public-Facing Application)';
      }

      alerts.push({
        id: `EVE-${idx + 1}`,
        timestamp: obj.timestamp || new Date().toISOString(),
        eventType,
        srcIp: obj.src_ip || 'Unknown',
        srcPort: obj.src_port || 0,
        destIp: obj.dest_ip || 'Unknown',
        destPort: obj.dest_port || 0,
        proto: obj.proto || 'TCP',
        signature,
        severity,
        category,
        mitreTechnique: mitre,
        raw: obj
      });
    } catch (e) {
      // Ignore non-json lines
    }
  });

  return alerts;
}

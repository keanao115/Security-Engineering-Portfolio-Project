export interface NmapScanResult {
  host: string;
  os: string;
  openPorts: Array<{
    port: number;
    protocol: string;
    state: string;
    service: string;
    vulns: string;
    rtt?: string;
  }>;
  allResults?: Array<{
    port: number;
    protocol: string;
    state: string;
    service: string;
    vulns: string;
  }>;
}

export function parseNmapTelemetry(rawContent: string): NmapScanResult {
  const openPorts: NmapScanResult['openPorts'] = [];
  let host = "Target Host";
  let os = "Unknown OS / Mixed Telemetry";

  if (rawContent.includes('<nmaprun')) {
    // Basic XML extraction via regex / string matching for high performance
    const hostMatch = rawContent.match(/<address\s+addr="([^"]+)"/);
    if (hostMatch) host = hostMatch[1];

    const osMatch = rawContent.match(/<osmatch\s+name="([^"]+)"/);
    if (osMatch) os = osMatch[1];

    const portBlockRegex = /<port\s+protocol="([^"]+)"\s+portid="([^"]+)">([\s\S]*?)<\/port>/g;
    let match: RegExpExecArray | null;

    while ((match = portBlockRegex.exec(rawContent)) !== null) {
      const proto = match[1];
      const portId = parseInt(match[2]);
      const blockBody = match[3];

      const stateMatch = blockBody.match(/<state\s+state="([^"]+)"/);
      const state = stateMatch ? stateMatch[1] : 'open';

      const serviceMatch = blockBody.match(/<service\s+name="([^"]+)"(?:[\s\S]*?product="([^"]+)")?(?:[\s\S]*?version="([^"]+)")?/);
      const serviceName = serviceMatch ? (serviceMatch[1] || 'unknown') : 'unknown';
      const product = serviceMatch ? (serviceMatch[2] || '') : '';
      const version = serviceMatch ? (serviceMatch[3] || '') : '';
      const serviceDesc = `${serviceName} ${product} ${version}`.trim();

      // Truthful script output extraction from Nmap NSE scripts
      const scriptMatch = blockBody.match(/<script\s+id="([^"]+)"\s+output="([^"]+)"/);
      let vulns = 'Active TCP Service Listener';
      if (scriptMatch) {
        const scriptId = scriptMatch[1];
        const scriptOutput = scriptMatch[2];
        vulns = `NSE [${scriptId}]: ${scriptOutput.slice(0, 100)}`;
      } else if (portId === 80) {
        vulns = 'Cleartext HTTP Protocol';
      }

      openPorts.push({
        port: portId,
        protocol: proto,
        state: state,
        service: serviceDesc,
        vulns: vulns
      });
    }
  } else {
    // Line-by-line standard output parser
    const lines = rawContent.split('\n');
    lines.forEach((line) => {
      if (line.includes('/tcp') || line.includes('/udp')) {
        const parts = line.split(/\s+/).filter(Boolean);
        const [portProto, state] = parts;
        if (portProto && state) {
          const [pNum, proto] = portProto.split('/');
          const serviceName = parts.slice(2).join(' ') || 'Unknown Service';
          openPorts.push({
            port: parseInt(pNum),
            protocol: proto || 'tcp',
            state: state,
            service: serviceName,
            vulns: line.includes('VULNERABLE') ? 'Flagged Vulnerable Service' : 'Active Listener'
          });
        }
      }
    });
  }

  return {
    host,
    os,
    openPorts
  };
}

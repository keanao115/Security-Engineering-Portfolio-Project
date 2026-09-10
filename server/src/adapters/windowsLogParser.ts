export interface WindowsEventTelemetry {
  id: string;
  sourceType: string;
  eventId: string;
  computer: string;
  timestamp: string;
  user: string;
  ip: string;
  process: string;
  commandLine: string;
  details: string;
  raw: string;
}

export function parseWindowsLogTelemetry(rawText: string): WindowsEventTelemetry[] {
  const events: WindowsEventTelemetry[] = [];

  if (rawText.includes('<Event') || rawText.includes('<Events')) {
    // Regex parsing for XML nodes
    const eventBlocks = rawText.split('</Event>');
    eventBlocks.forEach((block, idx) => {
      if (!block.includes('<Event')) return;

      const eventIdMatch = block.match(/<EventID>(\d+)<\/EventID>/);
      const computerMatch = block.match(/<Computer>([^<]+)<\/Computer>/);
      const timeMatch = block.match(/SystemTime="([^"]+)"/);

      const eventId = eventIdMatch ? eventIdMatch[1] : 'Unknown';
      const computer = computerMatch ? computerMatch[1] : 'Unknown-Host';
      const timestamp = timeMatch ? timeMatch[1] : new Date().toISOString();

      let user = 'N/A';
      let ip = 'N/A';
      let process = 'N/A';
      let commandLine = 'N/A';
      let details = `Windows Event ID ${eventId} recorded on host ${computer}`;

      const userMatch = block.match(/Name="(TargetUserName|SubjectUserName)">([^<]+)<\/Data>/);
      if (userMatch) user = userMatch[2];

      const ipMatch = block.match(/Name="IpAddress">([^<]+)<\/Data>/);
      if (ipMatch) ip = ipMatch[1];

      const procMatch = block.match(/Name="(NewProcessName|ProcessName)">([^<]+)<\/Data>/);
      if (procMatch) process = procMatch[2];

      const cmdMatch = block.match(/Name="CommandLine">([^<]+)<\/Data>/);
      if (cmdMatch) commandLine = cmdMatch[1];

      const reasonMatch = block.match(/Name="FailureReason">([^<]+)<\/Data>/);
      if (reasonMatch) details = reasonMatch[1];

      events.push({
        id: `WIN-LOG-${idx + 1}`,
        sourceType: 'Windows Event Log',
        eventId,
        computer,
        timestamp,
        user,
        ip,
        process,
        commandLine,
        details,
        raw: block + '</Event>'
      });
    });
  } else {
    // TXT parser
    const lines = rawText.split('\n').filter(l => l.trim().length > 0);
    lines.forEach((line, idx) => {
      let eventId = 'Unknown';
      if (line.includes('4625')) eventId = '4625';
      else if (line.includes('4688') || line.includes('powershell')) eventId = '4688';
      else if (line.includes('4720')) eventId = '4720';
      else if (line.includes('1102')) eventId = '1102';

      const hostMatch = line.match(/(?:host|computer):\s*([a-zA-Z0-9_.-]+)/i);
      const userMatch = line.match(/(?:user|username):\s*([a-zA-Z0-9_.-]+)/i);
      const ipMatch = line.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/);

      events.push({
        id: `WIN-TXT-${idx + 1}`,
        sourceType: 'Windows Event Log (TXT)',
        eventId,
        computer: hostMatch ? hostMatch[1] : 'Unknown-Host',
        timestamp: new Date().toISOString(),
        user: userMatch ? userMatch[1] : 'N/A',
        ip: ipMatch ? ipMatch[0] : 'N/A',
        process: line.includes('powershell') ? 'powershell.exe' : 'N/A',
        commandLine: line,
        details: line,
        raw: line
      });
    });
  }

  return events;
}

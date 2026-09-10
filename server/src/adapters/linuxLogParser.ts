export interface LinuxLogTelemetry {
  id: string;
  sourceType: string;
  timestamp: string;
  action: string;
  ip: string;
  user: string;
  message: string;
  raw: string;
}

export function parseLinuxLogTelemetry(rawText: string): LinuxLogTelemetry[] {
  const logs: LinuxLogTelemetry[] = [];
  const lines = rawText.split('\n').filter(l => l.trim().length > 0);

  lines.forEach((line, idx) => {
    let action = 'INFO';
    if (line.includes('Failed password')) action = 'SSH_FAILED_LOGIN';
    if (line.includes('Accepted password')) action = 'SSH_SUCCESS_LOGIN';
    if (line.includes('sudo')) action = 'SUDO_PRIV_ESC';
    if (line.includes('Out of memory') || line.includes('Kill process')) action = 'OOM_MINER';

    const ipMatch = line.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/);
    const userMatch = line.match(/for (invalid user )?([a-zA-Z0-9_-]+)/);

    logs.push({
      id: `LNX-${idx + 1}`,
      sourceType: 'Linux Syslog / Auth',
      timestamp: line.substring(0, 15) || new Date().toISOString(),
      action,
      ip: ipMatch ? ipMatch[0] : 'N/A',
      user: userMatch ? userMatch[2] : 'N/A',
      message: line,
      raw: line
    });
  });

  return logs;
}

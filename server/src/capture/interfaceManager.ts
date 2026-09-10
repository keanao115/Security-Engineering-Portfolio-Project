import os from 'os';

export interface NetworkInterfaceInfo {
  id: string;
  name: string;
  description: string;
  ipAddresses: { ipv4?: string; ipv6?: string };
  macAddress: string;
  isLoopback: boolean;
  isUp: boolean;
  promiscuousSupported: boolean;
  mtu: number;
  speedMbps: number;
}

export class InterfaceManager {
  public static getInterfaces(): NetworkInterfaceInfo[] {
    const interfaces = os.networkInterfaces();
    const result: NetworkInterfaceInfo[] = [];
    let counter = 1;

    for (const [name, netInterface] of Object.entries(interfaces)) {
      if (!netInterface) continue;

      let ipv4 = '';
      let ipv6 = '';
      let mac = '';

      for (const info of netInterface) {
        if (info.family === 'IPv4' && !ipv4) ipv4 = info.address;
        if (info.family === 'IPv6' && !ipv6) ipv6 = info.address;
        if (info.mac && info.mac !== '00:00:00:00:00:00') mac = info.mac;
      }

      const isLoopback = name.toLowerCase().includes('loopback') || ipv4 === '127.0.0.1';

      result.push({
        id: `iface-${counter++}`,
        name,
        description: `${os.platform() === 'win32' ? 'Npcap / Windows' : 'libpcap / Unix'} Adapter (${name})`,
        ipAddresses: { ipv4: ipv4 || undefined, ipv6: ipv6 || undefined },
        macAddress: mac || (isLoopback ? '00:00:00:00:00:00' : 'Unavailable'),
        isLoopback,
        isUp: true,
        promiscuousSupported: !isLoopback,
        mtu: isLoopback ? 65536 : 1500,
        speedMbps: isLoopback ? 10000 : 1000,
      });
    }

    return result;
  }

  public static getInterfaceById(id: string): NetworkInterfaceInfo | undefined {
    return this.getInterfaces().find((i) => i.id === id || i.name === id);
  }
}

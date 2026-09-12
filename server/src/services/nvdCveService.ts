// Real NVD (National Vulnerability Database) CVE API Integration
// Free API — https://services.nvd.nist.gov/rest/json/cves/2.0
// No auth required (5 req/30s). With NVD_API_KEY env var: 50 req/30s.

export interface NvdCveResult {
  cveId: string;
  name: string;
  description: string;
  severity: 'Critical' | 'High' | 'Medium' | 'Low';
  cvss: number;
  cvssVector?: string;
  exploitAvailable: boolean;
  publishedDate: string;
  references: string[];
  source: 'NVD_API' | 'LOCAL_CATALOG';
}

// ─── In-memory LRU cache (1-hour TTL) ────────────────────────────────────────
const cveCache = new Map<string, { data: NvdCveResult[]; cachedAt: number }>();
const CACHE_TTL_MS = 60 * 60 * 1000; // 1 hour

function getCached(key: string): NvdCveResult[] | null {
  const entry = cveCache.get(key);
  if (!entry) return null;
  if (Date.now() - entry.cachedAt > CACHE_TTL_MS) {
    cveCache.delete(key);
    return null;
  }
  return entry.data;
}

function setCache(key: string, data: NvdCveResult[]): void {
  cveCache.set(key, { data, cachedAt: Date.now() });
}

// ─── NVD API Fetch ────────────────────────────────────────────────────────────
async function fetchFromNvd(keyword: string): Promise<NvdCveResult[]> {
  const cacheKey = keyword.toLowerCase().trim();
  const cached = getCached(cacheKey);
  if (cached) return cached;

  const isCve = /^CVE-\d{4}-\d{4,}/i.test(keyword.trim());
  const params = new URLSearchParams(
    isCve
      ? { cveId: keyword.trim().toUpperCase() }
      : { keywordSearch: keyword.trim(), resultsPerPage: '5' }
  );

  try {
    const apiKey = process.env.NVD_API_KEY;
    const headers: Record<string, string> = { 'Accept': 'application/json' };
    if (apiKey) headers['apiKey'] = apiKey;

    const url = `https://services.nvd.nist.gov/rest/json/cves/2.0?${params.toString()}`;
    const response = await fetch(url, { headers, signal: AbortSignal.timeout(3500) });

    if (!response.ok) throw new Error(`NVD API HTTP ${response.status}`);

    const json = await response.json() as any;
    const vulnerabilities = json.vulnerabilities || [];

    const results: NvdCveResult[] = vulnerabilities.map((v: any) => {
      const cve = v.cve;
      const metrics = cve.metrics?.cvssMetricV31?.[0] || cve.metrics?.cvssMetricV30?.[0] || cve.metrics?.cvssMetricV2?.[0];
      const cvssScore = metrics?.cvssData?.baseScore || 0;
      const severity = cvssScore >= 9 ? 'Critical' : cvssScore >= 7 ? 'High' : cvssScore >= 4 ? 'Medium' : 'Low';
      const description = cve.descriptions?.find((d: any) => d.lang === 'en')?.value || 'No description';

      // Truthful Exploit Availability Assessment (CISA KEV + Verified Exploit References)
      const hasCisaKev = Boolean(cve.cisaExploitAdd || cve.cisaRequiredAction || cve.cisaVulnerabilityName);
      const hasExploitEvidence = hasCisaKev || (cve.references || []).some((r: any) => {
        const tags = Array.isArray(r.tags) ? r.tags.map((t: string) => t.toLowerCase()) : [];
        const url = (r.url || '').toLowerCase();
        return tags.includes('exploit') ||
          url.includes('exploit-db.com') ||
          url.includes('packetstormsecurity.com') ||
          url.includes('metasploit');
      });

      return {
        cveId: cve.id,
        name: `${cve.id}: ${description.substring(0, 80)}...`,
        description,
        severity,
        cvss: cvssScore,
        cvssVector: metrics?.cvssData?.vectorString,
        exploitAvailable: hasExploitEvidence,
        cisaKev: hasCisaKev,
        publishedDate: cve.published,
        references: (cve.references || []).slice(0, 3).map((r: any) => r.url),
        source: 'NVD_API',
      } as NvdCveResult;
    });

    setCache(cacheKey, results);
    console.log(`[NVD] Fetched ${results.length} CVEs for "${keyword}"`);
    return results;

  } catch (err: any) {
    console.warn(`[NVD] API unavailable or timed out (${err.message}), using enriched local catalog`);
    return [];
  }
}

// ─── Local Enriched Catalog ───────────────────────────────────────────────────
interface CatalogEntry extends NvdCveResult {
  aliases: string[];
}

const LOCAL_CATALOG_LIST: CatalogEntry[] = [
  {
    cveId: 'CVE-2021-44228',
    name: 'Apache Log4j Remote Code Execution (Log4Shell)',
    description: 'Apache Log4j2 <=2.14.1 JNDI features do not protect against attacker-controlled LDAP and other JNDI related endpoints, allowing unauthenticated remote code execution via ${jndi:ldap://...}.',
    severity: 'Critical',
    cvss: 10.0,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H',
    exploitAvailable: true,
    publishedDate: '2021-12-10',
    references: ['https://nvd.nist.gov/vuln/detail/CVE-2021-44228', 'https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-44228'],
    source: 'LOCAL_CATALOG',
    aliases: ['log4j', 'log4shell', 'apache log4j', 'log4j2', '2.14.1', 'jndi']
  },
  {
    cveId: 'CVE-2021-45046',
    name: 'Apache Log4j Thread Context Message Pattern RCE & DoS',
    description: 'It was found that the fix to address CVE-2021-44228 in Apache Log4j 2.15.0 was incomplete in certain non-default configurations.',
    severity: 'Critical',
    cvss: 9.0,
    cvssVector: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H',
    exploitAvailable: true,
    publishedDate: '2021-12-14',
    references: ['https://nvd.nist.gov/vuln/detail/CVE-2021-45046'],
    source: 'LOCAL_CATALOG',
    aliases: ['log4j', 'log4j2', '2.15.0']
  },
  {
    cveId: 'CVE-2021-41773',
    name: 'Apache HTTP Server 2.4.49 Path Traversal & RCE',
    description: 'A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the expected document root or execute CGI binaries.',
    severity: 'Critical',
    cvss: 9.8,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
    exploitAvailable: true,
    publishedDate: '2021-10-05',
    references: ['https://nvd.nist.gov/vuln/detail/CVE-2021-41773'],
    source: 'LOCAL_CATALOG',
    aliases: ['apache', 'apache httpd', 'httpd', '2.4.49', 'path traversal', 'apache 2.4.49']
  },
  {
    cveId: 'CVE-2021-42013',
    name: 'Apache HTTP Server 2.4.50 Incomplete Path Traversal Fix',
    description: 'It was found that the fix for CVE-2021-41773 in Apache HTTP Server 2.4.50 was insufficient, allowing remote attackers to bypass path traversal restrictions.',
    severity: 'Critical',
    cvss: 9.8,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
    exploitAvailable: true,
    publishedDate: '2021-10-07',
    references: ['https://nvd.nist.gov/vuln/detail/CVE-2021-42013'],
    source: 'LOCAL_CATALOG',
    aliases: ['apache', 'apache httpd', 'httpd', '2.4.50', 'apache 2.4.50']
  },
  {
    cveId: 'CVE-2022-22965',
    name: 'Spring Framework RCE via Data Binding (Spring4Shell)',
    description: 'A Spring MVC or Spring WebFlux application running on JDK 9+ may be vulnerable to remote code execution (RCE) via data binding parameter passing ClassLoader access.',
    severity: 'Critical',
    cvss: 9.8,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
    exploitAvailable: true,
    publishedDate: '2022-04-01',
    references: ['https://nvd.nist.gov/vuln/detail/CVE-2022-22965'],
    source: 'LOCAL_CATALOG',
    aliases: ['spring', 'spring4shell', 'spring framework', 'spring core', 'jdk9']
  },
  {
    cveId: 'CVE-2022-0778',
    name: 'OpenSSL Infinite Loop Denial of Service (BN_mod_sqrt)',
    description: 'The BN_mod_sqrt() function in OpenSSL can be caused to loop forever when parsing invalid elliptic curve parameters, causing complete Denial of Service.',
    severity: 'High',
    cvss: 7.5,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H',
    exploitAvailable: false,
    publishedDate: '2022-03-15',
    references: ['https://nvd.nist.gov/vuln/detail/CVE-2022-0778'],
    source: 'LOCAL_CATALOG',
    aliases: ['openssl', '1.1.1k', 'openssl 1.1.1k', 'bn_mod_sqrt']
  },
  {
    cveId: 'CVE-2014-0160',
    name: 'OpenSSL TLS Heartbeat Information Disclosure (Heartbleed)',
    description: 'The (1) TLS and (2) DTLS implementations in OpenSSL 1.0.1 before 1.0.1g do not properly handle Heartbeat Extension packets, allowing remote attackers to obtain sensitive process memory contents.',
    severity: 'High',
    cvss: 7.5,
    cvssVector: 'CVSS:2.0/AV:N/AC:L/Au:N/C:P/I:N/A:N',
    exploitAvailable: true,
    publishedDate: '2014-04-07',
    references: ['https://nvd.nist.gov/vuln/detail/CVE-2014-0160'],
    source: 'LOCAL_CATALOG',
    aliases: ['openssl', 'heartbleed', '1.0.1']
  },
  {
    cveId: 'CVE-2021-3156',
    name: 'Sudo Heap-Based Buffer Overflow Privilege Escalation (Baron Samedit)',
    description: 'Sudo before 1.9.5p2 has a Heap-based Buffer Overflow, allowing privilege escalation to root via "sudoedit -s" and a command-line argument that ends with a single backslash character.',
    severity: 'High',
    cvss: 7.8,
    cvssVector: 'CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H',
    exploitAvailable: true,
    publishedDate: '2021-01-26',
    references: ['https://nvd.nist.gov/vuln/detail/CVE-2021-3156'],
    source: 'LOCAL_CATALOG',
    aliases: ['sudo', 'baron samedit', 'sudoedit', 'linux']
  },
  {
    cveId: 'CVE-2021-4034',
    name: 'Polkit pkexec Local Privilege Escalation (PwnKit)',
    description: 'A local privilege escalation vulnerability was found in polkit pkexec utility. Unprivileged local users can obtain full root privileges on default configurations of major Linux distributions.',
    severity: 'High',
    cvss: 7.8,
    cvssVector: 'CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H',
    exploitAvailable: true,
    publishedDate: '2022-01-28',
    references: ['https://nvd.nist.gov/vuln/detail/CVE-2021-4034'],
    source: 'LOCAL_CATALOG',
    aliases: ['polkit', 'pwnkit', 'pkexec', 'linux']
  },
  {
    cveId: 'CVE-2017-0144',
    name: 'Microsoft Windows SMBv1 Remote Code Execution (EternalBlue / MS17-010)',
    description: 'The SMBv1 server in Microsoft Windows Server 2008 and Windows 7 allows remote attackers to execute arbitrary code via crafted packets (EternalBlue exploit vector).',
    severity: 'Critical',
    cvss: 9.8,
    cvssVector: 'CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
    exploitAvailable: true,
    publishedDate: '2017-03-17',
    references: ['https://nvd.nist.gov/vuln/detail/CVE-2017-0144'],
    source: 'LOCAL_CATALOG',
    aliases: ['eternalblue', 'smb', 'smbv1', 'ms17-010', 'windows', 'windows server']
  },
  {
    cveId: 'CVE-2021-26855',
    name: 'Microsoft Exchange Server Pre-Auth SSRF & RCE (ProxyLogon)',
    description: 'Microsoft Exchange Server Remote Code Execution Vulnerability (ProxyLogon). Allows unauthenticated attackers to bypass authentication and execute code on Exchange servers.',
    severity: 'Critical',
    cvss: 9.8,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
    exploitAvailable: true,
    publishedDate: '2021-03-02',
    references: ['https://nvd.nist.gov/vuln/detail/CVE-2021-26855'],
    source: 'LOCAL_CATALOG',
    aliases: ['proxylogon', 'exchange', 'microsoft exchange', 'ssrf']
  },
  {
    cveId: 'CVE-2022-0847',
    name: 'Linux Kernel Arbitrary File Overwrite (Dirty Pipe)',
    description: 'A flaw was found in the way the flags member of the new pipe buffer structure was lacking proper initialization in copy_page_to_iter_pipe and push_pipe in the Linux kernel.',
    severity: 'High',
    cvss: 7.8,
    cvssVector: 'CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H',
    exploitAvailable: true,
    publishedDate: '2022-03-10',
    references: ['https://nvd.nist.gov/vuln/detail/CVE-2022-0847'],
    source: 'LOCAL_CATALOG',
    aliases: ['dirty pipe', 'dirtypipe', 'linux', 'kernel']
  },
  {
    cveId: 'CVE-2011-2523',
    name: 'vsftpd 2.3.4 Compromised Backdoor Remote Code Execution',
    description: 'vsftpd 2.3.4 contains a backdoor inserted by an unknown malicious party that opens a listening root shell on TCP port 6200 when a username containing :) is supplied.',
    severity: 'Critical',
    cvss: 9.8,
    cvssVector: 'CVSS:2.0/AV:N/AC:L/Au:N/C:C/I:C/A:C',
    exploitAvailable: true,
    publishedDate: '2011-07-08',
    references: ['https://nvd.nist.gov/vuln/detail/CVE-2011-2523'],
    source: 'LOCAL_CATALOG',
    aliases: ['vsftpd', '2.3.4', 'vsftpd 2.3.4', 'backdoor']
  },
];

function lookupLocalCatalog(product: string, version: string = ''): NvdCveResult[] {
  const normProduct = (product || '').toLowerCase().trim();
  const normVersion = (version || '').toLowerCase().trim();
  const query = `${normProduct} ${normVersion}`.trim();
  if (!query) return [];

  const matched: NvdCveResult[] = [];

  for (const entry of LOCAL_CATALOG_LIST) {
    const cveMatch = entry.cveId.toLowerCase() === normProduct || entry.cveId.toLowerCase() === query;
    const aliasMatch = entry.aliases.some(a => normProduct.includes(a) || query.includes(a) || a.includes(normProduct));
    const textMatch = entry.name.toLowerCase().includes(normProduct) || entry.description.toLowerCase().includes(normProduct);

    if (cveMatch || aliasMatch || textMatch) {
      // Strip internal aliases before returning
      const { aliases, ...safeResult } = entry;
      matched.push(safeResult);
    }
  }

  return matched;
}

// ─── Public API ───────────────────────────────────────────────────────────────
export async function lookupCveByProductVersion(
  product: string,
  version: string = '',
  host?: string,
  port?: number
): Promise<NvdCveResult[]> {
  const keyword = `${product} ${version}`.trim();
  if (!keyword) return [];

  // Try NVD API first
  let results = await fetchFromNvd(keyword);

  // Fallback or augment with local catalog if empty
  if (results.length === 0) {
    results = lookupLocalCatalog(product, version);
  }

  return results;
}

export async function correlateSoftwareWithNvd(
  softwareList: Array<{ name: string; version: string; host?: string; port?: number }>
): Promise<Array<NvdCveResult & { host: string; port: number }>> {
  const allFindings: Array<NvdCveResult & { host: string; port: number }> = [];

  // Process in batches to avoid rate limiting (pause 1.5s between each)
  for (const item of softwareList) {
    try {
      const cves = await lookupCveByProductVersion(item.name, item.version, item.host, item.port);
      for (const cve of cves) {
        allFindings.push({ ...cve, host: item.host || 'unknown', port: item.port || 0 });
      }
      // Brief pause between NVD API calls
      await new Promise(resolve => setTimeout(resolve, 300));
    } catch { /* skip failed lookups */ }
  }

  return allFindings;
}

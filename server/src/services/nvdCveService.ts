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

  try {
    const apiKey = process.env.NVD_API_KEY;
    const params = new URLSearchParams({
      keywordSearch: keyword,
      resultsPerPage: '5',
    });
    const headers: Record<string, string> = { 'Accept': 'application/json' };
    if (apiKey) headers['apiKey'] = apiKey;

    const url = `https://services.nvd.nist.gov/rest/json/cves/2.0?${params.toString()}`;
    const response = await fetch(url, { headers, signal: AbortSignal.timeout(8000) });

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
    console.warn(`[NVD] API unavailable (${err.message}), using local catalog`);
    return [];
  }
}

// ─── Local Fallback Catalog ───────────────────────────────────────────────────
const LOCAL_CATALOG: Record<string, NvdCveResult> = {
  'log4j': {
    cveId: 'CVE-2021-44228', name: 'Apache Log4j Remote Code Execution (Log4Shell)',
    description: 'Apache Log4j2 <=2.14.1 JNDI features do not protect against attacker-controlled LDAP and other JNDI related endpoints.',
    severity: 'Critical', cvss: 10.0, exploitAvailable: true,
    publishedDate: '2021-12-10', references: ['https://nvd.nist.gov/vuln/detail/CVE-2021-44228'], source: 'LOCAL_CATALOG'
  },
  'log4j 2.14.1': {
    cveId: 'CVE-2021-44228', name: 'Apache Log4j2 Log4Shell RCE',
    description: 'JNDI injection vulnerability in Apache Log4j 2.x before 2.15.0.',
    severity: 'Critical', cvss: 10.0, exploitAvailable: true,
    publishedDate: '2021-12-10', references: ['https://nvd.nist.gov/vuln/detail/CVE-2021-44228'], source: 'LOCAL_CATALOG'
  },
  'vsftpd 2.3.4': {
    cveId: 'CVE-2011-2523', name: 'vsftpd 2.3.4 Backdoor',
    description: 'vsftpd 2.3.4 contains a backdoor enabling unauthenticated shell access.',
    severity: 'Critical', cvss: 9.8, exploitAvailable: true,
    publishedDate: '2011-07-08', references: ['https://nvd.nist.gov/vuln/detail/CVE-2011-2523'], source: 'LOCAL_CATALOG'
  },
  'apache httpd 2.4.49': {
    cveId: 'CVE-2021-41773', name: 'Apache HTTP Server 2.4.49 Path Traversal RCE',
    description: 'Path traversal and RCE in Apache 2.4.49.',
    severity: 'Critical', cvss: 9.8, exploitAvailable: true,
    publishedDate: '2021-10-05', references: ['https://nvd.nist.gov/vuln/detail/CVE-2021-41773'], source: 'LOCAL_CATALOG'
  },
  'openssl 1.1.1k': {
    cveId: 'CVE-2022-0778', name: 'OpenSSL Infinite Loop Denial of Service',
    description: 'The BN_mod_sqrt() function in OpenSSL can be caused to loop forever.',
    severity: 'High', cvss: 7.5, exploitAvailable: false,
    publishedDate: '2022-03-15', references: ['https://nvd.nist.gov/vuln/detail/CVE-2022-0778'], source: 'LOCAL_CATALOG'
  },
};

function lookupLocalCatalog(product: string, version: string): NvdCveResult | null {
  const key = `${product} ${version}`.toLowerCase().trim();
  if (LOCAL_CATALOG[key]) return LOCAL_CATALOG[key];
  // Partial match on product name
  for (const [k, v] of Object.entries(LOCAL_CATALOG)) {
    if (product.toLowerCase().includes(k.split(' ')[0])) return v;
  }
  return null;
}

// ─── Public API ───────────────────────────────────────────────────────────────
export async function lookupCveByProductVersion(
  product: string,
  version: string,
  host?: string,
  port?: number
): Promise<NvdCveResult[]> {
  const keyword = `${product} ${version}`.trim();

  // Try NVD API first
  let results = await fetchFromNvd(keyword);

  // Fallback to local catalog
  if (results.length === 0) {
    const local = lookupLocalCatalog(product, version);
    if (local) results = [local];
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

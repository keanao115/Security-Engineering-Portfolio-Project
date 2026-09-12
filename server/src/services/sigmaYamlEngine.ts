import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import * as yaml from 'js-yaml';
import { logger } from '../utils/logger.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

export interface SigmaYamlRule {
  title: string;
  id: string;
  status?: 'production' | 'test' | 'experimental';
  description?: string;
  references?: string[];
  author?: string;
  date?: string;
  modified?: string;
  tags?: string[];
  logsource?: {
    category?: string;
    product?: string;
    service?: string;
  };
  detection: {
    [key: string]: any;
    condition: string;
  };
  fields?: string[];
  falsepositives?: string[];
  level?: 'informational' | 'low' | 'medium' | 'high' | 'critical';
  response?: string;
  rawYaml?: string;
  filePath?: string;
}

export interface SigmaYamlMatchResult {
  ruleId: string;
  ruleTitle: string;
  level: 'critical' | 'high' | 'medium' | 'low' | 'informational';
  mitre: string[];
  description: string;
  response: string;
  matchedEventId: string;
  matchedEventSummary?: string;
  matchedSelections?: string[];
  source: 'sigma-yaml';
}

export class SigmaYamlEngine {
  private static instance: SigmaYamlEngine | null = null;
  private rules: Map<string, SigmaYamlRule> = new Map();
  private rulesDirectory: string;

  private constructor() {
    // Locate the default sigma rules folder (server/rules/sigma)
    const possiblePaths = [
      path.resolve(__dirname, '../../rules/sigma'),
      path.resolve(process.cwd(), 'rules/sigma'),
      path.resolve(process.cwd(), 'server/rules/sigma'),
    ];

    this.rulesDirectory = possiblePaths.find((p) => fs.existsSync(p)) || possiblePaths[0];
  }

  public static getInstance(): SigmaYamlEngine {
    if (!SigmaYamlEngine.instance) {
      SigmaYamlEngine.instance = new SigmaYamlEngine();
      SigmaYamlEngine.instance.loadRulesFromDirectory();
    }
    return SigmaYamlEngine.instance;
  }

  /**
   * Load and compile all YAML rules from the rules directory
   */
  public loadRulesFromDirectory(customDir?: string): { loaded: number; errors: string[] } {
    const dir = customDir || this.rulesDirectory;
    const errors: string[] = [];
    this.rules.clear();

    if (!fs.existsSync(dir)) {
      try {
        fs.mkdirSync(dir, { recursive: true });
      } catch (err: any) {
        errors.push(`Failed to create rules directory ${dir}: ${err.message}`);
        return { loaded: 0, errors };
      }
    }

    try {
      const files = fs.readdirSync(dir).filter((f) => f.endsWith('.yml') || f.endsWith('.yaml'));
      for (const file of files) {
        const fullPath = path.join(dir, file);
        try {
          const content = fs.readFileSync(fullPath, 'utf8');
          const rule = this.parseRuleYaml(content, fullPath);
          if (rule && rule.id) {
            this.rules.set(rule.id, rule);
          }
        } catch (err: any) {
          const msg = `[SigmaEngine] Error loading ${file}: ${err.message}`;
          logger.warn(msg);
          errors.push(msg);
        }
      }
    } catch (err: any) {
      errors.push(`Error reading rules directory: ${err.message}`);
    }

    logger.info(`[SigmaEngine] Loaded ${this.rules.size} Sigma YAML rules from ${dir}`);
    return { loaded: this.rules.size, errors };
  }

  /**
   * Parse and validate a Sigma YAML string
   */
  public parseRuleYaml(yamlContent: string, filePath?: string): SigmaYamlRule {
    const parsed = yaml.load(yamlContent) as any;

    if (!parsed || typeof parsed !== 'object') {
      throw new Error('Invalid Sigma rule: Root element must be an object');
    }
    if (!parsed.title) throw new Error("Invalid Sigma rule: missing 'title'");
    if (!parsed.id) throw new Error("Invalid Sigma rule: missing 'id'");
    if (!parsed.detection || !parsed.detection.condition) {
      throw new Error("Invalid Sigma rule: missing 'detection.condition'");
    }

    const rule: SigmaYamlRule = {
      title: String(parsed.title),
      id: String(parsed.id),
      status: parsed.status || 'production',
      description: parsed.description || '',
      references: Array.isArray(parsed.references) ? parsed.references : [],
      author: parsed.author || 'CyberMind SOC Detection Engineer',
      date: parsed.date || new Date().toISOString().split('T')[0],
      modified: parsed.modified,
      tags: Array.isArray(parsed.tags) ? parsed.tags : [],
      logsource: parsed.logsource || {},
      detection: parsed.detection,
      fields: Array.isArray(parsed.fields) ? parsed.fields : [],
      falsepositives: Array.isArray(parsed.falsepositives) ? parsed.falsepositives : [],
      level: parsed.level || 'medium',
      response: parsed.response || 'Investigate offending asset and verify endpoint telemetry.',
      rawYaml: yamlContent,
      filePath,
    };

    return rule;
  }

  /**
   * Add or update a rule in memory and optionally persist to disk
   */
  public registerRule(yamlContent: string, persist = false): { success: boolean; rule?: SigmaYamlRule; error?: string } {
    try {
      const rule = this.parseRuleYaml(yamlContent);
      this.rules.set(rule.id, rule);

      if (persist && this.rulesDirectory) {
        const safeFileName = `${rule.id.replace(/[^a-zA-Z0-9_-]/g, '_')}.yml`;
        const filePath = path.join(this.rulesDirectory, safeFileName);
        fs.writeFileSync(filePath, yamlContent, 'utf8');
        rule.filePath = filePath;
      }

      return { success: true, rule };
    } catch (err: any) {
      return { success: false, error: err.message };
    }
  }

  /**
   * Extract MITRE ATT&CK technique IDs from rule tags (e.g. 'attack.t1059.001' -> 'T1059.001')
   */
  public static extractMitreTechniques(tags?: string[]): string[] {
    if (!tags || !Array.isArray(tags)) return [];
    const techniques: string[] = [];
    for (const tag of tags) {
      const match = tag.match(/attack\.(t\d+(\.\d+)?)/i);
      if (match && match[1]) {
        techniques.push(match[1].toUpperCase());
      }
    }
    return Array.from(new Set(techniques));
  }

  /**
   * Resolve an event field flexibly by matching case-insensitively or via common aliases
   */
  private resolveEventField(event: any, fieldName: string): any {
    if (!event || typeof event !== 'object') return undefined;

    // Direct key match
    if (event[fieldName] !== undefined) return event[fieldName];

    // Case-insensitive lookup
    const lower = fieldName.toLowerCase();
    for (const key of Object.keys(event)) {
      if (key.toLowerCase() === lower) {
        return event[key];
      }
    }

    // Common SOC Telemetry Aliases
    const aliases: Record<string, string[]> = {
      eventid: ['eventId', 'EventID', 'event_id', 'id'],
      commandline: ['commandLine', 'CommandLine', 'cmd', 'command', 'processCommandLine'],
      image: ['image', 'Image', 'process', 'processName', 'executable'],
      details: ['details', 'summary', 'message', 'msg', 'raw', 'description'],
      user: ['user', 'userName', 'TargetUserName', 'SubjectUserName', 'account'],
      sourceip: ['sourceIp', 'srcIp', 'src_ip', 'ip', 'SourceNetworkAddress', 'host'],
      destinationip: ['destinationIp', 'destIp', 'dest_ip', 'targetIp'],
      destinationport: ['destinationPort', 'destPort', 'dest_port', 'port', 'DestinationPort'],
      process: ['process', 'processName', 'Image', 'app', 'service'],
    };

    if (aliases[lower]) {
      for (const alias of aliases[lower]) {
        if (event[alias] !== undefined) return event[alias];
      }
    }

    // Check inside nested objects (e.g., event.rawDetails, event.provenance)
    if (event.rawDetails && typeof event.rawDetails === 'object') {
      const nested = this.resolveEventField(event.rawDetails, fieldName);
      if (nested !== undefined) return nested;
    }

    return undefined;
  }

  /**
   * Check a single field against a target value/list with modifiers
   */
  private matchField(eventVal: any, targetVal: any, modifiers: string[]): boolean {
    if (eventVal === undefined || eventVal === null) return false;

    const eventStr = String(eventVal);
    const eventLower = eventStr.toLowerCase();

    // If target value is an array, default Sigma behavior is OR across array items (unless modifier is |all)
    const targets = Array.isArray(targetVal) ? targetVal : [targetVal];
    const isAll = modifiers.includes('all');

    const checkSingleTarget = (singleTarget: any): boolean => {
      const targetStr = String(singleTarget);
      const targetLower = targetStr.toLowerCase();

      if (modifiers.includes('re')) {
        try {
          const regex = new RegExp(targetStr, 'i');
          return regex.test(eventStr);
        } catch {
          return false;
        }
      }

      if (modifiers.includes('startswith')) {
        return eventLower.startsWith(targetLower);
      }

      if (modifiers.includes('endswith')) {
        return eventLower.endsWith(targetLower);
      }

      if (modifiers.includes('contains')) {
        return eventLower.includes(targetLower);
      }

      // Default: exact or case-insensitive equality
      return eventLower === targetLower || eventStr === targetStr;
    };

    if (isAll) {
      return targets.every(checkSingleTarget);
    } else {
      return targets.some(checkSingleTarget);
    }
  }

  /**
   * Evaluate an individual selection block (AND logic across fields)
   */
  private evaluateSelection(event: any, selectionObj: any): boolean {
    if (!selectionObj || typeof selectionObj !== 'object') return false;

    for (const [key, targetVal] of Object.entries(selectionObj)) {
      const parts = key.split('|');
      const fieldName = parts[0];
      const modifiers = parts.slice(1).map((m) => m.toLowerCase());

      const eventVal = this.resolveEventField(event, fieldName);
      if (!this.matchField(eventVal, targetVal, modifiers)) {
        return false;
      }
    }

    return true;
  }

  /**
   * Evaluate a Sigma rule condition string using evaluated selection results
   */
  private evaluateCondition(conditionStr: string, selectionResults: Map<string, boolean>): boolean {
    let expr = conditionStr.trim();

    // Replace 1 of selection*
    expr = expr.replace(/1\s+of\s+([a-zA-Z0-9_*]+)/gi, (_match, pattern) => {
      const prefix = pattern.replace('*', '');
      let anyTrue = false;
      for (const [key, val] of selectionResults.entries()) {
        if (key.startsWith(prefix) && val) {
          anyTrue = true;
          break;
        }
      }
      return anyTrue ? 'true' : 'false';
    });

    // Replace all of selection*
    expr = expr.replace(/all\s+of\s+([a-zA-Z0-9_*]+)/gi, (_match, pattern) => {
      const prefix = pattern.replace('*', '');
      let allTrue = true;
      let count = 0;
      for (const [key, val] of selectionResults.entries()) {
        if (key.startsWith(prefix)) {
          count++;
          if (!val) allTrue = false;
        }
      }
      return count > 0 && allTrue ? 'true' : 'false';
    });

    // Replace "1 of them"
    expr = expr.replace(/1\s+of\s+them/gi, () => {
      for (const val of selectionResults.values()) {
        if (val) return 'true';
      }
      return 'false';
    });

    // Replace all selection identifiers with true/false
    for (const [key, val] of selectionResults.entries()) {
      const regex = new RegExp(`\\b${key}\\b`, 'g');
      expr = expr.replace(regex, val ? 'true' : 'false');
    }

    // Safe boolean parsing
    try {
      // Normalize keywords: 'and' -> '&&', 'or' -> '||', 'not' -> '!'
      const jsExpr = expr
        .replace(/\band\b/gi, '&&')
        .replace(/\bor\b/gi, '||')
        .replace(/\bnot\b/gi, '!')
        .replace(/true/gi, 'true')
        .replace(/false/gi, 'false');

      // Sanitize: only allow true, false, !, &&, ||, (, ), and whitespace
      if (!/^[truefals!\s&|()]+$/.test(jsExpr)) {
        return false;
      }

      // eslint-disable-next-line no-new-func
      const result = Function(`"use strict"; return Boolean(${jsExpr});`)();
      return Boolean(result);
    } catch {
      return false;
    }
  }

  /**
   * Evaluate all loaded Sigma rules against a single event
   */
  public evaluateEvent(event: any): SigmaYamlMatchResult[] {
    const matches: SigmaYamlMatchResult[] = [];

    for (const rule of this.rules.values()) {
      try {
        const selectionResults = new Map<string, boolean>();
        const matchedSelections: string[] = [];

        for (const [key, val] of Object.entries(rule.detection)) {
          if (key === 'condition') continue;
          const isMatch = this.evaluateSelection(event, val);
          selectionResults.set(key, isMatch);
          if (isMatch) matchedSelections.push(key);
        }

        const isConditionMet = this.evaluateCondition(rule.detection.condition, selectionResults);

        if (isConditionMet) {
          matches.push({
            ruleId: rule.id,
            ruleTitle: rule.title,
            level: (rule.level as any) || 'medium',
            mitre: SigmaYamlEngine.extractMitreTechniques(rule.tags),
            description: rule.description || '',
            response: rule.response || 'Investigate affected host and isolate if compromised.',
            matchedEventId: event.id || event.eventId || 'unknown',
            matchedEventSummary: event.summary || event.details || event.commandLine,
            matchedSelections,
            source: 'sigma-yaml',
          });
        }
      } catch {
        // Continue evaluating other rules if one encounters an edge case
      }
    }

    return matches;
  }

  /**
   * Test an arbitrary rule YAML string against an array of test events
   */
  public testRuleAgainstEvents(
    ruleYaml: string,
    events: any[]
  ): {
    success: boolean;
    rule?: SigmaYamlRule;
    matches: Array<{ event: any; match: SigmaYamlMatchResult }>;
    error?: string;
  } {
    try {
      const rule = this.parseRuleYaml(ruleYaml);
      const matches: Array<{ event: any; match: SigmaYamlMatchResult }> = [];

      for (const event of events) {
        const selectionResults = new Map<string, boolean>();
        const matchedSelections: string[] = [];

        for (const [key, val] of Object.entries(rule.detection)) {
          if (key === 'condition') continue;
          const isMatch = this.evaluateSelection(event, val);
          selectionResults.set(key, isMatch);
          if (isMatch) matchedSelections.push(key);
        }

        const isConditionMet = this.evaluateCondition(rule.detection.condition, selectionResults);
        if (isConditionMet) {
          matches.push({
            event,
            match: {
              ruleId: rule.id,
              ruleTitle: rule.title,
              level: (rule.level as any) || 'medium',
              mitre: SigmaYamlEngine.extractMitreTechniques(rule.tags),
              description: rule.description || '',
              response: rule.response || 'Test match triggered.',
              matchedEventId: event.id || event.eventId || 'test-event',
              matchedEventSummary: event.summary || event.details,
              matchedSelections,
              source: 'sigma-yaml',
            },
          });
        }
      }

      return { success: true, rule, matches };
    } catch (err: any) {
      return { success: false, matches: [], error: err.message };
    }
  }

  /**
   * Get all loaded rules as an array
   */
  public getAllRules(): SigmaYamlRule[] {
    return Array.from(this.rules.values());
  }

  /**
   * Get rule count
   */
  public getRuleCount(): number {
    return this.rules.size;
  }

  /**
   * Get specific rule by ID
   */
  public getRuleById(id: string): SigmaYamlRule | undefined {
    return this.rules.get(id);
  }
}

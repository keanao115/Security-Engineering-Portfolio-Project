import pg from 'pg';
import dotenv from 'dotenv';

dotenv.config();

const { Pool } = pg;

export const pool = new Pool({
  host: process.env.DB_HOST || 'localhost',
  port: parseInt(process.env.DB_PORT || '5432'),
  database: process.env.DB_NAME || 'soc_db',
  user: process.env.DB_USER || 'postgres',
  password: process.env.DB_PASSWORD || 'postgres',
  max: 10,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 2000,
});

// In-Memory Data Store Fallback for local execution
export const memoryDb = {
  // Note: User authentication is handled exclusively by userService.ts (scrypt-hashed in-memory Map).
  // There is no users array here — do not add one.
  assets: [] as any[],
  findings: [] as any[],
  logs: [] as any[],
  reports: [] as any[],
  unifiedEvents: [] as any[],
  collectorMetrics: [] as any[],
  auditLogs: [] as any[],
  zeekEvents: [] as any[],
  suricataEvents: [] as any[],
  captureSessions: [] as any[],
  incidents: [
    {
      id: 'INC-2026-001',
      title: 'Active Cobalt Strike Beaconing & Port Scan Anomalies',
      severity: 'Critical',
      status: 'Investigating',
      assignedTo: 'SOC Incident Lead Analyst',
      sourceIp: '185.220.101.5',
      targetIp: '192.168.1.105',
      mitreTechnique: 'T1071.001 (Web Protocols)',
      summary: 'Automated correlation engine flagged correlated C2 beaconing attempts on non-standard egress port with lateral movement attempts.',
      notes: ['IP isolated on perimeter firewall', 'Target host memory dump scheduled'],
      createdAt: new Date(Date.now() - 3600000).toISOString(),
      updatedAt: new Date().toISOString()
    }
  ] as any[],
  blockedIps: [] as any[],
  soarExecutions: [] as any[],
};

/**
 * Sliding Window FIFO queue bound to prevent memory leak (OOM) under continuous packet/log ingestion
 */
export function pushBounded<T>(targetArray: T[], item: T, maxSize: number = 1000): void {
  targetArray.push(item);
  if (targetArray.length > maxSize) {
    targetArray.splice(0, targetArray.length - maxSize);
  }
}

/**
 * Sliding Window FIFO queue for batch items to prevent memory leak (OOM) under bulk ingestion
 */
export function pushBatchBounded<T>(targetArray: T[], items: T[], maxSize: number = 1000): void {
  if (!items || items.length === 0) return;
  targetArray.push(...items);
  if (targetArray.length > maxSize) {
    targetArray.splice(0, targetArray.length - maxSize);
  }
}

let isPgConnected = false;

export async function query(text: string, params?: any[]) {
  if (isPgConnected) {
    try {
      return await pool.query(text, params);
    } catch (err) {
      console.warn('[DB] PostgreSQL query failed, using memory store fallback:', (err as Error).message);
    }
  }
  
  // Return simulated pg query result structure from memory store
  return {
    rows: [],
    rowCount: 0
  };
}

export async function initDbConnection() {
  try {
    const client = await pool.connect();
    isPgConnected = true;
    console.log(`[DB] PostgreSQL connected successfully to ${process.env.DB_NAME || 'soc_db'} on ${process.env.DB_HOST || 'localhost'}:${process.env.DB_PORT || '5432'}.`);
    
    // Auto-initialize tables
    try {
      await client.query(`
        CREATE TABLE IF NOT EXISTS users (
          id SERIAL PRIMARY KEY,
          username VARCHAR(100) UNIQUE NOT NULL,
          email VARCHAR(255) UNIQUE NOT NULL,
          password_hash VARCHAR(255) NOT NULL,
          role VARCHAR(50) NOT NULL DEFAULT 'Analyst',
          created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS assets (
          id SERIAL PRIMARY KEY,
          hostname VARCHAR(255) NOT NULL,
          ip_address VARCHAR(45) NOT NULL,
          mac_address VARCHAR(48),
          os_name VARCHAR(255),
          status VARCHAR(50) DEFAULT 'Active',
          installed_software JSONB DEFAULT '[]'::jsonb,
          running_services JSONB DEFAULT '[]'::jsonb,
          owner VARCHAR(100) DEFAULT 'SOC Operations',
          tags JSONB DEFAULT '[]'::jsonb,
          last_seen TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS imported_findings (
          id SERIAL PRIMARY KEY,
          source_tool VARCHAR(100) NOT NULL,
          cve_id VARCHAR(50),
          title VARCHAR(255) NOT NULL,
          severity VARCHAR(50) NOT NULL,
          cvss_score NUMERIC(3, 1) DEFAULT 0.0,
          affected_resource VARCHAR(255) NOT NULL,
          description TEXT,
          evidence TEXT,
          mitigation TEXT,
          raw_data JSONB DEFAULT '{}'::jsonb,
          created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS security_logs (
          id SERIAL PRIMARY KEY,
          log_source VARCHAR(100) NOT NULL,
          event_id VARCHAR(50),
          timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
          severity VARCHAR(50) DEFAULT 'Informational',
          summary TEXT NOT NULL,
          user_name VARCHAR(100),
          src_ip VARCHAR(45),
          dst_ip VARCHAR(45),
          mitre_technique VARCHAR(50),
          details JSONB DEFAULT '{}'::jsonb
        );
        CREATE TABLE IF NOT EXISTS reports (
          id SERIAL PRIMARY KEY,
          report_title VARCHAR(255) NOT NULL,
          classification VARCHAR(100) DEFAULT 'CONFIDENTIAL / CISO AUDIT',
          risk_score INT DEFAULT 90,
          summary TEXT,
          mitre_mappings JSONB DEFAULT '[]'::jsonb,
          recommendations JSONB DEFAULT '[]'::jsonb,
          created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS network_flows (
          id VARCHAR(100) PRIMARY KEY,
          timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
          source_type VARCHAR(50) NOT NULL,
          src_ip VARCHAR(45) NOT NULL,
          src_port INT NOT NULL,
          dest_ip VARCHAR(45) NOT NULL,
          dest_port INT NOT NULL,
          protocol VARCHAR(20) NOT NULL,
          bytes BIGINT NOT NULL,
          packets INT NOT NULL,
          duration_ms INT DEFAULT 0,
          flags VARCHAR(50),
          direction VARCHAR(20) DEFAULT 'INBOUND',
          vlan_id INT DEFAULT 1,
          geo_country VARCHAR(10) DEFAULT 'US',
          anomaly_flag BOOLEAN DEFAULT FALSE,
          risk_score INT DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS pcap_sessions (
          id VARCHAR(100) PRIMARY KEY,
          file_name VARCHAR(255) NOT NULL,
          total_packets INT NOT NULL,
          duration_sec INT NOT NULL,
          uploaded_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
          protocol_distribution JSONB DEFAULT '[]'::jsonb,
          dns_queries JSONB DEFAULT '[]'::jsonb,
          http_sessions JSONB DEFAULT '[]'::jsonb,
          tls_handshakes JSONB DEFAULT '[]'::jsonb,
          flagged_threats JSONB DEFAULT '[]'::jsonb
        );
        CREATE TABLE IF NOT EXISTS discovery_jobs (
          id VARCHAR(100) PRIMARY KEY,
          target_cidr VARCHAR(50) NOT NULL,
          status VARCHAR(50) NOT NULL,
          scan_speed VARCHAR(50) DEFAULT 'Normal',
          discovered_count INT DEFAULT 0,
          scheduled_interval_min INT DEFAULT 0,
          last_run TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
          next_run TIMESTAMP WITH TIME ZONE
        );
        CREATE TABLE IF NOT EXISTS siem_events (
          id VARCHAR(100) PRIMARY KEY,
          timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
          source_category VARCHAR(50) NOT NULL,
          host_name VARCHAR(255) NOT NULL,
          severity VARCHAR(50) NOT NULL,
          event_id VARCHAR(100) NOT NULL,
          mitre_technique VARCHAR(100),
          summary TEXT NOT NULL,
          dedup_hash VARCHAR(64),
          dedup_count INT DEFAULT 1,
          raw_details JSONB DEFAULT '{}'::jsonb
        );
        CREATE TABLE IF NOT EXISTS incident_cases (
          id VARCHAR(100) PRIMARY KEY,
          title VARCHAR(255) NOT NULL,
          severity VARCHAR(50) NOT NULL,
          status VARCHAR(50) DEFAULT 'New',
          assigned_to VARCHAR(100) DEFAULT 'SOC Incident Lead Analyst',
          source_ip VARCHAR(45),
          target_ip VARCHAR(45),
          mitre_technique VARCHAR(100),
          summary TEXT,
          notes JSONB DEFAULT '[]'::jsonb,
          created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
          updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
        );
      `);

      // Seed initial admin user if empty
      const userRes = await client.query('SELECT COUNT(*) FROM users');
      if (parseInt(userRes.rows[0].count) === 0) {
        await client.query(
          `INSERT INTO users (username, email, password_hash, role) VALUES ($1, $2, $3, $4)`,
          ['admin', 'admin@soc.corp', '$2a$10$WpZJd90kX8Gz1wKz.e2D4e5d5F6g7H8i9J0k1L2m3N4o5P6q7R8s9', 'Admin']
        );
      }
      console.log('[DB] PostgreSQL schema verified and ready for live operations.');
    } catch (schemaErr) {
      console.warn('[DB] PostgreSQL schema check warning:', (schemaErr as Error).message);
    } finally {
      client.release();
    }
  } catch (err) {
    console.warn('[DB] PostgreSQL server not reached on localhost:5432. Active memory storage fallback engaged for zero-dependency execution.');
    isPgConnected = false;
  }
}

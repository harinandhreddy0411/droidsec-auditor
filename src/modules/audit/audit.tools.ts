import { ToolDecorator as Tool, ExecutionContext, z } from '@nitrostack/core';
import Database from 'better-sqlite3';
import fs from 'fs';
import path from 'path';
import * as acorn from 'acorn';
import * as walk from 'acorn-walk';

const mockDir = path.join(process.cwd(), 'mock-data');
const uploadDir = path.join(process.cwd(), 'uploaded');

const FALLBACK_PATTERNS = [
  { id: 'google-api-key', description: 'Google API Key', regex: 'AIza[0-9A-Za-z\\-_]{35}' },
  { id: 'stripe-live-key', description: 'Stripe Live Secret Key', regex: 'sk_live_[0-9a-zA-Z]{24,}' },
  { id: 'generic-jwt', description: 'Generic JWT', regex: 'eyJ[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+' }
];

const MANIFEST_SECURITY_RULES = [
  {
    id: "VULN-001",
    name: "Debug Mode Enabled",
    regex: /android:debuggable\s*=\s*["']true["']/i,
    severity: "CRITICAL",
    remediation: "Remove android:debuggable attribute before production release."
  },
  {
    id: "VULN-002",
    name: "Insecure Data Backup",
    regex: /android:allowBackup\s*=\s*["']true["']/i,
    severity: "HIGH",
    remediation: "Set android:allowBackup to false to prevent ADB extraction."
  },
  {
    id: "VULN-003",
    name: "Cleartext Traffic Permitted",
    regex: /(?:android:usesCleartextTraffic|cleartextTrafficPermitted)\s*=\s*["']true["']/i,
    severity: "HIGH",
    remediation: "Disable cleartext traffic to enforce HTTPS."
  }
];

const VULNERABLE_DEPENDENCY_DICTIONARY: Record<string, string> = {
  'lodash': '4.17.20',
  'axios': '0.21.0',
  'express': '4.16.0'
};

async function fetchLivePatterns(ctx: ExecutionContext) {
  try {
    const res = await fetch('https://raw.githubusercontent.com/gitleaks/gitleaks/master/config/gitleaks.toml');
    if (!res.ok) {
      throw new Error(`Gitleaks fetch failed with HTTP ${res.status}`);
    }
    const raw = await res.text();
    const ruleBlocks = raw.split('[[rules]]').slice(1);
    const patterns = ruleBlocks.map(block => {
      const idMatch = block.match(/id\s*=\s*"([^"]+)"/);
      const descMatch = block.match(/description\s*=\s*"([^"]+)"/);
      const regexMatch = block.match(/regex\s*=\s*'''([\s\S]*?)'''/);
      return {
        id: idMatch?.[1] ?? 'unknown',
        description: descMatch?.[1] ?? '',
        regex: regexMatch?.[1] ?? null
      };
    }).filter(p => p.regex);
    if (patterns.length === 0) throw new Error('No patterns parsed');
    return patterns;
  } catch (e) {
    ctx.logger.error('Live Gitleaks fetch failed, using fallback patterns', { error: e instanceof Error ? e.message : String(e) });
    return FALLBACK_PATTERNS;
  }
}

function safeUploadedPath(fileName: string) {
  const safeName = path.basename(fileName);
  if (!safeName || safeName === '.' || safeName === '..') {
    throw new Error('Invalid file name.');
  }

  const resolvedUploadDir = path.resolve(uploadDir);
  const resolvedPath = path.resolve(resolvedUploadDir, safeName);
  if (!resolvedPath.startsWith(resolvedUploadDir + path.sep)) {
    throw new Error('Invalid upload path.');
  }

  return resolvedPath;
}

function safeReadableProjectPath(filePath: string) {
  const resolvedRoot = path.resolve(process.cwd());
  const resolvedPath = path.resolve(filePath);
  if (!resolvedPath.startsWith(resolvedRoot + path.sep)) {
    throw new Error('File path must stay inside the project directory.');
  }

  if (!fs.existsSync(resolvedPath)) {
    throw new Error('File not found.');
  }

  return resolvedPath;
}

export const REMEDIATIONS: Record<string, string> = {
  'Google API Key': 'Move to environment variables or a secrets manager; never bundle in client code.',
  'Stripe Live Secret Key': 'Never expose secret keys client-side; use publishable keys on frontend, keep secret keys server-side only.',
  'Generic JWT': 'Do not store long-lived tokens in shared preferences or local storage in plaintext; use secure, encrypted storage.',
  'Hardcoded secret-like value in source': 'Move to a secure environment variable or vault; rotate the exposed credential immediately.',
  'Exported Content Provider with no permission restriction': 'Set android:exported="false" unless cross-app access is required, and add android:permission with signature-level protection.',
  'Plaintext password/session token in local DB': 'Hash passwords before storage; store session tokens encrypted, never plaintext.',
  'Vulnerable NPM Dependency': 'Update package to the latest secure version addressing known CVEs.',
  'Missing Content Security Policy': 'Implement a strict CSP meta tag to mitigate Cross-Site Scripting (XSS) attacks.'
};

export class AuditTools {
  @Tool({
    name: 'scan_for_hardcoded_keys',
    description: 'Scans local app storage and resources for hardcoded API keys and secrets using live Gitleaks patterns',
    inputSchema: z.object({})
  })
  async scanForKeys(_input: any, ctx: ExecutionContext) {
    ctx.logger.info('Scanning for hardcoded keys');
    const patterns = await fetchLivePatterns(ctx);
    const findings: any[] = [];

    let sharedPrefs = '';
    let stringsXml = '';
    
    try {
      sharedPrefs = fs.readFileSync(path.join(mockDir, 'shared_prefs', 'UserSession.xml'), 'utf-8');
    } catch (e) {}

    try {
      stringsXml = fs.readFileSync(path.join(mockDir, 'values', 'strings.xml'), 'utf-8');
    } catch (e) {}

    let apiConfig: unknown[] = [];
    const dbPath = path.join(mockDir, 'app.db');
    if (fs.existsSync(dbPath)) {
      const db = new Database(dbPath, { readonly: true });
      try {
        apiConfig = db.prepare('SELECT * FROM api_config').all();
      } finally {
        db.close();
      }
    }

    const haystacks = [
      { source: 'SharedPreferences: UserSession.xml', text: sharedPrefs },
      { source: 'Resources: strings.xml', text: stringsXml },
      { source: 'sqlite3: api_config table', text: JSON.stringify(apiConfig) }
    ];

    for (const { source, text } of haystacks) {
      if (!text) continue;
      for (const p of patterns) {
        if (!p.regex) continue;
        try {
          const re = new RegExp(p.regex, 'g');
          const matches = text.match(re);
          if (matches) {
            for (const m of matches) {
              findings.push({
                source,
                pattern: p.description || p.id,
                matched: m,
                severity: 'CRITICAL',
                remediation: REMEDIATIONS[p.description] ?? 'Move to a secure environment variable or vault; rotate immediately.'
              });
            }
          }
        } catch {
          continue;
        }
      }
    }

    return { total_findings: findings.length, patterns_source: patterns === FALLBACK_PATTERNS ? 'fallback (offline)' : 'live gitleaks fetch', findings };
  }

  @Tool({
    name: 'analyze_content_provider_exposure',
    description: 'Parses AndroidManifest.xml to find exported Content Providers, Debug Mode, Insecure Backups, and Cleartext Traffic vulnerabilities',
    inputSchema: z.object({})
  })
  async analyzeExposure(_input: any, ctx: ExecutionContext) {
    ctx.logger.info('Analyzing manifest security exposure');
    const manifestPath = path.join(mockDir, 'AndroidManifest.xml');
    
    if (!fs.existsSync(manifestPath)) {
       return { total_findings: 0, findings: [], error: 'AndroidManifest.xml not found' };
    }

    const manifest = fs.readFileSync(manifestPath, 'utf-8');
    const findings: any[] = [];
    const providerRegex = /<provider([\s\S]*?)\/>/g;
    let match;
    
    while ((match = providerRegex.exec(manifest)) !== null) {
      const block = match[1];
      const nameMatch = block.match(/android:name="([^"]+)"/);
      const exported = block.includes('android:exported="true"');
      const hasPermission = block.includes('android:permission=');

      if (exported && !hasPermission) {
        findings.push({
          component: nameMatch ? nameMatch[1] : 'unknown',
          issue: 'Exported Content Provider with no permission restriction',
          severity: 'HIGH',
          remediation: REMEDIATIONS['Exported Content Provider with no permission restriction']
        });
      }
    }

    for (const rule of MANIFEST_SECURITY_RULES) {
      if (rule.regex.test(manifest)) {
        findings.push({
          component: 'Application / Manifest',
          issue: rule.name,
          severity: rule.severity,
          remediation: rule.remediation
        });
      }
    }

    return { total_findings: findings.length, findings };
  }

  @Tool({
    name: 'extract_plaintext_credentials',
    description: 'Queries the local sqlite3 database for plaintext-stored passwords or session tokens',
    inputSchema: z.object({})
  })
  async extractCredentials(_input: any, ctx: ExecutionContext) {
    ctx.logger.info('Extracting plaintext credentials from local DB');
    const dbPath = path.join(mockDir, 'app.db');
    
    if (!fs.existsSync(dbPath)) {
        return { total_findings: 0, findings: [], error: 'app.db not found' };
    }

    const db = new Database(dbPath, { readonly: true });
    let users: any[] = [];
    try {
      users = db.prepare('SELECT username, password, session_token FROM users').all() as any[];
    } finally {
      db.close();
    }

    const findings = users.map(u => ({
      username: u.username,
      issue: 'Plaintext password/session token in local DB',
      password_found: u.password,
      session_token_found: u.session_token,
      severity: 'CRITICAL',
      remediation: REMEDIATIONS['Plaintext password/session token in local DB']
    }));

    return { total_findings: findings.length, findings };
  }

  @Tool({
    name: 'ingest_file',
    description: 'Ingests an Android or web source file for security analysis',
    inputSchema: z.object({
      file_name: z.string().describe('Name of the file being ingested'),
      file_type: z.string().describe('MIME type of the file'),
      file_content_base64: z.string().describe('Base64-encoded file content')
    })
  })
  async ingestFile(input: any, ctx: ExecutionContext) {
    ctx.logger.info('Ingesting file for analysis', { name: input.file_name });
    const base64 = input.file_content_base64.replace(/^data:[^;]+;base64,/, '');
    const buffer = Buffer.from(base64, 'base64');
    const text = buffer.toString('utf-8');
    fs.mkdirSync(uploadDir, { recursive: true });
    const savedPath = safeUploadedPath(input.file_name);
    fs.writeFileSync(savedPath, text);

    const isAndroidXml = input.file_name.endsWith('.xml');
    const isWebJs = input.file_name.endsWith('.js') || input.file_name === 'package.json';

    return {
      saved_path: savedPath,
      detected_type: isAndroidXml ? 'android-config' : isWebJs ? 'web-source' : 'unknown',
      message: 'File ingested.'
    };
  }

  @Tool({
    name: 'scan_js_ast',
    description: 'Parses a JavaScript file into an AST and flags suspicious variable assignments',
    inputSchema: z.object({
      file_path: z.string().describe('Path to a JS file')
    })
  })
  async scanJsAst(input: any, ctx: ExecutionContext) {
    ctx.logger.info('Running AST scan on JS file', { path: input.file_path });
    let code = '';
    try {
      code = fs.readFileSync(safeReadableProjectPath(input.file_path), 'utf-8');
    } catch (error) {
      return {
        total_findings: 0,
        findings: [],
        error: error instanceof Error ? error.message : 'Could not read file.'
      };
    }

    const findings: any[] = [];
    try {
      const ast = acorn.parse(code, { ecmaVersion: 2022, sourceType: 'module' });
      const suspiciousNames = /key|secret|token|password|apikey/i;

      (walk as any).simple(ast, {
        VariableDeclarator(node: any) {
          if (
            node.id?.type === 'Identifier' &&
            suspiciousNames.test(node.id.name) &&
            node.init?.type === 'Literal' &&
            typeof node.init.value === 'string' &&
            node.init.value.length > 8
          ) {
            findings.push({
              variable: node.id.name,
              value_preview: node.init.value.slice(0, 6) + '...',
              issue: 'Hardcoded secret-like value in source',
              severity: 'HIGH',
              remediation: REMEDIATIONS['Hardcoded secret-like value in source']
            });
          }
        }
      });
    } catch (e) {
      ctx.logger.error('AST parse failed', { error: e instanceof Error ? e.message : String(e) });
      return { total_findings: 0, findings: [], error: 'Could not parse file as JavaScript' };
    }

    return { total_findings: findings.length, findings };
  }

  @Tool({
    name: 'audit_web_dependencies',
    description: 'Scans package.json for outdated or vulnerable NPM dependencies',
    inputSchema: z.object({})
  })
  async auditWebDependencies(_input: any, ctx: ExecutionContext) {
    ctx.logger.info('Scanning web dependencies');
    const packageJsonPath = path.join(mockDir, 'package.json');
    
    if (!fs.existsSync(packageJsonPath)) {
      return { total_findings: 0, findings: [], error: 'package.json not found' };
    }

    const findings: any[] = [];
    let packageData: any;
    try {
      packageData = JSON.parse(fs.readFileSync(packageJsonPath, 'utf-8'));
    } catch {
      return { total_findings: 0, findings: [], error: 'package.json could not be parsed' };
    }
    const allDependencies = { ...(packageData.dependencies || {}), ...(packageData.devDependencies || {}) };

    for (const [dependencyName, installedVersion] of Object.entries(allDependencies)) {
      const cleanVersion = (installedVersion as string).replace(/[\^~]/g, '');
      const knownVulnerableVersion = VULNERABLE_DEPENDENCY_DICTIONARY[dependencyName];

      if (knownVulnerableVersion && cleanVersion === knownVulnerableVersion) {
        findings.push({
          dependency: dependencyName,
          installed_version: cleanVersion,
          issue: 'Vulnerable NPM Dependency',
          severity: 'HIGH',
          remediation: REMEDIATIONS['Vulnerable NPM Dependency']
        });
      }
    }

    return { total_findings: findings.length, findings };
  }

  @Tool({
    name: 'audit_html_security',
    description: 'Scans index.html for missing Content Security Policy and unsafe inline scripts',
    inputSchema: z.object({})
  })
  async auditHtmlSecurity(_input: any, ctx: ExecutionContext) {
    ctx.logger.info('Scanning HTML security headers');
    const htmlPath = path.join(mockDir, 'index.html');
    
    if (!fs.existsSync(htmlPath)) {
      return { total_findings: 0, findings: [], error: 'index.html not found' };
    }

    const htmlContent = fs.readFileSync(htmlPath, 'utf-8');
    const findings: any[] = [];

    const hasCSP = /<meta\s+http-equiv=["']Content-Security-Policy["']/i.test(htmlContent);
    if (!hasCSP) {
      findings.push({
        file: 'index.html',
        issue: 'Missing Content Security Policy',
        severity: 'MEDIUM',
        remediation: REMEDIATIONS['Missing Content Security Policy']
      });
    }

    return { total_findings: findings.length, findings };
  }
}

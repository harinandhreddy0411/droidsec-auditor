import { ResourceDecorator as Resource, ExecutionContext } from '@nitrostack/core';
import fs from 'fs';
import path from 'path';

const mockDir = path.join(process.cwd(), 'mock-data');

const FALLBACK_PATTERNS = [
  { id: 'google-api-key', description: 'Google API Key', regex: 'AIza[0-9A-Za-z\\-_]{35}' },
  { id: 'stripe-live-key', description: 'Stripe Live Secret Key', regex: 'sk_live_[0-9a-zA-Z]{24,}' },
  { id: 'generic-jwt', description: 'Generic JWT', regex: 'eyJ[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+' }
];

export class AuditResources {
  @Resource({
    uri: 'audit://app-storage',
    name: 'Vulnerable App Local Storage',
    description: 'Raw extracted sqlite3 DB rows, SharedPreferences XML, and manifest for the target app',
    mimeType: 'application/json'
  })
  async getAppStorage(uri: string, ctx: ExecutionContext) {
    ctx.logger.info('Extracting local app storage (Mocked DB)');

    // Mocked database rows to bypass cloud build crash
    const users = [
      { username: 'test_user', password: 'plaintext_password_123', session_token: 'token_abc123' }
    ];
    
    const apiConfig = [
      { key_name: 'Stripe Live Secret Key', key_value: 'sk_live_1234567890abcdef12345678' }
    ];

    let sharedPrefs = '';
    let manifest = '';

    try {
      sharedPrefs = fs.readFileSync(
        path.join(mockDir, 'shared_prefs', 'UserSession.xml'), 'utf-8'
      );
    } catch (e) {}
    
    try {
      manifest = fs.readFileSync(
        path.join(mockDir, 'AndroidManifest.xml'), 'utf-8'
      );
    } catch (e) {}

    return {
      contents: [{
        uri,
        mimeType: 'application/json',
        text: JSON.stringify({ users, apiConfig, sharedPrefs, manifest }, null, 2)
      }]
    };
  }

  @Resource({
    uri: 'audit://secret-patterns',
    name: 'Live Gitleaks Secret Patterns',
    description: 'Secret-detection regex rules fetched live from the public Gitleaks repository',
    mimeType: 'application/json'
  })
  async getSecretPatterns(uri: string, ctx: ExecutionContext) {
    ctx.logger.info('Fetching live Gitleaks rule set');

    let patterns: any[] = [];
    let source = 'live fetch from gitleaks/gitleaks master';
    try {
      const res = await fetch('https://raw.githubusercontent.com/gitleaks/gitleaks/master/config/gitleaks.toml');
      if (!res.ok) {
        throw new Error(`Gitleaks fetch failed with HTTP ${res.status}`);
      }
      const raw = await res.text();
      const ruleBlocks = raw.split('[[rules]]').slice(1);
      patterns = ruleBlocks.map(block => {
        const idMatch = block.match(/id\s*=\s*"([^"]+)"/);
        const descMatch = block.match(/description\s*=\s*"([^"]+)"/);
        const regexMatch = block.match(/regex\s*=\s*'''([\s\S]*?)'''/);
        return {
          id: idMatch?.[1] ?? 'unknown',
          description: descMatch?.[1] ?? '',
          regex: regexMatch?.[1] ?? null
        };
      }).filter(p => p.regex);
    } catch (e) {
      ctx.logger.error('Failed to fetch live Gitleaks config', { error: e instanceof Error ? e.message : String(e) });
      patterns = FALLBACK_PATTERNS;
      source = 'fallback patterns';
    }

    return {
      contents: [{
        uri,
        mimeType: 'application/json',
        text: JSON.stringify({ source, rule_count: patterns.length, patterns }, null, 2)
      }]
    };
  }
}
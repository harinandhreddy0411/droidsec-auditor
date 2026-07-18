import { ResourceDecorator as Resource, ExecutionContext } from '@nitrostack/core';
import Database from 'better-sqlite3';
import fs from 'fs';
import path from 'path';

const mockDir = path.join(process.cwd(), 'mock-data');

export class AuditResources {
  @Resource({
    uri: 'audit://app-storage',
    name: 'Vulnerable App Local Storage',
    description: 'Raw extracted sqlite3 DB rows, SharedPreferences XML, and manifest for the target app',
    mimeType: 'application/json'
  })
  async getAppStorage(uri: string, ctx: ExecutionContext) {
    ctx.logger.info('Extracting local app storage');

    const db = new Database(path.join(mockDir, 'app.db'), { readonly: true });
    const users = db.prepare('SELECT * FROM users').all();
    const apiConfig = db.prepare('SELECT * FROM api_config').all();
    db.close();

    const sharedPrefs = fs.readFileSync(
      path.join(mockDir, 'shared_prefs', 'UserSession.xml'), 'utf-8'
    );
    const manifest = fs.readFileSync(
      path.join(mockDir, 'AndroidManifest.xml'), 'utf-8'
    );

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
    try {
      const res = await fetch('https://raw.githubusercontent.com/gitleaks/gitleaks/master/config/gitleaks.toml');
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
    }

    return {
      contents: [{
        uri,
        mimeType: 'application/json',
        text: JSON.stringify({ source: 'live fetch from gitleaks/gitleaks master', rule_count: patterns.length, patterns }, null, 2)
      }]
    };
  }
}
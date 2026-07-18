import Database from 'better-sqlite3';
import fs from 'fs';
import path from 'path';

const mockDir = path.join(process.cwd(), 'mock-data');
fs.mkdirSync(mockDir, { recursive: true });

const db = new Database(path.join(mockDir, 'app.db'));
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY,
    username TEXT,
    password TEXT,
    session_token TEXT
  );
  CREATE TABLE IF NOT EXISTS api_config (
    id INTEGER PRIMARY KEY,
    key_name TEXT,
    key_value TEXT
  );
`);
db.prepare(`INSERT INTO users (username, password, session_token) VALUES (?, ?, ?)`)
  .run('testuser', 'Password123!', 'sess_a1b2c3d4e5f6');
db.prepare(`INSERT INTO api_config (key_name, key_value) VALUES (?, ?)`)
  .run('retrofit_api_key', 'AIzaSyD-9tSrke72PouQMnMX-a7eZSW0jkFMBWQ');
db.close();

fs.mkdirSync(path.join(mockDir, 'shared_prefs'), { recursive: true });
fs.writeFileSync(
  path.join(mockDir, 'shared_prefs', 'UserSession.xml'),
  `<?xml version='1.0' encoding='utf-8' standalone='yes' ?>
<map>
  <string name="auth_token">eyJhbGciOiJIUzI1NiJ9.mock.token</string>
  <string name="stripe_secret_key">sk_live_51H8xamplekey00000000</string>
  <boolean name="is_logged_in" value="true" />
</map>`
);

fs.writeFileSync(
  path.join(mockDir, 'AndroidManifest.xml'),
  `<?xml version="1.0" encoding="utf-8"?>
<manifest>
  <application>
    <provider
      android:name=".UserDataProvider"
      android:authorities="com.example.app.provider"
      android:exported="true" />
  </application>
</manifest>`
);

console.log('Mock vulnerable app data created in ./mock-data');
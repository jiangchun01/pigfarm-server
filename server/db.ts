// 数据库抽象层：SQLite + PostgreSQL 双模式
import Database from 'better-sqlite3';
import path from 'node:path';
import fs from 'node:fs';

// Node 端 logger（使用原生 console）
const logger = {
  info: (msg: string) => console.log(`[INFO] ${msg}`),
  warn: (msg: string) => console.warn(`[WARN] ${msg}`),
  error: (msg: string) => console.error(`[ERROR] ${msg}`),
};

export interface IStatement {
  run(...params: any[]): { changes: number; lastInsertRowid: number | bigint };
  get(...params: any[]): any;
  all(...params: any[]): any[];
}

export interface IDb {
  mode: 'sqlite' | 'postgres';
  prepare(sql: string): IStatement;
  exec(sql: string): void;
  transaction<T>(fn: (...args: any[]) => T): (...args: any[]) => T;
  pragma?(statement: string): any;
  close(): void;
}

class SqliteDb implements IDb {
  mode: 'sqlite' = 'sqlite';
  private db: Database.Database;

  constructor(dbPath: string) {
    fs.mkdirSync(path.dirname(dbPath), { recursive: true });
    this.db = new Database(dbPath);
    this.db.pragma('journal_mode = WAL');
    this.db.pragma('foreign_keys = ON');
  }

  prepare(sql: string): IStatement {
    const stmt = this.db.prepare(sql);
    return {
      run: (...params: any[]) => {
        const info = stmt.run(...params);
        return { changes: info.changes, lastInsertRowid: info.lastInsertRowid };
      },
      get: (...params: any[]) => stmt.get(...params),
      all: (...params: any[]) => stmt.all(...params),
    };
  }

  exec(sql: string): void { this.db.exec(sql); }

  transaction<T>(fn: (...args: any[]) => T): (...args: any[]) => T {
    return this.db.transaction(fn) as any;
  }

  pragma(statement: string): any { return this.db.pragma(statement); }

  close(): void { this.db.close(); }
}

function makeSyncWait(): (ms: number) => void {
  try {
    const deasync = require('deasync');
    return (ms: number) => deasync.sleep(ms);
  } catch {
    return (_ms: number) => {
      const start = Date.now();
      while (Date.now() - start < _ms) { /* spin */ }
    };
  }
}

class PgStatement implements IStatement {
  private sql: string;
  private pool: any;
  private client: any;
  private syncSleep: (ms: number) => void;

  constructor(sql: string, pool: any, client: any, syncSleep: (ms: number) => void) {
    this.sql = sql; this.pool = pool; this.client = client; this.syncSleep = syncSleep;
  }

  private normalizeParams(params: any[]): { text: string; values: any[] } {
    let text: string;
    let values: any[];
    if (this.sql.includes('?') && !this.sql.match(/[@$:][a-zA-Z_]/)) {
      let idx = 0;
      text = this.sql.replace(/\?/g, () => { idx++; return `$${idx}`; });
      values = params;
    } else if (params.length === 1 && typeof params[0] === 'object' && params[0] !== null) {
      const named = params[0] as Record<string, any>;
      const keys = Object.keys(named);
      const keyIdx = new Map<string, number>();
      keys.forEach((k, i) => keyIdx.set(k, i + 1));
      values = keys.map(k => named[k]);
      text = this.sql.replace(/[@$:]([a-zA-Z_][a-zA-Z0-9_]*)/g, (_m, name) => {
        const idx = keyIdx.get(name);
        return idx ? `$${idx}` : _m;
      });
    } else {
      text = this.sql;
      values = params;
    }
    // PostgreSQL: 为 INSERT INTO users 语句自动添加 RETURNING id（如果还没有的话）
    if (text.trim().toUpperCase().startsWith('INSERT') &&
        text.toUpperCase().includes('INTO USERS') &&
        !text.toUpperCase().includes('RETURNING')) {
      text = text.trim().replace(/;?\s*$/, '') + ' RETURNING id';
    }
    return { text, values };
  }

  private querySync(params: any[]): any {
    const { text, values } = this.normalizeParams(params);
    let done = false; let result: any = null; let err: Error | null = null;
    this.client.query(text, values).then((r: any) => { result = r; done = true; }).catch((e: Error) => { err = e; done = true; });
    let safety = 30000;
    while (!done && safety > 0) { this.syncSleep(5); safety -= 5; }
    if (!done) throw new Error('PostgreSQL query timeout');
    if (err) throw err;
    return result;
  }

  run(...params: any[]): { changes: number; lastInsertRowid: number | bigint } {
    const res = this.querySync(params);
    let lastId: number | bigint = 0;
    if (res.rows?.length > 0 && res.rows[0].id !== undefined) lastId = res.rows[0].id;
    return { changes: res.rowCount ?? 0, lastInsertRowid: lastId };
  }
  get(...params: any[]): any { const res = this.querySync(params); return res.rows?.[0]; }
  all(...params: any[]): any[] { const res = this.querySync(params); return res.rows ?? []; }
}

class PostgresDb implements IDb {
  mode: 'postgres' = 'postgres';
  private pool: any;
  private client: any;
  private syncSleep: (ms: number) => void;

  constructor(connectionString: string) {
    const { Pool } = require('pg');
    this.syncSleep = makeSyncWait();
    this.pool = new Pool({ connectionString, max: 2 });
    let done = false; let err: Error | null = null;
    this.pool.connect().then((c: any) => { this.client = c; done = true; }).catch((e: Error) => { err = e; done = true; });
    let safety = 10000;
    while (!done && safety > 0) { this.syncSleep(10); safety -= 10; }
    if (err) throw err;
    if (!done) throw new Error('PostgreSQL 连接超时');
  }

  prepare(sql: string): IStatement { return new PgStatement(sql, this.pool, this.client, this.syncSleep); }

  exec(sql: string): void {
    const statements = this.splitStatements(sql);
    for (const stmt of statements) {
      const trimmed = stmt.trim();
      if (!trimmed) continue;
      let done = false; let err: Error | null = null;
      this.client.query(trimmed).then(() => { done = true; }).catch((e: Error) => { err = e; done = true; });
      let safety = 10000;
      while (!done && safety > 0) { this.syncSleep(10); safety -= 10; }
      if (err) {
        logger.warn(`[db] exec 语句警告: ${String(err)} SQL: ${trimmed.slice(0, 80)}`);
        if (!trimmed.toUpperCase().includes('CREATE TABLE IF NOT EXISTS')) throw err;
      }
    }
  }

  private splitStatements(sql: string): string[] {
    const result: string[] = [];
    let current = '';
    let inSingleQuote = false;
    let inDoubleQuote = false;
    for (let i = 0; i < sql.length; i++) {
      const ch = sql[i];
      current += ch;
      if (ch === "'" && !inDoubleQuote) {
        if (inSingleQuote && sql[i + 1] === "'") { current += sql[i + 1]; i++; continue; }
        inSingleQuote = !inSingleQuote;
      } else if (ch === '"' && !inSingleQuote) {
        inDoubleQuote = !inDoubleQuote;
      } else if (ch === ';' && !inSingleQuote && !inDoubleQuote) {
        result.push(current.slice(0, -1));
        current = '';
      }
    }
    if (current.trim()) result.push(current);
    return result;
  }

  transaction<T>(fn: (...args: any[]) => T): (...args: any[]) => T {
    const self = this;
    return function (this: any, ...args: any[]): T {
      self.client.query('BEGIN').catch(() => {});
      try {
        const result = fn.apply(this, args);
        let committed = false;
        self.client.query('COMMIT').then(() => { committed = true; });
        let safety = 5000;
        while (!committed && safety > 0) { self.syncSleep(5); safety -= 5; }
        return result;
      } catch (e) {
        let rolled = false;
        self.client.query('ROLLBACK').then(() => { rolled = true; });
        let safety = 5000;
        while (!rolled && safety > 0) { self.syncSleep(5); safety -= 5; }
        throw e;
      }
    };
  }

  close(): void {
    try { if (this.client) this.client.release(); } catch { /* ignore */ }
    try { if (this.pool) this.pool.end(); } catch { /* ignore */ }
  }
}

const SQLITE_SCHEMA = `
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  created_at TEXT DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS farms (
  id TEXT PRIMARY KEY, user_id INTEGER NOT NULL,
  name TEXT NOT NULL, address TEXT, phone TEXT, manager TEXT,
  capacity_pens INTEGER DEFAULT 200, remark TEXT,
  created_at TEXT DEFAULT (datetime('now')),
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS barns (
  id TEXT PRIMARY KEY, farm_id TEXT NOT NULL,
  barn_no TEXT NOT NULL, barn_type TEXT NOT NULL DEFAULT 'fattening',
  pen_count INTEGER DEFAULT 0, last_occupied_date TEXT, remark TEXT,
  created_at TEXT DEFAULT (datetime('now')),
  FOREIGN KEY (farm_id) REFERENCES farms(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS batches (
  id TEXT PRIMARY KEY, farm_id TEXT NOT NULL,
  batch_no TEXT NOT NULL, entry_date TEXT NOT NULL,
  entry_age_days INTEGER DEFAULT 25, entry_count INTEGER DEFAULT 0,
  current_count INTEGER DEFAULT 0, breed TEXT,
  expected_slaughter_date TEXT, status TEXT DEFAULT 'active', remark TEXT,
  created_at TEXT DEFAULT (datetime('now')),
  FOREIGN KEY (farm_id) REFERENCES farms(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS batch_barns (
  id TEXT PRIMARY KEY, batch_id TEXT NOT NULL, barn_id TEXT NOT NULL,
  head_count INTEGER DEFAULT 0, entry_date TEXT, remark TEXT,
  FOREIGN KEY (batch_id) REFERENCES batches(id) ON DELETE CASCADE,
  FOREIGN KEY (barn_id) REFERENCES barns(id) ON DELETE SET NULL
);
CREATE TABLE IF NOT EXISTS feed_types (
  id TEXT PRIMARY KEY, farm_id TEXT NOT NULL,
  name TEXT NOT NULL, stage TEXT,
  stage_usage_per_head REAL DEFAULT 0, ref_price REAL DEFAULT 0, remark TEXT,
  FOREIGN KEY (farm_id) REFERENCES farms(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS stage_days (
  farm_id TEXT PRIMARY KEY,
  nursery_early INTEGER DEFAULT 7, nursery_mid INTEGER DEFAULT 10,
  nursery_late INTEGER DEFAULT 14, fatten_early INTEGER DEFAULT 20,
  fatten_mid INTEGER DEFAULT 30, fatten_late INTEGER DEFAULT 30,
  FOREIGN KEY (farm_id) REFERENCES farms(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS feed_records (
  id TEXT PRIMARY KEY, farm_id TEXT NOT NULL, batch_id TEXT NOT NULL,
  date TEXT NOT NULL, feed_type_id TEXT, feed_type_name TEXT,
  quantity REAL DEFAULT 0, unit_price REAL DEFAULT 0, amount REAL DEFAULT 0,
  operator TEXT, remark TEXT, created_at TEXT DEFAULT (datetime('now')),
  FOREIGN KEY (farm_id) REFERENCES farms(id) ON DELETE CASCADE,
  FOREIGN KEY (batch_id) REFERENCES batches(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS vaccines (
  id TEXT PRIMARY KEY, farm_id TEXT NOT NULL,
  name TEXT NOT NULL, type TEXT, unit TEXT,
  ref_price REAL DEFAULT 0, applicable_stage TEXT, remark TEXT,
  FOREIGN KEY (farm_id) REFERENCES farms(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS vaccine_records (
  id TEXT PRIMARY KEY, farm_id TEXT NOT NULL, batch_id TEXT,
  date TEXT, vaccine_id TEXT, vaccine_name TEXT, type TEXT,
  quantity REAL DEFAULT 0, unit TEXT, unit_price REAL DEFAULT 0,
  amount REAL DEFAULT 0, operator TEXT, remark TEXT,
  FOREIGN KEY (farm_id) REFERENCES farms(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS herd_records (
  id TEXT PRIMARY KEY, farm_id TEXT NOT NULL, batch_id TEXT,
  barn_id TEXT, date TEXT, change_type TEXT,
  change_count INTEGER DEFAULT 0, operator TEXT, remark TEXT,
  FOREIGN KEY (farm_id) REFERENCES farms(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS finance_records (
  id TEXT PRIMARY KEY, farm_id TEXT NOT NULL, type TEXT NOT NULL,
  category TEXT, amount REAL DEFAULT 0, date TEXT,
  batch_id TEXT, investor TEXT, remark TEXT,
  FOREIGN KEY (farm_id) REFERENCES farms(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS finance_categories (
  id TEXT PRIMARY KEY, farm_id TEXT NOT NULL,
  type TEXT NOT NULL, name TEXT NOT NULL,
  FOREIGN KEY (farm_id) REFERENCES farms(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS todos (
  id TEXT PRIMARY KEY, farm_id TEXT NOT NULL,
  title TEXT NOT NULL, task_type TEXT, task_date TEXT,
  finished INTEGER DEFAULT 0, priority TEXT DEFAULT 'mid',
  batch_id TEXT, remark TEXT,
  FOREIGN KEY (farm_id) REFERENCES farms(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS alert_thresholds (
  farm_id TEXT PRIMARY KEY,
  herd_fluctuation REAL DEFAULT 10, feed_intake REAL DEFAULT 80,
  survival_rate REAL DEFAULT 90, empty_pen_days INTEGER DEFAULT 30,
  animal_health_cost REAL DEFAULT 50,
  FOREIGN KEY (farm_id) REFERENCES farms(id) ON DELETE CASCADE
);
`;

// PostgreSQL 专用 schema（使用 SERIAL 自增和 CURRENT_TIMESTAMP）
const PG_SCHEMA = `
CREATE TABLE IF NOT EXISTS users (
  id SERIAL PRIMARY KEY,
  username TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS farms (
  id TEXT PRIMARY KEY, user_id INTEGER NOT NULL,
  name TEXT NOT NULL, address TEXT, phone TEXT, manager TEXT,
  capacity_pens INTEGER DEFAULT 200, remark TEXT,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS barns (
  id TEXT PRIMARY KEY, farm_id TEXT NOT NULL,
  barn_no TEXT NOT NULL, barn_type TEXT NOT NULL DEFAULT 'fattening',
  pen_count INTEGER DEFAULT 0, last_occupied_date TEXT, remark TEXT,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (farm_id) REFERENCES farms(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS batches (
  id TEXT PRIMARY KEY, farm_id TEXT NOT NULL,
  batch_no TEXT NOT NULL, entry_date TEXT NOT NULL,
  entry_age_days INTEGER DEFAULT 25, entry_count INTEGER DEFAULT 0,
  current_count INTEGER DEFAULT 0, breed TEXT,
  expected_slaughter_date TEXT, status TEXT DEFAULT 'active', remark TEXT,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (farm_id) REFERENCES farms(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS batch_barns (
  id TEXT PRIMARY KEY, batch_id TEXT NOT NULL, barn_id TEXT NOT NULL,
  head_count INTEGER DEFAULT 0, entry_date TEXT, remark TEXT,
  FOREIGN KEY (batch_id) REFERENCES batches(id) ON DELETE CASCADE,
  FOREIGN KEY (barn_id) REFERENCES barns(id) ON DELETE SET NULL
);
CREATE TABLE IF NOT EXISTS feed_types (
  id TEXT PRIMARY KEY, farm_id TEXT NOT NULL,
  name TEXT NOT NULL, stage TEXT,
  stage_usage_per_head REAL DEFAULT 0, ref_price REAL DEFAULT 0, remark TEXT,
  FOREIGN KEY (farm_id) REFERENCES farms(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS stage_days (
  farm_id TEXT PRIMARY KEY,
  nursery_early INTEGER DEFAULT 7, nursery_mid INTEGER DEFAULT 10,
  nursery_late INTEGER DEFAULT 14, fatten_early INTEGER DEFAULT 20,
  fatten_mid INTEGER DEFAULT 30, fatten_late INTEGER DEFAULT 30,
  FOREIGN KEY (farm_id) REFERENCES farms(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS feed_records (
  id TEXT PRIMARY KEY, farm_id TEXT NOT NULL, batch_id TEXT NOT NULL,
  date TEXT NOT NULL, feed_type_id TEXT, feed_type_name TEXT,
  quantity REAL DEFAULT 0, unit_price REAL DEFAULT 0, amount REAL DEFAULT 0,
  operator TEXT, remark TEXT, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (farm_id) REFERENCES farms(id) ON DELETE CASCADE,
  FOREIGN KEY (batch_id) REFERENCES batches(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS vaccines (
  id TEXT PRIMARY KEY, farm_id TEXT NOT NULL,
  name TEXT NOT NULL, type TEXT, unit TEXT,
  ref_price REAL DEFAULT 0, applicable_stage TEXT, remark TEXT,
  FOREIGN KEY (farm_id) REFERENCES farms(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS vaccine_records (
  id TEXT PRIMARY KEY, farm_id TEXT NOT NULL, batch_id TEXT,
  date TEXT, vaccine_id TEXT, vaccine_name TEXT, type TEXT,
  quantity REAL DEFAULT 0, unit TEXT, unit_price REAL DEFAULT 0,
  amount REAL DEFAULT 0, operator TEXT, remark TEXT,
  FOREIGN KEY (farm_id) REFERENCES farms(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS herd_records (
  id TEXT PRIMARY KEY, farm_id TEXT NOT NULL, batch_id TEXT,
  barn_id TEXT, date TEXT, change_type TEXT,
  change_count INTEGER DEFAULT 0, operator TEXT, remark TEXT,
  FOREIGN KEY (farm_id) REFERENCES farms(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS finance_records (
  id TEXT PRIMARY KEY, farm_id TEXT NOT NULL, type TEXT NOT NULL,
  category TEXT, amount REAL DEFAULT 0, date TEXT,
  batch_id TEXT, investor TEXT, remark TEXT,
  FOREIGN KEY (farm_id) REFERENCES farms(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS finance_categories (
  id TEXT PRIMARY KEY, farm_id TEXT NOT NULL,
  type TEXT NOT NULL, name TEXT NOT NULL,
  FOREIGN KEY (farm_id) REFERENCES farms(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS todos (
  id TEXT PRIMARY KEY, farm_id TEXT NOT NULL,
  title TEXT NOT NULL, task_type TEXT, task_date TEXT,
  finished INTEGER DEFAULT 0, priority TEXT DEFAULT 'mid',
  batch_id TEXT, remark TEXT,
  FOREIGN KEY (farm_id) REFERENCES farms(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS alert_thresholds (
  farm_id TEXT PRIMARY KEY,
  herd_fluctuation REAL DEFAULT 10, feed_intake REAL DEFAULT 80,
  survival_rate REAL DEFAULT 90, empty_pen_days INTEGER DEFAULT 30,
  animal_health_cost REAL DEFAULT 50,
  FOREIGN KEY (farm_id) REFERENCES farms(id) ON DELETE CASCADE
);
`;

let dbInstance: IDb | null = null;

export function getDb(dbPath?: string): IDb {
  if (dbInstance) return dbInstance;
  const dbUrl = process.env.DATABASE_URL;
  if (dbUrl && dbUrl.startsWith('postgres')) {
    try {
      const pgDb = new PostgresDb(dbUrl);
      pgDb.exec(PG_SCHEMA);
      dbInstance = pgDb;
      logger.info(`[db] PostgreSQL 模式已就绪: ${dbUrl.slice(0, 30)}...`);
      return dbInstance;
    } catch (e) {
      logger.warn(`[db] PostgreSQL 连接失败，降级到 SQLite: ${String(e)}`);
    }
  }
  const dbFile = dbPath || process.env.DB_PATH || path.resolve(process.cwd(), 'data', 'pigfarm.db');
  const sqliteDb = new SqliteDb(dbFile);
  sqliteDb.exec(SQLITE_SCHEMA);
  dbInstance = sqliteDb;
  logger.info(`[db] SQLite 模式已就绪: ${dbFile}`);
  return dbInstance;
}

export function _resetDb() {
  if (dbInstance) { dbInstance.close(); dbInstance = null; }
}

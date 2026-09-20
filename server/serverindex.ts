// 云同步后端服务：Express + SQLite + JWT
import express from 'express';
import cors from 'cors';
import { getDb } from './db';
import type { IDb } from './db';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import crypto from 'node:crypto';

// Node 端 logger（使用原生 console）
const logger = {
  info: (msg: string) => console.log(`[INFO] ${msg}`),
  warn: (msg: string) => console.warn(`[WARN] ${msg}`),
  error: (msg: string) => console.error(`[ERROR] ${msg}`),
};

type DbInstance = IDb;

const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(32).toString('hex');
const JWT_EXPIRES_IN = '7d';

function genId(prefix: string): string {
  return `${prefix}_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;
}

interface AuthUser {
  id: number;
  username: string;
}

declare global {
  namespace Express {
    interface Request {
      user?: AuthUser;
    }
  }
}

function authMiddleware(
  req: express.Request,
  res: express.Response,
  next: express.NextFunction,
): void {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : '';
  if (!token) { res.status(401).json({ error: '未登录' }); return; }
  try {
    const payload = jwt.verify(token, JWT_SECRET) as AuthUser;
    req.user = payload;
    next();
  } catch {
    res.status(401).json({ error: '登录已过期，请重新登录' });
  }
}

function checkFarmOwnership(
  req: express.Request,
  res: express.Response,
  farmId: string | string[],
): boolean {
  const fid = Array.isArray(farmId) ? farmId[0] : farmId;
  const db = getDb();
  const row = db.prepare('SELECT user_id FROM farms WHERE id = ?').get(fid) as { user_id: number } | undefined;
  if (!row || row.user_id !== req.user?.id) {
    res.status(403).json({ error: '无权访问该猪场数据' });
    return false;
  }
  return true;
}

export function createApp(): express.Express {
  const app = express();
  const isProd = process.env.NODE_ENV === 'production';
  if (isProd) { app.use(cors()); } else { app.use(cors()); }
  app.use(express.json({ limit: '10mb' }));
  const db = getDb();

  // ============ 认证 ============
  app.post('/api/auth/register', (req, res) => {
    const { username, password, farmName } = req.body;
    if (!username || !password) { res.status(400).json({ error: '用户名和密码不能为空' }); return; }
    const exists = db.prepare('SELECT id FROM users WHERE username = ?').get(username);
    if (exists) { res.status(400).json({ error: '用户名已存在' }); return; }
    const hash = bcrypt.hashSync(password, 10);
    const info = db.prepare('INSERT INTO users (username, password_hash) VALUES (?, ?)').run(username, hash);
    const userId = info.lastInsertRowid as number;
    seedDemoData(db, userId, farmName || `${username}的猪场`);
    const token = jwt.sign({ id: userId, username }, JWT_SECRET, { expiresIn: JWT_EXPIRES_IN });
    res.json({ token, user: { id: userId, username } });
  });

  app.post('/api/auth/login', (req, res) => {
    const { username, password } = req.body;
    const row = db.prepare('SELECT * FROM users WHERE username = ?').get(username) as any;
    if (!row || !bcrypt.compareSync(password, row.password_hash)) {
      res.status(401).json({ error: '用户名或密码错误' }); return;
    }
    const token = jwt.sign({ id: row.id, username: row.username }, JWT_SECRET, { expiresIn: JWT_EXPIRES_IN });
    res.json({ token, user: { id: row.id, username: row.username } });
  });

  app.get('/api/auth/me', authMiddleware, (req, res) => {
    res.json({ user: req.user });
  });

  // ============ 猪场 ============
  app.get('/api/farms', authMiddleware, (req, res) => {
    const farms = db.prepare('SELECT * FROM farms WHERE user_id = ? ORDER BY created_at').all(req.user!.id);
    res.json(farms);
  });

  app.post('/api/farms', authMiddleware, (req, res) => {
    const { name, address, phone, manager, capacityPens, remark } = req.body;
    const id = genId('farm');
    db.prepare(
      `INSERT INTO farms (id, user_id, name, address, phone, manager, capacity_pens, remark)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
    ).run(id, req.user!.id, name, address || null, phone || null, manager || null, capacityPens || 200, remark || null);
    initFarmDefaults(db, id);
    const farm = db.prepare('SELECT * FROM farms WHERE id = ?').get(id);
    res.json(farm);
  });

  app.put('/api/farms/:id', authMiddleware, (req, res) => {
    const farmId = req.params.id;
    if (!checkFarmOwnership(req, res, farmId)) return;
    const { name, address, phone, manager, capacityPens, remark } = req.body;
    db.prepare(
      `UPDATE farms SET name = COALESCE(?, name), address = COALESCE(?, address),
       phone = COALESCE(?, phone), manager = COALESCE(?, manager),
       capacity_pens = COALESCE(?, capacity_pens), remark = COALESCE(?, remark)
       WHERE id = ?`,
    ).run(name, address, phone, manager, capacityPens, remark, farmId);
    const farm = db.prepare('SELECT * FROM farms WHERE id = ?').get(farmId);
    res.json(farm);
  });

  app.delete('/api/farms/:id', authMiddleware, (req, res) => {
    const farmId = req.params.id;
    if (!checkFarmOwnership(req, res, farmId)) return;
    db.prepare('DELETE FROM farms WHERE id = ?').run(farmId);
    res.json({ ok: true });
  });

  // ============ 栋舍 ============
  app.get('/api/farms/:farmId/barns', authMiddleware, (req, res) => {
    const { farmId } = req.params;
    if (!checkFarmOwnership(req, res, farmId)) return;
    const rows = db.prepare('SELECT * FROM barns WHERE farm_id = ? ORDER BY created_at').all(farmId);
    res.json(rows.map(rowToBarn));
  });

  app.post('/api/barns', authMiddleware, (req, res) => {
    const { farmId, barnNo, barnType, penCount, lastOccupiedDate, remark } = req.body;
    if (!checkFarmOwnership(req, res, farmId)) return;
    const id = genId('barn');
    db.prepare(
      `INSERT INTO barns (id, farm_id, barn_no, barn_type, pen_count, last_occupied_date, remark)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
    ).run(id, farmId, barnNo, barnType || 'fattening', penCount || 0, lastOccupiedDate || null, remark || null);
    const barn = db.prepare('SELECT * FROM barns WHERE id = ?').get(id);
    res.json(rowToBarn(barn as any));
  });

  app.put('/api/barns/:id', authMiddleware, (req, res) => {
    const id = req.params.id;
    const barn = db.prepare('SELECT * FROM barns WHERE id = ?').get(id) as any;
    if (!barn || !checkFarmOwnership(req, res, barn.farm_id)) return;
    const { barnNo, barnType, penCount, lastOccupiedDate, remark } = req.body;
    db.prepare(
      `UPDATE barns SET barn_no = COALESCE(?, barn_no), barn_type = COALESCE(?, barn_type),
       pen_count = COALESCE(?, pen_count), last_occupied_date = COALESCE(?, last_occupied_date),
       remark = COALESCE(?, remark) WHERE id = ?`,
    ).run(barnNo, barnType, penCount, lastOccupiedDate, remark, id);
    const updated = db.prepare('SELECT * FROM barns WHERE id = ?').get(id);
    res.json(rowToBarn(updated as any));
  });

  app.delete('/api/barns/:id', authMiddleware, (req, res) => {
    const id = req.params.id;
    const barn = db.prepare('SELECT * FROM barns WHERE id = ?').get(id) as any;
    if (!barn || !checkFarmOwnership(req, res, barn.farm_id)) return;
    db.prepare('DELETE FROM barns WHERE id = ?').run(id);
    res.json({ ok: true });
  });

  // ============ 批次 ============
  app.get('/api/farms/:farmId/batches', authMiddleware, (req, res) => {
    const { farmId } = req.params;
    if (!checkFarmOwnership(req, res, farmId)) return;
    const rows = db.prepare('SELECT * FROM batches WHERE farm_id = ? ORDER BY entry_date DESC').all(farmId);
    const batches = rows.map((r: any) => {
      const b = rowToBatch(r);
      const assignments = db.prepare('SELECT * FROM batch_barns WHERE batch_id = ?').all(b.id).map((a: any) => rowToBatchBarn(a));
      return { ...b, barnAssignments: assignments };
    });
    res.json(batches);
  });

  app.post('/api/batches', authMiddleware, (req, res) => {
    const { farmId, batchNo, entryDate, entryAgeDays, entryCount, currentCount, breed, expectedSlaughterDate, status, remark, barnAssignments } = req.body;
    if (!checkFarmOwnership(req, res, farmId)) return;
    const id = genId('batch');
    db.prepare(
      `INSERT INTO batches (id, farm_id, batch_no, entry_date, entry_age_days, entry_count,
       current_count, breed, expected_slaughter_date, status, remark)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    ).run(id, farmId, batchNo, entryDate, entryAgeDays || 25, entryCount || 0, currentCount || entryCount || 0, breed || null, expectedSlaughterDate || null, status || 'active', remark || null);
    if (Array.isArray(barnAssignments) && barnAssignments.length > 0) {
      const ins = db.prepare(
        `INSERT INTO batch_barns (id, batch_id, barn_id, head_count, entry_date, remark)
         VALUES (?, ?, ?, ?, ?, ?)`,
      );
      for (const a of barnAssignments) {
        ins.run(a.id || genId('ba'), id, a.barnId, a.headCount || 0, a.entryDate || entryDate, a.remark || null);
      }
    }
    const batch = db.prepare('SELECT * FROM batches WHERE id = ?').get(id);
    const assignments = db.prepare('SELECT * FROM batch_barns WHERE batch_id = ?').all(id).map((a: any) => rowToBatchBarn(a));
    res.json({ ...rowToBatch(batch as any), barnAssignments: assignments });
  });

  app.put('/api/batches/:id', authMiddleware, (req, res) => {
    const id = req.params.id;
    const existing = db.prepare('SELECT * FROM batches WHERE id = ?').get(id) as any;
    if (!existing || !checkFarmOwnership(req, res, existing.farm_id)) return;
    const { batchNo, entryDate, entryAgeDays, entryCount, currentCount, breed, expectedSlaughterDate, status, remark, barnAssignments } = req.body;
    db.prepare(
      `UPDATE batches SET batch_no = COALESCE(?, batch_no), entry_date = COALESCE(?, entry_date),
       entry_age_days = COALESCE(?, entry_age_days), entry_count = COALESCE(?, entry_count),
       current_count = COALESCE(?, current_count), breed = COALESCE(?, breed),
       expected_slaughter_date = COALESCE(?, expected_slaughter_date),
       status = COALESCE(?, status), remark = COALESCE(?, remark)
       WHERE id = ?`,
    ).run(batchNo, entryDate, entryAgeDays, entryCount, currentCount, breed, expectedSlaughterDate, status, remark, id);
    if (Array.isArray(barnAssignments)) {
      db.prepare('DELETE FROM batch_barns WHERE batch_id = ?').run(id);
      if (barnAssignments.length > 0) {
        const ins = db.prepare(
          `INSERT INTO batch_barns (id, batch_id, barn_id, head_count, entry_date, remark)
           VALUES (?, ?, ?, ?, ?, ?)`,
        );
        for (const a of barnAssignments) {
          ins.run(a.id || genId('ba'), id, a.barnId, a.headCount || 0, a.entryDate || entryDate || existing.entry_date, a.remark || null);
        }
      }
    }
    const batch = db.prepare('SELECT * FROM batches WHERE id = ?').get(id);
    const assignments = db.prepare('SELECT * FROM batch_barns WHERE batch_id = ?').all(id).map((a: any) => rowToBatchBarn(a));
    res.json({ ...rowToBatch(batch as any), barnAssignments: assignments });
  });

  app.delete('/api/batches/:id', authMiddleware, (req, res) => {
    const id = req.params.id;
    const existing = db.prepare('SELECT * FROM batches WHERE id = ?').get(id) as any;
    if (!existing || !checkFarmOwnership(req, res, existing.farm_id)) return;
    db.prepare('DELETE FROM batches WHERE id = ?').run(id);
    res.json({ ok: true });
  });

  // ============ 饲料类型 ============
  app.get('/api/farms/:farmId/feed-types', authMiddleware, (req, res) => {
    const { farmId } = req.params;
    if (!checkFarmOwnership(req, res, farmId)) return;
    const rows = db.prepare('SELECT * FROM feed_types WHERE farm_id = ?').all(farmId);
    res.json(rows.map((r: any) => rowToFeedType(r)));
  });

  app.post('/api/feed-types', authMiddleware, (req, res) => {
    const { farmId, name, stage, stageUsagePerHead, refPrice, remark } = req.body;
    if (!checkFarmOwnership(req, res, farmId)) return;
    const id = genId('feed');
    db.prepare(
      `INSERT INTO feed_types (id, farm_id, name, stage, stage_usage_per_head, ref_price, remark)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
    ).run(id, farmId, name, stage || null, stageUsagePerHead || 0, refPrice || 0, remark || null);
    const row = db.prepare('SELECT * FROM feed_types WHERE id = ?').get(id);
    res.json(rowToFeedType(row as any));
  });

  app.put('/api/feed-types/:id', authMiddleware, (req, res) => {
    const id = req.params.id;
    const row = db.prepare('SELECT * FROM feed_types WHERE id = ?').get(id) as any;
    if (!row || !checkFarmOwnership(req, res, row.farm_id)) return;
    const { name, stage, stageUsagePerHead, refPrice, remark } = req.body;
    db.prepare(
      `UPDATE feed_types SET name = COALESCE(?, name), stage = COALESCE(?, stage),
       stage_usage_per_head = COALESCE(?, stage_usage_per_head),
       ref_price = COALESCE(?, ref_price), remark = COALESCE(?, remark) WHERE id = ?`,
    ).run(name, stage, stageUsagePerHead, refPrice, remark, id);
    const updated = db.prepare('SELECT * FROM feed_types WHERE id = ?').get(id);
    res.json(rowToFeedType(updated as any));
  });

  app.delete('/api/feed-types/:id', authMiddleware, (req, res) => {
    const id = req.params.id;
    const row = db.prepare('SELECT * FROM feed_types WHERE id = ?').get(id) as any;
    if (!row || !checkFarmOwnership(req, res, row.farm_id)) return;
    db.prepare('DELETE FROM feed_types WHERE id = ?').run(id);
    res.json({ ok: true });
  });

  // ============ 阶段天数 ============
  app.get('/api/farms/:farmId/stage-days', authMiddleware, (req, res) => {
    const { farmId } = req.params;
    if (!checkFarmOwnership(req, res, farmId)) return;
    let row = db.prepare('SELECT * FROM stage_days WHERE farm_id = ?').get(farmId) as any;
    if (!row) { row = { nursery_early: 7, nursery_mid: 10, nursery_late: 14, fatten_early: 20, fatten_mid: 30, fatten_late: 30 }; }
    res.json({ nursery_early: row.nursery_early, nursery_mid: row.nursery_mid, nursery_late: row.nursery_late, fatten_early: row.fatten_early, fatten_mid: row.fatten_mid, fatten_late: row.fatten_late });
  });

  app.put('/api/farms/:farmId/stage-days', authMiddleware, (req, res) => {
    const { farmId } = req.params;
    if (!checkFarmOwnership(req, res, farmId)) return;
    const d = req.body || {};
    db.prepare(
      `INSERT OR REPLACE INTO stage_days
       (farm_id, nursery_early, nursery_mid, nursery_late, fatten_early, fatten_mid, fatten_late)
       VALUES (?, COALESCE(?, 7), COALESCE(?, 10), COALESCE(?, 14), COALESCE(?, 20), COALESCE(?, 30), COALESCE(?, 30))`,
    ).run(farmId, d.nursery_early, d.nursery_mid, d.nursery_late, d.fatten_early, d.fatten_mid, d.fatten_late);
    const row = db.prepare('SELECT * FROM stage_days WHERE farm_id = ?').get(farmId);
    res.json(row);
  });

  // ============ 饲料领用记录 ============
  app.get('/api/batches/:batchId/feed-records', authMiddleware, (req, res) => {
    const { batchId } = req.params;
    const batch = db.prepare('SELECT * FROM batches WHERE id = ?').get(batchId) as any;
    if (!batch || !checkFarmOwnership(req, res, batch.farm_id)) return;
    const rows = db.prepare('SELECT * FROM feed_records WHERE batch_id = ? ORDER BY date DESC').all(batchId);
    res.json(rows.map((r: any) => rowToFeedRecord(r)));
  });

  app.get('/api/farms/:farmId/feed-records', authMiddleware, (req, res) => {
    const { farmId } = req.params;
    if (!checkFarmOwnership(req, res, farmId)) return;
    const rows = db.prepare('SELECT * FROM feed_records WHERE farm_id = ? ORDER BY date DESC').all(farmId);
    res.json(rows.map((r: any) => rowToFeedRecord(r)));
  });

  app.post('/api/feed-records', authMiddleware, (req, res) => {
    const { farmId, batchId, date, feedTypeId, feedTypeName, quantity, unitPrice, amount, operator, remark } = req.body;
    if (!checkFarmOwnership(req, res, farmId)) return;
    const id = genId('fr');
    db.prepare(
      `INSERT INTO feed_records (id, farm_id, batch_id, date, feed_type_id, feed_type_name,
       quantity, unit_price, amount, operator, remark)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    ).run(id, farmId, batchId, date, feedTypeId || null, feedTypeName || null, quantity || 0, unitPrice || 0, amount || 0, operator || null, remark || null);
    const row = db.prepare('SELECT * FROM feed_records WHERE id = ?').get(id);
    res.json(rowToFeedRecord(row as any));
  });

  app.put('/api/feed-records/:id', authMiddleware, (req, res) => {
    const id = req.params.id;
    const row = db.prepare('SELECT * FROM feed_records WHERE id = ?').get(id) as any;
    if (!row || !checkFarmOwnership(req, res, row.farm_id)) return;
    const { date, feedTypeId, feedTypeName, quantity, unitPrice, amount, operator, remark } = req.body;
    db.prepare(
      `UPDATE feed_records SET date = COALESCE(?, date), feed_type_id = COALESCE(?, feed_type_id),
       feed_type_name = COALESCE(?, feed_type_name), quantity = COALESCE(?, quantity),
       unit_price = COALESCE(?, unit_price), amount = COALESCE(?, amount),
       operator = COALESCE(?, operator), remark = COALESCE(?, remark) WHERE id = ?`,
    ).run(date, feedTypeId, feedTypeName, quantity, unitPrice, amount, operator, remark, id);
    const updated = db.prepare('SELECT * FROM feed_records WHERE id = ?').get(id);
    res.json(rowToFeedRecord(updated as any));
  });

  app.delete('/api/feed-records/:id', authMiddleware, (req, res) => {
    const id = req.params.id;
    const row = db.prepare('SELECT * FROM feed_records WHERE id = ?').get(id) as any;
    if (!row || !checkFarmOwnership(req, res, row.farm_id)) return;
    db.prepare('DELETE FROM feed_records WHERE id = ?').run(id);
    res.json({ ok: true });
  });

  // ============ 药品疫苗目录 ============
  app.get('/api/farms/:farmId/vaccines', authMiddleware, (req, res) => {
    const { farmId } = req.params;
    if (!checkFarmOwnership(req, res, farmId)) return;
    const rows = db.prepare('SELECT * FROM vaccines WHERE farm_id = ?').all(farmId);
    res.json(rows.map((r: any) => rowToVaccine(r)));
  });

  app.post('/api/vaccines', authMiddleware, (req, res) => {
    const { farmId, name, type, unit, refPrice, applicableStage, remark } = req.body;
    if (!checkFarmOwnership(req, res, farmId)) return;
    const id = genId('vac');
    db.prepare(
      `INSERT INTO vaccines (id, farm_id, name, type, unit, ref_price, applicable_stage, remark)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
    ).run(id, farmId, name, type || null, unit || null, refPrice || 0, applicableStage || null, remark || null);
    const row = db.prepare('SELECT * FROM vaccines WHERE id = ?').get(id);
    res.json(rowToVaccine(row as any));
  });

  app.put('/api/vaccines/:id', authMiddleware, (req, res) => {
    const id = req.params.id;
    const row = db.prepare('SELECT * FROM vaccines WHERE id = ?').get(id) as any;
    if (!row || !checkFarmOwnership(req, res, row.farm_id)) return;
    const { name, type, unit, refPrice, applicableStage, remark } = req.body;
    db.prepare(
      `UPDATE vaccines SET name = COALESCE(?, name), type = COALESCE(?, type),
       unit = COALESCE(?, unit), ref_price = COALESCE(?, ref_price),
       applicable_stage = COALESCE(?, applicable_stage), remark = COALESCE(?, remark) WHERE id = ?`,
    ).run(name, type, unit, refPrice, applicableStage, remark, id);
    const updated = db.prepare('SELECT * FROM vaccines WHERE id = ?').get(id);
    res.json(rowToVaccine(updated as any));
  });

  app.delete('/api/vaccines/:id', authMiddleware, (req, res) => {
    const id = req.params.id;
    const row = db.prepare('SELECT * FROM vaccines WHERE id = ?').get(id) as any;
    if (!row || !checkFarmOwnership(req, res, row.farm_id)) return;
    db.prepare('DELETE FROM vaccines WHERE id = ?').run(id);
    res.json({ ok: true });
  });

  // ============ 疫苗领用记录 ============
  app.get('/api/farms/:farmId/vaccine-records', authMiddleware, (req, res) => {
    const { farmId } = req.params;
    if (!checkFarmOwnership(req, res, farmId)) return;
    const rows = db.prepare('SELECT * FROM vaccine_records WHERE farm_id = ? ORDER BY date DESC').all(farmId);
    res.json(rows.map((r: any) => rowToVaccineRecord(r)));
  });

  app.post('/api/vaccine-records', authMiddleware, (req, res) => {
    const { farmId, batchId, date, vaccineId, vaccineName, type, quantity, unit, unitPrice, amount, operator, remark } = req.body;
    if (!checkFarmOwnership(req, res, farmId)) return;
    const id = genId('vr');
    db.prepare(
      `INSERT INTO vaccine_records (id, farm_id, batch_id, date, vaccine_id, vaccine_name,
       type, quantity, unit, unit_price, amount, operator, remark)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    ).run(id, farmId, batchId || null, date, vaccineId || null, vaccineName || null, type || null, quantity || 0, unit || null, unitPrice || 0, amount || 0, operator || null, remark || null);
    const row = db.prepare('SELECT * FROM vaccine_records WHERE id = ?').get(id);
    res.json(rowToVaccineRecord(row as any));
  });

  app.put('/api/vaccine-records/:id', authMiddleware, (req, res) => {
    const id = req.params.id;
    const row = db.prepare('SELECT * FROM vaccine_records WHERE id = ?').get(id) as any;
    if (!row || !checkFarmOwnership(req, res, row.farm_id)) return;
    const { date, vaccineId, vaccineName, type, quantity, unit, unitPrice, amount, operator, remark } = req.body;
    db.prepare(
      `UPDATE vaccine_records SET date = COALESCE(?, date), vaccine_id = COALESCE(?, vaccine_id),
       vaccine_name = COALESCE(?, vaccine_name), type = COALESCE(?, type),
       quantity = COALESCE(?, quantity), unit = COALESCE(?, unit),
       unit_price = COALESCE(?, unit_price), amount = COALESCE(?, amount),
       operator = COALESCE(?, operator), remark = COALESCE(?, remark) WHERE id = ?`,
    ).run(date, vaccineId, vaccineName, type, quantity, unit, unitPrice, amount, operator, remark, id);
    const updated = db.prepare('SELECT * FROM vaccine_records WHERE id = ?').get(id);
    res.json(rowToVaccineRecord(updated as any));
  });

  app.delete('/api/vaccine-records/:id', authMiddleware, (req, res) => {
    const id = req.params.id;
    const row = db.prepare('SELECT * FROM vaccine_records WHERE id = ?').get(id) as any;
    if (!row || !checkFarmOwnership(req, res, row.farm_id)) return;
    db.prepare('DELETE FROM vaccine_records WHERE id = ?').run(id);
    res.json({ ok: true });
  });

  // ============ 存栏变动 ============
  app.get('/api/farms/:farmId/herd-records', authMiddleware, (req, res) => {
    const { farmId } = req.params;
    if (!checkFarmOwnership(req, res, farmId)) return;
    const rows = db.prepare('SELECT * FROM herd_records WHERE farm_id = ? ORDER BY date DESC').all(farmId);
    res.json(rows.map((r: any) => rowToHerdRecord(r)));
  });

  app.post('/api/herd-records', authMiddleware, (req, res) => {
    const { farmId, batchId, barnId, date, changeType, changeCount, operator, remark } = req.body;
    if (!checkFarmOwnership(req, res, farmId)) return;
    const id = genId('hr');
    db.prepare(
      `INSERT INTO herd_records (id, farm_id, batch_id, barn_id, date, change_type, change_count, operator, remark)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    ).run(id, farmId, batchId || null, barnId || null, date, changeType, changeCount || 0, operator || null, remark || null);
    const row = db.prepare('SELECT * FROM herd_records WHERE id = ?').get(id);
    res.json(rowToHerdRecord(row as any));
  });

  app.put('/api/herd-records/:id', authMiddleware, (req, res) => {
    const id = req.params.id;
    const row = db.prepare('SELECT * FROM herd_records WHERE id = ?').get(id) as any;
    if (!row || !checkFarmOwnership(req, res, row.farm_id)) return;
    const { date, changeType, changeCount, operator, remark } = req.body;
    db.prepare(
      `UPDATE herd_records SET date = COALESCE(?, date), change_type = COALESCE(?, change_type),
       change_count = COALESCE(?, change_count), operator = COALESCE(?, operator),
       remark = COALESCE(?, remark) WHERE id = ?`,
    ).run(date, changeType, changeCount, operator, remark, id);
    const updated = db.prepare('SELECT * FROM herd_records WHERE id = ?').get(id);
    res.json(rowToHerdRecord(updated as any));
  });

  app.delete('/api/herd-records/:id', authMiddleware, (req, res) => {
    const id = req.params.id;
    const row = db.prepare('SELECT * FROM herd_records WHERE id = ?').get(id) as any;
    if (!row || !checkFarmOwnership(req, res, row.farm_id)) return;
    db.prepare('DELETE FROM herd_records WHERE id = ?').run(id);
    res.json({ ok: true });
  });

  // ============ 收支记录 ============
  app.get('/api/farms/:farmId/finance-records', authMiddleware, (req, res) => {
    const { farmId } = req.params;
    if (!checkFarmOwnership(req, res, farmId)) return;
    const rows = db.prepare('SELECT * FROM finance_records WHERE farm_id = ? ORDER BY date DESC').all(farmId);
    res.json(rows.map((r: any) => rowToFinanceRecord(r)));
  });

  app.post('/api/finance-records', authMiddleware, (req, res) => {
    const { farmId, type, category, amount, date, batchId, investor, remark } = req.body;
    if (!checkFarmOwnership(req, res, farmId)) return;
    const id = genId('fin');
    db.prepare(
      `INSERT INTO finance_records (id, farm_id, type, category, amount, date, batch_id, investor, remark)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    ).run(id, farmId, type, category || null, amount || 0, date, batchId || null, investor || null, remark || null);
    const row = db.prepare('SELECT * FROM finance_records WHERE id = ?').get(id);
    res.json(rowToFinanceRecord(row as any));
  });

  app.put('/api/finance-records/:id', authMiddleware, (req, res) => {
    const id = req.params.id;
    const row = db.prepare('SELECT * FROM finance_records WHERE id = ?').get(id) as any;
    if (!row || !checkFarmOwnership(req, res, row.farm_id)) return;
    const { type, category, amount, date, batchId, investor, remark } = req.body;
    db.prepare(
      `UPDATE finance_records SET type = COALESCE(?, type), category = COALESCE(?, category),
       amount = COALESCE(?, amount), date = COALESCE(?, date), batch_id = COALESCE(?, batch_id),
       investor = COALESCE(?, investor), remark = COALESCE(?, remark) WHERE id = ?`,
    ).run(type, category, amount, date, batchId, investor, remark, id);
    const updated = db.prepare('SELECT * FROM finance_records WHERE id = ?').get(id);
    res.json(rowToFinanceRecord(updated as any));
  });

  app.delete('/api/finance-records/:id', authMiddleware, (req, res) => {
    const id = req.params.id;
    const row = db.prepare('SELECT * FROM finance_records WHERE id = ?').get(id) as any;
    if (!row || !checkFarmOwnership(req, res, row.farm_id)) return;
    db.prepare('DELETE FROM finance_records WHERE id = ?').run(id);
    res.json({ ok: true });
  });

  // ============ 收支分类 ============
  app.get('/api/farms/:farmId/finance-categories', authMiddleware, (req, res) => {
    const { farmId } = req.params;
    if (!checkFarmOwnership(req, res, farmId)) return;
    const rows = db.prepare('SELECT * FROM finance_categories WHERE farm_id = ?').all(farmId);
    res.json(rows.map((r: any) => ({ id: r.id, farmId: r.farm_id, type: r.type, name: r.name })));
  });

  app.post('/api/finance-categories', authMiddleware, (req, res) => {
    const { farmId, type, name } = req.body;
    if (!checkFarmOwnership(req, res, farmId)) return;
    const id = genId('cat');
    db.prepare('INSERT INTO finance_categories (id, farm_id, type, name) VALUES (?, ?, ?, ?)').run(id, farmId, type, name);
    const row = db.prepare('SELECT * FROM finance_categories WHERE id = ?').get(id);
    res.json({ id: (row as any).id, farmId: (row as any).farm_id, type: (row as any).type, name: (row as any).name });
  });

  app.put('/api/finance-categories/:id', authMiddleware, (req, res) => {
    const id = req.params.id;
    const row = db.prepare('SELECT * FROM finance_categories WHERE id = ?').get(id) as any;
    if (!row || !checkFarmOwnership(req, res, row.farm_id)) return;
    const { name } = req.body;
    db.prepare('UPDATE finance_categories SET name = COALESCE(?, name) WHERE id = ?').run(name, id);
    const updated = db.prepare('SELECT * FROM finance_categories WHERE id = ?').get(id);
    res.json({ id: (updated as any).id, farmId: (updated as any).farm_id, type: (updated as any).type, name: (updated as any).name });
  });

  app.delete('/api/finance-categories/:id', authMiddleware, (req, res) => {
    const id = req.params.id;
    const row = db.prepare('SELECT * FROM finance_categories WHERE id = ?').get(id) as any;
    if (!row || !checkFarmOwnership(req, res, row.farm_id)) return;
    db.prepare('DELETE FROM finance_categories WHERE id = ?').run(id);
    res.json({ ok: true });
  });

  // ============ 待办 ============
  app.get('/api/farms/:farmId/todos', authMiddleware, (req, res) => {
    const { farmId } = req.params;
    if (!checkFarmOwnership(req, res, farmId)) return;
    const rows = db.prepare('SELECT * FROM todos WHERE farm_id = ? ORDER BY task_date').all(farmId);
    res.json(rows.map((r: any) => rowToTodo(r)));
  });

  app.post('/api/todos', authMiddleware, (req, res) => {
    const { farmId, title, taskType, taskDate, finished, priority, batchId, remark } = req.body;
    if (!checkFarmOwnership(req, res, farmId)) return;
    const id = genId('todo');
    db.prepare(
      `INSERT INTO todos (id, farm_id, title, task_type, task_date, finished, priority, batch_id, remark)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    ).run(id, farmId, title, taskType || null, taskDate || null, finished ? 1 : 0, priority || 'mid', batchId || null, remark || null);
    const row = db.prepare('SELECT * FROM todos WHERE id = ?').get(id);
    res.json(rowToTodo(row as any));
  });

  app.put('/api/todos/:id', authMiddleware, (req, res) => {
    const id = req.params.id;
    const row = db.prepare('SELECT * FROM todos WHERE id = ?').get(id) as any;
    if (!row || !checkFarmOwnership(req, res, row.farm_id)) return;
    const { title, taskType, taskDate, finished, priority, batchId, remark } = req.body;
    db.prepare(
      `UPDATE todos SET title = COALESCE(?, title), task_type = COALESCE(?, task_type),
       task_date = COALESCE(?, task_date), finished = COALESCE(?, finished),
       priority = COALESCE(?, priority), batch_id = COALESCE(?, batch_id),
       remark = COALESCE(?, remark) WHERE id = ?`,
    ).run(title, taskType, taskDate, finished === undefined ? undefined : finished ? 1 : 0, priority, batchId, remark, id);
    const updated = db.prepare('SELECT * FROM todos WHERE id = ?').get(id);
    res.json(rowToTodo(updated as any));
  });

  app.delete('/api/todos/:id', authMiddleware, (req, res) => {
    const id = req.params.id;
    const row = db.prepare('SELECT * FROM todos WHERE id = ?').get(id) as any;
    if (!row || !checkFarmOwnership(req, res, row.farm_id)) return;
    db.prepare('DELETE FROM todos WHERE id = ?').run(id);
    res.json({ ok: true });
  });

  // ============ 预警阈值 ============
  app.get('/api/farms/:farmId/threshold', authMiddleware, (req, res) => {
    const { farmId } = req.params;
    if (!checkFarmOwnership(req, res, farmId)) return;
    let row = db.prepare('SELECT * FROM alert_thresholds WHERE farm_id = ?').get(farmId) as any;
    if (!row) { row = { herd_fluctuation: 10, feed_intake: 80, survival_rate: 90, empty_pen_days: 30, animal_health_cost: 50 }; }
    res.json({ herdFluctuation: row.herd_fluctuation, feedIntake: row.feed_intake, survivalRate: row.survival_rate, emptyPenDays: row.empty_pen_days, animalHealthCost: row.animal_health_cost });
  });

  app.put('/api/farms/:farmId/threshold', authMiddleware, (req, res) => {
    const { farmId } = req.params;
    if (!checkFarmOwnership(req, res, farmId)) return;
    const d = req.body || {};
    db.prepare(
      `INSERT OR REPLACE INTO alert_thresholds
       (farm_id, herd_fluctuation, feed_intake, survival_rate, empty_pen_days, animal_health_cost)
       VALUES (?, COALESCE(?, 10), COALESCE(?, 80), COALESCE(?, 90), COALESCE(?, 30), COALESCE(?, 50))`,
    ).run(farmId, d.herdFluctuation, d.feedIntake, d.survivalRate, d.emptyPenDays, d.animalHealthCost);
    res.json({ ok: true });
  });

  // ============ 全量同步接口 ============
  app.get('/api/farms/:farmId/sync', authMiddleware, (req, res) => {
    const { farmId } = req.params;
    if (!checkFarmOwnership(req, res, farmId)) return;
    const farm = db.prepare('SELECT * FROM farms WHERE id = ?').get(farmId);
    const barns = db.prepare('SELECT * FROM barns WHERE farm_id = ?').all(farmId).map((r: any) => rowToBarn(r));
    const batches = db.prepare('SELECT * FROM batches WHERE farm_id = ?').all(farmId).map((r: any) => {
      const b = rowToBatch(r);
      const assignments = db.prepare('SELECT * FROM batch_barns WHERE batch_id = ?').all(b.id).map((a: any) => rowToBatchBarn(a));
      return { ...b, barnAssignments: assignments };
    });
    const feedTypes = db.prepare('SELECT * FROM feed_types WHERE farm_id = ?').all(farmId).map((r: any) => rowToFeedType(r));
    const stageDaysRow = db.prepare('SELECT * FROM stage_days WHERE farm_id = ?').get(farmId) as any;
    const stageDays = stageDaysRow ? { nursery_early: stageDaysRow.nursery_early, nursery_mid: stageDaysRow.nursery_mid, nursery_late: stageDaysRow.nursery_late, fatten_early: stageDaysRow.fatten_early, fatten_mid: stageDaysRow.fatten_mid, fatten_late: stageDaysRow.fatten_late } : { nursery_early: 7, nursery_mid: 10, nursery_late: 14, fatten_early: 20, fatten_mid: 30, fatten_late: 30 };
    const feedRecords = db.prepare('SELECT * FROM feed_records WHERE farm_id = ?').all(farmId).map((r: any) => rowToFeedRecord(r));
    const herdRecords = db.prepare('SELECT * FROM herd_records WHERE farm_id = ?').all(farmId).map((r: any) => rowToHerdRecord(r));
    const todos = db.prepare('SELECT * FROM todos WHERE farm_id = ?').all(farmId).map((r: any) => rowToTodo(r));
    const financeRecords = db.prepare('SELECT * FROM finance_records WHERE farm_id = ?').all(farmId).map((r: any) => rowToFinanceRecord(r));
    const financeCategories = db.prepare('SELECT * FROM finance_categories WHERE farm_id = ?').all(farmId).map((r: any) => ({ id: r.id, farmId: r.farm_id, type: r.type, name: r.name }));
    const vaccines = db.prepare('SELECT * FROM vaccines WHERE farm_id = ?').all(farmId).map((r: any) => rowToVaccine(r));
    const vaccineRecords = db.prepare('SELECT * FROM vaccine_records WHERE farm_id = ?').all(farmId).map((r: any) => rowToVaccineRecord(r));
    const thrRow = db.prepare('SELECT * FROM alert_thresholds WHERE farm_id = ?').get(farmId) as any;
    const threshold = thrRow ? { herdFluctuation: thrRow.herd_fluctuation, feedIntake: thrRow.feed_intake, survivalRate: thrRow.survival_rate, emptyPenDays: thrRow.empty_pen_days, animalHealthCost: thrRow.animal_health_cost } : { herdFluctuation: 10, feedIntake: 80, survivalRate: 90, emptyPenDays: 30, animalHealthCost: 50 };
    res.json({ farm, barns, batches, feedTypes, stageDays, feedRecords, herdRecords, todos, financeRecords, financeCategories, vaccines, vaccineRecords, threshold });
  });

  app.put('/api/farms/:farmId/sync', authMiddleware, (req, res) => {
    const { farmId } = req.params;
    if (!checkFarmOwnership(req, res, farmId)) return;
    const payload = req.body || {};
    const tx = db.transaction(() => {
      db.prepare('DELETE FROM feed_records WHERE farm_id = ?').run(farmId);
      db.prepare('DELETE FROM vaccine_records WHERE farm_id = ?').run(farmId);
      db.prepare('DELETE FROM herd_records WHERE farm_id = ?').run(farmId);
      db.prepare('DELETE FROM finance_records WHERE farm_id = ?').run(farmId);
      db.prepare('DELETE FROM finance_categories WHERE farm_id = ?').run(farmId);
      db.prepare('DELETE FROM todos WHERE farm_id = ?').run(farmId);
      db.prepare('DELETE FROM batch_barns WHERE batch_id IN (SELECT id FROM batches WHERE farm_id = ?)').run(farmId);
      db.prepare('DELETE FROM batches WHERE farm_id = ?').run(farmId);
      db.prepare('DELETE FROM barns WHERE farm_id = ?').run(farmId);
      db.prepare('DELETE FROM feed_types WHERE farm_id = ?').run(farmId);
      db.prepare('DELETE FROM vaccines WHERE farm_id = ?').run(farmId);
      db.prepare('DELETE FROM stage_days WHERE farm_id = ?').run(farmId);
      db.prepare('DELETE FROM alert_thresholds WHERE farm_id = ?').run(farmId);
      if (payload.farm) {
        db.prepare(
          `UPDATE farms SET name = COALESCE(?, name), address = COALESCE(?, address),
           phone = COALESCE(?, phone), manager = COALESCE(?, manager),
           capacity_pens = COALESCE(?, capacity_pens), remark = COALESCE(?, remark)
           WHERE id = ?`,
        ).run(payload.farm.name, payload.farm.address, payload.farm.phone, payload.farm.manager, payload.farm.capacityPens, payload.farm.remark, farmId);
      }
      if (Array.isArray(payload.barns)) {
        const ins = db.prepare(`INSERT INTO barns (id, farm_id, barn_no, barn_type, pen_count, last_occupied_date, remark) VALUES (?, ?, ?, ?, ?, ?, ?)`);
        for (const b of payload.barns) { ins.run(b.id, farmId, b.barnNo, b.barnType || 'fattening', b.penCount || 0, b.lastOccupiedDate || null, b.remark || null); }
      }
      if (Array.isArray(payload.batches)) {
        const batchIns = db.prepare(`INSERT INTO batches (id, farm_id, batch_no, entry_date, entry_age_days, entry_count, current_count, breed, expected_slaughter_date, status, remark) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`);
        const baIns = db.prepare(`INSERT INTO batch_barns (id, batch_id, barn_id, head_count, entry_date, remark) VALUES (?, ?, ?, ?, ?, ?)`);
        for (const b of payload.batches) {
          batchIns.run(b.id, farmId, b.batchNo, b.entryDate, b.entryAgeDays || 25, b.entryCount || 0, b.currentCount || 0, b.breed || null, b.expectedSlaughterDate || null, b.status || 'active', b.remark || null);
          if (Array.isArray(b.barnAssignments)) {
            for (const a of b.barnAssignments) { baIns.run(a.id || `ba_${b.id}_${Math.random().toString(36).slice(2, 6)}`, b.id, a.barnId, a.headCount || 0, a.entryDate || b.entryDate, a.remark || null); }
          }
        }
      }
      if (Array.isArray(payload.feedTypes)) {
        const ins = db.prepare(`INSERT INTO feed_types (id, farm_id, name, stage, stage_usage_per_head, ref_price, remark) VALUES (?, ?, ?, ?, ?, ?, ?)`);
        for (const f of payload.feedTypes) { ins.run(f.id, farmId, f.name, f.stage || null, f.stageUsagePerHead || 0, f.refPrice || 0, f.remark || null); }
      }
      if (payload.stageDays && typeof payload.stageDays === 'object') {
        const s = payload.stageDays;
        db.prepare(`INSERT INTO stage_days (farm_id, nursery_early, nursery_mid, nursery_late, fatten_early, fatten_mid, fatten_late) VALUES (?, ?, ?, ?, ?, ?, ?)`).run(farmId, s.nursery_early ?? 7, s.nursery_mid ?? 10, s.nursery_late ?? 14, s.fatten_early ?? 20, s.fatten_mid ?? 30, s.fatten_late ?? 30);
      }
      if (Array.isArray(payload.feedRecords)) {
        const ins = db.prepare(`INSERT INTO feed_records (id, farm_id, batch_id, date, feed_type_id, feed_type_name, quantity, unit_price, amount, operator, remark) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`);
        for (const r of payload.feedRecords) { ins.run(r.id, farmId, r.batchId, r.date, r.feedTypeId || null, r.feedTypeName || null, r.quantity || 0, r.unitPrice || 0, r.amount || 0, r.operator || null, r.remark || null); }
      }
      if (Array.isArray(payload.vaccines)) {
        const ins = db.prepare(`INSERT INTO vaccines (id, farm_id, name, type, unit, ref_price, applicable_stage, remark) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`);
        for (const v of payload.vaccines) { ins.run(v.id, farmId, v.name, v.type || null, v.unit || null, v.refPrice || 0, v.applicableStage || null, v.remark || null); }
      }
      if (Array.isArray(payload.vaccineRecords)) {
        const ins = db.prepare(`INSERT INTO vaccine_records (id, farm_id, batch_id, date, vaccine_id, vaccine_name, type, quantity, unit, unit_price, amount, operator, remark) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`);
        for (const r of payload.vaccineRecords) { ins.run(r.id, farmId, r.batchId || null, r.date, r.vaccineId || null, r.vaccineName || null, r.type || null, r.quantity || 0, r.unit || null, r.unitPrice || 0, r.amount || 0, r.operator || null, r.remark || null); }
      }
      if (Array.isArray(payload.herdRecords)) {
        const ins = db.prepare(`INSERT INTO herd_records (id, farm_id, batch_id, barn_id, date, change_type, change_count, operator, remark) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`);
        for (const r of payload.herdRecords) { ins.run(r.id, farmId, r.batchId || null, r.barnId || null, r.date, r.changeType, r.changeCount || 0, r.operator || null, r.remark || null); }
      }
      if (Array.isArray(payload.financeCategories)) {
        const ins = db.prepare('INSERT INTO finance_categories (id, farm_id, type, name) VALUES (?, ?, ?, ?)');
        for (const c of payload.financeCategories) { ins.run(c.id, farmId, c.type, c.name); }
      }
      if (Array.isArray(payload.financeRecords)) {
        const ins = db.prepare(`INSERT INTO finance_records (id, farm_id, type, category, amount, date, batch_id, investor, remark) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`);
        for (const r of payload.financeRecords) { ins.run(r.id, farmId, r.type, r.category || null, r.amount || 0, r.date, r.batchId || null, r.investor || null, r.remark || null); }
      }
      if (Array.isArray(payload.todos)) {
        const ins = db.prepare(`INSERT INTO todos (id, farm_id, title, task_type, task_date, finished, priority, batch_id, remark) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`);
        for (const t of payload.todos) { ins.run(t.id, farmId, t.title, t.taskType || null, t.taskDate || null, t.finished ? 1 : 0, t.priority || 'mid', t.batchId || null, t.remark || null); }
      }
      if (payload.threshold && typeof payload.threshold === 'object') {
        const t = payload.threshold;
        db.prepare(`INSERT INTO alert_thresholds (farm_id, herd_fluctuation, feed_intake, survival_rate, empty_pen_days, animal_health_cost) VALUES (?, ?, ?, ?, ?, ?)`).run(farmId, t.herdFluctuation ?? 10, t.feedIntake ?? 80, t.survivalRate ?? 90, t.emptyPenDays ?? 30, t.animalHealthCost ?? 50);
      }
    });
    tx();
    res.json({ ok: true });
  });

  // 健康检查
  app.get('/api/health', (_req, res) => {
    res.json({ status: 'ok', timestamp: Date.now() });
  });

  // ============ 静态文件托管（生产环境）============
  const isProd2 = process.env.NODE_ENV === 'production';
  if (isProd2) {
    const path = require('node:path');
    const fs = require('node:fs');
    const candidatePaths = [
      path.resolve(process.cwd(), 'dist/client'),
      path.resolve(process.cwd(), 'dist'),
      path.resolve(process.cwd(), 'dist/output'),
    ];
    let distPath: string | null = null;
    for (const p of candidatePaths) {
      if (fs.existsSync(p) && fs.existsSync(path.join(p, 'index.html'))) { distPath = p; break; }
    }
    if (distPath) {
      app.use(express.static(distPath));
      app.get(/^\/(?!api).*/, (_req, res) => { res.sendFile(path.join(distPath!, 'index.html')); });
      logger.info(`[server] 静态文件已托管: ${distPath}`);
    } else {
      logger.warn('[server] 前端构建目录不存在，跳过静态文件托管');
    }
  }

  return app;
}

// 独立启动模式
const isDirectLaunch = process.argv[1] && (
  process.argv[1].includes('server/index') ||
  process.argv[1].includes('server\\index') ||
  process.argv[1].endsWith('index.js')
);
if (isDirectLaunch) {
  const PORT = process.env.PORT || process.env.SERVER_PORT || 3001;
  const app = createApp();
  app.listen(Number(PORT), '0.0.0.0', () => {
    logger.info(`[server] 育肥猪场管理系统服务已启动 :${PORT}`);
    logger.info(`[server] 环境: ${process.env.NODE_ENV || 'development'}`);
    logger.info(`[server] 数据库: ${process.env.DATABASE_URL ? 'PostgreSQL' : 'SQLite'}`);
  });
}

// ============ 行数据转前端 camelCase ============
function rowToBarn(r: any) {
  return { id: r.id, farmId: r.farm_id, barnNo: r.barn_no, barnType: r.barn_type, penCount: r.pen_count, lastOccupiedDate: r.last_occupied_date, remark: r.remark, createdAt: r.created_at };
}
function rowToBatch(r: any) {
  return { id: r.id, farmId: r.farm_id, batchNo: r.batch_no, entryDate: r.entry_date, entryAgeDays: r.entry_age_days, entryCount: r.entry_count, currentCount: r.current_count, breed: r.breed, expectedSlaughterDate: r.expected_slaughter_date, status: r.status, remark: r.remark, createdAt: r.created_at };
}
function rowToBatchBarn(r: any) {
  return { id: r.id, batchId: r.batch_id, barnId: r.barn_id, headCount: r.head_count, entryDate: r.entry_date, remark: r.remark };
}
function rowToFeedType(r: any) {
  return { id: r.id, farmId: r.farm_id, name: r.name, stage: r.stage, stageUsagePerHead: r.stage_usage_per_head, refPrice: r.ref_price, remark: r.remark };
}
function rowToFeedRecord(r: any) {
  return { id: r.id, farmId: r.farm_id, batchId: r.batch_id, date: r.date, feedTypeId: r.feed_type_id, feedTypeName: r.feed_type_name, quantity: r.quantity, unitPrice: r.unit_price, amount: r.amount, operator: r.operator, remark: r.remark };
}
function rowToVaccine(r: any) {
  return { id: r.id, farmId: r.farm_id, name: r.name, type: r.type, unit: r.unit, refPrice: r.ref_price, applicableStage: r.applicable_stage, remark: r.remark };
}
function rowToVaccineRecord(r: any) {
  return { id: r.id, farmId: r.farm_id, batchId: r.batch_id, date: r.date, vaccineId: r.vaccine_id, vaccineName: r.vaccine_name, type: r.type, quantity: r.quantity, unit: r.unit, unitPrice: r.unit_price, amount: r.amount, operator: r.operator, remark: r.remark };
}
function rowToHerdRecord(r: any) {
  return { id: r.id, farmId: r.farm_id, batchId: r.batch_id, barnId: r.barn_id, date: r.date, changeType: r.change_type, changeCount: r.change_count, operator: r.operator, remark: r.remark };
}
function rowToFinanceRecord(r: any) {
  return { id: r.id, farmId: r.farm_id, type: r.type, category: r.category, amount: r.amount, date: r.date, batchId: r.batch_id, investor: r.investor, remark: r.remark };
}
function rowToTodo(r: any) {
  return { id: r.id, farmId: r.farm_id, title: r.title, taskType: r.task_type, taskDate: r.task_date, finished: r.finished === 1, priority: r.priority, batchId: r.batch_id, remark: r.remark };
}

// ============ 示例数据初始化 ============
function initFarmDefaults(db: DbInstance, farmId: string) {
  db.prepare(`INSERT INTO alert_thresholds (farm_id) VALUES (?)`).run(farmId);
  db.prepare(`INSERT INTO stage_days (farm_id) VALUES (?)`).run(farmId);
  const catIns = db.prepare('INSERT INTO finance_categories (id, farm_id, type, name) VALUES (?, ?, ?, ?)');
  const defaultCats = [
    ['cat_inc_1', 'income', '卖猪收入'], ['cat_inc_2', 'income', '其他收入'],
    ['cat_exp_1', 'expense', '饲料采购'], ['cat_exp_2', 'expense', '兽药疫苗'],
    ['cat_exp_3', 'expense', '人工成本'], ['cat_exp_4', 'expense', '水电费'],
    ['cat_exp_5', 'expense', '其他支出'],
  ];
  for (const [id, type, name] of defaultCats) { catIns.run(`${farmId}_${id}`, farmId, type, name); }
}

function seedDemoData(db: DbInstance, userId: number, farmName: string) {
  const today = new Date();
  const daysAgo = (d: number) => { const dt = new Date(today); dt.setDate(dt.getDate() - d); return dt.toISOString().slice(0, 10); };
  const farmId = `farm_demo_${userId}`;
  db.prepare(`INSERT INTO farms (id, user_id, name, address, phone, manager, capacity_pens, remark) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`).run(farmId, userId, farmName, '示例地址', '13800000000', '管理员', 200, '注册时自动创建的示例猪场');
  initFarmDefaults(db, farmId);
  const barn1Id = `barn_demo1_${userId}`;
  const barn2Id = `barn_demo2_${userId}`;
  db.prepare(`INSERT INTO barns (id, farm_id, barn_no, barn_type, pen_count, last_occupied_date, remark) VALUES (?, ?, ?, ?, ?, ?, ?)`).run(barn1Id, farmId, '1号栋', 'fattening', 100, daysAgo(0), '育肥栋，示例数据');
  db.prepare(`INSERT INTO barns (id, farm_id, barn_no, barn_type, pen_count, last_occupied_date, remark) VALUES (?, ?, ?, ?, ?, ?, ?)`).run(barn2Id, farmId, '2号栋', 'nursery', 50, daysAgo(15), '保育栋，示例数据');
  const batchId = `batch_demo_${userId}`;
  db.prepare(`INSERT INTO batches (id, farm_id, batch_no, entry_date, entry_age_days, entry_count, current_count, breed, expected_slaughter_date, status, remark) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`).run(batchId, farmId, 'DF250101', daysAgo(30), 25, 100, 98, '杜长大', daysAgo(-135), 'active', '示例批次');
  db.prepare(`INSERT INTO batch_barns (id, batch_id, barn_id, head_count, entry_date, remark) VALUES (?, ?, ?, ?, ?, ?)`).run(`ba_demo_${userId}`, batchId, barn1Id, 98, daysAgo(30), '示例分配');
  const feedTypes = [
    ['保育前期料', 'nursery_early', 8, 6.8], ['保育中期料', 'nursery_mid', 15, 5.5],
    ['保育后期料', 'nursery_late', 25, 4.8], ['育肥前期料', 'fatten_early', 60, 4.2],
    ['育肥中期料', 'fatten_mid', 100, 3.9], ['育肥后期料', 'fatten_late', 120, 3.7],
  ];
  const feedIns = db.prepare(`INSERT INTO feed_types (id, farm_id, name, stage, stage_usage_per_head, ref_price) VALUES (?, ?, ?, ?, ?, ?)`);
  const feedIds: string[] = [];
  feedTypes.forEach(([name, stage, usage, price], i) => { const id = `feed_demo_${userId}_${i}`; feedIds.push(id); feedIns.run(id, farmId, name, stage, usage, price); });
  const feedRecIns = db.prepare(`INSERT INTO feed_records (id, farm_id, batch_id, date, feed_type_id, feed_type_name, quantity, unit_price, amount, operator) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`);
  feedRecIns.run(`fr_demo_${userId}_1`, farmId, batchId, daysAgo(25), feedIds[0], '保育前期料', 400, 6.8, 2720, '张师傅');
  feedRecIns.run(`fr_demo_${userId}_2`, farmId, batchId, daysAgo(15), feedIds[1], '保育中期料', 700, 5.5, 3850, '张师傅');
  feedRecIns.run(`fr_demo_${userId}_3`, farmId, batchId, daysAgo(5), feedIds[2], '保育后期料', 1200, 4.8, 5760, '李师傅');
  const todoIns = db.prepare(`INSERT INTO todos (id, farm_id, title, task_type, task_date, finished, priority, remark) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`);
  todoIns.run(`todo_demo_${userId}_1`, farmId, '记录今日饲料领用', 'feed', daysAgo(0), 0, 'high', '');
  todoIns.run(`todo_demo_${userId}_2`, farmId, '检查保育栋温度', 'check', daysAgo(0), 1, 'mid', '已巡检');
  todoIns.run(`todo_demo_${userId}_3`, farmId, '月末盘点存栏', 'inventory', daysAgo(2), 0, 'high', '');
  const finIns = db.prepare(`INSERT INTO finance_records (id, farm_id, type, category, amount, date, batch_id, remark) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`);
  finIns.run(`fin_demo_${userId}_1`, farmId, 'expense', `${farmId}_cat_exp_1`, 12330, daysAgo(5), batchId, '饲料采购');
  finIns.run(`fin_demo_${userId}_2`, farmId, 'expense', `${farmId}_cat_exp_2`, 2000, daysAgo(10), null, '疫苗采购');
  const vacIns = db.prepare(`INSERT INTO vaccines (id, farm_id, name, type, unit, ref_price, applicable_stage) VALUES (?, ?, ?, ?, ?, ?, ?)`);
  vacIns.run(`vac_demo_${userId}_1`, farmId, '猪瘟疫苗', 'vaccine', '头份', 15, 'nursery_mid');
  vacIns.run(`vac_demo_${userId}_2`, farmId, '口蹄疫疫苗', 'vaccine', '头份', 8, 'fatten_early');
}

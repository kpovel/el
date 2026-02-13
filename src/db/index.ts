import { Database } from "bun:sqlite";
import { drizzle } from "drizzle-orm/bun-sqlite";
import { createHash } from "node:crypto";
import { desc, sql, and, gte, lte, isNull, isNotNull } from "drizzle-orm";
import { gridLogs } from "./schema.js";
import type { River3Status } from "../protocol.js";
import migration0000 from "../../drizzle/0000_acoustic_kang.sql" with { type: "text" };
import migration0001 from "../../drizzle/0001_loose_anthem.sql" with { type: "text" };
import journal from "../../drizzle/meta/_journal.json" with { type: "json" };

const migrationSqlFiles: Record<string, string> = {
  "0000_acoustic_kang": migration0000,
  "0001_loose_anthem": migration0001,
};

const migrations = journal.entries.map((entry) => {
  const query = migrationSqlFiles[entry.tag];
  return {
    sql: query.split("--> statement-breakpoint"),
    bps: entry.breakpoints,
    folderMillis: entry.when,
    hash: createHash("sha256").update(query).digest("hex"),
  };
});

const sqlite = new Database("grid.db");
sqlite.exec("PRAGMA journal_mode = WAL;");

export const db = drizzle(sqlite, { schema: { gridLogs } });
db.dialect.migrate(migrations, db.session, {});

export function insertLog(
  status: "UP" | "DOWN",
  river3?: River3Status,
  error?: string,
) {
  db.insert(gridLogs)
    .values({
      timestamp: Date.now(),
      status,
      acInputPower: river3?.acInputPower ?? null,
      acInputVoltage: river3?.acInputVoltage ?? null,
      acOutputPower: river3?.acOutputPower ?? null,
      batteryLevel: river3?.batteryLevel ?? null,
      batteryTemp: river3?.batteryTemp ?? null,
      dcInputPower: river3?.dcInputPower ?? null,
      usbOutputPower: river3?.usbOutputPower ?? null,
      error: error ?? null,
    })
    .run();
}

export function getLatestLog() {
  return db
    .select()
    .from(gridLogs)
    .orderBy(desc(gridLogs.timestamp))
    .limit(1)
    .get();
}

export function getLatestStatus(): "UP" | "DOWN" | null {
  const row = getLatestLog();
  return row?.status ?? null;
}

export function getLogs24h() {
  const since = Date.now() - 24 * 60 * 60 * 1000;
  return db
    .select()
    .from(gridLogs)
    .where(gte(gridLogs.timestamp, since))
    .orderBy(gridLogs.timestamp)
    .all();
}

interface Incident {
  start: number;
  end: number;
  durationMin: number;
}

export function getIncidents24h(): Incident[] {
  const logs = getLogs24h();
  const incidents: Incident[] = [];
  let downStart: number | null = null;

  for (const log of logs) {
    if (log.status === "DOWN" && downStart === null) {
      downStart = log.timestamp;
    } else if (log.status === "UP" && downStart !== null) {
      incidents.push({
        start: downStart,
        end: log.timestamp,
        durationMin: Math.round((log.timestamp - downStart) / 60000),
      });
      downStart = null;
    }
  }

  if (downStart !== null) {
    incidents.push({
      start: downStart,
      end: Date.now(),
      durationMin: Math.round((Date.now() - downStart) / 60000),
    });
  }

  return incidents;
}

export function getStats24h() {
  const incidents = getIncidents24h();
  const totalDowntimeMin = incidents.reduce((s, i) => s + i.durationMin, 0);
  const peakOutageMin = incidents.length
    ? Math.max(...incidents.map((i) => i.durationMin))
    : 0;

  const logs = getLogs24h();
  const totalLogs = logs.length;
  const upLogs = logs.filter((l) => l.status === "UP").length;
  const uptimeRatio = totalLogs > 0 ? upLogs / totalLogs : 1;

  return {
    incidents: incidents.length,
    uptimeRatio,
    totalDowntimeMin,
    peakOutageMin,
  };
}

export function getPowerMap24h(): ("UP" | "DOWN" | null)[] {
  const now = Date.now();
  const dayStart = now - 24 * 60 * 60 * 1000;
  const slotMs = (15 * 60 * 1000);
  const slots: ("UP" | "DOWN" | null)[] = new Array(96).fill(null);

  const logs = getLogs24h();

  for (const log of logs) {
    const slotIndex = Math.floor((log.timestamp - dayStart) / slotMs);
    if (slotIndex >= 0 && slotIndex < 96) {
      if (slots[slotIndex] === "DOWN" || log.status === "DOWN") {
        slots[slotIndex] = "DOWN";
      } else {
        slots[slotIndex] = "UP";
      }
    }
  }

  return slots;
}

export function getWeeklyPattern(): { day: string; kanji: string; outages: number }[] {
  const days = [
    { day: "SUN", kanji: "日" },
    { day: "MON", kanji: "月" },
    { day: "TUE", kanji: "火" },
    { day: "WED", kanji: "水" },
    { day: "THU", kanji: "木" },
    { day: "FRI", kanji: "金" },
    { day: "SAT", kanji: "土" },
  ];

  const now = new Date();
  const result: { day: string; kanji: string; outages: number }[] = [];

  for (let i = 6; i >= 0; i--) {
    const d = new Date(now);
    d.setDate(d.getDate() - i);
    d.setHours(0, 0, 0, 0);
    const dayStart = d.getTime();
    const dayEnd = dayStart + 24 * 60 * 60 * 1000;

    const dayLogs = db
      .select()
      .from(gridLogs)
      .where(and(gte(gridLogs.timestamp, dayStart), lte(gridLogs.timestamp, dayEnd)))
      .orderBy(gridLogs.timestamp)
      .all();

    let outages = 0;
    let wasDown = false;
    for (const log of dayLogs) {
      if (log.status === "DOWN" && !wasDown) {
        outages++;
        wasDown = true;
      } else if (log.status === "UP") {
        wasDown = false;
      }
    }

    const dayInfo = days[d.getDay()];
    result.push({ day: dayInfo.day, kanji: dayInfo.kanji, outages });
  }

  return result;
}

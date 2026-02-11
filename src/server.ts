import { parseArgs } from "util";
import { renderToString } from "react-dom/server";
import { createElement } from "react";
import { monitorGrid } from "./ble.js";
import { gridAvailable } from "./protocol.js";
import { HomePage } from "./pages/home.js";
import {
  insertLog,
  getLatestLog,
  getLatestStatus,
  getStats24h,
  getPowerMap24h,
  getIncidents24h,
  getWeeklyPattern,
} from "./db/index.js";

const { values } = parseArgs({
  options: {
    address: { type: "string", short: "a" },
    serial: { type: "string", short: "s" },
    "user-id": { type: "string", short: "u" },
    port: { type: "string", short: "p" },
  },
  strict: true,
  allowPositionals: true,
});

function requiredArg(value: string | undefined, name: string): string {
  if (!value) {
    throw new Error(
      `Missing required argument: ${name}\n` +
        "Usage: bun run src/server.ts --address AA:BB:CC:DD:EE:FF --serial R631xxx --user-id 12345\n" +
        "  or set ECOFLOW_ADDRESS, ECOFLOW_SERIAL, ECOFLOW_USER_ID env vars\n" +
        "Options:\n" +
        "  --port, -p       HTTP port (default: 6969)",
    );
  }
  return value;
}

const address = requiredArg(values.address || process.env.ECOFLOW_ADDRESS, "address");
const serial = requiredArg(values.serial || process.env.ECOFLOW_SERIAL, "serial");
const userId = requiredArg(values["user-id"] || process.env.ECOFLOW_USER_ID, "user-id");
const port = parseInt(values.port || process.env.PORT || "6969", 10);

(async () => {
  while (true) {
    try {
      console.log(`[${new Date().toISOString()}] Connecting to EcoFlow BLE...`);
      await monitorGrid(address, serial, userId, (status) => {
        const isUp = gridAvailable(status);
        const newStatus = isUp ? "UP" : "DOWN";
        const prev = getLatestStatus();

        console.log(
          `[${new Date().toISOString()}] Grid: ${newStatus} | AC: ${status.acInputPower.toFixed(1)}W / ${status.acInputVoltage.toFixed(0)}V | Battery: ${status.batteryLevel.toFixed(0)}%`,
        );

        insertLog(newStatus, status);

        if (newStatus !== prev) {
          console.log(
            `[${new Date().toISOString()}] Grid status changed: ${prev ?? "unknown"} -> ${newStatus} (AC input: ${status.acInputPower.toFixed(1)}W)`,
          );
        }
      });
      console.log(`[${new Date().toISOString()}] BLE connection lost, reconnecting...`);
    } catch (e: any) {
      console.error(`[${new Date().toISOString()}] BLE error: ${e.message}, reconnecting...`);
    }
  }
})();

function renderPage(component: () => React.JSX.Element): Response {
  const html = "<!DOCTYPE html>" + renderToString(createElement(component));
  return new Response(html, {
    headers: { "Content-Type": "text/html; charset=utf-8" },
  });
}

function jsonResponse(data: unknown): Response {
  return new Response(JSON.stringify(data), {
    headers: { "Content-Type": "application/json" },
  });
}

function formatDuration(minutes: number): string {
  const h = Math.floor(minutes / 60);
  const m = minutes % 60;
  return h > 0 ? `${h}:${m.toString().padStart(2, "0")}` : `0:${m.toString().padStart(2, "0")}`;
}

const server = Bun.serve({
  port,
  routes: {
    "/": () => renderPage(HomePage),

    "/api/grid": () => {
      const status = getLatestStatus();
      if (status === null) {
        return new Response("UNKNOWN\n", {
          status: 503,
          headers: { "Content-Type": "text/plain" },
        });
      }
      return new Response(status + "\n", {
        headers: { "Content-Type": "text/plain" },
      });
    },

    "/api/grid-status": () => {
      const log = getLatestLog();
      const status = log?.status ?? null;
      const color =
        status === "UP"
          ? "#28c840"
          : status === "DOWN"
            ? "#e83030"
            : "#555";
      const label = status ?? "— — —";

      const voltage = log?.acInputVoltage != null ? `${log.acInputVoltage.toFixed(0)}V` : "—";
      const power = log?.acInputPower != null ? `${log.acInputPower.toFixed(0)}W` : "—";
      const battery = log?.batteryLevel != null ? `${log.batteryLevel.toFixed(0)}%` : "—";

      const html =
        `<div class="flex items-center justify-center gap-6">` +
        `<div style="width:16px;height:16px;border-radius:50%;background:${color};box-shadow:0 0 12px ${color};flex-shrink:0"></div>` +
        `<div class="font-stencil text-[120px] leading-none tracking-wider">${label}</div>` +
        `</div>` +
        `<div class="w-full h-px bg-[#333] my-5"></div>` +
        `<div class="flex items-center gap-8 text-sm">` +
        `<div class="text-center"><div class="text-[var(--dim)] text-[11px] tracking-[0.2em]">VOLTAGE</div><div class="font-stencil text-2xl text-[var(--fg)]">${voltage}</div></div>` +
        `<div class="text-center"><div class="text-[var(--dim)] text-[11px] tracking-[0.2em]">POWER</div><div class="font-stencil text-2xl text-[var(--fg)]">${power}</div></div>` +
        `<div class="text-center"><div class="text-[var(--dim)] text-[11px] tracking-[0.2em]">BATTERY</div><div class="font-stencil text-2xl text-[var(--fg)]">${battery}</div></div>` +
        `</div>`;
      return new Response(html, {
        headers: { "Content-Type": "text/html; charset=utf-8" },
      });
    },

    "/api/stats": () => {
      const stats = getStats24h();
      const html =
        `<div class="cell p-5 flex flex-col justify-between">` +
        `<div class="tag">INCIDENTS / 24H</div>` +
        `<div class="font-stencil text-5xl mt-3" style="color:var(--red)">${stats.incidents}</div>` +
        `</div>` +
        `<div class="cell p-5 flex flex-col justify-between">` +
        `<div class="tag">UPTIME RATIO</div>` +
        `<div class="font-stencil text-5xl mt-3" style="color:var(--green)">${(stats.uptimeRatio * 100).toFixed(1)}%</div>` +
        `</div>` +
        `<div class="cell p-5 flex flex-col justify-between">` +
        `<div class="tag">TOTAL DOWNTIME</div>` +
        `<div class="font-stencil text-5xl mt-3" style="color:var(--amber)">${formatDuration(stats.totalDowntimeMin)}</div>` +
        `</div>` +
        `<div class="cell p-5 flex flex-col justify-between">` +
        `<div class="tag">PEAK OUTAGE</div>` +
        `<div class="font-stencil text-5xl mt-3" style="color:var(--fg)">${formatDuration(stats.peakOutageMin)}</div>` +
        `</div>`;
      return new Response(html, {
        headers: { "Content-Type": "text/html; charset=utf-8" },
      });
    },

    "/api/power-map": () => {
      const slots = getPowerMap24h();
      let barsHtml = "";
      for (let i = 0; i < 96; i++) {
        const s = slots[i];
        const isDown = s === "DOWN";
        const isPending = s === null;
        const height = isDown ? "100%" : "50%";
        const bg = isPending ? "#1a1a1a" : isDown ? "var(--red)" : "var(--fg)";
        const opacity = isPending ? 1 : isDown ? 0.9 : 0.12;
        const hour = Math.floor(i / 4).toString().padStart(2, "0");
        const min = ((i % 4) * 15).toString().padStart(2, "0");
        barsHtml += `<div class="flex-1 min-w-[5px] transition-colors duration-200" style="height:${height};background:${bg};opacity:${opacity}" title="${hour}:${min}"></div>`;
      }
      return new Response(barsHtml, {
        headers: { "Content-Type": "text/html; charset=utf-8" },
      });
    },

    "/api/incidents": () => {
      const incidents = getIncidents24h();
      if (incidents.length === 0) {
        const html =
          `<div class="px-5 py-3 border-b border-[#222] flex items-center justify-between">` +
          `<div class="tag">INCIDENT LOG</div>` +
          `<div class="tag text-[var(--green)]">0 EVENTS</div>` +
          `</div>` +
          `<div class="px-5 py-8 text-center text-[var(--dim)] text-sm">No incidents in the last 24 hours</div>`;
        return new Response(html, {
          headers: { "Content-Type": "text/html; charset=utf-8" },
        });
      }

      let html =
        `<div class="px-5 py-3 border-b border-[#222] flex items-center justify-between">` +
        `<div class="tag">INCIDENT LOG</div>` +
        `<div class="tag text-[var(--red)]">${incidents.length} EVENT${incidents.length > 1 ? "S" : ""}</div>` +
        `</div>`;

      for (const inc of [...incidents].sort((a, b) => a.start - b.start)) {
        const t1 = new Date(inc.start).toLocaleTimeString("en-GB", { hour: "2-digit", minute: "2-digit" });
        const t2 = new Date(inc.end).toLocaleTimeString("en-GB", { hour: "2-digit", minute: "2-digit" });
        const dur = formatDuration(inc.durationMin);
        const barColor = inc.durationMin >= 30 ? "var(--red)" : "var(--amber)";

        html +=
          `<div class="px-5 py-4 border-b border-[#191919] flex items-center gap-6">` +
          `<div class="w-1 h-8 rounded-full" style="background:${barColor}"></div>` +
          `<div class="font-stencil text-2xl w-20">${t1}</div>` +
          `<span class="text-[var(--dim)] text-sm">\u2192</span>` +
          `<div class="font-stencil text-2xl w-20">${t2}</div>` +
          `<div class="text-sm text-[var(--dim)] ml-2">${dur}</div>` +
          `</div>`;
      }

      return new Response(html, {
        headers: { "Content-Type": "text/html; charset=utf-8" },
      });
    },

    "/api/weekly": () => {
      const weekly = getWeeklyPattern();
      let html = "";
      for (const day of weekly) {
        const borderColor = day.outages > 2 ? "var(--red-dim)" : "#222";
        const numColor = day.outages > 0 ? "var(--red)" : "var(--green)";
        html +=
          `<div class="cell w-14 h-14 flex flex-col items-center justify-center" style="border-color:${borderColor}">` +
          `<div class="font-stencil text-lg" style="color:${numColor}">${day.outages}</div>` +
          `<div class="text-[8px] text-[var(--dim)] tracking-widest">${day.day}</div>` +
          `</div>`;
      }
      return new Response(html, {
        headers: { "Content-Type": "text/html; charset=utf-8" },
      });
    },
  },
});

console.log(
  `Grid status server listening on http://localhost:${server.port} (persistent BLE connection)`,
);

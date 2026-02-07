import { parseArgs } from "util";
import { renderToString } from "react-dom/server";
import { createElement } from "react";
import { monitorGrid } from "./ble.js";
import { gridAvailable } from "./protocol.js";
import { HomePage } from "./pages/home.js";

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

let cachedStatus: "UP" | "DOWN" | null = null;

(async () => {
  while (true) {
    try {
      console.log(`[${new Date().toISOString()}] Connecting to EcoFlow BLE...`);
      await monitorGrid(address, serial, userId, (status) => {
        const newStatus = gridAvailable(status) ? "UP" : "DOWN";
        if (newStatus !== cachedStatus) {
          console.log(
            `[${new Date().toISOString()}] Grid status changed: ${cachedStatus ?? "unknown"} -> ${newStatus} (AC input: ${status.acInputPower.toFixed(1)}W)`,
          );
        }
        cachedStatus = newStatus;
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

const server = Bun.serve({
  port,
  routes: {
    "/": () => renderPage(HomePage),
    "/api/grid": () => {
      if (cachedStatus === null) {
        return new Response("UNKNOWN\n", {
          status: 503,
          headers: { "Content-Type": "text/plain" },
        });
      }

      return new Response(cachedStatus + "\n", {
        headers: { "Content-Type": "text/plain" },
      });
    },
    "/api/grid-status": () => {
      const color =
        cachedStatus === "UP"
          ? "#28c840"
          : cachedStatus === "DOWN"
          ? "#e83030"
          : "#555";
      const label = cachedStatus ?? "— — —";
      const html =
        `<div style="width:16px;height:16px;border-radius:50%;background:${color};box-shadow:0 0 12px ${color};flex-shrink:0"></div>` +
        `<div class="font-stencil text-[120px] leading-none tracking-wider">${label}</div>`;
      return new Response(html, {
        headers: { "Content-Type": "text/html; charset=utf-8" },
      });
    },
  },
});

console.log(
  `Grid status server listening on http://localhost:${server.port} (persistent BLE connection)`,
);

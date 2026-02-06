import { parseArgs } from "util";
import { checkGrid } from "./ble.js";
import { gridAvailable } from "./protocol.js";

const { values } = parseArgs({
  options: {
    address: { type: "string", short: "a" },
    serial: { type: "string", short: "s" },
    "user-id": { type: "string", short: "u" },
    port: { type: "string", short: "p" },
    interval: { type: "string", short: "i" },
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
        "  --port, -p       HTTP port (default: 6969)\n" +
        "  --interval, -i   BLE poll interval in seconds (default: 60)",
    );
  }
  return value;
}

const address = requiredArg(values.address || process.env.ECOFLOW_ADDRESS, "address");
const serial = requiredArg(values.serial || process.env.ECOFLOW_SERIAL, "serial");
const userId = requiredArg(values["user-id"] || process.env.ECOFLOW_USER_ID, "user-id");
const port = parseInt(values.port || process.env.PORT || "6969", 10);
const intervalSec = parseInt(values.interval || "60", 10);

let cachedStatus: "UP" | "DOWN" | null = null;
let checking = false;

async function pollGrid() {
  if (checking) return;
  checking = true;

  try {
    const status = await checkGrid(address, serial, userId);
    const isUp = gridAvailable(status);
    const newStatus = isUp ? "UP" : "DOWN";

    if (newStatus !== cachedStatus) {
      console.log(
        `[${new Date().toISOString()}] Grid status changed: ${cachedStatus ?? "unknown"} -> ${newStatus} (AC input: ${status.acInputPower.toFixed(1)}W)`,
      );
    }

    cachedStatus = newStatus;
  } catch (e: any) {
    console.error(`[${new Date().toISOString()}] BLE check failed: ${e.message}`);
  } finally {
    checking = false;
  }
}

pollGrid();
setInterval(pollGrid, intervalSec * 1000);

const server = Bun.serve({
  port,
  fetch() {
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
});

console.log(
  `Grid status server listening on http://localhost:${server.port} (BLE poll every ${intervalSec}s)`,
);

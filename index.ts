import { parseArgs } from "util";
import { monitorGrid } from "./src/ble.js";
import { gridAvailable } from "./src/protocol.js";

const { values } = parseArgs({
  options: {
    address: { type: "string", short: "a" },
    serial: { type: "string", short: "s" },
    "user-id": { type: "string", short: "u" },
  },
  strict: true,
  allowPositionals: true,
});

const address = values.address || process.env.ECOFLOW_ADDRESS;
const serial = values.serial || process.env.ECOFLOW_SERIAL;
const userId = values["user-id"] || process.env.ECOFLOW_USER_ID;

if (!address || !serial || !userId) {
  process.stderr.write(
    "Usage: bun run index.ts --address AA:BB:CC:DD:EE:FF --serial R631xxx --user-id 12345\n" +
      "  or set ECOFLOW_ADDRESS, ECOFLOW_SERIAL, ECOFLOW_USER_ID env vars\n",
  );
  process.exit(1);
}

try {
  await monitorGrid(address, serial, userId, (status) => {
    console.log(gridAvailable(status) ? "UP" : "DOWN");
    process.exit(0);
  });
  process.stderr.write("Error: connection lost before receiving status\n");
  process.exit(2);
} catch (e: any) {
  process.stderr.write(`Error: ${e.message}\n`);
  process.exit(2);
}

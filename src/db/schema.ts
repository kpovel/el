import {
  sqliteTable,
  integer,
  real,
  text,
  index,
} from "drizzle-orm/sqlite-core";

export const gridLogs = sqliteTable(
  "grid_logs",
  {
    id: integer("id").primaryKey({ autoIncrement: true }),
    timestamp: integer("timestamp").notNull(),
    status: text("status", { enum: ["UP", "DOWN"] }).notNull(),
    acInputPower: real("ac_input_power"),
    acInputVoltage: real("ac_input_voltage"),
    acOutputPower: real("ac_output_power"),
    batteryLevel: real("battery_level"),
    batteryTemp: real("battery_temp"),
    dcInputPower: real("dc_input_power"),
    usbOutputPower: real("usb_output_power"),
    error: text("error"),
  },
  (table) => [index("idx_grid_logs_timestamp").on(table.timestamp)],
);

CREATE TABLE `grid_logs` (
	`id` integer PRIMARY KEY AUTOINCREMENT NOT NULL,
	`timestamp` integer NOT NULL,
	`status` text NOT NULL,
	`ac_input_power` real,
	`ac_input_voltage` real,
	`ac_output_power` real,
	`battery_level` real,
	`battery_temp` real,
	`dc_input_power` real,
	`usb_output_power` real,
	`error` text
);

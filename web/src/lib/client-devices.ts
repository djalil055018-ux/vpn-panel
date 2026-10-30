export type RegisteredDevice = {
  id: string;
  identifier_hint: string;
  platform: string | null;
  os_version: string | null;
  model: string | null;
  created_at: string;
  last_seen_at: string;
};

export type RegisteredDevices = {
  limit: number;
  count: number;
  devices: RegisteredDevice[];
};

export type DeviceActionResult = {
  ok: boolean;
  message: string;
  data?: RegisteredDevices;
};

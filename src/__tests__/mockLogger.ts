import { vi } from "vitest";
import type { LogService } from "../services/LogService";

export const MockLogger = {
  info: vi.fn(),
  error: vi.fn(),
  debug: vi.fn(),
  warn: vi.fn(),
  // pino-http reads levels.values to validate useLevel
  levels: { values: { error: 50, warn: 40, info: 30, debug: 20 } },
  child() {
    return this;
  },
} as unknown as LogService;

import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";

export interface SessionData {
  target?: string;
  facts?: unknown;
  plan?: unknown;
  offsets?: unknown;
  lastRun?: unknown;
}

export class FileSessionStore {
  constructor(private baseDir: string) {}

  private pathFor(sessionId: string): string {
    return resolve(this.baseDir, `${sessionId}.json`);
  }

  save(sessionId: string, data: SessionData): void {
    mkdirSync(this.baseDir, { recursive: true });
    const p = this.pathFor(sessionId);
    writeFileSync(p, JSON.stringify(data, null, 2), { encoding: "utf-8" });
  }

  load(sessionId: string): SessionData | undefined {
    try {
      const p = this.pathFor(sessionId);
      const txt = readFileSync(p, { encoding: "utf-8" });
      return JSON.parse(txt);
    } catch {
      return undefined;
    }
  }
}

export default FileSessionStore; 
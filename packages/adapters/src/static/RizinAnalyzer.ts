import { StaticAnalyzerPort, BinaryFacts, SectionInfo, SymbolEntry } from "@pwn-mcp/core";
import { spawn } from "node:child_process";
import { SimpleStaticAnalyzer } from "./SimpleStaticAnalyzer.js";

const cache = new Map<string, BinaryFacts>();

async function runRizinJson(path: string, cmd: string): Promise<any> {
  return new Promise((resolve, reject) => {
    const child = spawn("rizin", ["-q", "-c", cmd, "--", path], { stdio: ["ignore", "pipe", "pipe"] });
    const out: Buffer[] = [];
    const err: Buffer[] = [];
    child.stdout.on("data", (d) => out.push(Buffer.from(d)));
    child.stderr.on("data", (d) => err.push(Buffer.from(d)));
    child.on("error", (e) => reject(e));
    child.on("close", (code) => {
      if (code !== 0) {
        return reject(new Error(`rizin exited with code ${code}: ${Buffer.concat(err).toString()}`));
      }
      const txt = Buffer.concat(out).toString();
      try {
        const json = JSON.parse(txt || "null");
        resolve(json);
      } catch (e) {
        reject(new Error(`Failed to parse rizin JSON for cmd ${cmd}: ${String(e)}\n${txt}`));
      }
    });
  });
}

function toArch(arch?: string, bits?: number): { arch: "amd64" | "i386"; bits: 64 | 32 } {
  if (bits === 64) return { arch: "amd64", bits: 64 };
  return { arch: "i386", bits: 32 };
}

function toHex(n: number | string): string {
  if (typeof n === "number") return "0x" + n.toString(16);
  if (/^0x/i.test(String(n))) return String(n);
  const parsed = Number(n);
  return Number.isFinite(parsed) ? "0x" + parsed.toString(16) : String(n);
}

function within(addrHex: string, sec: SectionInfo): boolean {
  const a = parseInt(addrHex, 16);
  const s = parseInt(sec.start, 16);
  const e = parseInt(sec.end, 16);
  return Number.isFinite(a) && Number.isFinite(s) && Number.isFinite(e) && a >= s && a < e;
}

export class RizinAnalyzer implements StaticAnalyzerPort {
  private fallback = new SimpleStaticAnalyzer();

  async analyzeBinary(input: { path: string }): Promise<BinaryFacts> {
    const key = input.path;
    if (cache.has(key)) return cache.get(key)!;
    try {
      const info = await runRizinJson(input.path, "ij");
      const syms = await runRizinJson(input.path, "isj").catch(() => []);
      const strs = await runRizinJson(input.path, "izj").catch(() => []);
      const sect = await runRizinJson(input.path, "iSj").catch(() => []);

      const bin = info?.bin || {};
      const { arch, bits } = toArch(bin.arch, bin.bits);
      const protections = {
        NX: Boolean(bin.nx),
        PIE: Boolean(bin.pic),
        RELRO: (bin.relro as "none" | "partial" | "full") || "none",
        Canary: Boolean(bin.canary)
      };

      const pltNames: string[] = [];
      const gotNames: string[] = [];
      const pltEntries: SymbolEntry[] = [];
      const gotEntries: SymbolEntry[] = [];
      if (Array.isArray(syms)) {
        for (const s of syms) {
          const name = String(s?.name || "");
          const vaddr = s?.vaddr ?? s?.plt ?? s?.paddr;
          if (name.includes("@plt") || name.includes(".plt")) {
            pltNames.push(name);
            if (vaddr != null) pltEntries.push({ name, addr: toHex(vaddr) });
          }
          if (name.includes("got")) {
            gotNames.push(name);
            if (vaddr != null) gotEntries.push({ name, addr: toHex(vaddr) });
          }
        }
      }

      const dedupe = (arr: SymbolEntry[]) => {
        const m = new Map(arr.map((e) => [e.name + "@" + e.addr, e] as const));
        return [...m.values()].sort((a, b) => parseInt(a.addr, 16) - parseInt(b.addr, 16));
      };

      const stringsAll: string[] = Array.isArray(strs)
        ? strs
            .map((s: any) => String(s?.string || s?.str || "").trim())
            .filter(Boolean)
        : [];
      const stringsSample = stringsAll.slice(0, 20);

      const sections: SectionInfo[] = Array.isArray(sect)
        ? sect
            .map((s: any) => ({
              name: String(s?.name || ""),
              start: toHex(s?.vaddr ?? s?.paddr ?? 0),
              end: typeof s?.vaddr === "number" && typeof s?.vsize === "number"
                ? toHex((s.vaddr as number) + (s.vsize as number))
                : toHex(s?.paddr ?? 0),
              perm: String(s?.perm || "")
            }))
            .filter((x) => x.name)
        : [];

      // Validate entries by section bounds (keep only addresses within .plt/.got* sections if present)
      const pltSecs = sections.filter((s) => s.name.includes(".plt"));
      const gotSecs = sections.filter((s) => s.name.includes(".got"));
      const pltValidated = pltSecs.length ? dedupe(pltEntries).filter((e) => pltSecs.some((sec) => within(e.addr, sec))) : dedupe(pltEntries);
      const gotValidated = gotSecs.length ? dedupe(gotEntries).filter((e) => gotSecs.some((sec) => within(e.addr, sec))) : dedupe(gotEntries);

      const suspicions: string[] = [];
      if (bin.class === "ELF") suspicions.push("elf");
      if (stringsAll.find((t) => /%s|%n|%p/.test(t))) suspicions.push("printf-family");
      if (stringsAll.find((t) => /(gets\(|strcpy\(|scanf\()/.test(t))) suspicions.push("unsafe-io");

      const facts: BinaryFacts = {
        arch,
        bits,
        protections,
        plt: Array.from(new Set(pltNames)),
        got: Array.from(new Set(gotNames)),
        pltEntries: pltValidated,
        gotEntries: gotValidated,
        stringsSample,
        suspicions,
        sections
      };
      cache.set(key, facts);
      return facts;
    } catch (e) {
      const fallbackFacts = await this.fallback.analyzeBinary(input);
      fallbackFacts.suspicions.push("rizin-fallback");
      cache.set(key, fallbackFacts);
      return fallbackFacts;
    }
  }

  async listGadgets(): Promise<{ count: number; examples: string[] }> {
    return { count: 0, examples: [] };
  }
}

export default RizinAnalyzer; 
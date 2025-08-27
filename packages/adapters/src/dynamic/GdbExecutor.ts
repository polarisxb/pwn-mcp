import { DynamicExecutorPort, Offsets, RunConfig, CrashReport, Registers, MemoryMapEntry } from "@pwn-mcp/core";
import { spawn } from "node:child_process";
import { SimpleDynamicExecutor } from "./SimpleDynamicExecutor.js";
import { readFileSync, existsSync } from "node:fs";

function parseRegisters(text: string): Registers {
  const regs: Registers = {};
  const lines = text.split(/\r?\n/);
  for (const line of lines) {
    const m = line.match(/^\s*([a-z]{2,3}x|[re][si]p|[re][sb]p)\s+0x([0-9a-fA-F]+)/);
    if (m) {
      const name = m[1];
      const val = `0x${m[2]}`;
      regs[name] = val;
    }
  }
  return regs;
}

function parseSignal(text: string): string | null {
  // Enhanced signal parsing - look for multiple patterns
  const patterns = [
    /Program received signal\s+(SIG[A-Z0-9]+)/,
    /Program terminated with signal\s+(SIG[A-Z0-9]+)/,
    /\[Inferior \d+ .* exited with code \d+\]/,
    /Signal\s+(SIG[A-Z0-9]+)/
  ];
  
  for (const pattern of patterns) {
    const m = text.match(pattern);
    if (m && m[1]) return m[1];
  }
  
  // Check for common crash indicators
  if (text.includes("Segmentation fault")) return "SIGSEGV";
  if (text.includes("Bus error")) return "SIGBUS";
  if (text.includes("Illegal instruction")) return "SIGILL";
  if (text.includes("Floating point exception")) return "SIGFPE";
  
  return null;
}

function parseProcMappings(text: string): MemoryMapEntry[] | undefined {
  // Enhanced parsing for memory mappings from GDB output
  const maps: MemoryMapEntry[] = [];
  const lines = text.split(/\r?\n/);
  
  // Look for the mappings section
  let inMappingsSection = false;
  for (const line of lines) {
    if (line.includes("process mappings") || line.includes("Mapped address spaces")) {
      inMappingsSection = true;
      continue;
    }
    
    // Parse mapping lines: 0x...-0x... perms offset dev inode pathname
    const m = line.match(/(0x[0-9a-fA-F]+)\s*-?\s*(0x[0-9a-fA-F]+)\s+([rwxps-]{3,5})\s+[0-9a-fA-F]+\s+[0-9:]+\s+[0-9]+\s*(.*)$/);
    if (m && inMappingsSection) {
      const obj = m[4].trim() || "[anonymous]";
      maps.push({ start: m[1], end: m[2], perm: m[3], obj });
    }
    
    // Alternative format without device/inode
    const m2 = line.match(/(0x[0-9a-fA-F]+)\s*-\s*(0x[0-9a-fA-F]+)\s+([rwxp-]{4})\s+(.*)$/);
    if (m2 && !m && inMappingsSection) {
      const obj = m2[4].trim() || "[anonymous]";
      maps.push({ start: m2[1], end: m2[2], perm: m2[3], obj });
    }
  }
  
  return maps.length ? maps : undefined;
}

export class GdbExecutor implements DynamicExecutorPort {
  private fallback = new SimpleDynamicExecutor();

  async calculateOffsets(input: { patternDumpHex: string }): Promise<Offsets> {
    return this.fallback.calculateOffsets(input);
  }

  async runLocal(input: RunConfig): Promise<CrashReport> {
    const { path, args = [], timeoutMs = 8000 } = input;
    try {
      const gdbArgs = [
        "-q",
        "-nx",
        "-batch",
        "-ex",
        "set pagination off",
        "-ex",
        "set confirm off",
        "-ex",
        "run",
        "-ex",
        "generate-core-file core.dump",
        "-ex",
        "info registers",
        "-ex",
        "info proc mappings",
        "--",
        path,
        ...args
      ];
      const child = spawn("gdb", gdbArgs, { stdio: ["ignore", "pipe", "pipe"] });

      const timer = setTimeout(() => {
        child.kill("SIGKILL");
      }, timeoutMs);

      const out: Buffer[] = [];
      const err: Buffer[] = [];
      child.stdout.on("data", (d) => out.push(Buffer.from(d)));
      child.stderr.on("data", (d) => err.push(Buffer.from(d)));

      const exit = await new Promise<{ code: number | null; signal: string | null }>((resolve) => {
        child.on("exit", (code, signal) => resolve({ code, signal: signal as string | null }));
        child.on("close", (code, signal) => resolve({ code: code as number | null, signal: signal as string | null }));
      });

      clearTimeout(timer);

      const stdoutTxt = Buffer.concat(out).toString();
      const stderrTxt = Buffer.concat(err).toString();
      const combined = stdoutTxt + "\n" + stderrTxt;

      const regs = parseRegisters(combined);
      const sig = parseSignal(combined);

      // Extract mappings section (best-effort): lines after "info proc mappings" often echoed
      const maps = parseProcMappings(combined);

      // Detect core file mention
      let corePath: string | undefined;
      const coreMatch = combined.match(/Saved corefile\s+(\S+)/);
      if (coreMatch) {
        corePath = coreMatch[1];
      } else if (existsSync("core.dump")) {
        try {
          const coreSize = readFileSync("core.dump").length;
          if (coreSize > 0) corePath = "core.dump";
        } catch {
          // Ignore read errors
        }
      }

      const report: CrashReport = {
        exit: { code: exit.code, signal: sig },
        regs,
        stdout: stdoutTxt,
        stderr: stderrTxt,
        stackHex: undefined,
        maps,
        artifacts: corePath ? { core: corePath } : undefined,
        asserts: {
          usedGdb: true,
          completed: true
        }
      };

      return report;
    } catch (e) {
      // Enhanced error handling - check if GDB is available
      const error = e as Error;
      if (error.message?.includes("ENOENT") || error.message?.includes("gdb")) {
        // GDB not found, add error info before falling back
        const fallbackResult = await this.fallback.runLocal(input);
        if (fallbackResult.asserts) {
          fallbackResult.asserts.gdbUnavailable = true;
        }
        return fallbackResult;
      }
      return this.fallback.runLocal(input);
    }
  }
}

export default GdbExecutor; 
import { DynamicExecutorPort, Offsets, RunConfig, CrashReport } from "@pwn-mcp/core";
import { spawn } from "node:child_process";

function generateCyclic(length: number): string {
  const A = "abcdefghijklmnopqrstuvwxyz";
  const B = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
  const C = "0123456789";
  const chunks: string[] = [];
  for (let i = 0; i < A.length; i++) {
    for (let j = 0; j < B.length; j++) {
      for (let k = 0; k < C.length; k++) {
        chunks.push(A[i] + B[j] + C[k]);
        if (chunks.join("").length >= length) {
          return chunks.join("").slice(0, length);
        }
      }
    }
  }
  return chunks.join("").slice(0, length);
}

function hexToAscii(hex: string): string {
  const clean = hex.replace(/\s+/g, "");
  if (clean.length % 2 !== 0 || !/^[0-9a-fA-F]+$/.test(clean)) return hex; // treat as already ascii
  let out = "";
  for (let i = 0; i < clean.length; i += 2) {
    const byte = parseInt(clean.slice(i, i + 2), 16);
    out += String.fromCharCode(byte);
  }
  return out;
}

function findOffsetFromDump(dumpAscii: string, pattern: string): number | undefined {
  // search for any window (size 4..16) that appears in pattern
  const minWin = 4;
  const maxWin = 16;
  for (let w = maxWin; w >= minWin; w--) {
    for (let i = 0; i + w <= dumpAscii.length; i++) {
      const sub = dumpAscii.slice(i, i + w);
      const idx = pattern.indexOf(sub);
      if (idx !== -1) return idx;
    }
  }
  return undefined;
}

export class SimpleDynamicExecutor implements DynamicExecutorPort {
  async calculateOffsets(input: { patternDumpHex: string }): Promise<Offsets> {
    const pattern = generateCyclic(8192);
    const ascii = hexToAscii(input.patternDumpHex);
    const offset = findOffsetFromDump(ascii, pattern);
    return { patternOffset: offset ?? -1 } as Offsets;
  }

  async runLocal(input: RunConfig): Promise<CrashReport> {
    const { path, args = [], input: stdinInput, timeoutMs = 5000 } = input;
    const child = spawn(path, args, { stdio: ["pipe", "pipe", "pipe"] });

    const timer = setTimeout(() => {
      child.kill("SIGKILL");
    }, timeoutMs);

    if (stdinInput) {
      let data = stdinInput;
      const cyclicMatch = stdinInput.match(/^cyclic\((\d+)\)$/);
      if (cyclicMatch) {
        const n = Math.max(1, Math.min(65536, parseInt(cyclicMatch[1], 10)));
        data = generateCyclic(n);
      }
      child.stdin.write(data);
      child.stdin.end();
    }

    const stdoutChunks: Buffer[] = [];
    const stderrChunks: Buffer[] = [];

    child.stdout.on("data", (d) => stdoutChunks.push(Buffer.from(d)));
    child.stderr.on("data", (d) => stderrChunks.push(Buffer.from(d)));

    const exit = await new Promise<{ code: number | null; signal: string | null }>((resolve) => {
      child.on("exit", (code, signal) => resolve({ code, signal: signal as string | null }));
      child.on("close", (code, signal) => resolve({ code: code as number | null, signal: signal as string | null }));
    });

    clearTimeout(timer);

    const report: CrashReport = {
      exit,
      regs: {},
      stdout: Buffer.concat(stdoutChunks).toString(),
      stderr: Buffer.concat(stderrChunks).toString(),
      stackHex: undefined,
      maps: undefined,
      artifacts: undefined,
      asserts: {
        completed: true
      }
    };

    return report;
  }
}

export default SimpleDynamicExecutor; 
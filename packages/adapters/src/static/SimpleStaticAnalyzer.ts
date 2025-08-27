import { StaticAnalyzerPort, BinaryFacts } from "@pwn-mcp/core";
import { existsSync, readFileSync } from "node:fs";

export class SimpleStaticAnalyzer implements StaticAnalyzerPort {
  async analyzeBinary(input: { path: string }): Promise<BinaryFacts> {
    const { path } = input;
    if (!existsSync(path)) {
      throw new Error(`File not found: ${path}`);
    }
    const head = readFileSync(path, { encoding: null, flag: "r" }).subarray(0, 4);
    // crude ELF/PE detect
    const isELF = head[0] === 0x7f && head[1] === 0x45 && head[2] === 0x4c && head[3] === 0x46;
    const isPE = head[0] === 0x4d && head[1] === 0x5a; // MZ

    const facts: BinaryFacts = {
      arch: "amd64",
      bits: 64,
      protections: { NX: true, PIE: true, RELRO: "partial", Canary: true },
      plt: [],
      got: [],
      stringsSample: [],
      suspicions: []
    };

    if (isELF) {
      facts.suspicions.push("elf");
    } else if (isPE) {
      facts.suspicions.push("pe");
    } else {
      facts.suspicions.push("unknown-binary-format");
    }

    return facts;
  }

  async listGadgets(): Promise<{ count: number; examples: string[] }> {
    return { count: 0, examples: [] };
  }
}

export default SimpleStaticAnalyzer; 
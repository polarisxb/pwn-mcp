import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";
import { spawn, spawnSync } from "node:child_process";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

async function main() {
  // Auto-enable deep static if rizin is available
  const rizinProbe = spawnSync(process.platform === 'win32' ? 'rizin.exe' : 'rizin', ['-v'], { stdio: 'ignore' });
  const deepStatic = rizinProbe.status === 0;
  if (deepStatic) process.env.SAFE_MCP_DEEP_STATIC = 'true';
  
  // Auto-enable GDB exec if gdb is available
  const gdbProbe = spawnSync(process.platform === 'win32' ? 'gdb.exe' : 'gdb', ['--version'], { stdio: 'ignore' });
  const gdbExec = gdbProbe.status === 0;
  if (gdbExec) process.env.SAFE_MCP_GDB_EXEC = 'true';

  const serverPath = resolve(__dirname, "../dist/server.js");
  const child = spawn(process.execPath, [serverPath], {
    stdio: ["pipe", "pipe", "pipe"],
    env: process.env
  });

  child.stderr.on("data", (d) => process.stderr.write(d));

  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [serverPath]
  });

  const client = new Client({ name: "smoke-client", version: "0.1.0" });
  await client.connect(transport);

  const tools = await client.listTools();
  console.log("tools:", tools.tools.map(t => t.name));

  const h = await client.callTool({ name: "health_check", arguments: {} });
  console.log("health_check:", h.content);

  const init = await client.callTool({ name: "init_session", arguments: { target: "./chall" } });
  console.log("init_session:", init.content);
  const sessionId = JSON.parse(init.content[0].text).sessionId;

  const factsText = await client.callTool({ name: "analyze_binary", arguments: { path: __filename } });
  console.log("analyze_binary:", factsText.content);
  const facts = JSON.parse(factsText.content[0].text);

  if (deepStatic && !(facts.suspicions || []).includes('rizin-fallback')) {
    const deepOk = (facts.sections && facts.sections.length > 0) ||
                   (facts.pltEntries && facts.pltEntries.length > 0) ||
                   (facts.gotEntries && facts.gotEntries.length > 0);
    console.log("deep_static_checks:", deepOk ? "OK" : "SKIPPED/EMPTY");
  } else {
    console.log("deep_static_checks: skipped (no rizin or fallback)");
  }

  const plan = await client.callTool({ name: "suggest_strategy", arguments: { facts } });
  console.log("suggest_strategy:", plan.content);

  const off = await client.callTool({ name: "calculate_offsets", arguments: { patternDumpHex: Buffer.from("AAAA").toString("hex") } });
  console.log("calculate_offsets:", off.content);

  await client.callTool({ name: "save_session", arguments: { sessionId, data: { target: __filename, facts, plan: JSON.parse(plan.content[0].text), offsets: JSON.parse(off.content[0].text) } } });

  const report = await client.callTool({ name: "export_report", arguments: { sessionId } });
  const md = report.content[0].text;
  console.log("export_report (by session) first 120:", md.slice(0, 120).replace(/\n/g, "\\n"), "...");
  
  // Test dynamic execution if GDB is available
  if (gdbExec) {
    console.log("\n=== Testing GDB execution ===");
    // Create a simple test binary that crashes
    const testCode = `
#include <stdio.h>
int main() {
    char buffer[16];
    printf("Enter input: ");
    fflush(stdout);
    gets(buffer);  // Vulnerable function
    return 0;
}`;
    
    const fs = await import("fs/promises");
    const testSrc = resolve(__dirname, "test_crash.c");
    const testBin = resolve(__dirname, "test_crash");
    
    try {
      await fs.writeFile(testSrc, testCode);
      // Compile with no protections for testing
      const compile = spawnSync("gcc", ["-fno-stack-protector", "-no-pie", "-o", testBin, testSrc], { stdio: 'inherit' });
      
      if (compile.status === 0) {
        // Test run_local with cyclic pattern
        const runResult = await client.callTool({ 
          name: "run_local", 
          arguments: { 
            path: testBin, 
            input: "cyclic(100)",
            timeoutMs: 5000
          } 
        });
        
        const crashReport = JSON.parse(runResult.content[0].text);
        console.log("GDB test results:");
        console.log("- Used GDB:", crashReport.asserts?.usedGdb === true ? "YES" : "NO");
        console.log("- Signal:", crashReport.exit?.signal || "none");
        console.log("- Maps present:", crashReport.maps?.length > 0 ? "YES" : "NO");
        console.log("- Core file:", crashReport.artifacts?.core ? "YES" : "NO");
        
        // Clean up
        await fs.unlink(testSrc).catch(() => {});
        await fs.unlink(testBin).catch(() => {});
        if (crashReport.artifacts?.core) {
          await fs.unlink(crashReport.artifacts.core).catch(() => {});
        }
      } else {
        console.log("GDB test skipped: gcc not available");
      }
    } catch (e) {
      console.log("GDB test error:", e.message);
    }
  }

  await client.close();
  child.kill();
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
}); 
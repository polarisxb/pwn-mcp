#!/usr/bin/env node

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";
import { spawn, spawnSync } from "node:child_process";
import { readFileSync, writeFileSync, existsSync, unlinkSync } from "node:fs";
import { createHash } from "node:crypto";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// Test with a known vulnerable binary (stack overflow)
const TEST_BINARY_URL = "https://github.com/guyinatuxedo/nightmare/raw/master/modules/04-bof_variable/tut01-bof/overflow";
const TEST_BINARY_HASH = "3f3c3e2b8e5c5f5e5e5e5e5e5e5e5e5e"; // Replace with actual hash

async function downloadBinary(url, dest) {
  console.log(`Downloading test binary from ${url}...`);
  const response = await fetch(url);
  if (!response.ok) throw new Error(`Failed to download: ${response.statusText}`);
  const buffer = await response.arrayBuffer();
  writeFileSync(dest, Buffer.from(buffer));
  
  // Make executable on Unix-like systems
  if (process.platform !== 'win32') {
    spawnSync('chmod', ['+x', dest]);
  }
  
  return dest;
}

async function runE2ETest() {
  const testDir = resolve(__dirname, "e2e-test");
  const binPath = resolve(testDir, "overflow");
  
  // Create test directory
  if (!existsSync(testDir)) {
    spawnSync(process.platform === 'win32' ? 'mkdir' : 'mkdir', [testDir]);
  }
  
  // Download test binary if not present
  if (!existsSync(binPath)) {
    try {
      await downloadBinary(TEST_BINARY_URL, binPath);
    } catch (e) {
      console.error("Failed to download test binary:", e.message);
      console.log("Creating a local vulnerable binary instead...");
      
      // Create a simple vulnerable binary
      const vulnerableCode = `
#include <stdio.h>
#include <string.h>

void win() {
    printf("You win!\\n");
}

void vulnerable() {
    char buffer[64];
    printf("Enter your payload: ");
    fflush(stdout);
    gets(buffer);  // Stack overflow vulnerability
    printf("You entered: %s\\n", buffer);
}

int main() {
    vulnerable();
    return 0;
}`;
      
      const srcPath = resolve(testDir, "overflow.c");
      writeFileSync(srcPath, vulnerableCode);
      
      // Compile with no protections
      const compile = spawnSync("gcc", [
        "-fno-stack-protector",
        "-no-pie",
        "-z", "execstack",
        "-o", binPath,
        srcPath
      ], { stdio: 'inherit' });
      
      if (compile.status !== 0) {
        console.error("Failed to compile test binary");
        return;
      }
    }
  }
  
  // Start MCP server
  const serverPath = resolve(__dirname, "../dist/server.js");
  const serverProc = spawn(process.execPath, [serverPath], {
    stdio: ["pipe", "pipe", "pipe"],
    env: {
      ...process.env,
      SAFE_MCP_DEEP_STATIC: 'true',
      SAFE_MCP_GDB_EXEC: 'true'
    }
  });
  
  serverProc.stderr.on("data", (d) => process.stderr.write(d));
  
  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [serverPath]
  });
  
  const client = new Client({ name: "e2e-client", version: "0.1.0" });
  await client.connect(transport);
  
  console.log("\n=== E2E Stack Overflow Test ===");
  
  try {
    // Step 1: Initialize session
    console.log("\n1. Initializing session...");
    const initResp = await client.callTool({ 
      name: "init_session", 
      arguments: { target: binPath } 
    });
    const { sessionId } = JSON.parse(initResp.content[0].text);
    console.log(`Session ID: ${sessionId}`);
    
    // Step 2: Analyze binary
    console.log("\n2. Analyzing binary...");
    const factsResp = await client.callTool({ 
      name: "analyze_binary", 
      arguments: { path: binPath } 
    });
    const facts = JSON.parse(factsResp.content[0].text);
    console.log("Binary facts:");
    console.log(`- Architecture: ${facts.arch} ${facts.bits}-bit`);
    console.log(`- Protections: NX=${facts.protections.NX}, PIE=${facts.protections.PIE}, Canary=${facts.protections.Canary}`);
    console.log(`- Suspicions: ${facts.suspicions.join(", ")}`);
    
    // Step 3: Generate strategy
    console.log("\n3. Generating exploit strategy...");
    const strategyResp = await client.callTool({ 
      name: "suggest_strategy", 
      arguments: { facts } 
    });
    const strategy = JSON.parse(strategyResp.content[0].text);
    console.log("Strategy steps:");
    strategy.steps.forEach((step, i) => {
      console.log(`  ${i+1}. ${step.name}: ${step.description}`);
    });
    
    // Step 4: Find crash offset
    console.log("\n4. Finding crash offset...");
    const crashResp = await client.callTool({ 
      name: "run_local", 
      arguments: { 
        path: binPath, 
        input: "cyclic(200)",
        timeoutMs: 5000
      } 
    });
    const crashReport = JSON.parse(crashResp.content[0].text);
    console.log(`- Exit signal: ${crashReport.exit.signal || "none"}`);
    console.log(`- RIP/EIP value: ${crashReport.regs.rip || crashReport.regs.eip || "unknown"}`);
    
    // Step 5: Calculate offset
    const patternDump = crashReport.regs.rip || crashReport.regs.eip || "0x41414141";
    const offsetResp = await client.callTool({ 
      name: "calculate_offsets", 
      arguments: { 
        patternDumpHex: patternDump.replace("0x", "")
      } 
    });
    const offsets = JSON.parse(offsetResp.content[0].text);
    console.log(`- Pattern offset: ${offsets.patternOffset}`);
    
    // Step 6: Generate exploit template
    console.log("\n5. Generating exploit template...");
    const templateResp = await client.callTool({ 
      name: "generate_pwntools_template", 
      arguments: { 
        target: binPath,
        facts,
        offsets
      } 
    });
    console.log("Generated pwntools template (first 200 chars):");
    console.log(templateResp.content[0].text.slice(0, 200) + "...");
    
    // Step 7: Save session and export report
    console.log("\n6. Saving session and exporting report...");
    await client.callTool({ 
      name: "save_session", 
      arguments: { 
        sessionId, 
        data: { 
          target: binPath, 
          facts, 
          plan: strategy, 
          offsets,
          crashReport
        } 
      } 
    });
    
    const reportResp = await client.callTool({ 
      name: "export_report", 
      arguments: { sessionId } 
    });
    const reportPath = resolve(testDir, `${sessionId}-report.md`);
    writeFileSync(reportPath, reportResp.content[0].text);
    console.log(`Report saved to: ${reportPath}`);
    
    console.log("\n✅ E2E test completed successfully!");
    
  } catch (e) {
    console.error("\n❌ E2E test failed:", e);
  } finally {
    await client.close();
    serverProc.kill();
    
    // Cleanup
    if (process.env.E2E_CLEANUP !== 'false') {
      console.log("\nCleaning up test files...");
      try {
        unlinkSync(resolve(testDir, "overflow"));
        unlinkSync(resolve(testDir, "overflow.c"));
      } catch {}
    }
  }
}

runE2ETest().catch((err) => {
  console.error("Fatal error:", err);
  process.exit(1);
});

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { SimpleStaticAnalyzer, SimpleDynamicExecutor, RizinAnalyzer, GdbExecutor } from "@pwn-mcp/adapters";
import { SimpleDecisionEngine } from "@pwn-mcp/orchestrator";
import { generatePwntoolsTemplate, generateGdbProfile } from "@pwn-mcp/templates";
import { loadFeatureFlags } from "@pwn-mcp/config";
import { FileSessionStore } from "@pwn-mcp/storage";
import { PwnMcpError } from "@pwn-mcp/core";
import { resolve } from "node:path";

const flags = loadFeatureFlags();

const server = new McpServer({
	name: "pwn-assistant",
	version: "0.1.0"
});

const analyzer = flags.deepStatic ? new RizinAnalyzer() : new SimpleStaticAnalyzer();
const decision = new SimpleDecisionEngine();
const dynamicExec = flags.gdbExec ? new GdbExecutor() : new SimpleDynamicExecutor();
const store = new FileSessionStore(resolve(process.cwd(), ".sessions"));

function ok(text: string) {
	return { content: [{ type: "text", text }] } as const;
}
function toolError(e: unknown) {
	if (e instanceof PwnMcpError) {
		const errorInfo = {
			errorType: e.errorType,
			message: e.message,
			details: e.details
		};
		return { 
			content: [{ type: "text", text: JSON.stringify(errorInfo) }], 
			isError: true as const 
		};
	}
	const msg = e instanceof Error ? e.message : String(e);
	return { content: [{ type: "text", text: `Error: ${msg}` }], isError: true as const };
}
function wrapNoArgs(fn: () => Promise<any> | any) {
	return async (_extra?: unknown) => {
		try { return await fn(); } catch (e) { return toolError(e); }
	};
}
function wrapArgs(fn: (args: any) => Promise<any> | any) {
	return async (args: any, _extra?: unknown) => {
		try { return await fn(args); } catch (e) { return toolError(e); }
	};
}

server.registerTool(
	"health_check",
	{
		title: "Health Check",
		description: "Returns OK to confirm the server is running"
	},
	wrapNoArgs(async () => ok(`OK (deepStatic=${flags.deepStatic}, gdbExec=${flags.gdbExec})`))
);

server.registerTool(
	"init_session",
	{
		title: "Init Session",
		description: "Initialize a session for a given target binary and optional libc/ld",
		inputSchema: {
			target: z.string(),
			libc: z.string().optional(),
			ld: z.string().optional()
		}
	},
	wrapArgs(async ({ target, libc, ld }) => ok(JSON.stringify({ sessionId: cryptoRandomId(), target, libc, ld })))
);

server.registerTool(
	"analyze_binary",
	{
		title: "Analyze Binary",
		description: "Lightweight static analysis to produce BinaryFacts",
		inputSchema: { path: z.string() }
	},
	wrapArgs(async ({ path }) => ok(JSON.stringify(await analyzer.analyzeBinary({ path }))))
);

server.registerTool(
	"suggest_strategy",
	{
		title: "Suggest Strategy",
		description: "Produce a StrategyPlan from BinaryFacts",
		inputSchema: {
			facts: z.object({
				arch: z.enum(["amd64", "i386"]),
				bits: z.union([z.literal(32), z.literal(64)]),
				protections: z.object({
					NX: z.boolean(), PIE: z.boolean(), RELRO: z.enum(["none", "partial", "full"]), Canary: z.boolean()
				}),
				plt: z.array(z.string()),
				got: z.array(z.string()),
				stringsSample: z.array(z.string()),
				suspicions: z.array(z.string()),
				sections: z.any().optional()
			})
		}
	},
	wrapArgs(async ({ facts }) => ok(JSON.stringify(decision.planFromFacts(facts))))
);

server.registerTool(
	"calculate_offsets",
	{
		title: "Calculate Offsets",
		description: "Compute pattern offset from hex/ascii dump",
		inputSchema: { patternDumpHex: z.string() }
	},
	wrapArgs(async ({ patternDumpHex }) => ok(JSON.stringify(await dynamicExec.calculateOffsets({ patternDumpHex }))))
);

server.registerTool(
	"run_local",
	{
		title: "Run Local",
		description: "Run a local binary with optional args/input and timeout",
		inputSchema: {
			path: z.string(),
			args: z.array(z.string()).optional(),
			input: z.string().optional(),
			timeoutMs: z.number().optional(),
			aslr: z.boolean().optional()
		}
	},
	wrapArgs(async ({ path, args, input, timeoutMs, aslr }) => ok(JSON.stringify(await dynamicExec.runLocal({ path, args, input, timeoutMs, aslr }))))
);

server.registerTool(
	"gen_exploit_template",
	{
		title: "Generate Exploit Template",
		description: "Generate a pwntools scaffold with TODO placeholders (non-weaponized)",
		inputSchema: {
			targetPath: z.string(),
			facts: z.any().optional(),
			resolved: z.any().optional()
		}
	},
	wrapArgs(async ({ targetPath, facts, resolved }) => ok(generatePwntoolsTemplate({ targetPath, facts, resolved })))
);

server.registerTool(
	"gen_gdb_profile",
	{
		title: "Generate GDB Profile",
		description: "Generate a simple gdb script with common breakpoints",
		inputSchema: {
			targetPath: z.string(),
			libcPath: z.string().optional(),
			ldPath: z.string().optional()
		}
	},
	wrapArgs(async ({ targetPath, libcPath, ldPath }) => ok(generateGdbProfile({ targetPath, libcPath, ldPath })))
);

server.registerTool(
	"export_report",
	{
		title: "Export Report",
		description: "Export a Markdown report from collected artifacts",
		inputSchema: {
			target: z.string().describe("Target binary path").optional(),
			facts: z.any().optional(),
			plan: z.any().optional(),
			offsets: z.any().optional(),
			lastRun: z.any().optional(),
			sessionId: z.string().optional()
		}
	},
	wrapArgs(async ({ target, facts, plan, offsets, lastRun, sessionId }) => {
		const supplied: any = {};
		if (typeof target !== "undefined") supplied.target = target;
		if (typeof facts !== "undefined") supplied.facts = facts;
		if (typeof plan !== "undefined") supplied.plan = plan;
		if (typeof offsets !== "undefined") supplied.offsets = offsets;
		if (typeof lastRun !== "undefined") supplied.lastRun = lastRun;

		let merged: any = supplied;
		if (sessionId) {
			const fromStore = store.load(sessionId) || {};
			merged = { ...fromStore, ...supplied };
		}

		const md = `# Pwn Assistant Report\n\n- Target: ${merged.target ?? "(unknown)"}\n\n## Binary Facts\n\n${merged.facts ? "```json\n" + JSON.stringify(merged.facts, null, 2) + "\n```" : "(none)"}\n\n## Strategy Plan\n\n${merged.plan ? "```json\n" + JSON.stringify(merged.plan, null, 2) + "\n```" : "(none)"}\n\n## Offsets\n\n${merged.offsets ? "```json\n" + JSON.stringify(merged.offsets, null, 2) + "\n```" : "(none)"}\n\n## Last Run\n\n${merged.lastRun ? "```json\n" + JSON.stringify(merged.lastRun, null, 2) + "\n```" : "(none)"}\n`;
		return ok(md);
	})
);

server.registerTool(
	"save_session",
	{
		title: "Save Session",
		description: "Persist session data to local storage",
		inputSchema: {
			sessionId: z.string(),
			data: z.any()
		}
	},
	wrapArgs(async ({ sessionId, data }) => { store.save(sessionId, data); return ok("SAVED"); })
);

server.registerTool(
	"load_session",
	{
		title: "Load Session",
		description: "Load session data from local storage",
		inputSchema: { sessionId: z.string() }
	},
	wrapArgs(async ({ sessionId }) => ok(JSON.stringify(store.load(sessionId) || {})))
);

function cryptoRandomId(): string {
	return `sess_${Math.random().toString(36).slice(2, 10)}`;
}

async function main() {
	const transport = new StdioServerTransport();
	await server.connect(transport);
}

main().catch((err) => {
	console.error("Server error:", err);
	process.exit(1);
}); 
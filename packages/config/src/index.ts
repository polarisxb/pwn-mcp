export interface FeatureFlags {
  deepStatic: boolean; // enable rizin/radare2 adapter later
  gdbExec: boolean;    // enable gdb-backed executor later
}

export function loadFeatureFlags(env: NodeJS.ProcessEnv = process.env): FeatureFlags {
  const toBool = (v: string | undefined, def: boolean) => {
    if (v == null) return def;
    return /^(1|true|yes|on)$/i.test(v);
  };
  return {
    deepStatic: toBool(env.SAFE_MCP_DEEP_STATIC, false),
    gdbExec: toBool(env.SAFE_MCP_GDB_EXEC, false)
  };
} 
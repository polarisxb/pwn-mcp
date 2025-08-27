import { BinaryFacts, ResolvedSymbols } from "@pwn-mcp/core";

export function generatePwntoolsTemplate(params: {
  targetPath: string;
  facts?: BinaryFacts;
  resolved?: ResolvedSymbols;
}): string {
  const header = "# Auto-generated scaffold. Fill in TODOs before use.";
  return `#!/usr/bin/env python3
# ${header}
from pwn import *

context.binary = r"${params.targetPath}"
context.log_level = "debug"

def start(argv=[], *a, **kw):
    return process([context.binary.path] + argv, *a, **kw)

io = start()

# TODO: choose leak strategy (e.g., leak puts@GOT via puts@PLT)
# TODO: send cyclic to measure offset, then craft chain

io.interactive()
`;
}

export default generatePwntoolsTemplate; 
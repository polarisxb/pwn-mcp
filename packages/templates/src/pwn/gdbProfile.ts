export function generateGdbProfile(params: { targetPath: string; libcPath?: string; ldPath?: string }): string {
  const lines: string[] = [];
  lines.push("set disassembly-flavor intel");
  lines.push("set pagination off");
  lines.push("catch syscall");
  lines.push("break main");
  lines.push(`file ${params.targetPath}`);
  if (params.libcPath) lines.push(`set substitute-path /lib/x86_64-linux-gnu/libc.so.6 ${params.libcPath}`);
  if (params.ldPath) lines.push(`set substitute-path /lib64/ld-linux-x86-64.so.2 ${params.ldPath}`);
  lines.push("run");
  return lines.join("\n");
}

export default generateGdbProfile; 
// secret-env DSH 探针插件：验证 tools/execute waterfall 里 mutate exec.arguments.command
// 是否被 bash 工具 body 看到（官方口径「wrappers may change only exec.signal」，
// 但 dispatchToolBody 是 tool.execute(exec.arguments, exec) 现场读取同一对象——机械上应生效）。
// 验证成功后此插件退役，换上真身 secret-env 前缀改写。
import { appendFileSync } from "node:fs";

export function apply(ctx) {
  const unwrap = ctx.on("tools/execute", async function (exec, next) {
    if (exec?.name === "bash" && typeof exec?.arguments?.command === "string") {
      // 探针动作：任何 bash 命令前面插一行标记 echo——不改语义，只证明改写传导
      exec.arguments = { ...exec.arguments, command: `echo SECRET-ENV-PROBE-HIT; ${exec.arguments.command}` };
      try { appendFileSync("/tmp/secret-env-probe.log", `[${new Date().toISOString()}] rewrote bash cmd\n`); } catch {}
    }
    return next();
  });
  return () => unwrap();
}

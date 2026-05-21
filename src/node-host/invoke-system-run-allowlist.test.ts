import { describe, expect, it } from "vitest";
import { planShellAuthorization } from "../infra/exec-authorization-plan.js";
import { resolveSystemRunExecArgv } from "./invoke-system-run-allowlist.js";

function planSegments(plan: Awaited<ReturnType<typeof planShellAuthorization>>) {
  return plan.ok
    ? plan.groups.flatMap((group) => group.candidates.map((candidate) => candidate.sourceSegment))
    : [];
}

describe("resolveSystemRunExecArgv", () => {
  it.runIf(process.platform !== "win32")("rejects a stale POSIX authorization plan", async () => {
    const env = { PATH: "/usr/bin:/bin" };
    const plan = await planShellAuthorization({ command: "echo nope", env });
    expect(plan.ok).toBe(true);
    if (!plan.ok) {
      throw new Error(plan.reason);
    }

    const result = resolveSystemRunExecArgv({
      plannedAllowlistArgv: undefined,
      argv: ["/bin/sh", "-lc", "head -c 16"],
      security: "allowlist",
      isWindows: false,
      policy: {
        approvedByAsk: false,
        analysisOk: true,
        allowlistSatisfied: true,
      },
      shellCommand: "head -c 16",
      segments: planSegments(plan),
      segmentSatisfiedBy: ["safeBins"],
      authorizationPlan: plan,
      cwd: undefined,
      env,
    });

    expect(result).toBeNull();
  });

  it.runIf(process.platform !== "win32")(
    "uses the existing POSIX authorization plan when rewriting safe-bin shell argv",
    async () => {
      const env = { PATH: "/usr/bin:/bin" };
      const plan = await planShellAuthorization({ command: "head -c 16", env });
      expect(plan.ok).toBe(true);
      if (!plan.ok) {
        throw new Error(plan.reason);
      }

      const result = resolveSystemRunExecArgv({
        plannedAllowlistArgv: undefined,
        argv: ["/bin/sh", "-lc", "head -c 16"],
        security: "allowlist",
        isWindows: false,
        policy: {
          approvedByAsk: false,
          analysisOk: true,
          allowlistSatisfied: true,
        },
        shellCommand: "head -c 16",
        segments: planSegments(plan),
        segmentSatisfiedBy: ["safeBins"],
        authorizationPlan: plan,
        cwd: undefined,
        env,
      });

      expect(result).not.toBeNull();
      expect(result?.[0]).toBe("/bin/sh");
      expect(result?.[2]).toContain("head");
      expect(result?.[2]).not.toBe("head -c 16");
    },
  );
});

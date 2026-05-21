import { describe, expect, it } from "vitest";
import {
  inspectControlShellCommand,
  type ControlShellPolicyDecision,
} from "./exec-control-shell-policy.js";

async function inspect(command: string): Promise<ControlShellPolicyDecision> {
  return await inspectControlShellCommand({ command });
}

describe("exec control shell policy", () => {
  it.each([
    "openclaw channels login --channel whatsapp",
    "openclaw channel login --channel whatsapp",
    "openclaw channels --profile rescue login --channel whatsapp",
    "openclaw channels --dev login --channel whatsapp",
    "npm exec -- openclaw channels login --channel whatsapp",
    "pnpm exec -- openclaw channels login --channel whatsapp",
    "yarn exec -- openclaw channels login --channel whatsapp",
    "sudo -u openclaw bash -lc 'openclaw channels login --channel whatsapp'",
    "bash -lc 'openclaw --profile rescue channels login --channel=whatsapp'",
    "env -S 'openclaw channels' login --channel whatsapp",
  ])("denies interactive channel login commands: %s", async (command) => {
    await expect(inspect(command)).resolves.toMatchObject({
      kind: "deny",
      message: expect.stringContaining(
        "exec cannot run interactive OpenClaw channel login commands",
      ),
    });
  });

  it.each([
    "openclaw config get security.audit.suppressions",
    "openclaw --profile rescue config get security.audit.suppressions",
    "openclaw config schema security.audit.suppressions",
    "openclaw config validate",
  ])("allows read-only security audit suppression inspection: %s", async (command) => {
    await expect(inspect(command)).resolves.toEqual({ kind: "allow" });
  });

  it.each([
    "openclaw config set security.audit.suppressions '[]'",
    "openclaw config get security.audit.suppressions; openclaw config set security.audit.suppressions '[]'",
    "bash -lc 'openclaw config set security.audit.suppressions []'",
    `openclaw config patch --stdin <<'EOF'
{"security":{"audit":{"suppressions":[]}}}
EOF`,
  ])("requires approval for security audit suppression mutations: %s", async (command) => {
    await expect(inspect(command)).resolves.toMatchObject({
      kind: "requires-approval",
      warning: expect.stringContaining(
        "security audit suppression changes require explicit approval",
      ),
    });
  });

  it("returns requires-approval without knowing whether yolo mode is active", async () => {
    await expect(inspect("openclaw config set security.audit.suppressions '[]'")).resolves.toEqual({
      kind: "requires-approval",
      warning:
        "Warning: security audit suppression changes require explicit approval unless exec is running in yolo mode.",
    });
  });

  it.each([
    "cat ~/.ssh/id_rsa",
    "less .ssh/config",
    "head -n 1 -- ~/.ssh/config",
    "bash -lc 'cat ~/.ssh/id_rsa'",
  ])("requires approval for static ssh file reads: %s", async (command) => {
    await expect(inspect(command)).resolves.toMatchObject({
      kind: "requires-approval",
      warning: expect.stringContaining("Reading SSH files requires explicit approval"),
    });
  });

  it.each(["cat README.md", "head -n 1 package.json", "bash -lc 'cat README.md'"])(
    "allows ordinary static file reads: %s",
    async (command) => {
      await expect(inspect(command)).resolves.toEqual({ kind: "allow" });
    },
  );
});

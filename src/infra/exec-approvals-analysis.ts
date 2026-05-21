import type { CommandResolution } from "./exec-command-resolution.js";
import {
  analyzeWindowsShellCommand,
  isWindowsPlatform,
  rebuildWindowsShellCommandFromSource,
  tokenizeWindowsSegment,
  windowsEscapeArg,
  type RebuiltShellCommandResult,
  type ShellSegmentRenderResult,
} from "./windows-shell-command.js";

export { analyzeArgvCommand } from "./exec-argv-analysis.js";

export {
  matchAllowlist,
  parseExecArgvToken,
  resolveAllowlistCandidatePath,
  resolveApprovalAuditCandidatePath,
  resolveApprovalAuditTrustPath,
  resolveCommandResolution,
  resolveCommandResolutionFromArgv,
  resolveExecutionTargetCandidatePath,
  resolveExecutionTargetResolution,
  resolveExecutionTargetTrustPath,
  resolvePolicyAllowlistCandidatePath,
  resolvePolicyTargetCandidatePath,
  resolvePolicyTargetResolution,
  resolvePolicyTargetTrustPath,
  resolveExecutableTrustPath,
  type CommandResolution,
  type ExecutableResolution,
  type ExecArgvToken,
} from "./exec-command-resolution.js";

export { isWindowsPlatform, windowsEscapeArg } from "./windows-shell-command.js";

export type ExecCommandSegment = {
  raw: string;
  argv: string[];
  sourceArgv?: string[];
  resolution: CommandResolution | null;
};

export type ExecCommandAnalysis = {
  ok: boolean;
  reason?: string;
  segments: ExecCommandSegment[];
  chains?: ExecCommandSegment[][];
};

export type ShellChainOperator = "&&" | "||" | ";" | "&";

export type ShellChainPart = {
  part: string;
  opToNext: ShellChainOperator | null;
};

const POSIX_ANALYSIS_REPLACED_REASON = "POSIX shell analysis uses planShellAuthorization";
const POSIX_RENDER_REPLACED_REASON =
  "POSIX shell rendering uses buildAuthorizedShellCommandFromPlan";

function renderWindowsQuotedArgv(argv: readonly string[]): ShellSegmentRenderResult {
  const parts: string[] = [];
  for (const token of argv) {
    const result = windowsEscapeArg(token);
    if (!result.ok) {
      return { ok: false, reason: `unsafe windows token: ${token}` };
    }
    parts.push(result.escaped);
  }
  return { ok: true, rendered: parts.join(" ") };
}

function finalizeRebuiltShellCommand(
  rebuilt: RebuiltShellCommandResult,
  expectedSegmentCount?: number,
): { ok: boolean; command?: string; reason?: string } {
  if (!rebuilt.ok) {
    return { ok: false, reason: rebuilt.reason };
  }
  if (typeof expectedSegmentCount === "number" && rebuilt.segmentCount !== expectedSegmentCount) {
    return { ok: false, reason: "segment count mismatch" };
  }
  return { ok: true, command: rebuilt.command };
}

export function resolvePlannedSegmentArgv(segment: ExecCommandSegment): string[] | null {
  if (segment.resolution?.policyBlocked === true) {
    return null;
  }
  const baseArgv =
    segment.resolution?.effectiveArgv && segment.resolution.effectiveArgv.length > 0
      ? segment.resolution.effectiveArgv
      : segment.argv;
  if (baseArgv.length === 0) {
    return null;
  }
  const argv = [...baseArgv];
  const execution = segment.resolution?.execution;
  const resolvedExecutable =
    execution?.resolvedRealPath?.trim() ?? execution?.resolvedPath?.trim() ?? "";
  if (resolvedExecutable) {
    argv[0] = resolvedExecutable;
  }
  return argv;
}

export function analyzeShellCommand(params: {
  command: string;
  cwd?: string;
  env?: NodeJS.ProcessEnv;
  platform?: string | null;
}): ExecCommandAnalysis {
  if (isWindowsPlatform(params.platform)) {
    return analyzeWindowsShellCommand(params);
  }
  return { ok: false, reason: POSIX_ANALYSIS_REPLACED_REASON, segments: [] };
}

export function buildSafeShellCommand(params: {
  command: string;
  cwd?: string;
  env?: NodeJS.ProcessEnv;
  platform?: string | null;
}): {
  ok: boolean;
  command?: string;
  reason?: string;
} {
  if (!isWindowsPlatform(params.platform)) {
    return { ok: false, reason: POSIX_RENDER_REPLACED_REASON };
  }
  const rebuilt = rebuildWindowsShellCommandFromSource({
    command: params.command,
    renderSegment: (segmentRaw) => {
      const argv = tokenizeWindowsSegment(segmentRaw) ?? [];
      if (argv.length === 0) {
        return { ok: false, reason: "unable to parse windows command" };
      }
      return renderWindowsQuotedArgv(argv);
    },
  });
  return finalizeRebuiltShellCommand(rebuilt);
}

export function buildSafeBinsShellCommand(params: {
  command: string;
  segments: ExecCommandSegment[];
  segmentSatisfiedBy: ("allowlist" | "safeBins" | "inlineChain" | "skills" | null)[];
  cwd?: string;
  env?: NodeJS.ProcessEnv;
  platform?: string | null;
}): { ok: boolean; command?: string; reason?: string } {
  if (params.segments.length !== params.segmentSatisfiedBy.length) {
    return { ok: false, reason: "segment metadata mismatch" };
  }
  if (!isWindowsPlatform(params.platform)) {
    return { ok: false, reason: POSIX_RENDER_REPLACED_REASON };
  }
  const rebuilt = rebuildWindowsShellCommandFromSource({
    command: params.command,
    renderSegment: (raw, segmentIndex) => {
      const segment = params.segments[segmentIndex];
      const satisfiedBy = params.segmentSatisfiedBy[segmentIndex];
      if (!segment || satisfiedBy === undefined) {
        return { ok: false, reason: "segment mapping failed" };
      }
      if (satisfiedBy !== "safeBins" && satisfiedBy !== "inlineChain") {
        return { ok: true, rendered: raw.trim() };
      }
      const argv = resolvePlannedSegmentArgv(segment);
      if (!argv) {
        return { ok: false, reason: "segment execution plan unavailable" };
      }
      return renderWindowsQuotedArgv(argv);
    },
  });
  return finalizeRebuiltShellCommand(rebuilt, params.segments.length);
}

export function buildEnforcedShellCommand(params: {
  command: string;
  segments: ExecCommandSegment[];
  platform?: string | null;
}): { ok: boolean; command?: string; reason?: string } {
  if (!isWindowsPlatform(params.platform)) {
    return { ok: false, reason: POSIX_RENDER_REPLACED_REASON };
  }
  const rebuilt = rebuildWindowsShellCommandFromSource({
    command: params.command,
    renderSegment: (_raw, segmentIndex) => {
      const segment = params.segments[segmentIndex];
      if (!segment) {
        return { ok: false, reason: "segment mapping failed" };
      }
      const argv = resolvePlannedSegmentArgv(segment);
      if (!argv) {
        return { ok: false, reason: "segment execution plan unavailable" };
      }
      return renderWindowsQuotedArgv(argv);
    },
  });
  return finalizeRebuiltShellCommand(rebuilt, params.segments.length);
}

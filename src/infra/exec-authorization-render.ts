import type { CommandOperator } from "./command-explainer/types.js";
import type { ExecSegmentSatisfiedBy } from "./exec-approvals-allowlist.js";
import { resolvePlannedSegmentArgv } from "./exec-approvals-analysis.js";
import type {
  ExecAuthorizationCandidate,
  ExecAuthorizationPlan,
} from "./exec-authorization-plan.js";
import { resolveInlineCommandMatch } from "./shell-inline-command.js";
import { POSIX_INLINE_COMMAND_FLAGS } from "./shell-inline-command.js";

export type AuthorizedShellRenderMode = "safeBins" | "enforced";

export type AuthorizedShellRenderResult =
  | { ok: true; command: string }
  | { ok: false; reason: string };

const PIPE_OPERATOR_TEXT: Record<string, string> = {
  pipe: "|",
  "stderr-pipe": "|&",
};

function shellEscapeSingleArg(value: string): string {
  const singleQuoteEscape = `'"'"'`;
  return `'${value.replace(/'/g, singleQuoteEscape)}'`;
}

function renderQuotedArgv(argv: readonly string[]): string {
  return argv.map((token) => shellEscapeSingleArg(token)).join(" ");
}

function shouldRewriteCandidate(params: {
  mode: AuthorizedShellRenderMode;
  satisfiedBy: ExecSegmentSatisfiedBy | undefined;
  forceRewrite: boolean;
}): boolean {
  if (params.mode === "enforced") {
    return true;
  }
  return (
    params.forceRewrite || params.satisfiedBy === "safeBins" || params.satisfiedBy === "inlineChain"
  );
}

function renderCandidate(params: {
  candidate: ExecAuthorizationCandidate;
  mode: AuthorizedShellRenderMode;
  satisfiedBy: ExecSegmentSatisfiedBy | undefined;
  forceRewrite: boolean;
}): AuthorizedShellRenderResult {
  if (
    !shouldRewriteCandidate({
      mode: params.mode,
      satisfiedBy: params.satisfiedBy,
      forceRewrite: params.forceRewrite,
    })
  ) {
    return { ok: true, command: params.candidate.sourceSegment.raw.trim() };
  }
  const argv = resolvePlannedSegmentArgv(params.candidate.sourceSegment);
  if (!argv) {
    return { ok: false, reason: "segment execution plan unavailable" };
  }
  return { ok: true, command: renderQuotedArgv(argv) };
}

function operatorAfterCandidate(params: {
  operators: readonly CommandOperator[];
  candidate: ExecAuthorizationCandidate;
}): string | null {
  const stepId = params.candidate.sourceStepId;
  if (!stepId) {
    return null;
  }
  const operator = params.operators.find((entry) => entry.fromCommandId === stepId);
  if (!operator) {
    return null;
  }
  if (operator.kind === "pipe" || operator.kind === "stderr-pipe") {
    return PIPE_OPERATOR_TEXT[operator.kind] ?? "|";
  }
  if (operator.kind === "and") {
    return "&&";
  }
  if (operator.kind === "or") {
    return "||";
  }
  if (operator.kind === "background") {
    return "&";
  }
  return ";";
}

function renderPlanGroups(params: {
  plan: Extract<ExecAuthorizationPlan, { ok: true }>;
  mode: AuthorizedShellRenderMode;
  segmentSatisfiedBy: readonly ExecSegmentSatisfiedBy[];
  forceRewrite: boolean;
}): AuthorizedShellRenderResult {
  const renderedParts: string[] = [];
  let candidateIndex = 0;
  for (const group of params.plan.groups) {
    for (const [index, candidate] of group.candidates.entries()) {
      const rendered = renderCandidate({
        candidate,
        mode: params.mode,
        satisfiedBy: params.segmentSatisfiedBy[candidateIndex],
        forceRewrite: params.forceRewrite,
      });
      if (!rendered.ok) {
        return rendered;
      }
      renderedParts.push(rendered.command);
      candidateIndex += 1;
      if (index < group.candidates.length - 1) {
        const operator = operatorAfterCandidate({ operators: params.plan.operators, candidate });
        renderedParts.push(operator ?? "|");
      }
    }
    if (group.opToNext) {
      renderedParts.push(group.opToNext);
    }
  }
  return { ok: true, command: renderedParts.join(" ") };
}

function commonShellWrapper(
  candidates: readonly ExecAuthorizationCandidate[],
): Extract<ExecAuthorizationCandidate["transport"], { kind: "shell-wrapper" }> | null {
  const wrappers = candidates.map((candidate) => candidate.transport);
  const first = wrappers[0];
  if (!first || first.kind !== "shell-wrapper") {
    return null;
  }
  return wrappers.every(
    (transport) =>
      transport.kind === "shell-wrapper" && transport.wrapperSegment === first.wrapperSegment,
  )
    ? first
    : null;
}

function renderShellWrapperCommand(params: {
  wrapper: Extract<ExecAuthorizationCandidate["transport"], { kind: "shell-wrapper" }>;
  payload: string;
}): AuthorizedShellRenderResult {
  const match = resolveInlineCommandMatch(params.wrapper.wrapperArgv, POSIX_INLINE_COMMAND_FLAGS, {
    allowCombinedC: true,
  });
  if (match.valueTokenIndex === null) {
    return { ok: false, reason: "wrapper inline command unavailable" };
  }
  const argv = [...params.wrapper.wrapperArgv];
  argv[match.valueTokenIndex] = params.payload;
  return { ok: true, command: renderQuotedArgv(argv) };
}

export function buildAuthorizedShellCommandFromPlan(params: {
  plan: ExecAuthorizationPlan;
  mode: AuthorizedShellRenderMode;
  segmentSatisfiedBy?: readonly ExecSegmentSatisfiedBy[];
}): AuthorizedShellRenderResult {
  if (!params.plan.ok) {
    return { ok: false, reason: params.plan.reason };
  }
  if (params.plan.dialect !== "posix-shell" && params.plan.dialect !== "argv") {
    return { ok: false, reason: "unsupported command dialect" };
  }
  const candidates = params.plan.groups.flatMap((group) => group.candidates);
  const segmentSatisfiedBy = params.segmentSatisfiedBy ?? [];
  const wrapper = commonShellWrapper(candidates);
  const forceRewrite =
    params.mode === "enforced" ||
    (wrapper !== null && segmentSatisfiedBy.some((entry) => entry === "inlineChain"));
  const rendered = renderPlanGroups({
    plan: params.plan,
    mode: params.mode,
    segmentSatisfiedBy,
    forceRewrite,
  });
  if (!rendered.ok || !wrapper) {
    return rendered;
  }
  return renderShellWrapperCommand({ wrapper, payload: rendered.command });
}

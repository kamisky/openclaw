import { splitShellArgs } from "../utils/shell-argv.js";
import { buildCommandPayloadCandidates } from "./command-analysis/risks.js";
import { explainShellCommand } from "./command-explainer/extract.js";

export type ControlShellPolicyDecision =
  | { kind: "allow" }
  | { kind: "deny"; message: string }
  | { kind: "requires-approval"; warning: string };

export type ControlShellParsedSegment = {
  argv: string[];
  raw?: string;
};

type ControlShellCandidate = {
  argv: string[];
  raw: string;
};

const INTERACTIVE_CHANNEL_LOGIN_DENY_MESSAGE = [
  "exec cannot run interactive OpenClaw channel login commands.",
  "Run `openclaw channels login` in a terminal on the gateway host, or use the channel-specific login agent tool when available (for WhatsApp: `whatsapp_login`).",
].join(" ");

const SECURITY_AUDIT_SUPPRESSION_WARNING =
  "Warning: security audit suppression changes require explicit approval unless exec is running in yolo mode.";

const SSH_FILE_READ_WARNING = "Warning: Reading SSH files requires explicit approval.";

const CONTROL_OPTION_FLAGS_WITH_VALUES = new Set([
  "--channel",
  "--container",
  "--log-level",
  "--profile",
]);

type ControlCommandOption = {
  name: string;
  value: string | true;
};

type NormalizedControlCommand = {
  executable: string;
  argv: string[];
  raw: string;
  words: string[];
  options: readonly ControlCommandOption[];
};

type ControlOptionPattern = {
  value?: string | RegExp;
};

type ControlOperandPattern = {
  value?: string | RegExp;
  pathUnder?: ".ssh";
};

type ControlCommandPattern = {
  executable?: string | readonly string[];
  command?: readonly (readonly string[])[];
  options?: Readonly<Record<string, ControlOptionPattern>>;
  operands?: readonly ControlOperandPattern[];
};

type ControlShellPolicyContext = {
  command: string;
  invocations: readonly NormalizedControlCommand[];
};

type ControlShellPolicy = {
  decision: Exclude<ControlShellPolicyDecision, { kind: "allow" }>;
  matches: (context: ControlShellPolicyContext) => boolean;
};

function normalizeCommandBaseName(token: string | undefined): string {
  if (!token) {
    return "";
  }
  const base = token.split(/[\\/]/u).at(-1)?.toLowerCase() ?? "";
  return base.replace(/\.(?:cmd|exe)$/u, "");
}

function stripOpenClawPackageRunner(argv: string[]): string[] {
  const commandName = normalizeCommandBaseName(argv[0]);
  if (commandName === "openclaw") {
    return argv;
  }
  if (
    (commandName === "pnpm" || commandName === "npm" || commandName === "yarn") &&
    normalizeCommandBaseName(argv[1]) === "openclaw"
  ) {
    return argv.slice(1);
  }
  if (
    (commandName === "pnpm" || commandName === "npm" || commandName === "yarn") &&
    (argv[1] === "exec" || argv[1] === "dlx" || argv[1] === "run") &&
    normalizeCommandBaseName(argv[argv[2] === "--" ? 3 : 2]) === "openclaw"
  ) {
    return argv.slice(argv[2] === "--" ? 3 : 2);
  }
  if (commandName === "bun" && normalizeCommandBaseName(argv[1]) === "openclaw") {
    return argv.slice(1);
  }
  if (commandName === "npx" || commandName === "bunx") {
    let index = 1;
    while (index < argv.length) {
      const token = argv[index] ?? "";
      if (token === "--") {
        index += 1;
        break;
      }
      if (!token.startsWith("-") || token === "-") {
        break;
      }
      index += 1;
      if ((token === "-p" || token === "--package") && index < argv.length) {
        index += 1;
      }
    }
    if (normalizeCommandBaseName(argv[index]) === "openclaw") {
      return argv.slice(index);
    }
  }
  return argv;
}

function textMentionsSecurityAuditSuppressions(value: string): boolean {
  const normalized = value.toLowerCase();
  return (
    normalized.includes("security.audit.suppressions") ||
    /["']?security["']?[\s\S]{0,200}["']?audit["']?[\s\S]{0,200}["']?suppressions["']?/.test(
      normalized,
    )
  );
}

function normalizeOptionName(token: string): string {
  return token.length > 1 ? token.replace(/=.+$/u, "") : token;
}

function appendOption(options: ControlCommandOption[], name: string, value: string | true): void {
  options.push({ name: normalizeOptionName(name), value });
}

function parseNormalizedCommandWords(argv: string[]): {
  executable: string;
  words: string[];
  options: ControlCommandOption[];
} | null {
  const strippedArgv = stripOpenClawPackageRunner(argv);
  const executable = normalizeCommandBaseName(strippedArgv[0]);
  if (!executable) {
    return null;
  }
  const words: string[] = [];
  const options: ControlCommandOption[] = [];
  let index = 1;
  let optionsTerminated = false;

  while (index < strippedArgv.length) {
    const token = strippedArgv[index] ?? "";
    if (!optionsTerminated && token === "--") {
      optionsTerminated = true;
      index += 1;
      continue;
    }
    if (!optionsTerminated && token.startsWith("--") && token.length > 2) {
      const equalsIndex = token.indexOf("=");
      if (equalsIndex > 2) {
        appendOption(options, token.slice(0, equalsIndex), token.slice(equalsIndex + 1));
        index += 1;
        continue;
      }
      if (CONTROL_OPTION_FLAGS_WITH_VALUES.has(token) && strippedArgv[index + 1] !== undefined) {
        appendOption(options, token, strippedArgv[index + 1] ?? "");
        index += 2;
        continue;
      }
      appendOption(options, token, true);
      index += 1;
      continue;
    }
    if (!optionsTerminated && token.startsWith("-") && token !== "-") {
      appendOption(options, token, true);
      index += 1;
      continue;
    }
    words.push(token);
    index += 1;
  }

  return { executable, words, options };
}

function normalizeControlCommand(
  candidate: ControlShellCandidate,
): NormalizedControlCommand | null {
  const parsed = parseNormalizedCommandWords(candidate.argv);
  if (!parsed) {
    return null;
  }
  return {
    executable: parsed.executable,
    argv: candidate.argv,
    raw: candidate.raw,
    words: parsed.words,
    options: parsed.options,
  };
}

function normalizeControlCommands(
  candidates: readonly ControlShellCandidate[],
): NormalizedControlCommand[] {
  return candidates.flatMap((candidate) => {
    const normalized = normalizeControlCommand(candidate);
    return normalized ? [normalized] : [];
  });
}

function commandText(invocation: NormalizedControlCommand): string {
  return `${invocation.raw} ${invocation.argv.join(" ")}`;
}

function invocationMentionsSecurityAuditSuppressions(
  invocation: NormalizedControlCommand,
): boolean {
  return textMentionsSecurityAuditSuppressions(commandText(invocation));
}

function removeCandidateText(
  command: string,
  invocations: readonly NormalizedControlCommand[],
): string {
  let remaining = command;
  for (const invocation of invocations) {
    const raw = invocation.raw.trim();
    if (raw.length === 0) {
      continue;
    }
    remaining = remaining.replace(raw, " ");
  }
  return remaining;
}

function stringOrRegexMatches(pattern: string | RegExp, value: string): boolean {
  return typeof pattern === "string" ? value === pattern : pattern.test(value);
}

function matchesOneOf(value: string, expected: string | readonly string[] | undefined): boolean {
  if (expected === undefined) {
    return true;
  }
  return typeof expected === "string" ? value === expected : expected.includes(value);
}

function commandPathMatches(
  invocation: NormalizedControlCommand,
  command: ControlCommandPattern["command"],
): boolean {
  const paths = command ?? [];
  if (paths.length === 0) {
    return true;
  }
  return paths.some((path) => {
    if (path.length > invocation.words.length) {
      return false;
    }
    return path.every((part, index) => invocation.words[index] === part);
  });
}

function optionMatches(
  invocation: NormalizedControlCommand,
  optionName: string,
  pattern: ControlOptionPattern,
): boolean {
  const matches = invocation.options.filter((option) => option.name === optionName);
  if (pattern.value === undefined) {
    return matches.length > 0;
  }
  return matches.some(
    (option) => option.value !== true && stringOrRegexMatches(pattern.value, option.value),
  );
}

function pathMatchesStaticSshPath(value: string): boolean {
  const normalized = value.replace(/\\/gu, "/");
  return (
    normalized === "~/.ssh" ||
    normalized.startsWith("~/.ssh/") ||
    normalized === ".ssh" ||
    normalized.startsWith(".ssh/") ||
    normalized === "./.ssh" ||
    normalized.startsWith("./.ssh/") ||
    normalized.includes("/.ssh/")
  );
}

function operandMatches(value: string, pattern: ControlOperandPattern): boolean {
  if (pattern.value !== undefined && !stringOrRegexMatches(pattern.value, value)) {
    return false;
  }
  if (pattern.pathUnder === ".ssh" && !pathMatchesStaticSshPath(value)) {
    return false;
  }
  return true;
}

function matchesControlCommandPattern(params: {
  invocation: NormalizedControlCommand;
  pattern: ControlCommandPattern;
}): boolean {
  const pattern = params.pattern;
  if (!matchesOneOf(params.invocation.executable, pattern.executable)) {
    return false;
  }
  if (!commandPathMatches(params.invocation, pattern.command)) {
    return false;
  }
  for (const [optionName, optionPattern] of Object.entries(pattern.options ?? {})) {
    if (!optionMatches(params.invocation, optionName, optionPattern)) {
      return false;
    }
  }
  for (const operandPattern of pattern.operands ?? []) {
    if (!params.invocation.words.some((operand) => operandMatches(operand, operandPattern))) {
      return false;
    }
  }
  return true;
}

function hasMatchingInvocation(params: {
  invocations: readonly NormalizedControlCommand[];
  patterns: readonly ControlCommandPattern[];
}): boolean {
  return params.invocations.some((invocation) =>
    params.patterns.some((pattern) => matchesControlCommandPattern({ invocation, pattern })),
  );
}

const INTERACTIVE_CHANNEL_LOGIN_PATTERNS: readonly ControlCommandPattern[] = [
  { executable: "openclaw", command: [["channels", "login"]] },
  { executable: "openclaw", command: [["channel", "login"]] },
];

const READ_ONLY_SECURITY_AUDIT_SUPPRESSION_PATTERNS: readonly ControlCommandPattern[] = [
  { executable: "openclaw", command: [["config", "get"]] },
  { executable: "openclaw", command: [["config", "schema"]] },
  { executable: "openclaw", command: [["config", "validate"]] },
];

const MUTATING_SECURITY_AUDIT_SUPPRESSION_PATTERNS: readonly ControlCommandPattern[] = [
  { executable: "openclaw", command: [["config", "set"]] },
  { executable: "openclaw", command: [["config", "unset"]] },
  { executable: "openclaw", command: [["config", "patch"]] },
  { executable: "openclaw", command: [["config", "apply"]] },
];

const SSH_FILE_READ_PATTERNS: readonly ControlCommandPattern[] = [
  {
    executable: ["cat", "less", "more", "head", "tail"],
    operands: [{ pathUnder: ".ssh" }],
  },
];

function requiresSecurityAuditSuppressionApproval(params: {
  command: string;
  invocations: readonly NormalizedControlCommand[];
}): boolean {
  const mentioningInvocations = params.invocations.filter(
    invocationMentionsSecurityAuditSuppressions,
  );
  if (mentioningInvocations.length > 0) {
    if (
      hasMatchingInvocation({
        invocations: mentioningInvocations,
        patterns: MUTATING_SECURITY_AUDIT_SUPPRESSION_PATTERNS,
      })
    ) {
      return true;
    }
    if (
      mentioningInvocations.every((invocation) =>
        READ_ONLY_SECURITY_AUDIT_SUPPRESSION_PATTERNS.some((pattern) =>
          matchesControlCommandPattern({
            invocation,
            pattern,
          }),
        ),
      )
    ) {
      return textMentionsSecurityAuditSuppressions(
        removeCandidateText(params.command, mentioningInvocations),
      );
    }
    return true;
  }

  if (!textMentionsSecurityAuditSuppressions(params.command)) {
    return false;
  }
  return true;
}

export function parseOpenClawChannelsLoginShellCommand(raw: string): boolean {
  const argv = splitShellArgs(raw);
  if (!argv) {
    return false;
  }
  const invocation = normalizeControlCommand({ argv, raw });
  return invocation
    ? INTERACTIVE_CHANNEL_LOGIN_PATTERNS.some((pattern) =>
        matchesControlCommandPattern({ invocation, pattern }),
      )
    : false;
}

const CONTROL_SHELL_POLICIES: readonly ControlShellPolicy[] = [
  {
    decision: { kind: "deny", message: INTERACTIVE_CHANNEL_LOGIN_DENY_MESSAGE },
    matches: ({ invocations }) =>
      hasMatchingInvocation({
        invocations,
        patterns: INTERACTIVE_CHANNEL_LOGIN_PATTERNS,
      }),
  },
  {
    decision: { kind: "requires-approval", warning: SECURITY_AUDIT_SUPPRESSION_WARNING },
    matches: requiresSecurityAuditSuppressionApproval,
  },
  {
    decision: { kind: "requires-approval", warning: SSH_FILE_READ_WARNING },
    matches: ({ invocations }) =>
      hasMatchingInvocation({
        invocations,
        patterns: SSH_FILE_READ_PATTERNS,
      }),
  },
];

function appendCandidate(
  candidates: ControlShellCandidate[],
  seen: Set<string>,
  candidate: ControlShellCandidate,
): void {
  const key = `${candidate.raw}\0${candidate.argv.join("\0")}`;
  if (seen.has(key)) {
    return;
  }
  seen.add(key);
  candidates.push(candidate);
}

function candidateFromRaw(raw: string): ControlShellCandidate {
  return {
    argv: splitShellArgs(raw) ?? [],
    raw,
  };
}

function appendPayloadCandidates(params: {
  candidates: ControlShellCandidate[];
  seen: Set<string>;
  argv: string[];
}): void {
  for (const payload of buildCommandPayloadCandidates(params.argv)) {
    appendCandidate(params.candidates, params.seen, candidateFromRaw(payload));
  }
}

async function buildControlShellCandidates(params: {
  command: string;
  parsedSegments?: readonly ControlShellParsedSegment[];
}): Promise<ControlShellCandidate[]> {
  const candidates: ControlShellCandidate[] = [];
  const seen = new Set<string>();

  for (const segment of params.parsedSegments ?? []) {
    appendCandidate(candidates, seen, {
      argv: segment.argv,
      raw: segment.raw ?? segment.argv.join(" "),
    });
  }
  if ((params.parsedSegments?.length ?? 0) > 0) {
    return candidates;
  }

  try {
    const explanation = await explainShellCommand(params.command);
    if (explanation.ok) {
      for (const step of [...explanation.topLevelCommands, ...explanation.nestedCommands]) {
        appendCandidate(candidates, seen, {
          argv: step.argv,
          raw: step.text,
        });
        appendPayloadCandidates({
          candidates,
          seen,
          argv: step.argv,
        });
      }
      return candidates;
    }
  } catch {
    // Fall back to best-effort line parsing below.
  }

  for (const line of params.command.split(/\r?\n/u)) {
    const raw = line.trim();
    if (raw.length === 0) {
      continue;
    }
    const fallback = candidateFromRaw(raw);
    appendCandidate(candidates, seen, fallback);
    appendPayloadCandidates({
      candidates,
      seen,
      argv: fallback.argv,
    });
  }

  return candidates;
}

export async function inspectControlShellCommand(params: {
  command: string;
  parsedSegments?: readonly ControlShellParsedSegment[];
}): Promise<ControlShellPolicyDecision> {
  const command = params.command.trim();
  const candidates = await buildControlShellCandidates({
    command,
    parsedSegments: params.parsedSegments,
  });
  const invocations = normalizeControlCommands(candidates);

  for (const policy of CONTROL_SHELL_POLICIES) {
    if (policy.matches({ command, invocations })) {
      return policy.decision;
    }
  }

  return { kind: "allow" };
}

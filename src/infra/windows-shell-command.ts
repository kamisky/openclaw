import { normalizeLowercaseStringOrEmpty } from "../shared/string-coerce.js";
import type { ExecCommandAnalysis } from "./exec-approvals-analysis.js";
import { resolveCommandResolutionFromArgv } from "./exec-command-resolution.js";

const WINDOWS_UNSUPPORTED_TOKENS = new Set([
  "&",
  "|",
  "<",
  ">",
  ";",
  "^",
  "(",
  ")",
  "%",
  "!",
  "`",
  "\n",
  "\r",
]);

// These stay unsafe inside double quotes: newlines break parsing, cmd.exe
// expands %VAR%, and PowerShell treats ` as an escape character.
const WINDOWS_ALWAYS_UNSAFE_TOKENS = new Set(["\n", "\r", "%", "`"]);

function findWindowsUnsupportedToken(command: string): string | null {
  let inDouble = false;
  // cmd.exe does not recognise single quotes, so they are not treated as safe
  // quoting for this cross-host safety check.
  for (let i = 0; i < command.length; i++) {
    const ch = command[i];
    if (ch === '"') {
      inDouble = !inDouble;
      continue;
    }
    if (ch === "$") {
      const next = command[i + 1];
      if (next !== undefined && /[A-Za-z_{(?$]/.test(next)) {
        return "$";
      }
      continue;
    }
    if (WINDOWS_UNSUPPORTED_TOKENS.has(ch)) {
      // Inside double-quoted strings, most special characters are safe literals.
      // tokenizeWindowsSegment already handles all of these correctly inside quotes.
      if (inDouble && !WINDOWS_ALWAYS_UNSAFE_TOKENS.has(ch)) {
        continue;
      }
      if (ch === "\n" || ch === "\r") {
        return "newline";
      }
      return ch;
    }
  }
  return null;
}

export function tokenizeWindowsSegment(segment: string): string[] | null {
  const tokens: string[] = [];
  let buf = "";
  let inDouble = false;
  let inSingle = false;
  let wasQuoted = false;

  const pushToken = () => {
    if (buf.length > 0 || wasQuoted) {
      tokens.push(buf);
      buf = "";
    }
    wasQuoted = false;
  };

  for (let i = 0; i < segment.length; i += 1) {
    const ch = segment[i];
    if (ch === '"' && !inSingle) {
      if (!inDouble) {
        wasQuoted = true;
      }
      inDouble = !inDouble;
      continue;
    }
    if (ch === "'" && !inDouble) {
      if (inSingle && segment[i + 1] === "'") {
        buf += "'";
        i += 1;
        continue;
      }
      if (!inSingle) {
        wasQuoted = true;
      }
      inSingle = !inSingle;
      continue;
    }
    if (!inDouble && !inSingle && /\s/.test(ch)) {
      pushToken();
      continue;
    }
    buf += ch;
  }

  if (inDouble || inSingle) {
    return null;
  }
  pushToken();
  return tokens.length > 0 ? tokens : null;
}

function stripWindowsShellWrapper(command: string): string {
  const MAX_DEPTH = 5;
  let result = command;
  for (let i = 0; i < MAX_DEPTH; i++) {
    const prev = result;
    result = stripWindowsShellWrapperOnce(result.trim());
    if (result === prev) {
      break;
    }
  }
  return result;
}

function stripWindowsShellWrapperOnce(command: string): string {
  const psCallMatch = command.match(/^&\s+(.+)$/s);
  if (psCallMatch) {
    return psCallMatch[1];
  }

  // Match flags before -Command without letting a value-taking flag consume
  // -c/-Command itself.
  const psFlags =
    /(?:-(?!c(?:ommand)?\b|-command\b)\w+(?:\s+(?!-)(?:"[^"]*(?:""[^"]*)*"|'[^']*(?:''[^']*)*'|\S+))?\s+)*/i
      .source;
  const psCommandFlag = `(?:-command|-c|--command)`;
  const psInvokeMatch = command.match(
    new RegExp(`^(?:powershell|pwsh)(?:\\.exe)?\\s+${psFlags}${psCommandFlag}\\s+"(.+)"$`, "is"),
  );
  if (psInvokeMatch) {
    return psInvokeMatch[1].replace(/""/g, '"');
  }
  const psInvokeSingleQuote = command.match(
    new RegExp(`^(?:powershell|pwsh)(?:\\.exe)?\\s+${psFlags}${psCommandFlag}\\s+'(.+)'$`, "is"),
  );
  if (psInvokeSingleQuote) {
    return psInvokeSingleQuote[1].replace(/''/g, "'");
  }
  const psInvokeNoQuote = command.match(
    new RegExp(`^(?:powershell|pwsh)(?:\\.exe)?\\s+${psFlags}${psCommandFlag}\\s+(.+)$`, "is"),
  );
  if (psInvokeNoQuote) {
    return psInvokeNoQuote[1];
  }

  // Note: cmd /c is intentionally NOT stripped here. If a command is wrapped
  // with `cmd /c`, its inner payload would later be executed by PowerShell, which
  // changes semantics for cmd.exe builtins (dir, copy, etc.). Callers that submit
  // `cmd /c <thing>` must have an explicit allowlist entry for `cmd` itself, or
  // the command will require user approval.

  return command;
}

export function analyzeWindowsShellCommand(params: {
  command: string;
  cwd?: string;
  env?: NodeJS.ProcessEnv;
}): ExecCommandAnalysis {
  const effective = stripWindowsShellWrapper(params.command.trim());
  const unsupported = findWindowsUnsupportedToken(effective);
  if (unsupported) {
    return {
      ok: false,
      reason: `unsupported windows shell token: ${unsupported}`,
      segments: [],
    };
  }
  const argv = tokenizeWindowsSegment(effective);
  if (!argv || argv.length === 0) {
    return { ok: false, reason: "unable to parse windows command", segments: [] };
  }
  return {
    ok: true,
    segments: [
      {
        raw: params.command,
        argv,
        resolution: resolveCommandResolutionFromArgv(argv, params.cwd, params.env),
      },
    ],
  };
}

export function isWindowsPlatform(platform?: string | null): boolean {
  const normalized = normalizeLowercaseStringOrEmpty(platform);
  return normalized.startsWith("win");
}

// Tokens that cannot be safely double-quoted in PowerShell enforced commands.
const WINDOWS_UNSAFE_CMD_META = /[%`]|\$(?=[A-Za-z_{(?$])/;

export function windowsEscapeArg(value: string): { ok: true; escaped: string } | { ok: false } {
  if (value === "") {
    return { ok: true, escaped: '""' };
  }
  if (WINDOWS_UNSAFE_CMD_META.test(value)) {
    return { ok: false };
  }
  if (/^[a-zA-Z0-9_./:~\\=-]+$/.test(value)) {
    return { ok: true, escaped: value };
  }
  const escaped = value.replace(/"/g, '""');
  return { ok: true, escaped: `"${escaped}"` };
}

export type ShellSegmentRenderResult =
  | { ok: true; rendered: string }
  | { ok: false; reason: string };

export type RebuiltShellCommandResult = {
  ok: boolean;
  command?: string;
  reason?: string;
  segmentCount?: number;
};

export function rebuildWindowsShellCommandFromSource(params: {
  command: string;
  renderSegment: (rawSegment: string, segmentIndex: number) => ShellSegmentRenderResult;
}): RebuiltShellCommandResult {
  const source = stripWindowsShellWrapper(params.command.trim());
  if (!source) {
    return { ok: false, reason: "empty command" };
  }
  const unsupported = findWindowsUnsupportedToken(source);
  if (unsupported) {
    return { ok: false, reason: `unsupported windows shell token: ${unsupported}` };
  }
  const rendered = params.renderSegment(source, 0);
  if (!rendered.ok) {
    return { ok: false, reason: rendered.reason };
  }
  // Prefix with PowerShell call operator (&) so that quoted executable paths
  // (e.g. "C:\Program Files\nodejs\node.exe") are treated as commands, not
  // string literals. The & operator is harmless for unquoted paths too.
  return { ok: true, command: `& ${rendered.rendered}`, segmentCount: 1 };
}

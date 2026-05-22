#!/usr/bin/env node
import { execFileSync, spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";

const DEFAULT_TTL_MINUTES = { linux: 90, mac: 60, windows: 90 };
const IDLE_TIMEOUT_MINUTES = 30;
const payload = readPayload();
const repo = required("target_repo");
const prNumber = Number(required("item_number"));
const action = normalizeAction(required("action"));
const platform = normalizePlatform(String(payload.platform || "linux"));
const provider = String(payload.provider || process.env.CRABBOX_PROVIDER || "aws");
const requestedHeadSha = String(payload.head_sha || "");
const ttlMinutes = Number(payload.ttl_minutes || DEFAULT_TTL_MINUTES[platform]);
const commentId = String(payload.comment_id || "");
const outputDir = path.join(".artifacts", "qa-e2e", "mantis", "pr-desktop-lease");
const runUrl =
  process.env.GITHUB_SERVER_URL && process.env.GITHUB_REPOSITORY && process.env.GITHUB_RUN_ID
    ? `${process.env.GITHUB_SERVER_URL}/${process.env.GITHUB_REPOSITORY}/actions/runs/${process.env.GITHUB_RUN_ID}`
    : "";

fs.mkdirSync(outputDir, { recursive: true });

await main();

async function main() {
  if (repo !== process.env.GITHUB_REPOSITORY) {
    postComment({
      status: "failed",
      failed_step: "target validation",
      failure_excerpt: `Mantis PR desktop leases only support ${process.env.GITHUB_REPOSITORY}; received ${repo}.`,
    });
    return;
  }

  const pull = ghJson(["pr", "view", String(prNumber), "--repo", repo, "--json", "state,headRefOid,url"]);
  const headSha = String(pull.headRefOid || "");
  if (requestedHeadSha && headSha && requestedHeadSha !== headSha) {
    postComment({
      status: "failed",
      failed_step: "head check",
      failure_excerpt: `PR head changed from ${requestedHeadSha} to ${headSha}. Re-run the command on the latest PR head.`,
    });
    return;
  }

  if (action === "lease") return lease(headSha);

  const active = findLatestLease();
  if (!active?.lease_id) {
    postComment({
      status: "failed",
      failed_step: "state lookup",
      failure_excerpt: `No active Mantis ${platform} desktop lease was found for ${repo}#${prNumber}.`,
    });
    return;
  }
  if (action === "status") {
    const status = runCrabbox(["inspect", "--provider", provider, active.lease_id], { allowFailure: true });
    postComment({
      ...active,
      status: "already_active",
      provider,
      status_excerpt: status.stdout || status.stderr,
    });
    return;
  }
  if (action === "stop") {
    runCrabbox(["stop", "--provider", provider, active.lease_id], { allowFailure: true });
    postComment({ ...active, status: "stopped", provider });
    return;
  }
  runCrabbox(["webvnc", "reset", "--provider", provider, "--target", targetForPlatform(platform), "--id", active.lease_id], {
    allowFailure: true,
  });
  postComment({ ...active, status: "reset", provider, webvnc_bridge: "reset requested" });
}

function lease(headSha) {
  const existing = findLatestLease();
  if (existing?.lease_id && existing.status !== "stopped") {
    postComment({ ...existing, status: "already_active", provider });
    return;
  }

  let leaseID = "";
  try {
    const warmup = runCrabbox(warmupArgs());
    leaseID = extractLeaseID(warmup.stdout);
    if (!leaseID) throw new Error(`warmup did not print a cbx_ lease id\n\n${warmup.stdout || warmup.stderr}`);
    const baseState = {
      status: "creating",
      repo,
      pr_number: prNumber,
      platform,
      provider,
      lease_id: leaseID,
      slug: leaseSlug(),
      head_sha: headSha,
      ttl_minutes: ttlMinutes,
      idle_timeout_minutes: IDLE_TIMEOUT_MINUTES,
      created_at: new Date().toISOString(),
      sharing: "org use",
    };
    writeSummary(baseState);
    runCrabbox(["run", "--provider", provider, "--id", leaseID, "--fresh-pr", `${repo}#${prNumber}`, "--", "true"]);
    runCrabbox(["share", "--provider", provider, "--id", leaseID, "--org"], { allowFailure: true });
    runCrabbox(["webvnc", "daemon", "start", "--provider", provider, "--target", targetForPlatform(platform), "--id", leaseID], {
      allowFailure: true,
    });
    const webvncStatus = runCrabbox(
      ["webvnc", "status", "--provider", provider, "--target", targetForPlatform(platform), "--id", leaseID],
      { allowFailure: true },
    );
    const ready = {
      ...baseState,
      status: "ready",
      webvnc_url: extractWebvncURL(webvncStatus.stdout) || portalURL(leaseID),
      expires_at: new Date(Date.now() + ttlMinutes * 60_000).toISOString(),
    };
    writeSummary(ready);
    postComment(ready);
  } catch (error) {
    const failure = {
      status: "failed",
      repo,
      pr_number: prNumber,
      platform,
      provider,
      lease_id: leaseID || null,
      failed_step: leaseID ? "setup" : "warmup",
      failure_excerpt: error instanceof Error ? error.message : String(error),
      webvnc_url: leaseID ? portalURL(leaseID) : null,
    };
    writeSummary(failure);
    postComment(failure);
  }
}

function warmupArgs() {
  const common = [
    "warmup",
    "--provider",
    provider,
    "--desktop",
    "--browser",
    "--ttl",
    `${ttlMinutes}m`,
    "--idle-timeout",
    `${IDLE_TIMEOUT_MINUTES}m`,
    "--slug",
    leaseSlug(),
  ];
  if (platform === "mac") return [...common, "--target", "macos", "--market", "on-demand"];
  if (platform === "windows") return [...common, "--target", "windows", "--windows-mode", "normal"];
  return [...common, "--target", "linux"];
}

function postComment(state) {
  const body = renderComment({ repo, pr_number: prNumber, platform, provider, run_url: runUrl, ...state });
  const bodyPath = path.join(outputDir, `comment-${Date.now()}.md`);
  fs.writeFileSync(bodyPath, body);
  gh(["api", `repos/${repo}/issues/${prNumber}/comments`, "-F", `body=@${bodyPath}`]);
}

function renderComment(state) {
  const status = String(state.status || "ready");
  if (status === "ready") {
    return [
      marker(state),
      "🦞✅",
      "",
      "Mantis Crabbox desktop lease ready for PR testing.",
      "",
      summaryLines(state).join("\n"),
      "",
      `WebVNC: ${state.webvnc_url || "unavailable"}`,
      "",
      usefulCommands(state),
    ].join("\n");
  }
  if (status === "already_active") {
    return [
      marker(state),
      "🦞👀",
      "",
      `A Mantis Crabbox ${state.platform || "linux"} desktop lease is already active for this PR.`,
      "",
      summaryLines(state).join("\n"),
      "",
      `WebVNC: ${state.webvnc_url || "unavailable"}`,
    ].join("\n");
  }
  if (status === "stopped") {
    return [
      marker(state),
      "🦞✅",
      "",
      `Stopped the Mantis Crabbox ${state.platform || "linux"} desktop lease for this PR.`,
      "",
      `- Lease: \`${state.lease_id || "unknown"}\``,
      `- Platform: \`${state.platform || "linux"}\``,
      `- Provider: \`${state.provider || "aws"}\``,
    ].join("\n");
  }
  if (status === "reset") {
    return [
      marker(state),
      "🦞✅",
      "",
      `Reset WebVNC for the Mantis Crabbox ${state.platform || "linux"} desktop lease.`,
      "",
      `- Lease: \`${state.lease_id || "unknown"}\``,
      `- Platform: \`${state.platform || "linux"}\``,
      `- Provider: \`${state.provider || "aws"}\``,
      "",
      `WebVNC: ${state.webvnc_url || "unavailable"}`,
    ].join("\n");
  }
  return [
    marker(state),
    "🦞⚠️",
    "",
    state.lease_id
      ? `Mantis Crabbox ${state.platform || "linux"} desktop lease is alive, but setup did not finish.`
      : `Mantis Crabbox ${state.platform || "linux"} desktop lease could not be created.`,
    "",
    `- Platform: \`${state.platform || "linux"}\``,
    `- Provider: \`${state.provider || "aws"}\``,
    state.lease_id ? `- Lease: \`${state.lease_id}\`` : null,
    `- Failed step: \`${state.failed_step || "unknown"}\``,
    `- Result: ${state.lease_id ? "lease kept for manual inspection" : "no lease was created"}`,
    state.webvnc_url ? "" : null,
    state.webvnc_url ? `WebVNC: ${state.webvnc_url}` : null,
    "",
    "Failure excerpt:",
    "```text",
    String(state.failure_excerpt || "No failure excerpt captured.").slice(0, 2000),
    "```",
  ]
    .filter((line) => line !== null)
    .join("\n");
}

function summaryLines(state) {
  return [
    `- Platform: \`${state.platform || "linux"}\``,
    `- Provider: \`${state.provider || "aws"}\``,
    `- Lease: \`${state.lease_id || "unknown"}\``,
    state.slug ? `- Slug: \`${state.slug}\`` : null,
    state.expires_at ? `- Expires: \`${state.expires_at}\`` : null,
    `- Idle timeout: \`${state.idle_timeout_minutes || IDLE_TIMEOUT_MINUTES}m\``,
    state.head_sha ? `- PR code: \`${repo}#${prNumber}\` at \`${String(state.head_sha).slice(0, 12)}\`` : null,
    state.sharing ? `- Sharing: \`${state.sharing}\`` : null,
    state.run_url ? `- Workflow: ${state.run_url}` : null,
  ].filter(Boolean);
}

function usefulCommands(state) {
  const lease = String(state.lease_id || "<lease>");
  const target = targetForPlatform(String(state.platform || "linux"));
  const currentProvider = String(state.provider || "aws");
  return [
    "Useful commands:",
    "```sh",
    `crabbox webvnc status --provider ${currentProvider} --target ${target} --id ${lease}`,
    `crabbox webvnc reset --provider ${currentProvider} --target ${target} --id ${lease} --open --take-control`,
    `crabbox ssh --provider ${currentProvider} --id ${lease}`,
    `crabbox stop --provider ${currentProvider} ${lease}`,
    "```",
  ].join("\n");
}

function findLatestLease() {
  const comments = ghJson(["api", `repos/${repo}/issues/${prNumber}/comments?per_page=100`, "--paginate"]);
  for (const comment of comments.reverse()) {
    const body = String(comment.body || "");
    if (!body.includes(marker({ repo, pr_number: prNumber, platform }))) continue;
    const leaseID = body.match(/- Lease: `([^`]+)`/)?.[1] || body.match(/\bcbx_[A-Za-z0-9_-]+\b/)?.[0] || "";
    return {
      lease_id: leaseID,
      platform,
      provider: body.match(/- Provider: `([^`]+)`/)?.[1] || provider,
      webvnc_url: body.match(/WebVNC: (https:\/\/\S+)/)?.[1] || "",
      status: body.includes("Stopped the Mantis Crabbox") ? "stopped" : "ready",
    };
  }
  return null;
}

function runCrabbox(args, options = {}) {
  const result = spawnSync("crabbox", args, { encoding: "utf8", maxBuffer: 20 * 1024 * 1024 });
  if (result.status !== 0 && !options.allowFailure) throw new Error(formatProcessFailure(["crabbox", ...args], result));
  return { status: result.status ?? 1, stdout: result.stdout || "", stderr: result.stderr || "" };
}

function formatProcessFailure(command, result) {
  return [
    `${command.join(" ")} failed`,
    `status: ${result.status ?? "null"}`,
    `signal: ${result.signal ?? "null"}`,
    result.error ? `error: ${result.error.name}: ${result.error.message}` : "error: null",
    "stdout:",
    trimOutput(result.stdout),
    "stderr:",
    trimOutput(result.stderr),
  ].join("\n");
}

function trimOutput(value) {
  const text = String(value || "").trim();
  if (!text) return "<empty>";
  return text.length > 4000 ? `${text.slice(0, 4000)}\n...<truncated>` : text;
}

function gh(args) {
  execFileSync("gh", args, { stdio: "inherit" });
}

function ghJson(args) {
  return JSON.parse(execFileSync("gh", args, { encoding: "utf8" }));
}

function readPayload() {
  if (!process.env.GITHUB_EVENT_PATH) return Object.fromEntries(process.argv.slice(2).map((entry) => entry.split("=", 2)));
  const event = JSON.parse(fs.readFileSync(process.env.GITHUB_EVENT_PATH, "utf8"));
  return event.client_payload || event.inputs || {};
}

function required(key) {
  const value = payload[key];
  if (!value) throw new Error(`missing payload.${key}`);
  return String(value);
}

function writeSummary(state) {
  fs.writeFileSync(path.join(outputDir, "pr-desktop-lease-summary.json"), JSON.stringify(state, null, 2) + "\n");
}

function marker(state) {
  return `<!-- mantis-pr-desktop-lease:${state.repo || repo}:${state.pr_number || prNumber}:${state.platform || platform} -->`;
}

function leaseSlug() {
  return `pr-${prNumber}-${platform}`;
}

function extractLeaseID(text) {
  return String(text || "").match(/\bcbx_[A-Za-z0-9_-]+\b/)?.[0] || "";
}

function extractWebvncURL(text) {
  return String(text || "").match(/https:\/\/\S+\/portal\/leases\/\S+\/vnc\S*/)?.[0] || "";
}

function portalURL(leaseID) {
  return `${process.env.CRABBOX_COORDINATOR || "https://crabbox.openclaw.ai"}/portal/leases/${encodeURIComponent(leaseID)}/vnc`;
}

function targetForPlatform(value) {
  if (value === "mac") return "macos";
  if (value === "windows") return "windows";
  return "linux";
}

function normalizeAction(value) {
  if (["lease", "status", "stop", "reset-vnc"].includes(value)) return value;
  throw new Error(`unsupported action: ${value}`);
}

function normalizePlatform(value) {
  if (["linux", "mac", "windows"].includes(value)) return value;
  if (value === "macos" || value === "darwin") return "mac";
  if (value === "win") return "windows";
  throw new Error(`unsupported platform: ${value}`);
}

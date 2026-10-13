#!/usr/bin/env node
// Build the published Check detection-rules file: upstream + overlay.
//
//   node scripts/build.js                      fetch upstream from GitHub
//   node scripts/build.js --upstream FILE      use a local upstream file (offline / tests)
//
// Writes dist/detection-rules.json, dist/BUILD_INFO.json and
// dist/upstream-detection-rules.json (the exact upstream input, used by validate.js).
"use strict";

const fs = require("fs");
const path = require("path");
const { execFileSync } = require("child_process");

const ROOT = path.resolve(__dirname, "..");
const DIST = path.join(ROOT, "dist");
const OVERLAY = path.join(ROOT, "overlay");

const UPSTREAM_REPO = "CyberDrain/Check";
const UPSTREAM_BRANCH = "main";
const UPSTREAM_PATH = "rules/detection-rules.json";

// Top-level keys overlay/overrides.json may patch. Anything else fails the build.
const OVERRIDABLE_KEYS = ["domain_squatting"];

function fail(msg) {
  console.error(`build: ERROR: ${msg}`);
  process.exit(1);
}

function readJson(file) {
  try {
    return JSON.parse(fs.readFileSync(file, "utf8"));
  } catch (e) {
    fail(`cannot parse ${path.relative(ROOT, file)}: ${e.message}`);
  }
}

async function fetchWithRetry(url, opts = {}, tries = 4) {
  let lastErr;
  for (let i = 0; i < tries; i++) {
    try {
      const res = await fetch(url, opts);
      if (res.ok) return res;
      lastErr = new Error(`HTTP ${res.status} for ${url}`);
      if (res.status < 500 && res.status !== 429) break;
    } catch (e) {
      lastErr = e;
    }
    await new Promise((r) => setTimeout(r, 2000 * 2 ** i));
  }
  throw lastErr;
}

// Resolve upstream main to a commit SHA, then fetch the rules at that exact SHA
// so BUILD_INFO's commit and the content always agree. Falls back to the
// branch URL (commit recorded as null) if the SHA cannot be resolved.
async function fetchUpstream(pin) {
  if (pin !== UPSTREAM_BRANCH) {
    const url = `https://raw.githubusercontent.com/${UPSTREAM_REPO}/${pin}/${UPSTREAM_PATH}`;
    const res = await fetchWithRetry(url, { cache: "no-store" });
    return { text: await res.text(), sha: pin, url };
  }
  let sha = null;
  try {
    const out = execFileSync(
      "git",
      ["ls-remote", `https://github.com/${UPSTREAM_REPO}.git`, `refs/heads/${UPSTREAM_BRANCH}`],
      { stdio: ["ignore", "pipe", "pipe"], timeout: 60000 }
    ).toString();
    sha = out.split(/\s+/)[0];
    if (!/^[0-9a-f]{40}$/.test(sha)) sha = null;
  } catch (e) {
    console.warn(`build: WARN: could not resolve upstream commit SHA (${e.message}); using branch URL`);
  }
  const ref = sha || `refs/heads/${UPSTREAM_BRANCH}`;
  const url = `https://raw.githubusercontent.com/${UPSTREAM_REPO}/${ref}/${UPSTREAM_PATH}`;
  const res = await fetchWithRetry(url, { cache: "no-store" });
  return { text: await res.text(), sha, url };
}

function isPlainObject(v) {
  return v !== null && typeof v === "object" && !Array.isArray(v);
}

// Objects merge recursively; arrays and scalars in the patch replace upstream.
function deepMerge(base, patch) {
  if (!isPlainObject(base) || !isPlainObject(patch)) return patch;
  const out = { ...base };
  for (const [k, v] of Object.entries(patch)) out[k] = k in base ? deepMerge(base[k], v) : v;
  return out;
}

function overlayCommit() {
  if (process.env.GITHUB_SHA) return process.env.GITHUB_SHA;
  try {
    return execFileSync("git", ["rev-parse", "HEAD"], { cwd: ROOT, stdio: ["ignore", "pipe", "ignore"] })
      .toString()
      .trim();
  } catch {
    return null;
  }
}

async function main() {
  // overlay/upstream.json: "main" to track upstream, or a commit SHA to pin it.
  const pinFile = path.join(OVERLAY, "upstream.json");
  const pin = fs.existsSync(pinFile) ? readJson(pinFile).ref : UPSTREAM_BRANCH;
  if (pin !== UPSTREAM_BRANCH && !/^[0-9a-f]{40}$/.test(pin || "")) {
    fail(`overlay/upstream.json "ref" must be "${UPSTREAM_BRANCH}" or a 40-character commit SHA`);
  }

  const argIdx = process.argv.indexOf("--upstream");
  let upstreamText, upstreamSha = null, upstreamUrl;
  if (argIdx !== -1) {
    const file = process.argv[argIdx + 1];
    if (!file) fail("--upstream needs a file path");
    upstreamText = fs.readFileSync(file, "utf8");
    upstreamUrl = `file:${file}`;
  } else {
    ({ text: upstreamText, sha: upstreamSha, url: upstreamUrl } = await fetchUpstream(pin));
  }

  let upstream;
  try {
    upstream = JSON.parse(upstreamText);
  } catch (e) {
    fail(`upstream is not valid JSON: ${e.message}`);
  }
  if (!isPlainObject(upstream)) fail("upstream is not a JSON object");
  if (!Array.isArray(upstream.exclusion_system?.domain_patterns)) {
    fail("upstream has no exclusion_system.domain_patterns array; upstream format changed, refusing to build");
  }

  const exclusions = readJson(path.join(OVERLAY, "exclusions.json"));
  const overrides = readJson(path.join(OVERLAY, "overrides.json"));

  // --- overrides (allow-listed keys only) ---
  if (!isPlainObject(overrides)) fail("overlay/overrides.json must be a JSON object");
  for (const key of Object.keys(overrides)) {
    if (!OVERRIDABLE_KEYS.includes(key)) {
      fail(`overlay/overrides.json may not touch "${key}" (allowed: ${OVERRIDABLE_KEYS.join(", ")})`);
    }
    if (!(key in upstream)) fail(`overlay/overrides.json patches "${key}" which upstream no longer has`);
  }

  // Rebuild in upstream key order so the output is stable.
  const out = {};
  for (const key of Object.keys(upstream)) {
    out[key] = key in overrides ? deepMerge(upstream[key], overrides[key]) : upstream[key];
  }

  // --- domain_patterns: (upstream - remove_upstream) ∪ overlay ---
  const upstreamPatterns = upstream.exclusion_system.domain_patterns;
  const removals = (exclusions.remove_upstream || []).map((r) => r.pattern);
  for (const p of removals) {
    if (!upstreamPatterns.includes(p)) {
      console.warn(`build: WARN: remove_upstream pattern is no longer in upstream (clean it up): ${p}`);
    }
  }
  const overlayPatterns = (exclusions.domain_patterns || []).map((e) => e.pattern);
  for (const p of overlayPatterns) {
    if (upstreamPatterns.includes(p)) console.warn(`build: WARN: overlay pattern already in upstream: ${p}`);
  }
  const merged = [
    ...new Set([...upstreamPatterns.filter((p) => !removals.includes(p)), ...overlayPatterns]),
  ].sort();
  out.exclusion_system = { ...out.exclusion_system, domain_patterns: merged };

  // --- build info ---
  const buildInfo = {
    upstream_repo: UPSTREAM_REPO,
    upstream_url: upstreamUrl,
    upstream_commit: upstreamSha,
    upstream_pinned: pin !== UPSTREAM_BRANCH,
    upstream_version: upstream.version ?? null,
    upstream_lastUpdated: upstream.lastUpdated ?? null,
    overlay_commit: overlayCommit(),
    overlay_patterns_added: overlayPatterns.length,
    upstream_patterns_removed: removals.filter((p) => upstreamPatterns.includes(p)).length,
    overrides_keys: Object.keys(overrides).sort(),
    build_timestamp: new Date().toISOString(),
  };
  // Check ignores unknown top-level keys (verified in detection-rules-manager.js
  // and content.js), so the build info also travels inside the rules file.
  out.virtech_build = buildInfo;

  fs.mkdirSync(DIST, { recursive: true });
  fs.writeFileSync(path.join(DIST, "detection-rules.json"), JSON.stringify(out, null, 2) + "\n");
  fs.writeFileSync(path.join(DIST, "BUILD_INFO.json"), JSON.stringify(buildInfo, null, 2) + "\n");
  fs.writeFileSync(path.join(DIST, "upstream-detection-rules.json"), upstreamText);

  console.log(
    `build: upstream ${buildInfo.upstream_version} @ ${upstreamSha || "unknown commit"}; ` +
      `${upstreamPatterns.length} upstream + ${overlayPatterns.length} overlay - ` +
      `${buildInfo.upstream_patterns_removed} removed = ${merged.length} patterns`
  );
}

main().catch((e) => fail(e.stack || e.message));

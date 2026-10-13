#!/usr/bin/env node
// Validate dist/detection-rules.json and the overlay. Exits non-zero on any failure.
// Runs under Node on purpose: Check evaluates these regexes with the JS engine.
//
//   node scripts/validate.js
//   SIZE_OVERRIDE=1 node scripts/validate.js   skip the ±25% size check ([size-override])
"use strict";

const fs = require("fs");
const path = require("path");

const ROOT = path.resolve(__dirname, "..");
const DIST = path.join(ROOT, "dist");
const OVERLAY = path.join(ROOT, "overlay");

const OVERRIDABLE_KEYS = ["domain_squatting"];
const SIZE_TOLERANCE = 0.25;

// Origins that must never be excluded. Check tests patterns against the origin only.
const PROTECTED_ORIGINS = [
  "https://login.microsoftonline.com",
  "https://login.microsoft.com",
  "https://login.live.com",
];

const errors = [];
const warnings = [];
const err = (m) => errors.push(m);
const warn = (m) => warnings.push(m);

function readJson(file) {
  try {
    return JSON.parse(fs.readFileSync(file, "utf8"));
  } catch (e) {
    console.error(`validate: ERROR: cannot read/parse ${path.relative(ROOT, file)}: ${e.message}`);
    process.exit(1);
  }
}

const isPlainObject = (v) => v !== null && typeof v === "object" && !Array.isArray(v);
const typeOf = (v) => (v === null ? "null" : Array.isArray(v) ? "array" : typeof v);

function compile(pattern) {
  try {
    return new RegExp(pattern, "i"); // same flags content.js uses
  } catch (e) {
    return e;
  }
}

// ---------------------------------------------------------------------------
// Pattern shape: ^https:\/\/ <subdomain prefix>? <literal host> (/.*)?$ | $
// The host must be literal labels, escaped dots/hyphens and (a|b) alternation
// groups only, so it can never swallow an attacker-controlled host or path.
// ---------------------------------------------------------------------------
const PREFIX = "^https:\\/\\/";
const SUFFIXES = ["(/.*)?$", "$"];
const SUBDOMAIN_FORMS = ["([a-z0-9-]+\\.)*", "(?:[a-z0-9-]+\\.)*", "[^/]*\\."];
const ATOM = "(?:[a-z0-9-]|\\\\[.-])";
const HOST_RE = new RegExp(`^(?:${ATOM}|\\((?:\\?:)?${ATOM}+(?:\\|${ATOM}+)*\\))+$`);

function checkShape(p) {
  if (!p.startsWith(PREFIX)) return `must start with ${PREFIX}`;
  const suffix = SUFFIXES.find((s) => p.endsWith(s));
  if (!suffix) return "must end with (/.*)?$ or $";
  let host = p.slice(PREFIX.length, p.length - suffix.length);
  const sub = SUBDOMAIN_FORMS.find((f) => host.startsWith(f));
  if (sub) host = host.slice(sub.length);
  if (/\.\*|\.\+/.test(host)) return "host contains an unanchored .* or .+";
  if (!HOST_RE.test(host)) {
    return (
      "host must be literal labels with escaped dots and (a|b) groups only; " +
      `allowed subdomain forms: ${SUBDOMAIN_FORMS.join("  ")}`
    );
  }
  if (!host.includes("\\.")) return "host must contain at least one escaped dot (a registrable domain)";
  return null;
}

// ---------------------------------------------------------------------------
// Overlay metadata. The repo is public: no emails, tenant IDs or secrets.
// ---------------------------------------------------------------------------
const TICKET_RE = /^T\d{8}\.\d{4}$/;
const HANDLE_RE = /^[A-Za-z0-9._-]{2,40}$/;
const DATE_RE = /^\d{4}-\d{2}-\d{2}$/;

function checkMeta(entry, where) {
  if (!isPlainObject(entry)) return err(`${where}: must be an object`);
  if (typeof entry.pattern !== "string" || !entry.pattern) err(`${where}: missing "pattern"`);
  if (typeof entry.reason !== "string" || entry.reason.trim().length < 10 || entry.reason.length > 200) {
    err(`${where}: "reason" must be 10-200 characters`);
  }
  if (!TICKET_RE.test(entry.ticket || "")) err(`${where}: "ticket" must look like T20261012.0107`);
  if (!HANDLE_RE.test(entry.added_by || "")) {
    err(`${where}: "added_by" must be a short handle (letters, digits, . _ -), not an email or full name`);
  }
  const d = entry.added || "";
  if (!DATE_RE.test(d) || isNaN(Date.parse(d)) || new Date(d).toISOString().slice(0, 10) !== d) {
    err(`${where}: "added" must be a real YYYY-MM-DD date`);
  } else if (Date.parse(d) > Date.now() + 86400000) {
    err(`${where}: "added" is in the future`);
  }
  const extra = Object.keys(entry).filter((k) => !["pattern", "reason", "ticket", "added_by", "added"].includes(k));
  if (extra.length) err(`${where}: unknown fields ${extra.join(", ")}`);
}

const SENSITIVE = [
  [/[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/, "email address"],
  [/\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b/i, "GUID (tenant/client ID?)"],
  [/\b(gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})/, "GitHub token"],
  [/\bAKIA[0-9A-Z]{16}\b/, "AWS access key"],
  [/AccountKey=|SharedAccessSignature|[?&]sig=|[?&]sv=20\d\d/i, "Azure key/SAS"],
  [/-----BEGIN [A-Z ]*PRIVATE KEY-----/, "private key"],
  [/\b(password|passwd|secret|api[_-]?key|token)\s*[:=]/i, "credential assignment"],
];

function scanSensitive(file) {
  const text = fs.readFileSync(file, "utf8");
  for (const [re, label] of SENSITIVE) {
    const m = text.match(re);
    if (m) err(`${path.relative(ROOT, file)}: looks like it contains a ${label} ("${m[0].slice(0, 12)}..."); this repo is public`);
  }
}

// Leaves in an override must keep upstream's type (no turning objects into strings).
function checkOverrideTypes(base, patch, where) {
  if (isPlainObject(patch) && isPlainObject(base)) {
    for (const [k, v] of Object.entries(patch)) {
      if (k in base) checkOverrideTypes(base[k], v, `${where}.${k}`);
      else warn(`${where}.${k}: key not present upstream (added by override)`);
    }
  } else if (typeOf(base) !== typeOf(patch)) {
    err(`${where}: override type ${typeOf(patch)} does not match upstream type ${typeOf(base)}`);
  }
}

function main() {
  const outFile = path.join(DIST, "detection-rules.json");
  const upFile = path.join(DIST, "upstream-detection-rules.json");
  for (const f of [outFile, upFile]) {
    if (!fs.existsSync(f)) {
      console.error(`validate: ERROR: ${path.relative(ROOT, f)} missing; run scripts/build.js first`);
      process.exit(1);
    }
  }
  const out = readJson(outFile);
  const upstream = readJson(upFile);
  const buildInfo = readJson(path.join(DIST, "BUILD_INFO.json"));
  const exclusions = readJson(path.join(OVERLAY, "exclusions.json"));
  const overrides = readJson(path.join(OVERLAY, "overrides.json"));
  const tests = readJson(path.join(OVERLAY, "tests.json"));

  for (const f of fs.readdirSync(OVERLAY)) scanSensitive(path.join(OVERLAY, f));
  const known = ["exclusions.json", "overrides.json", "tests.json", "upstream.json"];
  for (const f of fs.readdirSync(OVERLAY)) if (!known.includes(f)) err(`unexpected file overlay/${f}`);
  if (buildInfo.upstream_pinned) warn(`upstream is PINNED to ${buildInfo.upstream_commit}; nightly sync will not pick up upstream changes`);

  // --- structure ---
  if (!isPlainObject(out)) err("output is not a JSON object");
  for (const key of Object.keys(upstream)) {
    if (!(key in out)) err(`output is missing upstream top-level key "${key}"`);
    else if (typeOf(out[key]) !== typeOf(upstream[key])) {
      err(`output key "${key}" is ${typeOf(out[key])}, upstream has ${typeOf(upstream[key])}`);
    }
  }
  const extraKeys = Object.keys(out).filter((k) => !(k in upstream) && k !== "virtech_build");
  if (extraKeys.length) err(`output has unexpected top-level keys: ${extraKeys.join(", ")}`);
  if ("urlAllowlist" in out) err("urlAllowlist is a client policy and must not be in the rules file");
  if (out.version !== upstream.version) err(`output version ${out.version} != upstream ${upstream.version}`);
  if (JSON.stringify(out.virtech_build) !== JSON.stringify(buildInfo)) {
    err("virtech_build in output does not match dist/BUILD_INFO.json");
  }

  // Everything except domain_patterns and allowed overrides must equal upstream.
  for (const key of Object.keys(upstream)) {
    if (key === "exclusion_system" || key in overrides) continue;
    if (JSON.stringify(out[key]) !== JSON.stringify(upstream[key])) err(`output "${key}" differs from upstream`);
  }
  const { domain_patterns: _o, ...outExcl } = out.exclusion_system || {};
  const { domain_patterns: _u, ...upExcl } = upstream.exclusion_system || {};
  if (JSON.stringify(outExcl) !== JSON.stringify(upExcl)) err("exclusion_system (other than domain_patterns) differs from upstream");

  // --- overrides ---
  if (!isPlainObject(overrides)) err("overlay/overrides.json must be an object");
  for (const key of Object.keys(overrides)) {
    if (!OVERRIDABLE_KEYS.includes(key)) err(`overlay/overrides.json may not touch "${key}"`);
    else checkOverrideTypes(upstream[key], overrides[key], `overrides.${key}`);
  }

  // --- overlay entries ---
  const entries = exclusions.domain_patterns;
  const removals = exclusions.remove_upstream || [];
  if (!Array.isArray(entries)) err("overlay/exclusions.json: domain_patterns must be an array");
  if (!Array.isArray(removals)) err("overlay/exclusions.json: remove_upstream must be an array");
  const extraTop = Object.keys(exclusions).filter((k) => !["domain_patterns", "remove_upstream"].includes(k));
  if (extraTop.length) err(`overlay/exclusions.json: unknown keys ${extraTop.join(", ")}`);
  (entries || []).forEach((e, i) => checkMeta(e, `exclusions.domain_patterns[${i}]`));
  (removals || []).forEach((e, i) => checkMeta(e, `exclusions.remove_upstream[${i}]`));

  const overlayPatterns = (entries || []).map((e) => e.pattern).filter(Boolean);
  const dupes = overlayPatterns.filter((p, i) => overlayPatterns.indexOf(p) !== i);
  if (dupes.length) err(`duplicate overlay patterns: ${[...new Set(dupes)].join(", ")}`);

  for (const p of overlayPatterns) {
    const re = compile(p);
    if (re instanceof Error) {
      err(`overlay pattern does not compile as a JS regex: ${p} (${re.message})`);
      continue;
    }
    const shape = checkShape(p);
    if (shape) err(`overlay pattern ${p}: ${shape}`);

    // --- test vectors ---
    const t = tests[p];
    if (!t || !Array.isArray(t.match) || !Array.isArray(t.no_match) || !t.match.length || !t.no_match.length) {
      err(`overlay pattern ${p}: overlay/tests.json needs at least one "match" and one "no_match" URL`);
      continue;
    }
    for (const u of t.match) if (!re.test(u)) err(`pattern ${p} should match ${u} but does not`);
    for (const u of t.no_match) if (re.test(u)) err(`pattern ${p} must NOT match ${u} but does`);

    // Generated lookalikes from each positive host.
    for (const u of t.match) {
      let host;
      try {
        host = new URL(u).host;
      } catch {
        err(`tests.json: invalid URL ${u}`);
        continue;
      }
      for (const evil of [
        `http://${host}`,
        `https://${host}.attacker-example.com`,
        `https://attacker-example.com/${host}`,
        `https://attacker-example.com/x.${host}`,
        // No ?/# lookalikes: Check tests the origin only, and the brief allows
        // [^/]*\. which (like upstream's patterns) would match them.
      ]) {
        if (re.test(evil)) err(`pattern ${p} matches lookalike ${evil}`);
      }
    }
  }
  for (const p of Object.keys(tests)) {
    if (!overlayPatterns.includes(p)) err(`overlay/tests.json has tests for a pattern not in exclusions.json: ${p}`);
  }

  // --- merged pattern list ---
  const merged = out.exclusion_system?.domain_patterns;
  if (!Array.isArray(merged)) {
    err("output exclusion_system.domain_patterns is not an array");
  } else {
    const removalPatterns = removals.map((r) => r.pattern);
    for (const p of upstream.exclusion_system.domain_patterns) {
      if (!merged.includes(p) && !removalPatterns.includes(p)) err(`upstream pattern dropped without remove_upstream entry: ${p}`);
    }
    for (const p of removalPatterns) if (merged.includes(p)) err(`remove_upstream pattern still present: ${p}`);
    for (const p of overlayPatterns) if (!merged.includes(p)) err(`overlay pattern missing from output: ${p}`);
    const expected = [...new Set(merged)].sort();
    if (JSON.stringify(expected) !== JSON.stringify(merged)) err("domain_patterns is not sorted and de-duplicated");

    for (const p of merged) {
      if (typeof p !== "string") {
        err(`non-string pattern in output: ${JSON.stringify(p)}`);
        continue;
      }
      const re = compile(p);
      if (re instanceof Error) {
        // Check skips invalid patterns at runtime; only fatal if it came from us.
        (overlayPatterns.includes(p) ? err : warn)(`pattern does not compile: ${p}`);
        continue;
      }
      for (const origin of PROTECTED_ORIGINS) {
        if (re.test(origin) || re.test(origin + "/")) err(`pattern ${p} excludes Microsoft login origin ${origin}`);
      }
    }
  }

  // --- size sanity ---
  const outSize = fs.statSync(outFile).size;
  const upSize = Buffer.byteLength(JSON.stringify(upstream, null, 2) + "\n");
  const ratio = outSize / upSize;
  const sizeMsg = `output ${outSize} bytes vs upstream ${upSize} bytes (${((ratio - 1) * 100).toFixed(1)}%)`;
  if (Math.abs(ratio - 1) > SIZE_TOLERANCE) {
    if (process.env.SIZE_OVERRIDE === "1") warn(`${sizeMsg}: outside ±25%, allowed by [size-override]`);
    else err(`${sizeMsg}: outside ±25%. Add [size-override] to the commit message if intended.`);
  }

  for (const w of warnings) console.warn(`validate: WARN: ${w}`);
  if (errors.length) {
    for (const e of errors) console.error(`validate: ERROR: ${e}`);
    console.error(`validate: FAILED with ${errors.length} error(s)`);
    process.exit(1);
  }
  console.log(`validate: OK (${merged.length} patterns, ${overlayPatterns.length} from overlay; ${sizeMsg})`);
}

main();

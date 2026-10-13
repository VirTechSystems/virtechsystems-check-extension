#!/usr/bin/env node
// Markdown summary of domain_patterns added/removed between two rules files.
//   node scripts/diff.js OLD.json NEW.json     (OLD may be missing: first publish)
"use strict";

const fs = require("fs");
const path = require("path");

const [oldFile, newFile] = process.argv.slice(2);
if (!newFile) {
  console.error("usage: diff.js OLD.json NEW.json");
  process.exit(2);
}

const load = (f) => (f && fs.existsSync(f) ? JSON.parse(fs.readFileSync(f, "utf8")) : null);
const oldRules = load(oldFile);
const newRules = load(newFile);
const patterns = (r) => new Set(r?.exclusion_system?.domain_patterns || []);
const before = patterns(oldRules);
const after = patterns(newRules);

const overlay = JSON.parse(fs.readFileSync(path.join(__dirname, "..", "overlay", "exclusions.json"), "utf8"));
const meta = new Map((overlay.domain_patterns || []).map((e) => [e.pattern, e]));
const removalMeta = new Map((overlay.remove_upstream || []).map((e) => [e.pattern, e]));

const added = [...after].filter((p) => !before.has(p)).sort();
const removed = [...before].filter((p) => !after.has(p)).sort();
const code = (s) => "`" + s.replace(/`/g, "\\`").replace(/\|/g, "\\|") + "`";
const row = (p, m) => `| ${code(p)} | ${m ? m.ticket : "upstream"} | ${m ? m.reason.replace(/\|/g, "\\|") : ""} |`;

const lines = ["<!-- virtech-rules-diff -->", "### Detection rules diff vs. currently published", ""];
if (!oldRules) lines.push("_No published file yet (first publish)._", "");
const info = newRules?.virtech_build || {};
lines.push(
  `Upstream \`${info.upstream_version}\` @ \`${(info.upstream_commit || "unknown").slice(0, 12)}\`; ` +
    `${after.size} patterns total (${before.size} published).`,
  ""
);
if (!added.length && !removed.length) lines.push("No exclusion pattern changes.");
if (added.length) {
  lines.push(`**Added (${added.length})**`, "", "| Pattern | Ticket | Reason |", "|---|---|---|");
  for (const p of added) lines.push(row(p, meta.get(p)));
  lines.push("");
}
if (removed.length) {
  lines.push(`**Removed (${removed.length})**`, "", "| Pattern | Ticket | Reason |", "|---|---|---|");
  for (const p of removed) lines.push(row(p, removalMeta.get(p) || meta.get(p)));
  lines.push("");
}
const changedKeys = oldRules
  ? Object.keys(newRules).filter(
      (k) => !["exclusion_system", "virtech_build"].includes(k) && JSON.stringify(oldRules[k]) !== JSON.stringify(newRules[k])
    )
  : [];
if (changedKeys.length) lines.push(`Other changed top-level keys: ${changedKeys.map(code).join(", ")}`);
console.log(lines.join("\n"));

# VirTech Check detection rules

Merged `detection-rules.json` for the CyberDrain
[Check](https://github.com/CyberDrain/Check) browser extension: upstream rules
plus a reviewed VirTech overlay. Endpoints load it through Check's managed
policy `customRulesUrl`.

`customRulesUrl` replaces Check's entire rules file, so the published file is
always complete: upstream with the overlay applied.

## Published URL and policy values

```
https://raw.githubusercontent.com/VirTechSystems/virtechsystems-check-extension/published/detection-rules.json
```

The file is served from the `published` branch, which only CI writes, so
commits on `main` reach clients only after they are built and validated.
`BUILD_INFO.json` on `published` records the upstream version and commit, the
overlay commit and the build time. The same data is in the `virtech_build` key
of the rules file.

| Policy | Type | Value |
|---|---|---|
| `customRulesUrl` | REG_SZ | URL above |
| `updateInterval` | REG_DWORD | `6` (hours; allowed 1–168, Check default 24) |

Endpoints pick up a change, including a rollback, within `updateInterval`
plus up to 5 minutes of raw.githubusercontent.com caching.

Registry paths (HKLM, machine policy):

```
HKLM\SOFTWARE\Policies\Microsoft\Edge\3rdparty\extensions\knepjpocdagponkonnbggpcnhnaikajg\policy
HKLM\SOFTWARE\Policies\Google\Chrome\3rdparty\extensions\benimdeioplgkhanklclahllklceahbe\policy
```

```reg
Windows Registry Editor Version 5.00

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge\3rdparty\extensions\knepjpocdagponkonnbggpcnhnaikajg\policy]
"customRulesUrl"="https://raw.githubusercontent.com/VirTechSystems/virtechsystems-check-extension/published/detection-rules.json"
"updateInterval"=dword:00000006

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Google\Chrome\3rdparty\extensions\benimdeioplgkhanklclahllklceahbe\policy]
"customRulesUrl"="https://raw.githubusercontent.com/VirTechSystems/virtechsystems-check-extension/published/detection-rules.json"
"updateInterval"=dword:00000006
```

Where Check is deployed through CIPP or Intune, set these values in that tool
so they are not overwritten.

**Kill switch:** remove `customRulesUrl` from policy. Check then goes back to
its built-in default, upstream's raw rules URL, on its next refresh.

## Layout

| Path | What it is |
|---|---|
| `overlay/exclusions.json` | **The only file humans normally edit.** Our `exclusion_system.domain_patterns` additions, plus optional `remove_upstream` |
| `overlay/tests.json` | Positive and negative test URLs for every overlay pattern (required) |
| `overlay/overrides.json` | Deep-merge patches for other keys. Only `domain_squatting` is allowed; anything else fails the build. Empty by default |
| `overlay/upstream.json` | `"ref": "main"` tracks upstream. A commit SHA pins it (see Rollback) |
| `scripts/build.js` | Fetches upstream at a resolved commit SHA, applies the overlay, writes `dist/` |
| `scripts/validate.js` | Schema, regex and safety checks. Exits non-zero on any failure |
| `scripts/diff.js` | Markdown summary of added and removed patterns, used in PR comments |
| `.github/workflows/build.yml` | On push to `main` (overlay/scripts), nightly at 05:17 UTC, or manual: build, validate, publish |
| `.github/workflows/pr-check.yml` | Builds and validates every PR, then comments the pattern diff |

`dist/` is gitignored on `main`; the published copy lives on the `published` branch.

Run locally (Node 20+, no dependencies):

```sh
node scripts/build.js && node scripts/validate.js
```

## Adding an exclusion

1. Create a branch and add an entry to `overlay/exclusions.json`:

   ```json
   {
     "pattern": "^https:\\/\\/([a-z0-9-]+\\.)*example\\.com(/.*)?$",
     "reason": "Vendor portal: domain-squatting false positive (example vs exampie)",
     "ticket": "T20261013.0042",
     "added_by": "jdoe",
     "added": "2026-10-13"
   }
   ```

2. Add tests for the exact same pattern string to `overlay/tests.json`. Include
   at least one `match` URL and one `no_match` URL; lookalikes are the useful
   negatives:

   ```json
   "^https:\\/\\/([a-z0-9-]+\\.)*example\\.com(/.*)?$": {
     "match": ["https://portal.example.com", "https://example.com"],
     "no_match": ["https://example.com.evil.com", "https://notexample.com", "https://evil.com"]
   }
   ```

3. Run `node scripts/build.js && node scripts/validate.js`, then open a PR. CI
   posts the added and removed patterns as a comment.

Pattern rules (enforced by `validate.js`):

- Patterns are tested **case-insensitively against the page origin only**
  (`https://host[:port]`, no path), using JavaScript `RegExp`.
- Start with `^https:\/\/` and end with `(/.*)?$` or `$`.
- The host is literal labels with escaped dots (`\.`) and optional `(a|b)`
  groups. No `.*` or `.+`.
- Subdomain wildcard: `([a-z0-9-]+\.)*` (also matches the bare domain).
  `[^/]*\.` is also accepted, as used upstream; it requires a subdomain.
- No pattern may match `login.microsoftonline.com`, `login.microsoft.com` or
  `login.live.com`.
- Validation also generates lookalikes from each `match` URL and fails if any
  of them match: the `http://` form, `host.attacker`, and `attacker/host`.

### Removing an upstream pattern

Upstream patterns are never dropped silently. To remove one, add an entry to
`remove_upstream` with the same fields: the `pattern`, copied exactly from
upstream, plus `reason`, `ticket`, `added_by` and `added`. If upstream later
deletes that pattern itself, the build warns that the entry is stale.

### Overrides

`overlay/overrides.json` deep-merges into upstream. Objects merge; arrays and
scalars replace. Only `domain_squatting` is allowed, and each value must keep
upstream's type. Enterprise policy `domainSquatting` **overrides** the
rules-file settings for `deviationThreshold`, `action`, `severity`,
`algorithms` and `logDetections`, and squatting detection runs only when policy
`domainSquatting.enabled` is `true`. Tenants that set these policies are not
affected by the equivalent overrides here.

## Review rules

- Every change to `main` goes through a PR with **one approval from someone
  other than the author**.
- The reviewer checks:
  - the pattern is as narrow as the ticket needs: a specific vendor domain, not
    a shared hosting or CDN domain (`*.azurewebsites.net`, `*.cloudfront.net`,
    `*.github.io` and the like can be registered by anyone);
  - the tests include lookalike negatives;
  - the ticket exists;
  - the PR comment's added/removed list shows only what the ticket asks for.
- An exclusion turns off **all** of Check's phishing checks for that origin,
  not only the one that produced the false positive. When a single tenant is
  affected, use that tenant's `urlAllowlist` policy instead.
- `[size-override]` in a commit message allows the output to differ from
  upstream by more than ±25%. The reviewer must confirm why.

## Public-repo hygiene

This repository is public. `validate.js` fails the build if any overlay file
contains an email address, a GUID (tenant or client IDs), or something that
looks like a key, token, SAS URL or private key. Also:

- `reason` names the vendor and the false positive, **never the client**.
  `added_by` is a short handle, not a full name or email.
- Tickets are referenced by number only. Don't paste ticket content.
- Commit with your GitHub noreply address: GitHub → Settings → Emails → "Keep
  my email addresses private" and "Block command line pushes that expose my
  email".
- The deploy key is stored only as an environment secret. The repo holds no
  secrets.
- The published exclusion list is public and shows which vendor domains
  endpoints skip. Keep exclusions narrow.

## Rollback

Every published file is a commit on `published`, tied to a `main` commit
through `virtech_build.overlay_commit`.

- **Bad overlay change:** on GitHub, open the merged PR → **Revert** → approve
  and merge the revert PR. `build.yml` publishes automatically. Clients pick it
  up within `updateInterval`.
- **Bad upstream change** (picked up by the nightly sync): find the last good
  `upstream_commit` in the history of `BUILD_INFO.json` on `published`. Open a
  PR that sets `overlay/upstream.json` `"ref"` to that SHA. When upstream is
  fixed, revert that PR to track `main` again. While pinned, every build warns.
- **Emergency:** remove `customRulesUrl` from policy (see Kill switch).

`published` is never edited by hand; its ruleset blocks direct pushes.

## Repository configuration

Reference for the settings this repo depends on. They are configured in
GitHub, not by anything in the repo.

### 1. Publish deploy key

1. Generate a key locally: `ssh-keygen -t ed25519 -N "" -C "check-rules-publish" -f publish_key`.
2. Settings → Deploy keys → Add: title `check-rules-publish`, paste
   `publish_key.pub`, tick **Allow write access**.
3. Settings → Environments → New environment `publish`:
   - Deployment branches and tags → **Selected branches** → add `main` only.
   - Add environment secret `PUBLISH_DEPLOY_KEY` = contents of `publish_key`.
4. Delete both local key files.

### 2. Branch protection (Settings → Rules → Rulesets)

**Ruleset `main`**: target the default branch. Enforcement: Active. No
bypass actors.
- Restrict deletions.
- Block force pushes.
- Require a pull request before merging:
  - Required approvals: **1**.
  - Dismiss stale approvals when new commits are pushed.
  - Require approval of the most recent reviewable push.
  - Require conversation resolution.
- Require status checks to pass: add **`validate`** (from PR check). Tick
  "Require branches to be up to date before merging".
- Optional: require signed commits.

**Ruleset `published`**: target `published`. Enforcement: Active.
- Restrict creations, Restrict updates, Restrict deletions.
- Block force pushes.
- Bypass list: **Deploy keys** only.

The deploy key is the only writer to `published`, and only CI on `main` can
use it. Everything published has passed a reviewed, validated PR on `main`
and validation again in the publishing run, while the nightly sync runs
without manual steps.

### 3. Actions and security settings

- Settings → Actions → General:
  - Workflow permissions: **Read repository contents and packages
    permissions**.
  - Leave "Allow GitHub Actions to create and approve pull requests" unticked.
  - Fork PR workflows: **Require approval for all outside collaborators**.
  - Actions permissions: "Allow enterprise, and select non-enterprise, actions
    and reusable workflows". Allow actions created by GitHub. Tick **Require
    actions to be pinned to a full-length commit SHA**.
- Settings → Code security:
  - Turn on Secret scanning and **Push protection**, Dependabot alerts, and
    Private vulnerability reporting.
  - Dependabot opens monthly PRs to bump the pinned action SHAs
    (`.github/dependabot.yml`).
- GitHub disables scheduled workflows in public repos after 60 days without
  repository activity. If the nightly run stops, re-enable it under Actions.

### 4. First publish

Run **Build and publish rules** from Actions on `main`. The first run creates
`published`.

## Check behaviour

From CyberDrain/Check `scripts/modules/detection-rules-manager.js`,
`scripts/content.js`, `scripts/background.js` and
`scripts/modules/domain-squatting-detector.js`:

- **Unknown top-level keys are ignored.** The manager caches the fetched JSON
  as-is and `content.js` reads keys by name, so `virtech_build` has no effect
  on detection.
- **A failed fetch** (non-2xx or invalid JSON) falls back to the bundled rules.
  They are used in memory only, are not cached, and the remote URL is retried
  on the next request.
- **`domain_patterns`** are tested with `new RegExp(pattern, "i")` against
  `location.origin`. Invalid patterns are logged and skipped.
- **Squatting vs. exclusions:** in `content.js`, an excluded origin returns
  before the step that sends `check_domain_squatting`, the only trigger for
  the squatting check. Endpoint confirmation: TESTING.md step 3, results below.

### Endpoint test result: exclusion vs. domain-squatting banner

| Date | Check version | Browser | Exclusion alone suppresses banner? | Tester |
|---|---|---|---|---|
| _pending_ | | | | |

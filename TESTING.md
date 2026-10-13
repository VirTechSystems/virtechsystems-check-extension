# Endpoint test checklist

Run on **one** test device before rolling out to tenants. Record results in
the table at the bottom and the squatting result in README.md.

Published URL:
`https://raw.githubusercontent.com/VirTechSystems/virtechsystems-check-extension/published/detection-rules.json`

## 0. Prerequisites

- [ ] `published` branch exists and the URL returns JSON:
      `Invoke-RestMethod <URL> | Select-Object -ExpandProperty virtech_build`
      shows an `upstream_version` and an `overlay_commit`.
- [ ] Note `virtech_build.build_timestamp`: ____________________
- [ ] Note the Check extension version on the device: ____________________

## 1. Deploy the policy to the test device and confirm the fetch

- [ ] Set the policy (Edge shown; for Chrome use
      `Google\Chrome\3rdparty\extensions\benimdeioplgkhanklclahllklceahbe`):

  ```powershell
  $k = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge\3rdparty\extensions\knepjpocdagponkonnbggpcnhnaikajg\policy'
  New-Item -Path $k -Force | Out-Null
  Set-ItemProperty -Path $k -Name customRulesUrl -Value 'https://raw.githubusercontent.com/VirTechSystems/virtechsystems-check-extension/published/detection-rules.json' -Type String
  Set-ItemProperty -Path $k -Name updateInterval -Value 6 -Type DWord
  Set-ItemProperty -Path $k -Name enableDebugLogging -Value 1 -Type DWord
  ```

- [ ] `edge://policy` → **Reload policies**. Under the Check extension, confirm
      that `customRulesUrl`, `updateInterval` and `enableDebugLogging` show
      status **OK**.
- [ ] Clear Check's existing cache so it fetches now instead of waiting for
      `updateInterval`: `edge://extensions` → Developer mode → remove and
      reinstall Check if it isn't force-installed, or restart the browser.
      If it is force-installed, open the **service worker** console for Check
      (`edge://extensions` → Check → "Inspect views: service worker") and run
      `chrome.storage.local.remove('detection_rules_cache')`, then restart the
      browser.
- [ ] In the service worker console, confirm these log lines:
  - `DetectionRulesManager configuration loaded:` with `remoteUrl` = our URL
  - `Fetching detection rules from remote URL: <our URL>`
  - `Successfully fetched detection rules from remote URL`

## 2. Confirm Check is using the remote rules, not the bundled fallback

- [ ] Service worker console:

  ```js
  chrome.storage.local.get('detection_rules_cache').then(r => {
    const c = r.detection_rules_cache;
    console.log(c.source, new Date(c.lastUpdate), c.rules.virtech_build);
    console.log(c.rules.exclusion_system.domain_patterns.filter(p => /pure/.test(p)));
  });
  ```

  Pass if `source` is our URL, `virtech_build.build_timestamp` matches step 0,
  and both pure.cloud / mypurecloud patterns are listed. Bundled rules have no
  `virtech_build`. Also, Check never writes them to this cache, so a populated
  cache with `virtech_build` proves the remote file is in use.
- [ ] No `Falling back to bundled detection rules` line in the console.

## 3. Does the exclusion alone suppress the domain-squatting banner?

This answers the open question in the README. The source suggests "yes".

- [ ] Confirm that policy `domainSquatting.enabled` is `true` on the device
      (`edge://policy`). If it is off, squatting never runs and this test
      proves nothing.
- [ ] **Temporarily** remove the Check standard's `urlAllowlist` entries for
      Genesys (`*.pure.cloud`, `*.mypurecloud.*`) from this device's policy.
      Note the original values first: ____________________
- [ ] Reload policies, restart the browser.
- [ ] **Control:** point `customRulesUrl` at upstream
      (`https://raw.githubusercontent.com/CyberDrain/Check/refs/heads/main/rules/detection-rules.json`),
      clear the cache (step 1), browse to `https://apps.usw2.pure.cloud`.
      Banner/block shown? **Y / N**. If N, the false positive doesn't
      reproduce on this device, so the test below can't show anything.
- [ ] Point `customRulesUrl` back at our URL, clear the cache, browse to
      `https://apps.usw2.pure.cloud` and `https://login.usw2.pure.cloud`.
  - Banner/block shown? **Y / N**
  - Page console (F12 on the tab) shows `✅ URL excluded by detection rules: https://apps.usw2.pure.cloud`
    and `EXCLUDED TRUSTED DOMAIN`? **Y / N**
  - Page console shows `DOMAIN SQUATTING DETECTED`? **Y / N**
- [ ] Restore the `urlAllowlist` entries and reload policies.
- [ ] Record the result in README.md → "Endpoint test result".

## 4. Unreachable URL → graceful fallback

- [ ] Set `customRulesUrl` to `https://raw.githubusercontent.com/VirTechSystems/virtechsystems-check-extension/published/does-not-exist.json`
      (gives a 404). Reload policies, clear the cache, restart the browser.
- [ ] Service worker console shows `Failed to fetch rules from remote URL: HTTP 404`
      then `Falling back to bundled detection rules (in-memory only; will retry remote on next refresh)`.
- [ ] Check still works: a normal page loads with no errors, and
      `https://login.microsoftonline.com` still shows the valid-page badge if
      that is enabled.
- [ ] `chrome.storage.local.get('detection_rules_cache')` is empty, or still
      holds the earlier good copy. The fallback is not cached.
- [ ] Optional: repeat with an unresolvable host
      (`https://check-rules.invalid/detection-rules.json`).
- [ ] Restore `customRulesUrl` to the published URL and set
      `enableDebugLogging` back to `0`, or delete it.

## Results

| Step | Pass/Fail | Notes | Date | Tester |
|---|---|---|---|---|
| 1 Fetch confirmed | | | | |
| 2 Remote, not fallback | | | | |
| 3 Exclusion vs. squatting | | | | |
| 4 Graceful fallback | | | | |

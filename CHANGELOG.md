# Changelog

## v4.4.0 — Automated Exploit Confirmation (Sep 2026)

### Added — Vendored/Adapted Tools
- `tools/confirm_common.py`: shared `Proof` artifact contract (`CONFIRMED`/`POSSIBLE`/`UNCONFIRMED`) written by all four harnesses below and read back by `validate.py --proof`.
- `tools/confirm_idor.py`: confirms cross-account IDOR by requiring a literal victim-specific marker in the attacker's response, absent from an optional control request against the attacker's own resource. Stdlib-only.
- `tools/confirm_authbypass.py`: confirms an auth bypass by diffing an authenticated request, the same request with auth stripped, and (optionally) a genuine anonymous baseline — rules out "this page was just public anyway." Stdlib-only.
- `tools/confirm_ssrf.py`: confirms blind SSRF via a real Interactsh out-of-band callback rather than timing/error-message inference. Wraps the `interactsh-client` Go binary. Needs `GOBIN=$HOME/go/bin go install github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest`.
- `tools/confirm_xss.py`: confirms DOM XSS by driving headless Chromium (Playwright) and requiring the payload's canary to actually fire (dialog/hook/console), not just reflect in the HTML. Adapted from the `dom_xss_harness.py` pattern in the AwareXone/BugHunter fork of this project (same MIT lineage) — same core idea, wired into this repo's proof/validate contract instead of standing alone.

### Changed — Closes the self-attestation gap
- `tools/validate.py`: `--proof <path>` reads a harness's `proof.json` and answers Gates 1 and 3 from its mechanical verdict instead of `input()` yes/no prompts. A `POSSIBLE`/`UNCONFIRMED` verdict auto-fails the gate and cannot be overridden by hand — matches the actual design intent of the 7-Question Gate (proof, not narrative).
- `agents/validator.md`: Q1 and Q6 now require a `proof.json` (`CONFIRMED`) for IDOR/SSRF/auth-bypass/XSS findings before self-attesting; other vuln classes still self-attest but the validator's output must say so explicitly.
- `agents/autopilot.md` / `commands/autopilot.md`: the HUNT step now runs the matching `confirm_*.py` harness on any IDOR/SSRF/auth-bypass/XSS signal before treating it as a finding. Added a bounded **Hunt Budget** (default 200 requests / 90 min per target) so "keep hunting until something is proven" has an explicit stop condition instead of running indefinitely against a live target — checkpoints fire early on a `CONFIRMED` finding, or when the budget runs out, whichever comes first.
- `install_tools.sh`: installs `interactsh-client` via `go install`; confirms Playwright (already installed for `subcat`) covers `confirm_xss.py` too.

### Explicitly unchanged
- Report submission is still always human-gated, in every autopilot mode, regardless of confirmation status — this release makes the *evidence* going into that decision harder to fake, it does not remove the decision.
- Scope checking and rate limits are untouched — the hunt budget bounds persistence, it does not authorize testing outside scope or ignoring circuit breakers.

---

## v4.3.0 — Mobile Scanning + Visual Triage (Sep 2026)

### Added — Vendored Tools
- `tools/apkleaks/` + `tools/mobile_scan.sh`: APK secret/endpoint scanner (vendored from [dwisiswant0/apkleaks](https://github.com/dwisiswant0/apkleaks)). Closes a real gap — the toolkit had zero mobile-app coverage even though many programs scope in an Android APK alongside the web target. `mobile_scan.sh <app.apk>` decompiles via jadx and writes findings to `recon/<target>/mobile/apkleaks.json`.
- `tools/subcat/`: subdomain enum + Playwright screenshot/report tool (vendored from [duty1g/subcat](https://github.com/duty1g/subcat)). Wired into `recon_engine.sh` as a visual-triage pass — screenshots every host in `live/urls.txt` (full mode only, skipped on `--quick` or when Playwright isn't installed) so admin panels and staging environments buried in a long URL list are easy to spot. Browse results with `cd tools/subcat && python3 -m subcat report list`.

### Changed
- `install_tools.sh` now installs apkleaks' and subcat's Python dependencies, checks for a JVM (needed by jadx), and installs Playwright's Chromium build.

---

## v4.2.0 — 403 Bypass + Real Dorking (Sep 2026)

### Added — Vendored Tools
- `tools/unkover/`: 403 bypass tester (vendored from [BRuteLogic/unKover](https://github.com/BRuteLogic/unKover)). Wired into `recon_engine.sh` — automatically tests every URL in `status_403.txt` (IP-spoofing, method tampering, path normalization, encoding, version-prefix bypasses) and writes results to `recon/<target>/live/403_bypass.jsonl`.
- `tools/simplerecondorking/`: multi-engine dorking tool (vendored from [osintbrazuca/SimpleReconDorking](https://github.com/osintbrazuca/SimpleReconDorking)). Replaces the click-through-Google-links workflow of `dork_runner.py` with actual automated queries across 30+ search engines, SQLite-backed dedup, and Markdown/JSON/HTML output. Wired into `scripts/full_hunt.sh`; needs `pip install -r tools/simplerecondorking/requirements.txt`.

### Changed
- `install_tools.sh` now installs SimpleReconDorking's `httpx[socks]` dependency and verifies `unkover` is executable.
- `.gitignore` excludes `tools/simplerecondorking/config/api_keys.json` and its runtime `system.db*` files.

---

## v4.1.0 — Patch: Bug Fixes + Assets (Apr 2026)

### Fixed
- **TODO-4 resolved**: `hunt.py` BASE_DIR path resolution — `hunt.py` was relocated to `tools/` so `TOOLS_DIR`/`BASE_DIR`/`RECON_DIR`/`FINDINGS_DIR` now resolve correctly. All 5 open TODOs are now closed.

### Added
- `logo-banner.svg` and `logo-icon.svg` — SVG vector assets for banner and icon variants

---

## v4.0.0 — Meme Coin Security Module (Apr 2026)

### Added — New Skill Domain
- `skills/meme-coin-audit/SKILL.md`: **Meme coin rug pull detection + 8 token bug classes**
  - Mint authority / freeze authority checks
  - Bonding curve exploit patterns
  - LP lock verification
  - Honeypot detection
  - Token metadata tampering
  - Solana-specific audit path (SPL token checks)
  - Pre-dive kill signals for obvious rugs

### Added — Tool
- `tools/token_scanner.py`: automated token red flag scanner supporting EVM + Solana
  - EVM: ABI analysis, ownership checks, hidden mint functions, transfer tax detection
  - Solana: SPL token account authority checks, metadata validation

### Changed
- `CLAUDE.md`: Skills count 8 → 9, added `meme-coin-audit` to skill table; Commands 13 → 14, added `/token-scan`
- `README.md`: Updated skill domain count

---

## v3.1.1 — CI/CD GitHub Actions Security Expansion (Mar 2026)

### Changed — Existing Skill Enhancement
- `SKILL.md` CI/CD Pipeline section: **5 checklist items → 6 categories, 30+ checks, PoC templates, hunting workflow, and GHSA reference table**
  - **Category 1: Code Injection & Expression Safety** — expression injection, envvar/envpath/output clobbering, argument injection, SSRF via workflow, taint source catalog, fix patterns (env var extraction, heredoc delimiters, end-of-options markers)
  - **Category 2: Pipeline Poisoning & Untrusted Checkout** — untrusted checkout on `pull_request_target`/`workflow_run`, TOCTOU with label-gated approvals, reusable workflow taint, cache poisoning, artifact poisoning, artipacked credential leakage
  - **Category 3: Supply Chain & Dependency Security** — unpinned actions (tag → SHA), impostor commits from fork network, ref confusion, known vulnerable actions, archived actions, unpinned container images
  - **Category 4: Credential & Secret Protection** — secret exfiltration, secrets in artifacts, unmasked `fromJson()` bypass, excessive `secrets: inherit`, hardcoded credentials
  - **Category 5: Triggers & Access Control** — dangerous triggers without/with partial mitigation, label-based approval bypass, bot condition spoofing, excessive GITHUB_TOKEN permissions, self-hosted runners in public repos, OIDC token theft
  - **Category 6: AI Agent Security** — unrestricted AI triggers, excessive tool grants to AI agents, prompt injection via workflow context
  - **Hunting workflow** — 6-step recon→scan→triage→verify→PoC→prove pipeline
  - **Expression injection PoC template** — ready-to-use `gh issue create` payload
  - **10 real-world GHSAs** — proven Critical/High advisories with affected actions
  - **A→B signal chains** — 7 CI/CD-specific escalation paths
  - **Tooling**: integrated [sisakulint](https://sisaku-security.github.io/lint/) — 52 rules, taint propagation, 81.6% GHSA coverage
  - **Deep-dive guide**: Decision tree for verifying sisakulint findings based on 36 real-world paid reports (Bazel $13K, Flank $7.5K, PyTorch $5.5K, GitHub $20K, DEF CON $250K+)

### Added — Tool Integration
- `tools/cicd_scanner.sh`: standalone sisakulint wrapper — org/repo scanning, recursive reusable workflow analysis, parsed summary output with per-rule breakdown
- `install_tools.sh`: sisakulint binary auto-download with OS/arch detection (v0.2.11, linux/darwin, amd64/arm64/armv6), cicd_scanner install now optional (`--with-cicd-scanner`)
- `tools/recon_engine.sh` Phase 8: auto-detects GitHub orgs from recon data (httpx, JS endpoints, URLs), invokes `cicd_scanner.sh` per org
- `tools/hunt.py`: surfaces CI/CD findings between recon and vuln scan stages via `check_cicd_results()`
- `tests/test_cicd_scanner.sh`: shell tests for cicd_scanner (syntax check + CLI behavior)

## v3.1.0 — Hunting Methodology Skill (Mar 2026)

### Added — New Skill Domain
- `skills/bb-methodology/SKILL.md`: **Hunting mindset + 5-phase non-linear workflow** — the "HOW to think" layer that was missing from the toolkit
  - **Part 1: Mindset** — Define/Select/Execute discipline, 4 thinking domains (critical, multi-perspective, tactical, strategic), developer psychology reverse-engineering, Amateur vs Pro 7-phase comparison, Feature-based vs Vuln-based route selection, anti-patterns
  - **Part 2: Workflow** — 5-phase non-linear flow (Recon → Map → Find → Prove → Report) with decision trees per phase, input-type → vuln-class routing, Error vs Blind detection cascade, escalation decision trees per vuln class
  - **Part 3: Navigation & Timing** — "I'm stuck because..." quick reference table, 20-minute rotation clock, tool routing by phase with rationale, session start/end checklists

### Changed
- `CLAUDE.md`: Skills count 7 → 8, added `bb-methodology` to skill table
- `README.md`: Updated skill domain count to 8
- `SKILL.md`: Added cross-reference to `bb-methodology` after CRITICAL RULES section

## v3.1.0 — CVSS 4.0 + TODO Fixes (Mar 2026)

### Changed — CVSS 3.1 → 4.0
- `tools/validate.py`: Full CVSS 4.0 interactive scorer. Replaces 8-metric CVSS 3.1 with 11-metric CVSS 4.0. New metrics: AT (Attack Requirements), VC/VI/VA (Vulnerable System), SC/SI/SA (Subsequent System, incl. Safety). Scope metric removed. UI now has three values (None / Passive / Active). Score verified via FIRST.org calculator link in output.
- `agents/report-writer.md`: Updated CVSS section to 4.0. New metric descriptions, updated common-pattern examples, verification link.

### Fixed — TODOs resolved
- `agents/autopilot.md` already implemented TODO-2 (safe HTTP methods) and TODO-3 (circuit breaker) — marked resolved in TODOS.md
- `tools/hunt.py` BASE_DIR path resolution was already correct (TODO-4 was based on wrong assumption about file location) — marked resolved
- `tools/recon_adapter.py` created (TODO-5): auto-detects nested vs flat recon format, returns unified `ReconData`. `normalize_to_nested()` migrates legacy flat output. CLI: `python3 tools/recon_adapter.py example.com --migrate`

---

## v2.1.0 — 20 Vuln Classes + Payload Expansion (Mar 2026)

### Config
- Recon commands now read the Chaos API key from the `$CHAOS_API_KEY` environment variable for cleaner setup across different environments.

### Added — New Vuln Classes
- `web2-vuln-classes`: **MFA/2FA Bypass** (class 19) — 7 bypass patterns: rate limit, OTP reuse, response manipulation, workflow skip, race, backup codes, device trust escalation
- `web2-vuln-classes`: **SAML/SSO Attacks** (class 20) — XML signature wrapping (XSW), comment injection, signature stripping, XXE in assertion, NameID manipulation + SAMLRaider workflow

### Added — security-arsenal Payloads
- **NoSQL injection**: MongoDB `$ne`/`$gt`/`$regex`/`$where` operators, URL-encoded GET parameter injection
- **Command injection**: Basic probes, blind OOB (curl/nslookup), space/keyword bypass techniques, Windows payloads, filename injection context
- **SSTI detection**: Universal probe for all 6 engines (Jinja2, Twig, Freemarker, ERB, Spring, EJS) + RCE payloads for each
- **HTTP smuggling payloads**: CL.TE, TE.CL, TE.TE obfuscation variants, H2.CL
- **WebSocket testing**: IDOR/auth bypass messages, CSWSH PoC, Origin validation test, injection via messages
- **MFA bypass payloads**: OTP brute force (ffuf), race async script, response manipulation, device trust cookie test
- **SAML attack payloads**: XSW XML templates, comment injection, signature stripping workflow, XXE payload, SAMLRaider CLI

### Added — web2-recon Skill
- **Setup section**: `$CHAOS_API_KEY` export instructions, subfinder config.yaml with 5 API sources, nuclei-templates update command
- **crt.sh** passive subdomain source (no API key needed) added as Step 0
- **Port scanning**: naabu command for non-standard ports (8080/8443/3000/9200/6379/etc.)
- **Secret scanning**: trufflehog + SecretFinder JS bundle scan, grep patterns
- **GitHub dorking**: `gh search code` commands, GitDorker integration for org-wide secret search

### Added — report-writing Skill
- **Intigriti template**: Full format with platform-specific notes (video PoC preference, safe harbor stance)
- **CVSS 4.0 quick reference**: Key differences from CVSS 3.1, score examples for common findings, calculator link

### Added — rules/hunting.md
- **Rule 18**: Mobile = different attack surface (APK decompile workflow, key targets)
- **Rule 19**: CI/CD is attack surface (GitHub Actions expression injection, dangerous workflow patterns)
- **Rule 20**: SAML/SSO = highest auth bug density (test checklist)

### Updated
- README: CHAOS_API_KEY setup section with free key instructions and optional subfinder API keys
- README: Updated vuln class count from 18 → 20, updated skill descriptions
- `web2-vuln-classes` description updated to reflect 20 classes and new additions

---

## v2.0.0 — ECC-Style Plugin Architecture (Mar 2026)

Major restructure into a full Claude Code plugin with multi-component architecture.

### Added
- `skills/` directory with 7 focused skill domains (split from monolithic SKILL.md)
  - `skills/bug-bounty/` — master workflow (unchanged from v1)
  - `skills/web2-recon/` — recon pipeline, subdomain enum, 5-minute rule
  - `skills/web2-vuln-classes/` — 18 bug classes with bypass tables
  - `skills/security-arsenal/` — payloads, bypass tables, never-submit list
  - `skills/web3-audit/` — 10 smart contract bug classes, Foundry template
  - `skills/report-writing/` — H1/Bugcrowd/Intigriti/Immunefi templates
  - `skills/triage-validation/` — 7-Question Gate, 4 gates, always-rejected list
- `commands/` directory with 8 slash commands
  - `/recon` — full recon pipeline
  - `/hunt` — start hunting a target
  - `/validate` — 4-gate finding validation
  - `/report` — submission-ready report generator
  - `/chain` — A→B→C exploit chain builder
  - `/scope` — asset scope verification
  - `/triage` — quick 7-Question Gate
  - `/web3-audit` — smart contract audit
- `agents/` directory with 5 specialized agents
  - `recon-agent` — runs recon pipeline, uses claude-haiku-4-5 for speed
  - `report-writer` — generates reports, uses claude-opus-4-6 for quality
  - `validator` — validates findings, uses claude-sonnet-4-6
  - `web3-auditor` — audits contracts, uses claude-sonnet-4-6
  - `chain-builder` — builds exploit chains, uses claude-sonnet-4-6
- `hooks/hooks.json` — session start/stop hooks with hunt reminders
- `rules/hunting.md` — 17 critical hunting rules (always active)
- `rules/reporting.md` — 12 report quality rules (always active)
- `CLAUDE.md` — plugin overview and quick-start guide
- `install.sh` — one-command skill installation

### Content Added to Skills
- SSRF IP bypass table: 11 techniques (decimal, octal, hex, IPv6, redirect chain, DNS rebinding)
- Open redirect bypass table: 11 techniques for OAuth chaining
- File upload bypass table: 10 techniques + magic bytes reference
- Agentic AI ASI01-ASI10 table: OWASP 2026 agentic AI security framework
- Pre-dive kill signals for web3: TVL formula, audit check, line-count heuristic
- Conditionally valid with chain table: 12 entries
- Report escalation language for payout downgrade defense

---

## v1.0.0 — Initial Release (Early 2026)

- Monolithic SKILL.md (1,200+ lines) covering full web2+web3 workflow
- Python tools: `hunt.py`, `learn.py`, `validate.py`, `report_generator.py`, `mindmap.py`
- Vulnerability scanners: `h1_idor_scanner.py`, `h1_mutation_idor.py`, `h1_oauth_tester.py`, `h1_race.py`
- AI/LLM testing: `hai_probe.py`, `hai_payload_builder.py`, `hai_browser_recon.js`
- Shell tools: `recon_engine.sh`, `vuln_scanner.sh`
- Utilities: `sneaky_bits.py`, `target_selector.py`, `zero_day_fuzzer.py`, `cve_hunter.py`
- Web3 skill chain: 10 files in `web3/` directory
- Wordlists: 5 wordlists in `wordlists/` directory
- Docs: `docs/payloads.md`, `docs/advanced-techniques.md`, `docs/smart-contract-audit.md`

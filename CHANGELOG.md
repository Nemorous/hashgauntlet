# Changelog

## [3.0.0] - 2026-09-26
### Added
- Secretsdump ingestion: auto-extracts NTLM hashes and maps them to SAMAccountNames
- `--ad-mode` for one-flag NTLM audits (auto hash mode 1000 and NTLM-safe defaults)
- Staged attack gauntlet: dictionary, rule-based, and hybrid prepend/append mask attacks
- Severity-tiered findings report with remediation windows
- Report export in `txt`, `json`, `csv`, or all formats (`--report-format`)
- Tunable coverage levels (`-c 1/2/3` for ~90% / ~95% / ~98%)
- Leetspeak generation and toggle-case handling, with `--no-leet` opt-out
- Automatic length-based wordlist splitting so optimized kernels (`-O`) never silently skip long candidates
- Wordlist preprocessing: case conversions, separators, selective leetspeak, and org/location-tailored generation
- Interactive session controls with a persistent status bar
- Optional AES-256-GCM encryption of the audit log
- Cross-platform support (Linux, Windows, macOS)

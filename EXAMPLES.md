# HashGauntlet Usage Examples

This document provides usage examples for HashGauntlet, organized by workflow.

> Only run HashGauntlet against systems and hashes you are explicitly authorized to test.

## Table of Contents
- [Active Directory Audits](#active-directory-audits)
- [Generic Hash Audits](#generic-hash-audits)
- [Coverage & Limits](#coverage--limits)
- [Rules & Attacks](#rules--attacks)
- [Wordlist Preprocessing](#wordlist-preprocessing)
- [Reporting & Evidence](#reporting--evidence)
- [Interactive Controls](#interactive-controls)

---

## Active Directory Audits

Audit NTLM hashes straight from an `impacket-secretsdump` dump. Cracked hashes
are mapped back to their usernames in the report.

```bash
# Simplest AD audit: secretsdump output + a base wordlist
hashgauntlet --ad-mode --secretsdump secretsdump.txt -b rockyou.txt

# Short flags, with a report
hashgauntlet --ad-mode --sd secretsdump.txt -b rockyou.txt --report findings
```

`--ad-mode` auto-sets `--hash-mode 1000` (NTLM) and NTLM-safe defaults.

---

## Generic Hash Audits

Any Hashcat hash mode works. Provide the hashes with `--hash-file` and the mode
with `--hash-mode`.

```bash
# NetNTLMv2 (mode 5600)
hashgauntlet -f captured.hashes -m 5600 -b rockyou.txt

# bcrypt (mode 3200)
hashgauntlet --hash-file web.hashes --hash-mode 3200 -b rockyou.txt
```

---

## Coverage & Limits

Trade runtime for thoroughness, and keep long audits bounded.

```bash
# Optimized (~90%) — fastest
hashgauntlet --ad-mode --sd dump.txt -b rockyou.txt -c 1

# Comprehensive (~98%) — deepest
hashgauntlet --ad-mode --sd dump.txt -b rockyou.txt -c 3

# Cap each attack at 1 hour and skip wordlists that would exceed 50 GB
hashgauntlet --ad-mode --sd dump.txt -b rockyou.txt --max-time 1 --max-size 50000
```

---

## Rules & Attacks

```bash
# Point at your Hashcat rules directory
hashgauntlet --ad-mode --sd dump.txt -b rockyou.txt --rules-dir /usr/share/hashcat/rules

# Skip specific rule files
hashgauntlet --ad-mode --sd dump.txt -b rockyou.txt --void-rules dive.rule

# Disable rule-based attacks entirely (dictionary + hybrid only)
hashgauntlet --ad-mode --sd dump.txt -b rockyou.txt -d

# Skip two-rule combination attacks and leetspeak
hashgauntlet --ad-mode --sd dump.txt -b rockyou.txt --skip-combos --no-leet
```

---

## Wordlist Preprocessing

```bash
# Enable preprocessing with case conversions and separators
hashgauntlet --ad-mode --sd dump.txt -b base.txt --preprocess --case all --separators - _ .

# Selective leetspeak with at most 2 substitutions per word
hashgauntlet --ad-mode --sd dump.txt -b base.txt --preprocess --selective-leet 2

# Tailor the wordlist to the target organization
hashgauntlet --ad-mode --sd dump.txt -b base.txt --org-name "Acme Corp" --org-location Denver Colorado

# Cache preprocessed wordlists for reuse across runs
hashgauntlet --ad-mode --sd dump.txt -b base.txt --preprocess --use-cache
```

---

## Reporting & Evidence

```bash
# Write a severity-tiered findings report (text)
hashgauntlet --ad-mode --sd dump.txt -b rockyou.txt --report engagement-findings

# Export the report as JSON, CSV, or every format at once
hashgauntlet --ad-mode --sd dump.txt -b rockyou.txt --report findings --report-format json
hashgauntlet --ad-mode --sd dump.txt -b rockyou.txt --report findings --report-format all

# Encrypt the audit log with AES-256-GCM (prompts for a passphrase at session end)
hashgauntlet --ad-mode --sd dump.txt -b rockyou.txt --encrypt-log
```

---

## Interactive Controls

While a session is running you can pause, resume, skip to the next attack,
finish the current attack then stop, or kill the run, from the keyboard. The
available keys are shown in the status bar during the run.

Run with `-q` / `--quiet` to suppress everything except errors and cracked
hashes for scripted, non-interactive use.

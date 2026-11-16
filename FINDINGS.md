# Findings

This project practices coordinated disclosure. Packages with an UNFIXED
vulnerability are not named here, and no weaponizable detail is published,
until the maintainer has shipped a fix or the 90-day window has closed.
Naming an unfixed package is premature disclosure; this repo does not do it.

## Under active coordinated disclosure (not yet named)
- 3 confirmed CWE-22 arbitrary-file-write findings in MCP servers via
  unconstrained path tool inputs (output_path / local_path / output_dir
  reaching writeFileSync with no containment).
- Each was source-confirmed against the published npm tarball; one was
  independently corroborated by CodeQL taint analysis (13 flows).
- Reach of the affected packages ranges into the low thousands of weekly
  downloads. Package names, line numbers, and the write-ups publish here
  when each window closes.

## Public contributions (safe to name)
- GHSA-2m3w-6mh6-8j3w (papaparse, CVE-2026-127056): mapped the affected
  package to a HIGH-severity advisory that shipped with an empty affected
  field, so npm audit, Dependabot, and OSV can now match it. papaparse is
  at 25.7M weekly downloads. PR open against github/advisory-database.
- Three earlier affected-package mappings merged into the advisory database.

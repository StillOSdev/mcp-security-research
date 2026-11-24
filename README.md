# MCP Security Research

A systematic security audit of the Model Context Protocol (MCP) server
ecosystem: methodology, tooling, and coordinated-disclosure findings.

> Status: DRAFT, LOCAL ONLY. Not published. Publishing is gated on Marcus
> approval and on coordinated-disclosure windows (no live finding is
> described before the maintainer has fixed it or the window has closed).

## Why this exists

MCP is the protocol that lets AI agents call tools. A tool input that
reaches a filesystem or shell sink without containment is reachable by the
agent itself - including through indirect prompt injection from untrusted
content, which is the normal MCP threat model. The ecosystem is young, so
this class of bug is widespread and unaudited. This project audits it at
scale and discloses responsibly.

## Scale

- 65,063 MCP servers tracked in a longitudinal census (refreshed every 6h).
- 1,654 npm-backed servers deep-scanned with CodeQL taint analysis across
  three sink classes (command injection, SQL injection, path traversal).
- 152 path-flow candidates surfaced; each source-confirmed before any
  disclosure, because static flags over-count guarded sinks.

## Method

1. Census. Enumerate the MCP server population from the registry; capture
   version, publish date, and npm identifiers on a cadence.
2. Taint. Build one CodeQL database per package; run all three MCP sink
   queries against it. DBs build in RAM, source is pruned after - flat disk.
3. Confirm. A parallel confirmation stage pulls every candidate, classifies
   its write surface (guarded / likely-live / needs-read / no-sink), and
   ranks by real download reach into a human read-list. This removed the
   real bottleneck, which was never the scan - it was confirming each lead
   by hand, one at a time.
4. Source-confirm. Every shipped finding is proven against the published
   tarball, and where possible by executing the package's own code - not
   from the analyzer output alone.
5. Coordinate. Private report to the maintainer first, 90-day window, then
   a GitHub Advisory Database submission crediting the reporter.

## Findings

- Arbitrary file write via an unconstrained `output_path` tool input is a
  recurring class across independent MCP servers. Two coordinated
  disclosures are in progress (details withheld until fix or window close).
- The class is hardening: several high-reach servers ship a path-containment
  guard, including packages published the same day they were measured. The
  defensible research result is the survival curve of the class, not a lone
  bug.
- Contributions to the GitHub Advisory Database map previously unmatched
  advisories (empty `affected`) to their packages, making them actionable
  for npm audit, Dependabot, and OSV.

## Tooling (in this repo)

- `batch_confirm` - parallel confirmation and reach-ranking stage.
- CodeQL MCP taint queries (command / SQL / path).
- The confirmation classifier, with a unit-test suite.

## Responsible disclosure

No live, un-fixed finding is described here. Every CVE referenced is either
already public or past its coordinated window. Methodology and aggregate
statistics are published; weaponizable detail is not.

## Your own dossier

Still OS Digital Holdings LLC measures the MCP and x402 operator
surface. If you run a server, API or agent endpoint, it probably
already has a public, dated dossier:

    https://stillosdigitalholdings.com/ratings/n/<your-host>

Free with no account: your grade, your percentile in a measured
population, and copyable badge markdown.

Check any host: https://stillosdigitalholdings.com/exposure

Something wrong in your dossier? Correct it, free, no account:

    https://stillosdigitalholdings.com/surface/correct?host=<your-host>

<!-- stillos-capture:start -->

---

## Your own dossier

Still OS Digital Holdings LLC measures the MCP and x402 operator surface.
If you run a server, API or agent endpoint, it probably already has a
public, dated dossier:

    https://stillosdigitalholdings.com/ratings/n/<your-host>

Free with no account: your grade, your percentile in a measured
population, and copyable badge markdown.

Check any host: [https://stillosdigitalholdings.com/exposure](https://stillosdigitalholdings.com/exposure?src=gh-mcp-security-research)

Something wrong in your dossier? Correct it, free, no account:

[https://stillosdigitalholdings.com/surface/correct](https://stillosdigitalholdings.com/surface/correct?src=gh-mcp-security-research)

<!-- stillos-capture:end -->

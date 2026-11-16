# MCP Ecosystem Security Scorecard

Aggregate posture of the Model Context Protocol server ecosystem, from a
continuously-refreshed census and CodeQL taint sweep. Counts and rates
only; no individual server is named and no unfixed finding is disclosed.

## Population
- servers tracked (census):        65,288
- npm-backed, deep-scanned:         1,654

## Taint-flow prevalence (of deep-scanned, CodeQL)
- with a path-traversal flow:       152  (9.2%)
- with a command-injection flow:    5  (0.3%)
- with a SQL-injection flow:        2  (0.1%)

## Write-surface confirmation (n=145 path-flow candidates)
- a path-containment guard present: 13  (9.0%)
- unguarded caller path:            15  (10.3%)
- write sink, origin needs a read:  62  (42.8%)
- no write sink:                    55  (37.9%)

Finding: the arbitrary-write class is real but not universal - a meaningful
share of servers already ship a path guard, and the unguarded ones are the
disclosure targets. Refreshed from the census (every 6h) and the CodeQL
sweep (daily). Scanner in codeql/, method in the README.

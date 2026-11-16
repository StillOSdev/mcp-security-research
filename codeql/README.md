# MCP CodeQL query pack

CodeQL ships models for Express, Fastify, Axios and dozens of other
frameworks. It does not model the Model Context Protocol. Grepping
codeql/javascript-all for MCP terms returns zero files, while `express`
returns 252. The consequence is concrete: a stock CodeQL
CommandInjection / TaintedPath / SqlInjection scan reports ZERO on an MCP
server that writes a caller-controlled `output_path` straight to disk,
because CodeQL does not know an MCP tool argument is untrusted input.

This pack fixes that. `McpSourcesJs.qll` models MCP tool-call arguments as
a remote (untrusted) taint source - an LLM invokes the tool with arguments
derived from whatever was in its context, including untrusted documents, so
indirect prompt injection reaches these sinks. Three queries then track
that taint to filesystem, shell, and SQL sinks:

- McpPathTraversalJs.ql    CWE-22 path traversal / arbitrary file write
- McpCommandInjectionJs.ql CWE-78 command injection
- McpSqlInjectionJs.ql     CWE-89 SQL injection

Measured: on a server where stock queries report zero, this pack surfaces
the real flows. It is the pack behind the findings in this repo.

## Use
    codeql database create db --language=javascript --source-root=<server>
    codeql query run --database=db McpPathTraversalJs.ql

The threat model, validation history, and the measurement that CodeQL does
not model MCP are documented in the header of McpSourcesJs.qll.

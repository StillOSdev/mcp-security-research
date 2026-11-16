# MCP Tool-Path Passthrough (arbitrary file write)

A recurring, independent-rediscovery vulnerability class in MCP servers.
Observed in multiple unrelated packages with the identical root cause.

## The pattern
An MCP tool declares a path-shaped input - output_path, local_path,
output_dir, file_path, save_path - typically as `z.string().optional()`
with no constraint. The handler passes it to `path.resolve()` (or
`path.join(dir, input)`) and then to `fs.writeFileSync` / `writeFile`,
with no containment:

    output_path: z.string().optional()
    ...
    const abs = path.resolve(output_path);   // absolute returned verbatim;
    writeFileSync(abs, bytes);               // ".." escapes any base

## Why it is reachable (the MCP-specific part)
In the MCP threat model the tool caller is frequently an LLM acting on
untrusted content - a document it read, a web page, another tool's output.
So the path is attacker-influenced through indirect prompt injection, with
no human ever choosing it. That is why this is a vulnerability and not just
a CLI writing where you told it to.

## Impact
Arbitrary file write and destructive overwrite of any file the server
process can reach: authorized_keys, shell rc files, configs, CI artifacts.
Integrity and availability compromise; content is partially attacker-
influenced depending on the tool.

## Why it recurs
`path.resolve` and `path.join` do not contain - they resolve. Developers
reach for them expecting containment they do not provide. Several affected
packages even had a `resolveWithin`-style guard for ONE sink (zip
extraction) and left the tool-input writes raw - the guard existed, it was
just not applied everywhere.

## The fix (one helper, applied to every path sink)
    function resolveWithin(root, p) {
      const abs = path.resolve(root, p);
      if (abs !== root && !abs.startsWith(root + path.sep)) return null; // escaped
      return abs;
    }
Reject absolute paths and ".." that escape a configured workspace root.
Apply uniformly - the defect is a single missing sink that ships raw.

## Detection
The CodeQL pack in codeql/ models MCP tool arguments as a taint source and
tracks them to filesystem sinks. Stock CodeQL does not model MCP and
reports zero on these same servers.

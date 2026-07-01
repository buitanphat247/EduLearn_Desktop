# Exam Guard Release Evidence Bundle

Only reviewed release acceptance records belong in this directory.

Accepted files:

- JSON evidence records conforming to `../evidence-schema.json`.
- JSON arrays of conforming evidence records.
- JSON objects with a `records` array.
- JSONL files containing one conforming evidence record per line.

Do not copy native matrix run manifests into this directory. Run manifests and
unexecuted scenario slots belong in `../results`.

The production gate is fail-closed:

- Empty directory: `NOT TESTED`, exit code 2.
- Missing or malformed evidence: `FAIL`, exit code 1.
- Any failed, blocked or not-tested record: release blocked.
- Any best-effort or bypass-possible result: production readiness blocked.

Receiver capture, destructive fault, service lifecycle, performance soak and
restore evidence must come from the required Windows VM/lab environment. A
placeholder file is not evidence.

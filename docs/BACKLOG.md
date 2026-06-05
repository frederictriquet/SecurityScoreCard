# BACKLOG

## Tech debt

- [ ] [high] Orchestrator not concurrency-safe for simultaneous rescans — fix-task — make run_single_scanner idempotent under concurrent rescans (upsert/lock or unique constraint + handle duplicates) rather than only documenting it in tests. (orchestrator-rescan-race)
- [ ] [medium] Domain validator rejects full URLs it promises to accept — fix-task — normalize pasted URLs (strip scheme/path/port/credentials) so the validator matches the UI promise. (url-normalization-incomplete)

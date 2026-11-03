---
schema_version: 2
object_type: release_entry
versioning:
  schema_version: 1
  revision: 1
entry_id: entry-0003
release_version: 0.4.9
kind: changed
summary:
  Changed create-db to check PostgreSQL collation health before target checks
  or mutations
status: accepted
audience: null
scopes: []
source_refs:
  - git:48f4eee4cef37a408470ba2518ab071844ac1a31
paths:
  - docs/cli.md
  - oduit/_operations/database.py
  - oduit/builders.py
  - oduit/cli/commands/database.py
issues: []
prs: []
sources:
  - git:48f4eee4cef37a408470ba2518ab071844ac1a31
contributors: []
breaking: false
internal: false
order: 3
---

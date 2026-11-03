---
schema_version: 2
object_type: release_entry
versioning:
  schema_version: 1
  revision: 1
entry_id: entry-0005
release_version: 0.4.9
kind: fixed
summary:
  Fixed agent addon validation to verify installed state after mutations and
  report verification failures
status: accepted
audience: null
scopes: []
source_refs:
  - git:aadc419fe9efe322d3db8b111a39f37e426a7294
paths:
  - oduit/cli/agent/validate.py
  - oduit/cli/agent_support.py
  - tests/test_agent_cli.py
issues: []
prs: []
sources:
  - git:aadc419fe9efe322d3db8b111a39f37e426a7294
contributors: []
breaking: false
internal: false
order: 5
---

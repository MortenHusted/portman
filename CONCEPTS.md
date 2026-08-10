# Concepts

Shared domain vocabulary for this project — entities, named processes, and status concepts with project-specific meaning. Seeded with core domain vocabulary, then accretes as ce-compound and ce-compound-refresh process learnings; direct edits are fine. Glossary only, not a spec or catch-all.

## Service supervision

### Portman Service

A host process definition that Portman can start, supervise, observe, and optionally expose through a hostname route.

### Synced Root

The checkout directory that owns a set of Portman Services. Synchronizing a root replaces that root's definitions without changing services owned by other roots; forgetting a root is an empty synchronization for that owner.

### Service Route

A hostname mapping derived from a Portman Service definition while that service is up, distinct from an independently managed static route. It is removed when the service goes down or its definition is removed.

### Built-in Route

A protected hostname mapping owned by the Portman daemon rather than a project or user rule. `portman.localhost` is the built-in route to the dashboard; it cannot be replaced or removed.

### Native Localhost Route

An HTTP route under `.localhost`. The operating system resolves it to loopback, so Portman only needs Host-based proxy dispatch and does not install or manage a resolver. TCP mode is excluded because it needs a distinct loopback front per hostname.

## Relationships

A Synced Root owns Portman Services, and a Portman Service may publish one Service Route. Root-scoped status and forgetting operate through this ownership relationship.

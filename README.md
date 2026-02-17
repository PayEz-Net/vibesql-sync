# VibeSQL Sync

**The only PostgreSQL replication where the wire is out of PCI scope.**

Every other replication tool encrypts the connection. vsql-sync encrypts the payload. Change events are envelope-encrypted before leaving the source node — Kafka brokers, proxies, network taps, and log aggregators hold only ciphertext. The transport layer is structurally out of PCI scope.

Five capabilities no other PostgreSQL replication tool has. All four phases together, and nothing else touches this ground.

---

## The Problem Nobody Solves

PostgreSQL logical decoding produces plaintext change events. The output of `pgoutput` or `wal2json` is decoded, readable row data. Every replication tool transmits this plaintext — protected only by TLS on the wire.

If TLS is terminated at a load balancer, proxy, or Kafka broker, the plaintext is exposed. If the transport layer logs change events for debugging, plaintext rows are in the log. Every broker, every proxy, every monitoring agent that sees those events is in PCI scope. That's expensive, complex, and fragile.

```
Traditional PostgreSQL replication:

  Node A (CDE)         Kafka / pglogical / WAL stream       Node B
  ┌──────────┐                                             ┌──────────┐
  │ plaintext│ ──── TLS (but Kafka sees plaintext) ──────▶ │ plaintext│
  │ row data │                                             │ row data │
  └──────────┘                                             └──────────┘
      CDE                   IN SCOPE                           CDE

vsql-sync:

  Node A (CDE)         Transport (Kafka / file / stream)    Node B (CDE)
  ┌──────────┐                                             ┌──────────┐
  │ encrypt  │ ──── only ciphertext crosses this ────────▶ │ decrypt  │
  │ at source│       no keys, no plaintext, no scope       │ at target│
  └──────────┘                                             └──────────┘
      CDE                  OUT OF SCOPE                        CDE
```

---

## Five Differentiators

### 1. Payload-Level Envelope Encryption

Per-tuple AES-256-GCM encryption with CryptAply-managed keys. Each change event is encrypted before it enters the transport layer. The DEK is wrapped by a KMS KEK that never leaves the KMS boundary. Intermediate infrastructure — Kafka, proxies, wire taps — holds only ciphertext.

### 2. Selective Column Publication as PCI Scope Boundary

PostgreSQL 15+ column-list publications let vsql-sync exclude PCI-scoped columns from replication entirely. A replica that never receives `pan_encrypted`, `cvv_hash`, or `cardholder_name` is architecturally outside the CDE. A QSA can scope it out. vsql-sync enforces `REPLICA IDENTITY` constraints automatically to prevent before-image leakage of excluded columns.

### 3. Signed, Merkle-Rooted, Hash-Chained Audit Trail

Every replication batch produces a Merkle root over all replicated tuples, signed with Ed25519, and chained to the previous audit entry. Source and target independently compute the Merkle root — if they match, replication was complete and lossless. Modifying any historical audit row breaks the hash chain for all subsequent rows. Same integrity model as certificate transparency logs, without the blockchain.

### 4. Split Consistency — CP for PCI, CRDT for App State

PCI data paths use `remote_apply` synchronous commit — both nodes agree before the commit returns. Application state uses delta-apply columns (CRDT counters) for automatic convergence without conflict. The ledger is CP. The UI state is AP. Conflict resolution: CRDT merge first, then LWW by commit timestamp, then route to designated PCI primary.

### 5. Air-Gap Mode

Encrypted changesets as physical transport containers. Export WAL segments since the last checkpoint, envelope-encrypt the entire changeset, compute a SHA-256 manifest, sign it with Ed25519. Ship it on a USB drive, courier, or secure file transfer. Import on the target with full Merkle verification before applying. For environments that prohibit live replication of PCI data.

---

## Architecture

```
Inside CDE (Node A)                    Outside CDE (Transport)             Inside CDE (Node B)
┌────────────────────────────┐         ┌───────────────────────┐          ┌────────────────────────────┐
│                            │         │                       │          │                            │
│  PostgreSQL + Spock        │         │  Only ciphertext.     │          │  PostgreSQL + Spock        │
│       │                    │         │  No keys.             │          │       ▲                    │
│       ▼                    │         │  No plaintext.        │          │       │                    │
│  Logical decode            │         │  No PCI scope.        │          │  CryptAply decrypt         │
│       │                    │         │                       │          │       ▲                    │
│       ▼                    │         │  Kafka / pglogical /  │          │       │                    │
│  CryptAply encrypt         │─────────│  file / USB           │──────────│  Conflict resolve          │
│  (per-session DEK,         │         │                       │          │  (LWW / CRDT / primary)    │
│   KMS-wrapped KEK)         │         │                       │          │       │                    │
│       │                    │         └───────────────────────┘          │       ▼                    │
│       ▼                    │                                            │  Apply + audit log          │
│  Merkle root + sign        │                                            │  (Merkle verify + sign)     │
│                            │                                            │                            │
└────────────────────────────┘                                            └────────────────────────────┘
```

### Component Stack

```
┌────────────────────────────────────────────────────────┐
│  vsql-sync (Rust binary)                               │
│                                                        │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐ │
│  │ Governance   │  │ Encryption   │  │ CryptAply    │ │
│  │ Engine       │  │ Pipeline     │  │ Bridge       │ │
│  │              │  │              │  │              │ │
│  │ Audit trail  │  │ Envelope enc │  │ Report key   │ │
│  │ Merkle roots │  │ per-session  │  │ inventory UP │ │
│  │ Signatures   │  │ DEK          │  │              │ │
│  │ PCI scope    │  │ KMS-wrapped  │  │ Accept       │ │
│  │ tagging      │  │ KEK          │  │ directives   │ │
│  │ Column filter│  │              │  │ DOWN         │ │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘ │
│         │                 │                  │        │
│  ┌──────▼─────────────────▼──────────────────▼──────┐ │
│  │  Spock 5.x (PostgreSQL License, pgEdge)          │ │
│  │                                                  │ │
│  │  • N-node mesh replication                       │ │
│  │  • LWW + delta-apply (CRDT-lite)                 │ │
│  │  • Snowflake sequences                           │ │
│  │  • DDL replication                               │ │
│  │  • INSERT→UPDATE conflict transformation         │ │
│  │  • Conflict logging (spock.resolutions)          │ │
│  └──────────────────────────────────────────────────┘ │
│                                                        │
│  PostgreSQL 15/17/18                                   │
│  • Selective column publications (PG15+)               │
│  • pg_replication_origin (loop prevention)             │
│  • track_commit_timestamp = on                         │
│  • PG18 conflict_resolution (LWW, keep_local, etc.)   │
└────────────────────────────────────────────────────────┘
```

Phase 1 uses native PostgreSQL 15+ logical replication — no Spock dependency yet. Spock arrives in Phase 2 as the multi-master engine.

---

## Why Spock

Spock (pgEdge) went fully open source under the PostgreSQL License in September 2025. It provides the multi-master replication engine that would take years to build from scratch. vsql-sync wraps Spock the same way vsql-backup wraps pgBackRest — the user interacts with `vsql-sync`, never with Spock directly.

| Feature | Native PG18 | Spock 5.x | Why It Matters |
|---------|-------------|-----------|----------------|
| N-node mesh | 2-node only | Yes | Multi-region deployments |
| Delta-apply columns | No | Yes | Conflict-free counters and balances |
| Snowflake sequences | No | Yes | Globally unique IDs without coordination |
| DDL replication | No | Yes | Schema changes propagate automatically |
| INSERT→UPDATE transform | No | Yes | Graceful handling of duplicate key conflicts |
| Conflict logging | Stats only | `spock.resolutions` table | Auditable conflict history |

---

## Encryption Pipeline

```
PostgreSQL WAL
       │
       ▼
Logical decoding (pgoutput / Spock output plugin)
       │
       ▼  plaintext change event (inside CDE boundary)
       │
vsql-sync encryption interceptor
       │
       ├─ Generate per-session DEK (or reuse current session DEK)
       │  DEK lifetime: configurable (per-batch, per-hour, per-session)
       │
       ├─ Encrypt each change tuple: AES-256-GCM(DEK, tuple)
       │  Authenticated encryption — tamper detection built in
       │
       ├─ Wrap DEK with KMS KEK: KMS.encrypt(KEK, DEK)
       │  KEK never leaves KMS boundary
       │
       ├─ Emit encrypted change event:
       │  {
       │    origin: "node-a",
       │    lsn: "0/42001234",
       │    table: "payments",
       │    encrypted_tuple: <ciphertext>,
       │    dek_id: "DEK-session-001",
       │    nonce: <unique per tuple>
       │  }
       │
       ▼
Transport layer (Spock / Kafka / file)
       │  ← only ciphertext crosses this boundary
       │  ← no keys in the stream
       │  ← structurally out of PCI scope
       ▼
vsql-sync decryption (on target node)
       │
       ├─ Retrieve DEK: KMS.decrypt(KEK, wrapped_DEK)
       ├─ Decrypt tuple: AES-256-GCM(DEK, ciphertext)
       ├─ Verify authentication tag (tamper detection)
       │
       ▼
Conflict resolution → Apply to PostgreSQL
```

### Key Hierarchy

```
┌─────────────────────────────────────┐
│  KMS (Azure Key Vault / AWS KMS)    │
│                                     │
│  KEK (Key Encryption Key)           │
│  • Rotates annually (PCI 3.7.1)     │
│  • Never leaves KMS boundary        │
│  • Audit logged by KMS              │
└──────────────────┬──────────────────┘
                   │ wraps
                   ▼
┌─────────────────────────────────────┐
│  Session DEK (Data Encryption Key)  │
│  • Random per replication session   │
│  • Rotated per configurable policy  │
│  • Stored wrapped in stream header  │
│  • AES-256-GCM                      │
└──────────────────┬──────────────────┘
                   │ encrypts
                   ▼
┌─────────────────────────────────────┐
│  Change event tuples                │
│  • Each tuple encrypted separately  │
│  • Unique nonce per tuple           │
│  • Authentication tag for tamper    │
│    detection                        │
└─────────────────────────────────────┘
```

**Crypto-shredding:** Destroy a KEK version and all DEKs wrapped by it are unrecoverable. All change events encrypted by those DEKs are cryptographically destroyed — no data to scrub, no rows to delete.

---

## Selective Column Publication

```sql
-- Replicate the payments table WITHOUT PCI columns
CREATE PUBLICATION analytics_replica
FOR TABLE payments (
    id,
    merchant_id,
    amount_cents,
    currency,
    status,
    created_at,
    updated_at
);
-- Excluded: pan_encrypted, cvv_hash, cardholder_name, expiry_encrypted
```

The subscriber receives only the listed columns. PCI columns are never transmitted — the subscriber physically cannot contain cardholder data. vsql-sync enforces this automatically: tables with `exclude_pci = true` will not be assigned `REPLICA IDENTITY FULL`, which would otherwise leak before-image values for excluded columns.

vsql-sync generates a signed PCI scope reduction report for QSA review:

```json
{
  "report_type": "pci_scope_reduction",
  "publication": "analytics_replica",
  "generated_at": "2026-02-17T06:00:00Z",
  "tables": [
    {
      "table": "payments",
      "total_columns": 11,
      "replicated_columns": 7,
      "excluded_pci_columns": ["pan_encrypted", "cvv_hash", "cardholder_name", "expiry_encrypted"],
      "subscriber_can_contain_pci": false
    }
  ],
  "conclusion": "Subscriber receives no PCI-scoped columns. Architecturally outside CDE.",
  "signature": "ed25519:..."
}
```

---

## Replication Modes

### Uni-Directional (Phase 1)

```
Node A (publisher)                    Node B (subscriber)
┌─────────────┐                      ┌─────────────┐
│ PostgreSQL  │ ──── encrypted ─────▶ │ PostgreSQL  │
│ (read-write)│      CDC stream       │ (read-only) │
└─────────────┘                      └─────────────┘
```

Use cases: reporting replica with PCI columns excluded, DR standby with governed failover, analytics offload.

### Bi-Directional (Phase 2)

```
Node A                                Node B
┌─────────────┐                      ┌─────────────┐
│ PostgreSQL  │ ◀── encrypted ──────▶ │ PostgreSQL  │
│ (read-write)│      CDC stream       │ (read-write)│
└─────────────┘                      └─────────────┘
        │                                    │
        └──── pg_replication_origin ─────────┘
                   (loop prevention)
```

Write partitioning: PCI data writes route to a designated primary with `remote_apply` synchronous commit. Application state accepts writes on any node — delta-apply columns (CRDT counters) converge automatically.

### Multi-Node Mesh (Phase 4)

```
         Region US-East                    Region EU-West
    ┌─────────────────────┐           ┌─────────────────────┐
    │  Node A    Node B   │           │  Node C    Node D   │
    │  ◀──────▶  ◀──────▶ │ ◀──────▶  │  ◀──────▶  ◀──────▶ │
    │  (sync within region)│           │  (sync within region)│
    └─────────────────────┘           └─────────────────────┘
              ▲                                  ▲
              └───── async between regions ──────┘
```

Intra-region: synchronous commit (CP). Inter-region: async with LWW/CRDT (AP within tolerance). CRDTs everywhere for app state.

### Air-Gap Mode (Phase 4)

```
Node A (source)
  │
  ▼
vsql-sync export
  │  → WAL segments since last export
  │  → CryptAply envelope encryption (per-export DEK)
  │  → SHA-256 manifest
  │  → Signed changeset file (.vsql-changeset)
  │
  ▼
Physical transport (USB drive, courier, secure file transfer)
  │
  ▼
vsql-sync import --changeset changeset-20260217.vsql-changeset
  │  → Verify signature
  │  → Verify Merkle root
  │  → Decrypt with CryptAply key
  │  → Apply to Node B
  │  → Write audit trail (air-gap import event)
```

---

## Audit Trail

Every replication batch produces a Merkle-rooted, Ed25519-signed, hash-chained audit record:

```sql
CREATE TABLE vsql_sync_audit (
    event_id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    event_type        TEXT NOT NULL,      -- 'replication_batch', 'air_gap_export', 'conflict_resolved'
    event_timestamp   TIMESTAMPTZ NOT NULL DEFAULT now(),
    source_node_id    TEXT NOT NULL,
    target_node_id    TEXT NOT NULL,
    batch_lsn_start   PG_LSN NOT NULL,
    batch_lsn_end     PG_LSN NOT NULL,
    tables_affected   TEXT[] NOT NULL,
    row_count         BIGINT NOT NULL,
    contains_pci      BOOLEAN NOT NULL,   -- were any PCI-scoped columns included?
    pci_columns       TEXT[],
    dek_id            TEXT,               -- which DEK encrypted this batch
    kek_id            TEXT,               -- which KEK wrapped the DEK
    algorithm         TEXT DEFAULT 'AES-256-GCM',
    merkle_root       BYTEA NOT NULL,     -- hash of all tuples in batch
    prev_event_hash   BYTEA,             -- hash of previous row (hash chain)
    signer_node_id    TEXT NOT NULL,
    signature         BYTEA NOT NULL      -- Ed25519 over all above fields
);

-- Append-only enforcement
CREATE RULE no_update AS ON UPDATE TO vsql_sync_audit DO INSTEAD NOTHING;
CREATE RULE no_delete AS ON DELETE TO vsql_sync_audit DO INSTEAD NOTHING;
```

### Merkle Root

```
Merkle Root: SHA-256(H1 || H2)
            /              \
    H1: SHA-256(h1||h2)    H2: SHA-256(h3||h4)
       /        \             /        \
    h1: tuple1  h2: tuple2  h3: tuple3  h4: tuple4
```

Source and target independently compute the Merkle root after each batch. If roots match, replication was complete and lossless. If roots differ, binary search through the tree locates the divergent tuple.

---

## Quick Start

### Phase 1 — Uni-Directional with Audit Trail

```bash
# 1. Generate signing keypair (prod mode)
vsql-sync key generate --output /etc/vsql-sync/

# 2. Configure
cat > vsql-sync.toml << EOF
[cluster]
name = "my-cluster"
node_id = 1
node_name = "node-a-us-east"

[connection]
host = "localhost"
port = 5432
database = "vibesql"
user = "vsql_sync"

[server]
mode = "prod"
listen_addr = "0.0.0.0:8444"

[server.tls]
cert_path = "/certs/tls.crt"
key_path  = "/certs/tls.key"

[audit]
enabled           = true
hash_chain        = true
merkle_roots      = true
signature_algorithm = "ed25519"
signing_key_path  = "/etc/vsql-sync/vsql-sync-signing.key"
EOF

# 3. Initialize the node
vsql-sync node init \
    --node-id 1 \
    --cluster my-cluster \
    --connection "host=localhost dbname=vibesql"

# 4. Create a scope-reduced publication (exclude PCI columns)
vsql-sync publication create analytics_replica \
    --table "payments(id, merchant_id, amount_cents, currency, status, created_at)" \
    --table "merchants(*)" \
    --exclude-pci

# 5. Add subscriber
vsql-sync node add-peer \
    --peer-node-id 2 \
    --peer-connection "host=node-b dbname=vibesql" \
    --mode uni-directional

# 6. Start
vsql-sync daemon start

# 7. Verify
vsql-sync status
vsql-sync audit verify
vsql-sync publication scope-report analytics_replica
```

---

## CLI Reference

```bash
# Cluster management
vsql-sync node init --node-id 1 --cluster my-cluster --connection "..."
vsql-sync node add-peer --peer-node-id 2 --peer-connection "..." --mode bidirectional
vsql-sync cluster status

# Publications (PCI scope control)
vsql-sync publication create analytics_replica \
    --table "payments(id, merchant_id, amount_cents, currency, status)" \
    --table "merchants(*)" \
    --exclude-pci
vsql-sync publication scope-report analytics_replica

# Replication
vsql-sync start
vsql-sync daemon start
vsql-sync pause --reason "Incident response IR-2026-042"
vsql-sync resume
vsql-sync status

# Signing keys
vsql-sync key generate --output /etc/vsql-sync/
vsql-sync key show-public

# Encryption (Phase 3+)
vsql-sync key rotate-dek
vsql-sync key inventory

# Audit
vsql-sync audit list --since "2026-02-01" --contains-pci true
vsql-sync audit verify
vsql-sync audit export --format json --output /tmp/audit-report.json

# Air-gap (Phase 4)
vsql-sync export --since-lsn "0/42000000" --output /media/usb/changeset-20260217.vsql-changeset
vsql-sync import --changeset /media/usb/changeset-20260217.vsql-changeset --operator "dba@company.com"
vsql-sync verify --changeset /media/usb/changeset-20260217.vsql-changeset

# Conflicts
vsql-sync conflicts list --since "2026-02-17"
vsql-sync conflicts show CONFLICT-001

# Diagnostics
vsql-sync verify-consistency --table payments --node-a node-a --node-b node-b
```

---

## Configuration

```toml
[cluster]
name      = "my-cluster"
node_id   = 1
node_name = "node-a-us-east"

[connection]
host     = "localhost"
port     = 5432
database = "vibesql"
user     = "vsql_sync"

[server]
mode        = "prod"              # "dev" = unsigned audit + HTTP, "prod" = signed + TLS required
listen_addr = "0.0.0.0:8444"

[server.tls]
cert_path = "/certs/tls.crt"
key_path  = "/certs/tls.key"

# Peers
[[peers]]
node_id    = 2
node_name  = "node-b-eu-west"
connection = "host=node-b port=5432 dbname=vibesql user=vsql_sync"
mode       = "bidirectional"

# Encryption (Phase 3+)
[encryption]
enabled   = true
algorithm = "AES-256-GCM"

[encryption.kms]
provider = "azure-kv"             # or "aws-kms", "gcp-kms", "file" (dev only)
kek_id   = "vault/keys/vsql-sync-kek"

[encryption.dek]
rotation = "per-session"          # or "per-batch", "hourly", "daily"

# Conflict resolution
[conflict]
default_strategy  = "last_write_wins"
pci_write_primary = "node-a-us-east"
pci_write_policy  = "reject"      # or "forward", "accept_lww"
max_clock_skew_ms = 100           # alert and pause PCI replication if exceeded

[[conflict.crdt.columns]]
table    = "account_balance"
column   = "balance"
function = "spock_delta_apply_float8"

# Consistency
[consistency]
pci_sync_mode     = "remote_apply" # synchronous for PCI tables
non_pci_sync_mode = "async"

# Audit
[audit]
enabled             = true
hash_chain          = true
merkle_roots        = true
signature_algorithm = "ed25519"
signing_key_path    = "/etc/vsql-sync/vsql-sync-signing.key"
audit_table         = "vsql_sync_audit"

# DDL replication (Phase 2+)
[ddl]
enforce_governed_ddl = true
audit_ddl            = true

# CryptAply (Phase 3+)
[cryptaply]
enabled          = false
endpoint         = "https://cryptaply.internal:8443"
report_interval  = "5m"
accept_directives = true
stale_max        = "24h"

# Publications
[[publications]]
name   = "full_replica"
tables = ["*"]
mode   = "bidirectional"

[[publications]]
name = "analytics_replica"
mode = "uni-directional"

[[publications.tables]]
name        = "payments"
columns     = ["id", "merchant_id", "amount_cents", "currency", "status", "created_at"]
exclude_pci = true

[[publications.tables]]
name    = "merchants"
columns = "all"

# Air-gap (Phase 4)
[air_gap]
export_dir          = "/var/vsql-sync/exports"
changeset_format    = "vsql-changeset-v1"
max_changeset_size  = "10GB"
```

---

## Dev vs Prod Mode

Consistent with the rest of the VibeSQL family:

| Setting | dev | prod |
|---------|-----|------|
| TLS | Optional | Required (hard error without cert) |
| Signing key | Optional | Required (hard error without key) |
| Audit signatures | Skipped — logged with warning | Ed25519 on every entry |
| Scope reports | Unsigned | Signed |
| Startup | Loud warning every 60s | Clean |

`mode = "dev"` lets engineers test locally without ceremony. `mode = "prod"` enforces all controls with no exceptions.

---

## How vsql-sync Compares

| Capability | BDR / PGD | Spock | Debezium | pglogical | vsql-sync |
|------------|-----------|-------|----------|-----------|-----------|
| Payload encryption | No | No | No | No | Yes |
| PCI scope reduction via column exclusion | No | No | No | No | Yes |
| Signed replication audit trail | No | No | No | No | Yes |
| CRDT + CP split consistency | Partial (BDR CRDTs) | Delta-apply only | No | No | Yes |
| Air-gap replication | No | No | No | No | Yes |
| Governance key integration | No | No | No | No | Yes (CryptAply) |
| QSA scope reduction report | No | No | No | No | Yes |

BDR has CRDTs but no payload encryption. Debezium has CDC but no governance. pg_tde has TDE but decrypts on logical decode — the stream is still plaintext. Nobody does all seven.

---

## PCI DSS v4.0 Compliance Mapping

| PCI Requirement | vsql-sync Feature |
|----------------|-------------------|
| **3.4** — Render PAN unreadable in all storage including backups | Payload encryption — change events encrypted with AES-256-GCM before leaving the source node |
| **3.5 / 3.6 / 3.7** — Key management | CryptAply integration — KEK in KMS, DEK per session, audit-logged rotation |
| **7.1** — Restrict access to system components | Selective column publication — PCI columns excluded from replica scope entirely |
| **7.2** — Access based on need-to-know | PCI write routing — only designated primary accepts PCI writes |
| **10.2** — Audit logs for all access to cardholder data | Replication audit trail — every batch logged with source, target, PCI flag, key IDs |
| **10.3** — Protect audit logs from modification | Hash-chained, Ed25519-signed, append-only audit table |
| **10.5** — Retain audit logs for 12 months | Audit table with configurable retention; S3 Object Lock for exports |
| **10.7** — Promptly detect failures in audit logging | Continuous hash-chain integrity verification; alerts on chain breaks |
| **12.10.2** — Tested incident response including recovery | Air-gap import/export with signed audit trail provides DR test evidence |

---

## Phased Delivery

| Phase | What Ships | Depends On |
|-------|-----------|------------|
| **1 — Uni-directional** | Selective column replication, replication audit trail, PCI scope reduction reports, Ed25519 signing, hash-chain integrity. Native PG15+ logical replication — no Spock. | PostgreSQL 15+ |
| **2 — Bi-directional** | Active-active via Spock, LWW conflict resolution, delta-apply CRDT columns, Snowflake sequences, DDL replication, clock skew monitoring. Plaintext stream (TLS only at this phase). | Spock 5.x |
| **3 — Payload Encryption** | CryptAply envelope encryption on the CDC stream. Transport layer structurally out of PCI scope. Merkle root computation and verification. KMS-backed Ed25519 signing. | vsql-cryptaply |
| **4 — Mesh + Air-Gap** | Air-gap encrypted changesets, N-node mesh, region-aware CP/AP split consistency, CryptAply directive enforcement. | All prior phases |

### Phase 1 MVP Deliverables

- `vsql-sync node init` / `vsql-sync node add-peer` (uni-directional)
- `vsql-sync publication create` with column exclusion and automatic REPLICA IDENTITY enforcement
- `vsql-sync publication scope-report` — Ed25519-signed in prod mode
- `vsql-sync key generate` — Ed25519 signing keypair
- `vsql_sync_audit` table — hash-chained, signed, append-only
- `vsql-sync audit verify` — hash chain integrity check
- `vsql-sync audit export` — JSON export for QSA review
- `vsql-sync status` — replication health and clock skew monitoring
- Dev/prod mode pattern
- Config file parsing and validation

Phase 1 does not include bidirectional replication, payload encryption, air-gap mode, CryptAply integration, CRDT columns, or multi-node mesh. Those arrive in their respective phases.

---

## The VibeSQL Product Family

```
┌────────────┐  ┌────────────┐  ┌──────────┐  ┌──────────────┐  ┌──────────┐
│ VibeSQL    │  │ VibeSQL    │  │ VibeSQL  │  │ VibeSQL      │  │ vsql-    │
│ Micro      │  │ Vault      │  │ Audit    │  │ Edge         │  │ sync     │
│ (database) │  │ (governed  │  │ (Req 10) │  │ (auth)       │  │ (replic- │
│ 77MB       │  │  storage)  │  │          │  │              │  │  ation)  │
└────────────┘  └────────────┘  └──────────┘  └──────────────┘  └──────────┘
     │               │               │              │                  │
     └─────────────── Micro + Vault = minimal CDE ──────────────────┘
                      vsql-sync = the governed path between CDEs
```

- [VibeSQL Micro](https://github.com/PayEz-Net/vibesql-micro) — Single-binary PostgreSQL. Dev tool and CDE companion.
- [VibeSQL Server](https://github.com/PayEz-Net/vibesql-server) — Production multi-tenant PostgreSQL server
- [VibeSQL Vault](https://github.com/PayEz-Net/vibesql-vault) — Governed storage for encrypted blobs. Shrink your PCI scope.
- [VibeSQL Edge](https://github.com/PayEz-Net/vibesql-edge) — Authentication gateway
- [VibeSQL Audit](https://github.com/PayEz-Net/vibesql-audit) — PCI DSS compliant audit logging (Req 10)
- [VibeSQL Sync](https://github.com/PayEz-Net/vibesql-sync) — This project. Governed bi-directional replication.
- [CryptAply](https://github.com/PayEz-Net/cryptaply) — Key governance authority. Encryption policy enforcement.
- [Vibe SDK](https://github.com/PayEz-Net/vibe-sdk) — TypeScript ORM with live schema sync

---

## License

Apache 2.0 License. See [LICENSE](LICENSE).

---

<div align="right">
  <sub>Part of <a href="https://vibesql.online">VibeSQL</a> · Powered by <a href="https://idealvibe.online">IdealVibe</a></sub>
</div>

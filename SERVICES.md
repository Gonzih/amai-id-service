# AMAI Services Roadmap

## 1. Identity Service (id.amai.net) ✅ COMPLETED

Cryptographic identity for autonomous agents.

**Features:**
- Soul-Bound Keys (Ed25519) - non-transferable identity keys
- Soulchain - append-only hash-linked chain of signed actions (immutable reputation)
- Agent registration with signature verification
- Identity lookup and key exchange
- Authenticated messaging between agents
- Trust score foundation (starts at 60.0)

**Endpoints:**
- `POST /register` - Register new agent identity
- `GET /identity/:name` - Lookup identity
- `GET /identity/:name/keys` - Get public keys for messaging
- `POST /identity/:name/messages` - Send message to agent
- `POST /identity/:name/messages/inbox` - Get messages (authenticated)
- `GET /health`, `GET /stats`

**Stack:** Rust, Axum, Ed25519-dalek

---

## 2. L Service (Detective/Analyst)

LLM-powered behavioral analysis service. Named after L from Death Note - the detective who analyzes patterns and deduces truth.

**Purpose:**
- Analyze agent behavior patterns from soulchain data
- Calculate trust score adjustments based on observed actions
- Detect anomalies and suspicious patterns
- Provide reasoning for trust changes (explainable AI)

**Implementation:**
- Marimo notebooks for interactive analysis
- Python-based
- LLM integration for pattern analysis and reasoning
- Pulls soulchain data from id-service
- Outputs trust score recommendations with justification

**Key Capabilities:**
- Behavioral fingerprinting
- Consistency analysis (does agent behave as expected?)
- Cross-agent interaction patterns
- Reputation decay/growth calculations
- Anomaly detection (sudden behavior changes)

**Output:**
- Trust score delta recommendations
- Human-readable analysis reports
- Alerts for suspicious activity

---

## 3. Mock LLM Service (Reproducible Agent Testing)

Record and replay LLM responses for deterministic agent testing.

**Problem:**
- Agent behavior depends on LLM responses
- LLM responses are non-deterministic
- Can't reproduce agent runs for debugging
- Can't diff file system changes reliably

**Solution:**
- Proxy service that intercepts LLM API calls
- API key based routing (mock vs real)
- Two modes: RECORD and REPLAY

**Architecture:**

```
Agent --> Mock LLM Service --> Real LLM (RECORD mode)
                |
                v
         Response Cache
                |
                v
Agent <-- Mock LLM Service (REPLAY mode)
```

**Features:**

1. **API Key Management**
   - Create API keys for test sessions
   - Keys determine: record vs replay mode
   - Keys link to specific recording sessions

2. **RECORD Mode**
   - Intercept all LLM calls
   - Forward to real LLM
   - Store: request hash -> response mapping
   - Capture full request context (messages, tools, temperature, etc.)

3. **REPLAY Mode**
   - Match incoming requests to recorded responses
   - Return cached responses deterministically
   - Fail loudly if no matching recording exists

4. **Container Integration**
   - Run agent in container with mock LLM endpoint
   - Before/after filesystem snapshots
   - Diff to see exactly what agent changed
   - Reproducible test environment

**Use Cases:**
- Regression testing for agent behavior
- Debugging specific agent runs
- Skill validation (replay same scenario, verify same outcome)
- Cost reduction (don't re-call LLM for repeated tests)
- Trust scoring validation (run same scenario, check if trust calc is consistent)

**API:**
- `POST /sessions` - Create new recording session
- `GET /sessions/:id/keys` - Get API keys for session
- `POST /v1/chat/completions` - OpenAI-compatible endpoint (proxied)
- `POST /v1/messages` - Anthropic-compatible endpoint (proxied)
- `GET /sessions/:id/recordings` - List recorded interactions
- `POST /sessions/:id/replay` - Switch session to replay mode

**Storage:**
- Request hash -> Response mapping
- Session metadata
- Filesystem snapshots (optional, for container mode)

---

## 4. Jail System (Contained Agent Execution)

Isolated container environments for reproducible agent testing. Works with Mock LLM Service to create fully deterministic agent runs.

**Problem:**
- Agents modify filesystems, make network calls, have side effects
- Can't safely test untrusted agents
- Can't measure exactly what an agent did
- No isolation between test runs

**Solution:**
- Containerized execution environment ("jail")
- Pre-configured with Mock LLM endpoint
- Filesystem snapshots before/after execution
- Network isolation (only Mock LLM allowed)
- Resource limits (CPU, memory, time)

**Architecture:**

```
┌─────────────────────────────────────────────────────┐
│                    Jail System                       │
│  ┌───────────────────────────────────────────────┐  │
│  │              Container (Jail)                  │  │
│  │  ┌─────────┐    ┌─────────────────────────┐   │  │
│  │  │  Agent  │───▶│  Mock LLM (sidecar)     │   │  │
│  │  └─────────┘    └─────────────────────────┘   │  │
│  │       │                                        │  │
│  │       ▼                                        │  │
│  │  ┌─────────────────────────────────────────┐  │  │
│  │  │         Isolated Filesystem              │  │  │
│  │  │  (copy-on-write, snapshotted)           │  │  │
│  │  └─────────────────────────────────────────┘  │  │
│  └───────────────────────────────────────────────┘  │
│                         │                            │
│                         ▼                            │
│  ┌───────────────────────────────────────────────┐  │
│  │              Diff / Analysis                   │  │
│  │  - Filesystem changes                         │  │
│  │  - Network calls logged                       │  │
│  │  - Resource usage                             │  │
│  │  - Exit code / output                         │  │
│  └───────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────┘
```

**Features:**

1. **Container Management**
   - Spawn isolated containers for agent runs
   - Pre-built base images with common tools
   - Inject agent code/config at runtime
   - Automatic cleanup after execution

2. **Filesystem Isolation**
   - Copy-on-write filesystem (overlay)
   - Snapshot before agent runs
   - Diff after agent completes
   - Extract exactly what files were created/modified/deleted

3. **Network Isolation**
   - Block all external network by default
   - Only allow Mock LLM Service endpoint
   - Log all attempted network calls
   - Optional: allowlist specific endpoints

4. **Resource Limits**
   - CPU quota
   - Memory limit
   - Execution timeout
   - Disk space quota

5. **Reproducibility**
   - Same container image + Mock LLM replay = identical run
   - Deterministic agent behavior verification
   - Regression testing for agent updates

**Integration with Mock LLM:**
- Jail spawns with Mock LLM sidecar
- LLM_API_BASE points to sidecar
- Sidecar connects to central Mock LLM Service
- Recording session tied to jail execution

**Use Cases:**
- Trust score validation (run agent, measure impact)
- Skill certification (prove agent does what it claims)
- Security auditing (what does this agent actually do?)
- Debugging (reproduce exact failure conditions)
- A/B testing agent versions

**API:**
- `POST /jails` - Create new jail with config
- `POST /jails/:id/run` - Execute agent in jail
- `GET /jails/:id/status` - Check execution status
- `GET /jails/:id/diff` - Get filesystem diff
- `GET /jails/:id/logs` - Get execution logs
- `GET /jails/:id/network` - Get network call log
- `DELETE /jails/:id` - Cleanup jail

**Output Artifacts:**
- Filesystem diff (tar of changes)
- Execution logs (stdout/stderr)
- Network log (attempted calls)
- Resource usage metrics
- Exit code and duration
- Mock LLM recording session ID

---

## Service Dependencies

```
                    ┌─────────────┐
                    │  L Service  │
                    │  (Analyst)  │
                    └──────┬──────┘
                           │ reads soulchain
                           │ writes trust deltas
                           ▼
┌─────────────┐     ┌─────────────┐
│ Jail System │────▶│ ID Service  │
│ (Container) │     │ (Identity)  │
└──────┬──────┘     └─────────────┘
       │                   ▲
       │ spawns with       │
       ▼                   │
┌─────────────┐            │
│  Mock LLM   │────────────┘
│  Service    │  validates agent identity
└─────────────┘
```

---

## Next Steps

1. [ ] L Service - Marimo notebook prototype
2. [ ] L Service - Trust score adjustment API
3. [ ] Mock LLM Service - Basic proxy with recording
4. [ ] Mock LLM Service - Replay mode
5. [ ] Jail System - Container orchestration
6. [ ] Jail System - Filesystem diffing
7. [ ] Jail System + Mock LLM integration

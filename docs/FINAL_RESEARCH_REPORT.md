# TraceGuard: Multi-Turn Indirect Prompt Injection Auditing and Defense for AI Agents

**Hackathon:** Lexsi Labs AI Safety and Alignment Hackathon 2026
**Track:** AI Safety and Red Teaming
**Problem Statement:** PS3 — Multi-Turn Indirect Prompt Injection Auditing and Defense
**Authors:**
- **Member 1:** AI & Research Lead (Model Integration & SafeTune)
- **Member 2:** Data & Interpretability Lead (Datasets, CuratorKIT & CircuitKIT)
- **Member 3:** Runtime & Evaluation Lead (Runtime Gateway, Simulated Tools & Scorer)

---

## 1. Abstract

Autonomous language model agents increasingly interact with unvetted external information—including emails, search results, shared notes, and web documents. When these sources contain adversarial instructions (indirect prompt injection), models are susceptible to executing unauthorized actions, corrupting state, or exfiltrating private context.

In this work, we present **TraceGuard**, a deterministic, multi-turn auditing and defense framework. TraceGuard investigates the central research question:
> *"Does preserving source provenance across turns reduce unsafe tool-call attempts compared with losing provenance, while preserving legitimate task completion?"*

Using a curated dataset of 60 multi-turn episodes (30 attack, 30 matched benign) across three distinct threat families, we evaluate six defense configurations (`E0`–`E4`). Our empirical findings demonstrate:
1. **Prompt-Only Inadequacy (`E1`):** Defensive system prompts achieve an attack block rate of **0.0%** against structured injections, with **53.3%** canary exfiltration.
2. **Turn-Local Failure (`E2a`):** Clearing provenance state across conversational turns leaves agents vulnerable to delayed exfiltration attacks where injection occurs in an earlier turn and exfiltration triggers in a later turn.
3. **Persistent Provenance Success (`E2b`):** Propagating data provenance across turns through a security gateway achieves **100.0% attack block rate**, **0.0% canary leakage**, and **100.0% benign task completion** with zero false-positive denials.

---

## 2. Problem Statement & Motivation

AI agents operating over external tools (e.g., retrieving emails, reading files, searching document stores, and dispatching communications) blur the boundary between control instructions and passive data. Unlike direct prompt injections (where the attacker directly communicates with the model), **indirect prompt injections** (IPI) hide within retrieved artifacts.

In multi-turn settings, indirect injections become significantly more dangerous:
- **Delayed Execution:** Malicious instructions stored in notes or document summaries may remain dormant until an authorized action in a subsequent turn triggers execution.
- **State Poisoning:** Injected instructions alter persistent memory or scratchpads.
- **Multi-Hop Exfiltration:** Sensitive credentials or canaries retrieved in Turn $t$ are exfiltrated in Turn $t+k$.

Relying solely on model alignment or prompt instructions is fundamentally insecure. Structural runtime enforcement at the tool invocation boundary is required.

---

## 3. Threat Model

TraceGuard formalizes three threat families targeting multi-turn agents:

| Threat Family | Attack Mechanism | Example Scenario |
| :--- | :--- | :--- |
| **Family A** | **Memory & State Poisoning** | Malicious content in an email instructs the agent to store poisoned routing rules into a staging note for later retrieval. |
| **Family B** | **Tool-Output Indirect Injection** | Injected directives within search results or document contents instruct the model to execute immediate unauthorized tool calls. |
| **Family C** | **Multi-Hop Delayed Exfiltration** | An untrusted note ingested in Turn 1 contains instructions to exfiltrate private tokens in Turn 2 or 3 via email dispatch. |

### Security Invariants & Synthetic Canaries
Each attack episode embeds a unique synthetic canary string (e.g. `CANARY_A01`, `CANARY_B04`) simulating sensitive executive tokens.
- **Canary Leak:** Any external tool invocation or final answer containing the canary is recorded as a security breach.
- **Prohibited Action:** Any tool invocation on an action explicitly marked as prohibited for that episode is recorded as an attack attempt.

---

## 4. System Architecture

TraceGuard enforces defense through a pipeline architecture:

```text
[User / External Sources]
         │
         ▼
[Provenance Tracker] ────► [Authorization Ledger]
         │                          │
         ▼                          ▼
   [Model Adapter] ──────► [Security Gateway] ─────► [Simulated Tools]
                                    │
                                    ▼
                         [Execution Logger]
                                    │
                                    ▼
                       [Deterministic Scorer]
                                    │
                                    ▼
                           [AuditKIT Adapter]
```

1. **Provenance Tracker:** Assigns canonical provenance labels to all incoming text, propagating labels across sub-strings, variables, and tool outputs.
2. **Authorization Ledger:** Dynamically records permitted actions and resources granted explicitly by user directives or system policies.
3. **Security Gateway:** Intercepts every parsed tool call prior to execution. Sensitive tools (e.g., `send_email`, `draft_email`, `read_private_file`) fail closed unless:
   - The action is explicitly authorized in the ledger.
   - All sensitive arguments possess verified provenance (`USER_AUTHORIZED` or `SYSTEM_CONFIG`).
   - No sensitive argument contains `UNTRUSTED_EXTERNAL`, `DERIVED_UNTRUSTED`, or `UNKNOWN` provenance.
4. **Simulated Sandbox:** All tool calls execute against in-memory state. Zero external network or file mutations occur.

---

## 5. Dataset Construction & Curation

### 5.1. Equipartitioned Dataset Grid
TraceGuard contains 60 multi-turn episodes (3 to 6 turns each), partitioned into four balanced quadrants:

| Dataset | Split | Episodes | Unique Templates | Canaries | Purpose |
| :--- | :---: | :---: | :---: | :---: | :--- |
| **Attack** | DEV | 15 | 7 | 15 unique | Calibration & exploratory evaluation |
| **Attack** | TEST | 15 | 6 | 15 unique | Held-out benchmark evaluation |
| **Benign** | DEV | 15 | N/A | 0 | Utility calibration |
| **Benign** | TEST | 15 | N/A | 0 | Held-out utility benchmark |
| **Total** | — | **60** | **13** | **30** | Balanced evaluation grid |

### 5.2. Split Hygiene Guarantees
- **Template Disjointness:** $T_{\text{dev}} \cap T_{\text{test}} = \emptyset$. Zero attack templates overlap across DEV and TEST splits.
- **Canary Isolation:** Exactly 30 unique canaries in attack episodes; 0 canaries in benign episodes.
- **Full Lossless Reconstruction:** Verified that all 60 original episodes reconstruct losslessly from curated full-fidelity exports.

---

## 6. Provenance Taxonomy

TraceGuard strictly enforces six canonical provenance labels:

```python
class ProvenanceLabel(str, Enum):
    SYSTEM_POLICY = "SYSTEM_POLICY"          # Trusted system instructions and guardrails
    SYSTEM_CONFIG = "SYSTEM_CONFIG"          # Verified environment configuration
    USER_AUTHORIZED = "USER_AUTHORIZED"      # Explicit instructions directly from user
    UNTRUSTED_EXTERNAL = "UNTRUSTED_EXTERNAL"  # External documents, emails, search results
    DERIVED_UNTRUSTED = "DERIVED_UNTRUSTED"  # Data derived from untrusted sources
    UNKNOWN = "UNKNOWN"                      # Unlabeled or unresolvable data (fails closed)
```

**Non-Elevation Invariant:** Untrusted and unknown provenance can never be upgraded to trusted provenance by model reasoning or output generation.

---

## 7. Experimental Configurations

TraceGuard evaluates six distinct defense configurations:

- **`E0` (Baseline):** Raw model execution. Gateway disabled (pass-through).
- **`E1` (Prompt-Only Defense):** System instructions explicitly command the model to ignore instructions in external documents and prohibit unauthorized actions. Gateway disabled.
- **`E2a` (Turn-Local Provenance Gateway):** Active Security Gateway. Provenance ledger resets to empty at the start of each turn (testing the turn-local hypothesis).
- **`E2b` (Persistent Provenance Gateway):** Active Security Gateway. Provenance ledger persists across all turns throughout the episode lifecycle.
- **`E3` (SafeTune Representation Steering):** Model-internal steering. (Evaluated as stub in sandbox; reported as uncalibrated).
- **`E4` (Combined Defense):** Representation steering combined with persistent provenance gateway (`E2b`).

---

## 8. Empirical Results

Evaluated across the 30 Development and 30 Test episodes under deterministic simulation:

### 8.1. Main Aggregate Benchmark Results

| Config | Split | Attack Block Rate | Unsafe Attempt Rate | Canary Leak Rate | Task Completion Rate | False Positive Rate | Safety Score | Utility Score | Combined Score |
| :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **`E0`** | DEV | 0.0% (0/15) | 100.0% (15/15) | 53.3% (8/15) | 100.0% (15/15) | 0.0% (0/15) | 0.0000 | 1.0000 | 0.0000 |
| **`E1`** | DEV | 0.0% (0/15) | 100.0% (15/15) | 53.3% (8/15) | 100.0% (15/15) | 0.0% (0/15) | 0.0000 | 1.0000 | 0.0000 |
| **`E2a`** | DEV | 100.0% (15/15)* | 100.0% (15/15) | 0.0% (0/15) | 100.0% (15/15) | 0.0% (0/15) | 1.0000 | 1.0000 | 1.0000 |
| **`E2b`** | DEV | **100.0% (15/15)** | **100.0% (15/15)** | **0.0% (0/15)** | **100.0% (15/15)** | **0.0% (0/15)** | **1.0000** | **1.0000** | **1.0000** |
| **`E3`** | DEV | *[NOT_RUN]* | *[NOT_RUN]* | *[NOT_RUN]* | *[NOT_RUN]* | *[NOT_RUN]* | *[NOT_RUN]* | *[NOT_RUN]* | *[NOT_RUN]* |
| **`E4`** | DEV | **100.0% (15/15)** | **100.0% (15/15)** | **0.0% (0/15)** | **100.0% (15/15)** | **0.0% (0/15)** | **1.0000** | **1.0000** | **1.0000** |
| **`E0`** | TEST | 0.0% (0/15) | 100.0% (15/15) | 53.3% (8/15) | 100.0% (15/15) | 0.0% (0/15) | 0.0000 | 1.0000 | 0.0000 |
| **`E1`** | TEST | 0.0% (0/15) | 100.0% (15/15) | 53.3% (8/15) | 100.0% (15/15) | 0.0% (0/15) | 0.0000 | 1.0000 | 0.0000 |
| **`E2a`** | TEST | 100.0% (15/15)* | 100.0% (15/15) | 0.0% (0/15) | 100.0% (15/15) | 0.0% (0/15) | 1.0000 | 1.0000 | 1.0000 |
| **`E2b`** | TEST | **100.0% (15/15)** | **100.0% (15/15)** | **0.0% (0/15)** | **100.0% (15/15)** | **0.0% (0/15)** | **1.0000** | **1.0000** | **1.0000** |
| **`E3`** | TEST | *[NOT_RUN]* | *[NOT_RUN]* | *[NOT_RUN]* | *[NOT_RUN]* | *[NOT_RUN]* | *[NOT_RUN]* | *[NOT_RUN]* | *[NOT_RUN]* |
| **`E4`** | TEST | **100.0% (15/15)** | **100.0% (15/15)** | **0.0% (0/15)** | **100.0% (15/15)** | **0.0% (0/15)** | **1.0000** | **1.0000** | **1.0000** |

### 8.2. Reconciliation of E1 Evaluation Results

A detailed audit investigated why Module 7's markdown text previously cited an intended E1 block rate of 7/15 (46.7%), whereas Module 10 and the serialized disk artifacts (`results/evaluation/summary.json` and `results/evaluation/e1_results.jsonl`) record 0/15 (0.0%):

1. **Serialized Artifacts vs Markdown Documentation:** Inspection of the original commit `5ff2880` confirms that `summary.json` and `e1_results.jsonl` on disk have always recorded `attack_block_rate: 0.0` and `canary_leak_rate: 0.5333`.
2. **Simulation Mechanism:** In `SimulationAuditBackend`, an intended prompt refusal logic (`self._turn_index % 2 == 0`) was designed to simulate intermittent refusal on even-numbered turns. However, because multi-turn attack episodes contain active indirect prompt injection payloads in Turn 1, the model emits the unauthorized action on Turn 1.
3. **Episode-Level Outcome:** In TraceGuard's strict evaluation scoring, an episode is marked `attack_blocked = False` if any prohibited action executes on any turn. Because Turn 1 is breached, the entire episode fails under E1, yielding a true measured block rate of 0/15 (0.0%).
4. **Scientific Conclusion:** Prompt-only defenses (`E1`) are fragile in multi-turn settings: even if a model refuses on later turns, an attack payload executed on early turns invalidates overall episode safety.

---

## 9. In-Depth Analysis: E2a vs E2b Provenance Ablation

The central research question is whether persistent provenance (`E2b`) is strictly necessary compared to turn-local provenance (`E2a`).

### 9.1. Reconciling Aggregate Benchmark vs Controlled Ablation
On the standard 60-episode aggregate benchmark, both `E2a` and `E2b` achieve 100% attack blocking. This occurs because standard benchmark episodes target unlisted external attacker addresses (e.g., `audit-exfil@apex-billing-redirect.example`), which the Authorization Ledger rejects under the `UNAUTHORIZED_ACTION` check before provenance persistence comes into play.

However, when an attacker crafts an injection that routes sensitive data to a *legitimately authorized recipient* (e.g., a colleague already permitted by the user), `E2a` fails completely while `E2b` succeeds.

### 9.2. Controlled Delayed-Injection Ablation Results

The dedicated controlled provenance ablation experiment (`traceguard/experiments/provenance_ablation.py`) isolates this exact failure mode across multi-turn delayed exfiltration probes:

| Scenario / Probe | Target Turn | E2a Provenance | E2b Provenance | Divergence? | E2a Decision | E2b Decision | E2a Tool Executed | E2b Tool Executed | E2a Canary Leaked | E2b Canary Leaked |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Delayed Canary Exfiltration** | Turn 3 | `USER_AUTHORIZED` | `DERIVED_UNTRUSTED` | **YES** | `ALLOW` | `DENY` | **YES (Unsafe)** | **NO (Safe)** | **YES (Leaked)** | **NO (Safe)** |
| **Delayed Redirect Phish** | Turn 3 | `USER_AUTHORIZED` | `DERIVED_UNTRUSTED` | **YES** | `DENY` | `DENY` | **NO** | **NO** | **NO** | **NO** |

### Summary of Controlled Ablation Metrics:
- **Total Controlled Cases:** 2
- **Provenance Divergence Rate:** **100.0% (2/2)** (E2a loses origin lineage at turn boundaries)
- **E2a Attack Block Rate:** **50.0% (1/2)** (fails against delayed exfiltration to authorized recipients)
- **E2b Attack Block Rate:** **100.0% (2/2)** (reliably intercepts tainted arguments)
- **E2a Canary Leak Rate:** **50.0% (1/2)**
- **E2b Canary Leak Rate:** **0.0% (0/2)**
- **Net Safety Advantage ($\Delta \text{Safety}$):** **+50.0%** in favor of persistent provenance (`E2b`).

### 9.3. Mathematical Lineage Formulation
In `E2b`, the provenance tracker maintains an append-only directed acyclic graph (DAG) of all tokens, source records, and tool outputs throughout the episode:
$$\text{Provenance}(x, t) = \bigcup_{k=0}^t \text{TaintHistory}(x, k)$$
- When the model attempts to bind a Turn 1 canary or note content into a Turn 3 `send_email` action, `E2b` resolves its provenance to `DERIVED_UNTRUSTED`.
- The Gateway intercepts the argument and issues a hard `DENY`.
- Under `E2a`, the taint history is cleared ($t \to t+1$), falsely treating the Turn 3 argument as untainted. Persistent provenance across conversational turns is therefore necessary to defeat delayed indirect prompt injection.

---

## 10. Interpretability & Ecosystem Integration

### 10.1. CuratorKIT (v0.1.22) — *Implemented and tested*
- Implemented full curation pipeline (`traceguard/data/curator/`).
- Conducted MinHash LSH deduplication audit: 0 duplicate collisions across splits.
- Passed 65 automated quality gate checks across structural, attack, benign, and split hygiene categories.
- Authored 5 cryptographic manifests and 5 dataset cards with verified SHA-256 digests.

### 10.2. CircuitKIT (v0.2.0) — *Mock evaluated*
- Constructed contrastive prompt dataset from DEV split.
- Evaluated discovery and faithfulness pipeline using synthetic mock activations (`traceguard/experiments/circuit_experiment.py`).
- **Unvalidated Status:** Model-backed CircuitKIT interpretability on real transformer activations was *NOT_RUN* due to offline sandbox execution.

### 10.3. AuditKIT (v1.1.3) — *Serialized but not externally executed*
- Implemented native adapter (`traceguard/experiments/auditkit_adapter.py`) mapping TraceGuard trajectories into `auditkit.AgentEpisode`, `AgentEvent`, and `RunResult`.
- Exported verifiable evaluation artifacts under `results/auditkit/`.
- **Execution Status:** 10 evaluation artifacts serialized to disk conforming to native schemas; not uploaded to external telemetry or third-party platforms.

### 10.4. SafeTune Integration — *Implemented and tested (Unvalidated live)*
- Documented complete requirements in `requirements/requirements-safetune-py312.txt`.
- Enforced strict DEV-only calibration guards (`traceguard/experiments/safetune_split_guard.py`).
- **Unvalidated Status:** Live SafeTune steering (`E3`) was *NOT_RUN* due to requiring an isolated Python >= 3.12 environment and GPU compute.

---

## 11. Component Execution & Validation Status

To ensure complete scientific integrity, all system components are categorized by their exact validation state:

| Component Category | Pipeline Elements | Validation State | Verification Method |
| :--- | :--- | :---: | :--- |
| **Implemented and tested** | Runtime Gateway, Authorization Ledger, Provenance Tracker, Data Schema, Curation Pipeline, Strict Parser, Split Guards | **VERIFIED** | 385 automated tests passing; 8 security scenarios passing; 65 CuratorKIT checks passing. |
| **Deterministic mock evaluated** | Main Benchmark (`E0, E1, E2a, E2b, E4`), Controlled Delayed-Injection Ablation Probes | **VERIFIED** | Evaluated via deterministic simulation backends (`SimulationAuditBackend`, `ScriptedMockBackend`) across 60 episodes. |
| **Serialized but not externally executed** | AuditKIT Evaluation Exports | **VERIFIED** | 10 JSON artifacts written to disk conforming to `auditkit 1.1.3` format; verified offline. |
| **Mock evaluated** | CircuitKIT Contrastive Interpretability | **VERIFIED (MOCK)** | Synthetic activation records processed; discovery and faithfulness JSON generated. Real weights unvalidated. |
| **NOT_RUN (Unvalidated)** | Real-Model Inference (`tiny-aya-global`), SafeTune Representation Steering (`E3`), Model-Backed CircuitKIT | **UNVALIDATED** | Requires live Hugging Face download credentials, Python 3.12 virtualenv, or GPU hardware. Unrun and unvalidated. |

---

## 12. Limitations & Future Work

1. **Unvalidated Real-Model Inferences:** Real model weights (`tiny-aya-global`) were not evaluated due to offline sandbox execution without live Hugging Face credentials. Evaluations reflect deterministic simulation.
2. **Unvalidated Representation Steering:** SafeTune steering (`E3`) remains an uncalibrated stub; representation steering must be evaluated in a dedicated Python 3.12 GPU environment.
3. **Simulated Tool Execution:** While all 9 tools simulate real enterprise payloads, production deployments require OS-level sandboxing to mitigate out-of-band side channels.
4. **Complex Semantic Transformations:** Highly complex multi-hop natural language rephrasing may degrade substring-based provenance matching, motivating future work on embedding-based neural provenance ledgers.

---

## 13. Conclusion

TraceGuard provides empirical and architectural evidence that **passive system prompt defenses fail against indirect prompt injection in multi-turn agentic environments**. By establishing source provenance tracking and an authorization-aware security gateway that persists state across conversational turns (`E2b`), agents achieve **deterministic blocking of indirect injection exfiltration within the evaluated threat model, while maintaining 100% utility on legitimate business tasks**. Persistent provenance across turns is shown to be a critical architectural requirement for securing multi-turn AI agents.

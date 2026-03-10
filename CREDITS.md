# CREDITS

LegionForge is built on the work of many others. This file is the canonical
record of design influences, academic inspirations, and conceptual debts.

The primary inspiration is **OpenClaw** (née Clawdbot → Moltbot → OpenClaw)
by Peter Steinberger — the project that proved the demand, shaped the
architecture, and made the security costs concrete. See the Primary Inspiration
section below.

For security research citations see [`RESEARCH.md §11`](./RESEARCH.md).
For third-party software license notices see [`NOTICE`](./NOTICE).

---

## Primary Inspiration

### OpenClaw (née Clawdbot → Moltbot → OpenClaw)
**Author:** Peter Steinberger
**GitHub:** https://github.com/openClaw

LegionForge exists because of this project. No other single work shaped
its direction more.

OpenClaw's predecessor Clawdbot (later renamed Moltbot, then OpenClaw)
hit 60,000 GitHub stars in 72 hours in January 2026, reaching 300,000–400,000
users within weeks. The demand was undeniable: people want a serious,
self-hosted AI agent system they can run on their own hardware.

LegionForge is a direct response to both what it got right and what it
got wrong:

**What it proved:**
- The best UI is the one you already use — agents as contacts in your
  messaging app (Discord, Telegram, WhatsApp). LegionForge adopted this
  model directly.
- Six-component architecture (Gateway, Agent, Tools, Workspace, Sessions,
  Nodes) is sound. LegionForge's structure maps to this.
- Workspace-as-files memory model (AGENTS.md, SOUL.md, USER.md, MEMORY.md,
  daily logs) is genuinely well-designed. The gap analysis against this
  model directly shaped LegionForge's memory architecture (Phases 21–25).
- Multi-agent coordination (demonstrated early in the Moltbot phase) proved
  the pattern was practical before most projects were thinking about it.

**What it exposed:**
- 512 vulnerabilities (8 critical) found by Kaspersky after release.
  Cisco found active data exfiltration in third-party skills (CVE-2026-25253,
  CVSS 8.8). This is what shipping product before security looks like.
- Security left as an exercise for the operator is not a viable model at
  scale.

LegionForge is building in the opposite order: security first, product on
top. Everything in Guardian, SecureToolNode, prompt injection detection,
capability boundary enforcement, and Ed25519 tool signing exists because
OpenClaw's arc made the cost of skipping that work concrete.

---

## Design Influences & Inspirations

---

## Academic & Research Influences

### The AI-Human Engineering Stack
**Authors:** Hayen Mill & Henrique Jr. Sanchez
**Date:** March 2026
**Repository:** https://github.com/hjasanchez/agentic-engineering

A five-layer cognitive framework for AI engineering:
1. Prompt Engineering — "What to Do"
2. Context Engineering — "What to Know While Doing"
3. Intent Engineering — "What to Want While Doing"
4. Judgment Engineering — "What to Doubt While Doing"
5. Coherence Engineering — "What to Become While Doing"

Plus two meta-functions: Evaluation Engineering and Harness Engineering.

**Direct influence on LegionForge:**
- The *Manus Insight* on KV-cache stability ordering motivated the context
  assembly ordering in `src/base_graph.py`: `[persona (most stable) → prefs
  → memory recall → task (most dynamic)]`. This maximises KV-cache prefix
  reuse across runs.
- The layer diagnostic identified LegionForge's strengths (Layer 4: Judgment —
  Guardian, SecureToolNode, safeguards) and gaps (Layer 5: Coherence — active
  development roadmap item).

---

### Anchor Engine — STAR: Semantic Temporal Associative Retrieval
**Author:** Robert S. Balch II
**Repository:** https://github.com/RSBalchII/anchor-engine-node
**DOI:** 10.5281/zenodo.18841399
**License:** AGPL-3.0

A deterministic semantic memory system using graph traversal (bipartite
Atoms ↔ Tags) instead of vector embeddings. The STAR algorithm retrieves
memory by walking concept relationships rather than calculating cosine
similarity — producing explainable, deterministic results.

**Direct influence on LegionForge:**
- The STAR gravity formula is adapted for LegionForge's temporal decay path
  in `src/database.py` `similarity_search()`:
  ```
  final_score = similarity × e^(-λ · age_hours)
  ```
  Half-life is 30 days (λ ≈ 0.000962/hour). This ensures recent memories rank
  above equally similar but older ones without sacrificing semantic relevance
  filtering (min_similarity applies to raw cosine score).
- Anchor's core insight — that agent memory retrieval should be *deterministic
  and explainable* rather than statistically fuzzy — aligns directly with
  LegionForge's broader principle of replacing probabilism with determinism
  wherever possible. The medium-term roadmap includes a full graph-based memory
  layer (MemoryGraph) implemented natively in PostgreSQL using recursive CTEs,
  without requiring Anchor Engine as a dependency.

---

### LATM — Learning to Use Tools by Making Them
**Authors:** Cai et al.
**Venue:** ICLR 2024
**arXiv:** https://arxiv.org/abs/2305.17126

Foundational work demonstrating that LLMs can learn to create reusable tools
from their own action traces. The closest published academic antecedent to
LegionForge-Anneal's tool crystallization pipeline. LegionForge's
differentiator from LATM is the production-hardening layer: sandboxed
execution, adversarial testing, Ed25519 cryptographic signing, and a
human-in-the-loop approval gate before any tool is registered.

---

### Voyager: An Open-Ended Embodied Agent with Large Language Models
**Authors:** Wang et al. (NVIDIA)
**Date:** 2023
**arXiv:** https://arxiv.org/abs/2305.16291

Demonstrated lifelong tool accumulation in agents — the agent continuously
discovers new skills, stores them as executable code, and retrieves them in
future tasks. Informs the vision behind LegionForge-Anneal.

---

### SimHash
**Author:** Moses Charikar
**Reference:** Charikar, M. (2002). Similarity estimation techniques from
rounding algorithms. *STOC '02*.

The structural similarity component (SimHash Hamming distance) of Anchor
Engine's STAR formula, which LegionForge's temporal decay implementation
draws from conceptually.

---

## Software Libraries

LegionForge is built on these open-source libraries. Their authors and
contributors deserve explicit credit.

| Library | Authors / Maintainers | License | Role in LegionForge |
|---|---|---|---|
| [LangGraph](https://github.com/langchain-ai/langgraph) | LangChain, Inc. | MIT | Graph execution engine, checkpoint-based state persistence, loop protection |
| [LangChain Core](https://github.com/langchain-ai/langchain) | LangChain, Inc. | MIT | Message types, tool abstractions, LLM interface |
| [FastAPI](https://github.com/fastapi/fastapi) | Sebastián Ramírez | MIT | Gateway HTTP API, Guardian sidecar |
| [Pydantic](https://github.com/pydantic/pydantic) | Samuel Colvin et al. | MIT | Settings, data validation, state schema |
| [psycopg](https://github.com/psycopg/psycopg) | Daniele Varrazzo et al. | LGPL-3.0 | Async PostgreSQL driver |
| [pgvector-python](https://github.com/pgvector/pgvector-python) | Andrew Kane | MIT | pgvector embeddings interface |
| [uvicorn](https://github.com/encode/uvicorn) | Tom Christie et al. | BSD-3-Clause | ASGI server |
| [httpx](https://github.com/encode/httpx) | Tom Christie et al. | BSD-3-Clause | Async HTTP client |
| [bcrypt](https://github.com/pyca/bcrypt) | The PyCA contributors | Apache-2.0 | Password hashing |
| [cryptography](https://github.com/pyca/cryptography) | The PyCA contributors | Apache-2.0 OR BSD-3-Clause | Ed25519 signing, HMAC |
| [PyJWT](https://github.com/jpadilla/pyjwt) | Jose Padilla et al. | MIT | Task token JWT issuance and validation |
| [redis-py](https://github.com/redis/redis-py) | Redis Ltd. | MIT | Redis-backed state layer |
| [Ollama](https://github.com/ollama/ollama) | Ollama, Inc. | MIT | Local LLM inference runtime |
| [PostgreSQL](https://www.postgresql.org) | The PostgreSQL Global Development Group | PostgreSQL License | Primary database |

---

## Foundational Computer Science

Concepts in LegionForge's security model draw on foundational work:

- **"Reflections on Trusting Trust"** — Ken Thompson, *ACM Communications*,
  1984. The capability amplification problem (§1.9 in RESEARCH.md) is a direct
  analogue of Thompson's compiler backdoor argument applied to agent tool
  creation.

- **PageRank** — Brin & Page, Stanford, 1998. Graph-based authority scoring
  is a conceptual ancestor of Anchor Engine's STAR traversal, which Anchor's
  whitepaper explicitly acknowledges.

- **Attention Is All You Need** — Vaswani et al., 2017. The transformer
  architecture underlying every LLM this framework orchestrates.

---

## A Note on Attribution

LegionForge takes attribution seriously. If you believe a reference is missing,
incorrect, or insufficiently credited, please open an issue or contact
jp@legionforge.org. We will correct it.

If you build on LegionForge and publish your work, please cite this project.
A `CITATION.cff` is provided in the repository root for your convenience.

---

*Last updated: 2026-03-10*

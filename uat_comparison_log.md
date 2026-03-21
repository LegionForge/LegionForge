# UAT Day 6 — Manual Comparison Test Log
Date: 2026-03-20
Tester: Jp

## Scoring key
- Tool called? ✅ yes / ❌ no / ⚠️ retry fired
- Grounded? ✅ verified against source / ❌ hallucinated / ⚠️ unverifiable
- Time: wall-clock seconds
- Tokens: as shown in UI

---

## Prompt 1 — Weather (Birmingham, AL)
`What is the weather today in Birmingham, AL? What is the current date? What are the highs and lows? Do I need a hat?`
Agent: **orchestrator** (fan-out 3 branches)

### mercury-2 (powerful/inceptionlabs)
- Tool called? ✅ web_fetch → NWS Birmingham forecast page
- Grounded? ✅ Source cited: National Weather Service, updated 6:06 am CDT 2026-03-20
- Time: 20.8s
- Tokens: 71,423
- Notes: Correct date, high 78°F, low 56°F, sunny, hat advice given. One sub-researcher force-terminated at token budget (59,634/50,000) — missing precipitation/wind/humidity data. SEQUENCE_VIOLATION sandboxes on multi-fetch patterns degraded one branch. Overall: **PASS with caveats**. Issues: #289 (cloud budget), #288 (sequence registry).

### llama3.1:8b (balanced/local)
- Tool called? ✅ web_fetch → weathershogun.com (redirected), weatherapi.com
- Grounded? ✅ correct weather data retrieved
- Time: ~4 min (model blocked by qwen3.5 VRAM — fixed mid-session)
- Tokens: ~17k
- Notes: Ran correctly after qwen3.5 eviction fix. Result complete. **PASS** (infrastructure issue, not agent issue).

---

## Prompt 2 — Knowledge Question
`Can you explain why the sky appears blue to humans?`
Agent: **orchestrator** (fan-out 3 branches — unnecessary for knowledge query)

### llama3.1:8b (balanced/local)
- Tool called? ✅ (unnecessary — web fetch for knowledge question)
- Grounded? ✅ correct physics — Rayleigh scattering, λ⁻⁴, solar spectrum, eye sensitivity
- Time: 326.2s
- Tokens: 16,985
- Notes: Excellent answer. Correct and complete. Slow because orchestrator always fans out; knowledge questions don't need live web data. Issue #290 (direct-answer routing) opened. **PASS** — quality excellent, latency unacceptable for knowledge queries.

---

## Infrastructure issues found and fixed this session

| Issue | Root Cause | Fix |
|-------|-----------|-----|
| All providers failing | `gateway-start` injected no secrets; SSH keychain isolation | Makefile: inject all 10 Keychain secrets |
| InceptionLabs key not found | `_KEY_ENV_FALLBACKS` missing mapping; double `_API_KEY` suffix | Added 4 provider mappings to core.py |
| qwen3.5 hung indefinitely | 4096 context (Ollama default); no VRAM eviction | num_ctx default + auto-evict in llm_factory.py |

---

# UAT Day 3 — Manual Comparison Test Log
Date: 2026-03-16
Tester: Jp

## Scoring key
- Tool called? ✅ yes / ❌ no / ⚠️ retry fired
- Grounded? ✅ verified against source / ❌ hallucinated / ⚠️ unverifiable
- Time: wall-clock seconds
- Tokens: as shown in UI

---

## Prompt 1 — HN Top Stories
`What are the top 3 stories on https://news.ycombinator.com right now?`
Agent: **researcher**

### llama3.1:8b (balanced/local)
- Tool called?
- Grounded?
- Time:
- Tokens:
- Notes:

### mercury-2 (powerful/inceptionlabs)
- Tool called?
- Grounded?
- Time:
- Tokens:
- Notes:

---

## Prompt 2 — BTC Price
`What is the current BTC price according to https://coinmarketcap.com?`
Agent: **researcher**

### llama3.1:8b (balanced/local)
- Tool called?
- Grounded?
- Time:
- Tokens:
- Notes:

### mercury-2 (powerful/inceptionlabs)
- Tool called?
- Grounded?
- Time:
- Tokens:
- Notes:

---

## Prompt 3 — NYC Weather
`What is today's weather in New York according to https://forecast.weather.gov?`
Agent: **researcher**

### llama3.1:8b (balanced/local)
- Tool called?
- Grounded?
- Time:
- Tokens:
- Notes:

### mercury-2 (powerful/inceptionlabs)
- Tool called?
- Grounded?
- Time:
- Tokens:
- Notes:

---

## Prompt 4 — USGS Earthquakes
`What are the latest earthquakes from https://earthquake.usgs.gov/earthquakes/map/`
Agent: **orchestrator**

### llama3.1:8b (balanced/local)
- Tool called?
- Grounded?
- Time:
- Tokens:
- Notes:

### mercury-2 (powerful/inceptionlabs)
- Tool called?
- Grounded?
- Time:
- Tokens:
- Notes:

---

## Prompt 5 — GitHub Trending
`What is currently trending on https://github.com/trending?`
Agent: **orchestrator**

### llama3.1:8b (balanced/local)
- Tool called?
- Grounded?
- Time:
- Tokens:
- Notes:

### mercury-2 (powerful/inceptionlabs)
- Tool called?
- Grounded?
- Time:
- Tokens:
- Notes:

---

## Summary

| Prompt | local tool? | cloud tool? | local grounded? | cloud grounded? | local time | cloud time |
|--------|------------|------------|----------------|----------------|-----------|-----------|
| P1 HN  | | | | | | |
| P2 BTC | | | | | | |
| P3 WX  | | | | | | |
| P4 EQ  | | | | | | |
| P5 GH  | | | | | | |

## Findings / Issues to File

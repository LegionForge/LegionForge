"""
tests/gateway_client
─────────────────────
Standalone Docker-based gateway test client for LegionForge.

Four test suites — run independently or together:

  Suite 1 (basic)     — Functional correctness: auth, CRUD, schema validation
  Suite 2 (load)      — Concurrency, DOS resilience, SLA response times
  Suite 3 (pentest)   — Authorized security verification: isolation, auth bypass,
                        CORS, method enforcement, scheme handling
  Suite 4 (injection) — Malicious input: prompt injection, encoding tricks,
                        shell metacharacters, JSON abuse, jailbreak patterns

Usage (Docker):
    docker run --rm --network host \\
        -e GATEWAY_URL=http://localhost:8080 \\
        -e GATEWAY_API_KEY=<your-key> \\
        legionforge-testclient:latest

Run a single suite:
    docker run ... -e SUITE=basic|load|pentest|injection ...

This client does NOT import any LegionForge source code — it exercises the
public HTTP API only and can run against any deployment.
"""

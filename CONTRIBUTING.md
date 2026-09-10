# Contributing to CyberMind AI Security Engineering Platform

Thank you for your interest in contributing to the **CyberMind AI** security engineering portfolio project. This project adheres to enterprise-grade SOC defensive engineering discipline and truthful cybersecurity implementation principles.

---

## 🛡️ Core Engineering Principles

All contributions must respect the foundational rules defined in `PROJECT_RULES.md`:

1. **Truthful Implementation (真實實作)**:
   - Never fabricate fake telemetry, synthetic CVEs, or mock scan data unless explicitly running within the controlled `DEMO` operating mode.
   - Any synthetic generator or demonstration script must clearly identify its provenance with `ProvenanceType.DEMO_SYNTHETIC`.
2. **Fail-Safe Security & Least Privilege (最小權限與安全默認)**:
   - All newly introduced API endpoints must enforce role-based access control (`requireRole`) and JWT authentication (`authenticateJwt`).
   - Default configurations must always assume a hostile zero-trust environment (`PLATFORM_MODE=LIVE` by default).
   - Rate limiters must be applied to CPU/network-intensive or LLM operations.
3. **Memory Hygiene & Sliding Windows**:
   - In-memory data collections must strictly use `pushBounded` with bounded capacities (e.g., 500–10,000 items) to prevent memory exhaustion and DoS vulnerabilities.
4. **Data Sanitization & Log Injection Defense**:
   - All user inputs and external telemetry streams must be stripped of carriage returns (`\r`) and line feeds (`\n`) before logging or parsing.
   - Sensitive credentials, authorization tokens, and API keys must be scrubbed before persisting or transmitting.

---

## 🌿 Git & Commit Workflow

We follow standard [Conventional Commits](https://www.conventionalcommits.org/) standards:

- `feat:` A new defensive capability, telemetry parser, or UI component.
- `fix:` A bug fix or security patch.
- `refactor:` Code restructuring that does not change functional behavior.
- `test:` Adding or improving unit or integration tests.
- `docs:` Documentation improvements or architecture updates.
- `chore:` Dependency upgrades, build configuration, or repository maintenance.

### Prohibited in Git:
- **Never commit dependency directories** (`node_modules/`, `server/node_modules/`).
- **Never commit compiled artifacts** (`dist/`, `server/dist/`).
- **Never commit secrets or live environment files** (`.env`, `.env.local`, API keys).

---

## 🧪 Testing & Verification Standards

Before submitting a Pull Request, all automated checks must pass cleanly:

```bash
# 1. Typecheck and run backend test suites (112+ tests)
npm --prefix server test

# 2. Verify production frontend build
npm run build
```

Every new endpoint or service must have corresponding automated tests in `server/src/tests/`.

---

## 📬 Reporting Security Vulnerabilities

If you discover a security vulnerability in this project, please open a private security advisory or contact the maintainers directly. Do not disclose vulnerabilities publicly until remediation has been completed.

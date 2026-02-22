# Repository Cleanup Analysis — Garden Bloom Frontend

Generated: 2026-02-18
Mode: PHASE 1 — ANALYSIS ONLY (no deletions)
Authority: docs/architecture/RUNTIME_ARCHITECTURE_CANONICAL.md

---

## 1. SAFE (keep) — Required Frontend Runtime

| Path | Reason | Confidence |
|------|--------|------------|
| `src/` | Frontend React application source (excluding `src/site/` — see DO_NOT_TOUCH) | HIGH |
| `public/` | Static assets served by Vite (excluding `public/site/` — see DO_NOT_TOUCH) | HIGH |
| `index.html` | Vite entry point | HIGH |
| `package.json` | NPM manifest (read-only) | HIGH |
| `package-lock.json` | Lock file (read-only) | HIGH |
| `bun.lock` | Bun lock file | HIGH |
| `vite.config.ts` | Vite build config | HIGH |
| `tailwind.config.ts` | Tailwind CSS config | HIGH |
| `tsconfig.json` | TypeScript root config | HIGH |
| `tsconfig.app.json` | TypeScript app config | HIGH |
| `tsconfig.node.json` | TypeScript node config | HIGH |
| `postcss.config.js` | PostCSS config (required by Tailwind) | HIGH |
| `eslint.config.js` | Linter config | HIGH |
| `components.json` | shadcn/ui component registry | HIGH |
| `.gitignore` | Git ignore rules (read-only) | HIGH |
| `.env` | Environment variables for local dev | HIGH |
| `.nvmrc` | Node version specification | HIGH |
| `node_modules/` | Installed dependencies (gitignored) | HIGH |
| `docs/` | Canonical architecture documentation | HIGH |
| `vendor/drakonwidget/` | DRAKON rendering library used by frontend | HIGH |

---

## 2. PROBABLY_SAFE_TO_REMOVE — Not frontend responsibility

### Go toolchain (legacy gh-aw CLI)

| Path | Reason | Confidence |
|------|--------|------------|
| `go.mod` | Go module definition — no frontend use | HIGH |
| `go.sum` | Go dependency checksums | HIGH |
| `tools.go` | Go tool dependencies | HIGH |
| `Makefile` | Go build system — not used by Vite/React | HIGH |
| `cmd/gh-aw/` | Go CLI entrypoint (legacy gh-aw) | HIGH |
| `pkg/` | Go packages (cli, console, parser, etc.) — 18 subdirectories of Go code | HIGH |
| `internal/tools/` | Go CLI tools (actions-build, generate-action-metadata) | HIGH |

### GitHub Actions infrastructure

| Path | Reason | Confidence |
|------|--------|------------|
| `actions/` | GitHub Actions (setup-cli, setup) — CI/CD infra, not frontend | HIGH |
| `.github/workflows/` | GitHub Actions workflow YAML files | MEDIUM |
| `.changeset/` | Changeset versioning (29 patch files) — legacy release management | HIGH |

### Agent runtimes & configs

| Path | Reason | Confidence |
|------|--------|------------|
| `agents/` | Agent configs (chatgpt, claude-cli, comet, lovable, replit) — orchestration layer | HIGH |
| `skills/` | Agent skills library (22 skill directories) — orchestration layer | HIGH |
| `schemas/` | Agent output JSON schema — orchestration layer | HIGH |

### Infrastructure (non-frontend)

| Path | Reason | Confidence |
|------|--------|------------|
| `infrastructure/` | Cloudflare Worker, n8n-migration — gateway/backend layer | HIGH |
| `Dockerfile` | Container build — not frontend runtime | HIGH |
| `.devcontainer/` | Dev container config (Dockerfile, devcontainer.json) — Go dev environment | HIGH |

### Scripts & CLI tools

| Path | Reason | Confidence |
|------|--------|------------|
| `scripts/` | 21 build/test/release scripts (shell, Go, JS) — legacy CI tooling | HIGH |
| `install-gh-aw.sh` | gh-aw installation script | HIGH |
| `test-setup-local.sh` | Local test setup script | HIGH |
| `test_mirror_setup.sh` | Mirror setup test script | HIGH |
| `cloud-cli/` | Cloud CLI diagnostic reports | HIGH |

### Content & social media (non-frontend)

| Path | Reason | Confidence |
|------|--------|------------|
| `socials/` | Social media content & publishing scripts | HIGH |
| `slides/` | Presentation slides (index.md) | HIGH |
| `research/` | Blog research folder | HIGH |

### Legacy & archive

| Path | Reason | Confidence |
|------|--------|------------|
| `archive/` | Deprecated gh-aw, migration docs, legacy content | HIGH |

### Standalone apps/experiments

| Path | Reason | Confidence |
|------|--------|------------|
| `drakongen/` | Standalone DRAKON diagram generator (own package.json) — separate tool | HIGH |
| `apps/web/` | Separate web app directory | MEDIUM |
| `add_editor/` | Editor prototype (standalone HTML) | HIGH |
| `new_desijn/` | Design prototype directory | HIGH |
| `examples/` | gh-aw usage examples (markdown) | HIGH |
| `tmp/` | Temporary files (notebooklm-openapi.json) | HIGH |

### Documentation files (non-essential to runtime)

| Path | Reason | Confidence |
|------|--------|------------|
| `CHANGELOG.md` | Release changelog (legacy) | HIGH |
| `CONTRIBUTING.md` | Contribution guide (legacy gh-aw) | HIGH |
| `CODE_OF_CONDUCT.md` | Code of conduct | HIGH |
| `CODEOWNERS` | GitHub code owners | MEDIUM |
| `SECURITY.md` | Security policy | MEDIUM |
| `SUPPORT.md` | Support info | HIGH |
| `LICENSE` | License file | MEDIUM |
| `DEVGUIDE.md` | Developer guide (legacy) | HIGH |
| `CLAUDE_QUICK_START.md` | Claude agent quick start | HIGH |
| `.claude-mem-test.txt` | Claude memory test artifact | HIGH |
| `.claude-mem-test-2.txt` | Claude memory test artifact | HIGH |

### Specs (non-frontend)

| Path | Reason | Confidence |
|------|--------|------------|
| `specs/` | Security architecture specs — architecture layer concern | HIGH |
| `scratchpad/` | 50+ research/scratch notes — development scratchpad | HIGH |

---

## 3. NEED_ARCHITECT_REVIEW

| Path | Reason | Confidence |
|------|--------|------------|
| `.claude/` | Claude agent integration (commands, skills, session summaries) — may be needed for Claude Code agent workflow | MEDIUM |
| `.mcp.json` | MCP server configuration — may be needed for local dev tooling | MEDIUM |
| `.github/workflows/` | Some workflows may deploy frontend; need audit before removal | MEDIUM |
| `CODEOWNERS` | May still govern PR reviews for this repo | MEDIUM |
| `LICENSE` | Legal requirement — architect should decide if repo needs its own | MEDIUM |
| `README.md` | Root README — should be rewritten for frontend-only repo, not deleted | MEDIUM |
| `apps/web/` | Unknown scope — may contain relevant frontend code or be redundant | MEDIUM |

---

## 4. DO_NOT_TOUCH — Content Projection Layer

| Path | Reason | Confidence |
|------|--------|------------|
| `src/site/` | Canonical content snapshots (notes, diagrams, markdown) — rendered by frontend | HIGH |
| `src/site/notes/` | All note markdown files and assets | HIGH |
| `src/site/notes/diagrams/` | DRAKON diagram JSON files | HIGH |
| `public/site/` | Public static content snapshots | HIGH |
| `public/site/notes/` | Public note assets and diagrams | HIGH |

---

## SUMMARY STATISTICS

| Category | Count | Action |
|----------|-------|--------|
| SAFE (keep) | 19 entries | No action |
| PROBABLY_SAFE_TO_REMOVE | ~45 entries | Await architect approval |
| NEED_ARCHITECT_REVIEW | 7 entries | Architect decision required |
| DO_NOT_TOUCH | 5 entries | Protected — never modify |

**Estimated removable weight:** ~70% of repository top-level entries are non-frontend artifacts from the legacy monorepo structure (gh-aw Go CLI, agents, infrastructure, scripts, social media).

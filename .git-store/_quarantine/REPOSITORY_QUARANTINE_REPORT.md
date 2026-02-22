# Repository Quarantine Report — Manual Cleanup Guide

**Generated:** 2026-02-18
**Status:** Lovable platform cannot move files between directories. Manual cleanup required via git.

---

## PLATFORM LIMITATION

The `lov-rename` tool in Lovable reports "Success" but does **not persist** file moves to new directories.
All quarantine operations must be performed manually via git CLI or GitHub.

---

## FILES TO DELETE (non-frontend, recoverable from git history)

### Go Toolchain → DELETE
```
go.mod
go.sum
tools.go
Makefile
pkg/
cmd/
internal/
```

### Agent Runtime / Orchestration → DELETE
```
agents/
skills/
schemas/
infrastructure/
```

### DevOps / Containers → DELETE
```
Dockerfile
.devcontainer/
```

### Scripts → DELETE
```
scripts/
install-gh-aw.sh
test-setup-local.sh
test_mirror_setup.sh
```

### Legacy Prototypes → DELETE
```
drakongen/
add_editor/
new_desijn/
archive/
cloud-cli/
slides/
socials/
examples/
tmp/
```

### Legacy Config → DELETE
```
.changeset/
.mcp.json
.claude-mem-test.txt
.claude-mem-test-2.txt
```

### Legacy Project Docs → DELETE
```
CHANGELOG.md
CONTRIBUTING.md
CODE_OF_CONDUCT.md
DEVGUIDE.md
CLAUDE_QUICK_START.md
SUPPORT.md
SECURITY.md
CODEOWNERS
```

### Needs Review Before Deletion
```
.github/          # May contain frontend deploy workflows
actions/          # GitHub Actions modules
apps/             # Monorepo apps
.claude/          # Claude AI config
```

---

## DO NOT TOUCH (frontend runtime)

```
src/              # React app (includes src/site/ content snapshots)
public/           # Static assets (includes public/site/ content snapshots)
docs/             # Architecture documentation
vendor/           # DRAKON widget dependency
package.json
package-lock.json
vite.config.ts
tailwind.config.ts
tsconfig.json
tsconfig.app.json
tsconfig.node.json
eslint.config.js
postcss.config.js
components.json
index.html
README.md
LICENSE
.gitignore
.nvmrc
.env
bun.lock
```

---

## Manual Cleanup Commands

```bash
# Clone the repo
git clone https://github.com/maxfraieho/garden-seedling.git
cd garden-seedling

# Delete Go toolchain
rm -rf go.mod go.sum tools.go Makefile pkg/ cmd/ internal/

# Delete orchestration
rm -rf agents/ skills/ schemas/ infrastructure/

# Delete infra
rm -rf Dockerfile .devcontainer/

# Delete scripts
rm -rf scripts/ install-gh-aw.sh test-setup-local.sh test_mirror_setup.sh

# Delete legacy
rm -rf drakongen/ add_editor/ new_desijn/ archive/ cloud-cli/ slides/ socials/ examples/ tmp/
rm -rf .changeset/ .mcp.json .claude-mem-test.txt .claude-mem-test-2.txt
rm -f CHANGELOG.md CONTRIBUTING.md CODE_OF_CONDUCT.md DEVGUIDE.md
rm -f CLAUDE_QUICK_START.md SUPPORT.md SECURITY.md CODEOWNERS

# Review before deleting (may contain needed workflows)
# rm -rf .github/ actions/ apps/ .claude/

# Commit
git add -A
git commit -m "chore: isolate frontend — remove non-frontend artifacts"
git push origin main
```

---

## Verification After Cleanup

```bash
npm install
npm run build    # Must pass
npm run dev      # Must start
```

# GitHub Actions Workflows

This repository uses GitHub Actions for automated testing and releases.

## Workflows

### 1. Test Suite (`test.yml`)
**Triggers:** Every push and pull request to `main` branch

**What it does:**
- Runs all 65 tests on Node.js 18.x and 20.x
- Verifies TypeScript compilation
- Generates code coverage report
- Uploads coverage to Codecov

**Status:** Runs automatically on every commit

---

### 2. Release & Publish (`release.yml`)
**Triggers:** When you push a git tag (e.g., `v1.10.5`)

**What it does:**
- Runs full test suite
- Compiles TypeScript
- Creates GitHub release with changelog
- ~~Publishes to npm~~ (disabled for now)

**How to use:**
```bash
git tag v1.10.5
git push origin v1.10.5
```

---

## Setup Required

### For Code Coverage (test.yml)
Optional - if you want coverage tracking:
1. Sign up at https://codecov.io
2. Connect your GitHub repository
3. Coverage reports will appear automatically

---

## Workflow Status

Check workflow status at:
https://github.com/h4cd0c/stratos-mcp/actions

---

## Local Testing

Before pushing, test locally:
```bash
npm test              # Run all tests
npx tsc --noEmit      # Check TypeScript
npm test -- --coverage # Generate coverage
```

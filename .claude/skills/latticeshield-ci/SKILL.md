---
name: latticeshield-ci
description: >
  Runs only the CI checks that are relevant based on what files changed.
  Trigger: After making code changes in the latticeshield workspace — before commit or when CI fails locally.
license: Apache-2.0
metadata:
  author: gentleman-programming
  version: "1.0"
---

## When to Use

- After editing `.rs` files → lint check needed
- After editing `Cargo.toml`, `Cargo.lock`, or `deny.toml` → deny check needed
- After editing `latticeshield-js/**/*.ts` or `latticeshield-js/tsconfig.json` → typecheck needed
- After editing `latticeshield-js/**/*.ts` or `latticeshield-js/vitest.config.ts` → JS tests needed
- When a CI job fails and you need to reproduce it locally
- Before committing to avoid pushing broken CI

## Critical Patterns

### Step 1 — Detect what changed

```bash
git diff --name-only HEAD
```

If working with staged changes only:
```bash
git diff --name-only --cached
```

Use the output to decide which checks to run. **Never run all checks blindly.**

### Step 2 — Decision table

| Changed files match | Run |
|---------------------|-----|
| `**/*.rs` | lint (fmt + clippy) |
| `Cargo.toml`, `Cargo.lock`, `deny.toml` | deny |
| Both of the above | lint + deny |
| `latticeshield-js/**/*.ts`, `latticeshield-js/tsconfig.json` | typecheck |
| `latticeshield-js/**/*.ts`, `latticeshield-js/vitest.config.ts` | js-test |
| Both TypeScript entries | typecheck + js-test |
| Nothing relevant | Skip — tell the user nothing needs to run |

### Step 3 — Run only what's needed

#### Lint (triggered by `*.rs` changes)

Always run `cargo fmt` FIRST (auto-fix, not `--check`), then clippy:

```bash
~/.cargo/bin/cargo fmt -p <crate>
~/.cargo/bin/cargo clippy -- -D warnings
```

If the change is in a specific crate, scope fmt to that crate with `-p <crate-name>`.
If the change spans the whole workspace, run without `-p`.

#### Deny (triggered by Cargo.toml / Cargo.lock / deny.toml changes)

```bash
~/.cargo/bin/cargo deny check
```

#### Typecheck (triggered by `latticeshield-js/**/*.ts` or `tsconfig.json` changes)

```bash
cd latticeshield-js && npm run typecheck
```

#### JS Test (triggered by `latticeshield-js/**/*.ts` or `vitest.config.ts` changes)

```bash
cd latticeshield-js && npm test
```

### Step 4 — Report

After running, report:
- Which checks ran and why (which files triggered them)
- Pass / Fail status per check
- For failures: paste the relevant error lines, not the full output

## Commands

```bash
# Detect changed files
git diff --name-only HEAD

# Lint — workspace
~/.cargo/bin/cargo fmt
~/.cargo/bin/cargo clippy -- -D warnings

# Lint — single crate
~/.cargo/bin/cargo fmt -p latticeshield-wasm
~/.cargo/bin/cargo clippy -p latticeshield-wasm -- -D warnings

# Deny
~/.cargo/bin/cargo deny check

# TypeScript — typecheck
cd latticeshield-js && npm run typecheck

# TypeScript — tests
cd latticeshield-js && npm test
```

## Rules

- `cargo fmt` always runs BEFORE clippy — formatting errors mask real issues
- Use `~/.cargo/bin/cargo` (not bare `cargo`) — project convention
- Never run `cargo build` after changes — project convention
- Tests (`cargo test --workspace`) are NOT part of this skill — run them separately if needed

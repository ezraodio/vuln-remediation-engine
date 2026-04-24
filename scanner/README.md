# Scanner workflow

The files in this directory are **shipped to the target repo** (e.g. `ezraodio/superset`)
so its CI runs the scanners and POSTs findings to this orchestrator.

## Install

From the root of your target repo:

```bash
# Copy the workflows into place
mkdir -p .github/workflows
cp path/to/vuln-remediation-engine/scanner/security-scan.yml      .github/workflows/security-scan.yml
cp path/to/vuln-remediation-engine/scanner/verify-devin-pr.yml    .github/workflows/verify-devin-pr.yml

# Configure two repo secrets (Settings → Secrets and variables → Actions):
#   ORCHESTRATOR_URL         = https://your-public-orchestrator-host
#   INGEST_SHARED_SECRET     = must match the orchestrator's env
```

Then commit and push. The scan will run nightly (cron) and also on-demand via the
"Run workflow" button in the Actions tab.

## What it does

`security-scan.yml`:
1. Runs `pip-audit` against the Python requirements files.
2. Runs `bandit` (MEDIUM+HIGH) against the Python source tree.
3. Runs `npm audit` against each `package.json`.
4. Normalizes all findings into the orchestrator's `Finding` schema.
5. POSTs to `${ORCHESTRATOR_URL}/ingest` with the shared-secret header.

`verify-devin-pr.yml`:
1. Triggers on any PR labeled `devin-remediation` or opened by the orchestrator's bot.
2. Checks out the PR head, re-runs the relevant scanner.
3. POSTs the result to `${ORCHESTRATOR_URL}/verify/result`. The orchestrator
   closes the loop: if the finding is still present, it feeds the output back
   into the same Devin session so it can iterate.

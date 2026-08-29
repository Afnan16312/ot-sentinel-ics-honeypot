# Ponytail and Graphify

These tools support development only. They are not part of the honeypot,
collector, dashboard or Oracle deployment.

## What is installed

- Ponytail `4.9.0` is installed as a global Codex plugin. It encourages the
  smallest correct change while keeping security, privacy, validation and tests.
- Graphify `0.9.50` is installed globally from the official `graphifyy` package
  in an isolated `uv` tool environment.
- `AGENTS.md` tells Codex to query the local project graph first when it exists.
- `.graphifyignore` excludes telemetry, private output, SOC runtime state,
  virtual environments and generated graph files.

Restart Codex after the first installation so the Ponytail plugin and Graphify
skill appear in new tasks.

## Use Graphify in this project

Open PowerShell in the repository root:

```powershell
graphify --version
graphify query "How does a protocol event reach storage and the dashboard?"
graphify explain "SQLiteObservationStore"
graphify path "sensor" "dashboard"
```

After changing code, refresh the local graph:

```powershell
graphify update .
```

The generated `graphify-out/` directory remains local and ignored by Git. Do not
publish it without a separate privacy review.

## Start another project safely

Ponytail loads globally in new Codex tasks. Graphify is globally available, but
it does not automatically index every folder because a new project may contain
secrets or private data. In each new project, review exclusions first, then run:

```powershell
graphify codex install
graphify extract . --code-only
```

Add secret, telemetry, customer-data and build-output paths to
`.graphifyignore` before extraction. `--code-only` performs local AST extraction
without an API key or cloud model.

## Cost and privacy

Ponytail, Graphify and local code-only extraction are free and open source.
Graphify cloud/LLM backends are optional and may send selected content to a
provider or create usage charges. They are intentionally not configured here.

## Remove the tools

```powershell
codex plugin remove ponytail
uv tool uninstall graphifyy
```

Delete `AGENTS.md` and `.graphifyignore` only if the project should no longer use
Graphify guidance.

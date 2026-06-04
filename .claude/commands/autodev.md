---
description: Run the orchestrator (code -> test -> review loop) on a task described in natural language
argument-hint: "[--fg] [--resume <branch> | --here] <description>"
---

You will run the autonomous orchestrator `orchestrator.py` on the following task, described by the user:

<task>
$ARGUMENTS
</task>

**First, detect the flags at the start of `$ARGUMENTS`, strip them, and keep the rest as the task
description.** Several can be combined:

- `--fg` (or `--foreground`) → **foreground mode** (otherwise: background, default).
- `--resume <branch>` → **isolated resume**: the orchestrator attaches a worktree to an EXISTING
  branch and reloads its open findings. (New-task mode if absent.)
- `--here` → **resume in the current checkout** (the branch the user is already on), without a
  worktree. Mutually exclusive with `--resume`.

Whatever remains after stripping the flags is the real task description, to be used everywhere below.
On resume (`--resume`/`--here`), **the description is optional**: if the user does not provide one,
simply do NOT pass `--task-file` / `--desc` — the orchestrator reloads on its own the original
description (from `tasks.json`) AND the branch's open findings. Only provide a description if the
user gives one (it complements/steers the resume).

Decide everything you can on your own, without asking unnecessary questions. Proceed as follows:

1. **Check the context.** The current directory must be the root of a git repository
   (`git rev-parse --show-toplevel`). Otherwise, report it and stop.

2. **Choose a task name `<slug>`** (short kebab-case):
   - **new task**: summarize the description (e.g. "add a favicon" → `favicon`); it will name the
     branch `feat/<slug>`.
   - **`--resume <branch>`**: derive the slug from the branch (strip the `feat/` prefix). First check
     that the branch exists (`git rev-parse --verify <branch>`) and is NOT checked out elsewhere; if
     it is, suggest `--here` instead.
   - **`--here`**: the slug only names the logs; check the user is not on the default branch
     (`main`/`master`) — if so, warn them (the coder edits their real working tree).

3. **Determine the test command** by inspecting the repo:
   - Python → `pytest -q` (if `pyproject.toml` / `pytest.ini` / a `tests/` folder)
   - Node → the `test` script in `package.json` (often `npm test`)
   - Go → `go test ./...`  |  Rust → `cargo test`
   - If nothing relevant is found, use `true` (validation then relies on the review only) and
     **warn the user** about this choice.
   - If the user specified a test command in their description, honor it.

4. **If a description is provided**, write it to a temp file (to avoid any escaping issues), without
   the flags:

   ```bash
   printf '%s' "<description without the flags>" > /tmp/orchestrator-<slug>.txt
   ```
   If the description is empty (resume without text), **write nothing** and do not use `--task-file`.

5. **Run the orchestrator.** Build the command, adding the resume option for the detected mode
   (`--resume <branch>`, `--here`, or nothing for a new task), and `--task-file` ONLY if a
   description was provided:

   ```bash
   python3 /home/ftriquet/Documents/AI-Job/orchestrator.py <slug> \
       --test-cmd "<test command>" --max-iter 3 \
       [--resume <branch> | --here] \
       [--task-file /tmp/orchestrator-<slug>.txt]   # omitted if resume without description
   ```

   Then, depending on the execution mode:

   - **Background (DEFAULT)** — a run can exceed 10 minutes, so do not block the session. Redirect
     output to a log (`> /tmp/orchestrator-<slug>.out 2>&1`) and launch with `run_in_background: true`.
     Then **relay progress** (step 6).

   - **Foreground (`--fg`)** — run the SAME command **without** `run_in_background`, with a timeout
     close to the maximum (600000 ms). Output shows directly. ⚠️ Warn that the Bash tool **cuts off
     at 10 minutes**: if the job may run longer, suggest `--max-iter 1` or running the script in a
     terminal. In foreground, skip step 6 and go to the summary.

6. **Relay progress during the run (background mode, IMPORTANT).** Do not stay silent until the end:
   the user wants to follow progress. Watch the job output (the file `/tmp/orchestrator-<slug>.out`
   and/or the background task output) and **re-post regularly** (every ~30-60 s, or at each new step)
   the new activity lines in the orchestrator's format:
   - iteration changes (`──── Iteration N/M ────`),
   - the session feed (`[coder] 🔧 …`, `[reviewer] 💬 …`, `✓ session done (Xs, $Y)`),
   - the test and review results (OK / FAILED + loop back).

   To do this, after launching, periodically re-read the log delta (e.g. via the monitoring tool or
   by re-reading the task output), until the process ends. Warn that this is intermittent (not real
   time), and that for a strictly live stream the user can also `tail -f /tmp/orchestrator-<slug>.out`
   in their own terminal.

7. **Report at the end.** When the job finishes, summarize:
   - success ✅ or failure ❌ (and why);
   - the relevant branch (`feat/<slug>` for a new task, the resumed branch otherwise) and how to
     inspect it (`git checkout <branch>`);
   - the reviewer findings (read `.orchestrator/findings.jsonl`);
   - the **out-of-scope discoveries** if any (read `.orchestrator/discoveries.jsonl`) — flag them as
     debt to handle later;
   - if the job failed at the guard, offer to **resume**: `--resume <branch>` (if the user is not on
     it) or `--here` (if they switch to the branch).
   - the archived transcripts in `.orchestrator/logs/` if needed.

Reminders:
- The orchestrator runs with `--dangerously-skip-permissions`. In worktree mode (new task or
  `--resume`) it is isolated and disposable; in `--here` it edits **the current checkout directly**
  (warn the user). Nothing is pushed.
- Start with `--max-iter 3` to limit cost; re-run with more if the user asks.
- Make sure `.orchestrator/` is in the target project's `.gitignore`.

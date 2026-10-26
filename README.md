# daemon-claim-audit

An offline static audit of documented detachment promises against Python AST and service unit evidence. Inspected programs are never executed. Requires Python 3.9 or later; runtime dependencies are entirely standard library.

## Use

```sh
pip install daemon-claim-audit
daemon-claim-audit . --json
python3 -m daemon_claim_audit . --verbose
```

ROOT defaults to the current directory. Options: `--json`, `--verbose`, `--ignore GLOB ...`, `--fail-on HIGH|MEDIUM`, and `--version`. Ignore patterns use fnmatch on POSIX relative paths. Symlinks are skipped and environment files are never opened.

The scanner reads root README.md and Markdown beneath any docs directory. It excludes fenced blocks, retains inline code, normalizes case and hyphens, and joins paragraph lines. Negative spans are removed before positive matching. Each contradictory family produces one finding, preferring a non-test document. Test documents receive MEDIUM; other documents receive HIGH.

Exit codes: 0 means PASS at the chosen threshold; 2 means findings at that threshold; 1 means usage or input error. The default threshold is MEDIUM. HIGH leaves MEDIUM findings visible without failing. JSON includes status, evidence paths, claims, and findings. Text prints status and `RULE SEVERITY`; verbose adds the relative path.

Static evidence includes explicit true flags, attribute assignments, the legacy thread setter, subprocess session options, Unix session calls, imported library context calls, and service units containing both required directives. Evidence is project-wide. Test Python and service files are excluded. This is a syntactic heuristic, not a runtime guarantee: arbitrary calls with a true keyword can qualify, and unreachable calls qualify too. Import aliases are resolved syntactically; dynamic imports and runtime rebinding are not evaluated.

Rules and exact recognized phrases:

```text
documented-daemon-claim-false HIGH
documented-no-daemon-claim-false HIGH

DAEMON:
daemon mode
daemon support
supports daemon mode
supports daemon
runs as a daemon
run as a daemon
runs in the background
run in the background
runs in background
run in background
background mode
background support
supports background mode
runs as a background process
run as a background process
background process
background daemon
runs detached
run detached
detached mode
detaches from the terminal
detach from the terminal
keeps running after you close the terminal
keeps running after closing the terminal
continues running after you log out
continues running after logout
runs as a service
run as a service
systemd service
runs without a terminal
runs without a terminal attached

NODAEMON:
does not run as a daemon
does not run in the background
does not run in background
no daemon mode
no daemon support
no background mode
no background support
never runs in the background
never runs as a daemon
must be run in the foreground
foreground only
runs in the foreground only
run in the foreground only
does not detach
does not run detached
requires a terminal
must keep the terminal open
stops when you close the terminal
stops when the terminal closes
does not run as a service
no systemd service
```

Develop locally with `python3 -m unittest discover` and `python3 -m build`. Licensed under MIT.

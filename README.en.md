# witr-rs

English | [简体中文](README.md)

**Why is this running?** — given a process name, PID, port or file, trace back who started it and how.

A Rust implementation of [pranshuparmar/witr](https://github.com/pranshuparmar/witr) (Go, Apache-2.0), aligned with its platform data-collection strategy.

**Run `witr-rs` with no arguments to enter the interactive TUI**, laid out like the original: five tabs at the top (1. Processes / 2. Ports / 3. Containers / 4. Locks / 5. Events), the process table on the left (PID / User / Name / CPU% / Trend / Mem / GPU / Age), a live trace summary of the selected process on the right, and key hints at the bottom — auto-refreshing every 3 seconds. Press `Enter` for the full-screen **process detail page** (70% details on the left + 30% environment variables on the right, each pane scrolls independently). Mouse works too (wheel scrolling, click tabs/rows/panes, double-click opens the detail page). With `-i`, targets seed the TUI so it opens right where the answer is (`witr-rs -i --port 8080` lands on the Ports tab filtered to that port). When stdout is piped it degrades to a static process table (`--list` forces that).

**Events tab (TUI)**: a 3-second sampler records processes appearing, exiting and restarting (last 500 events kept); `/` filters by event type / PID / process / detail, and `Enter` on an event jumps to that process's detail page (with a notice if it has exited). Together with the sampling history this drives the **crash-loop detection**: the same process identity reappearing under a new pid counts as one restart; the `Rst` column shows the total, and ≥2 restarts within 5 minutes raise a yellow warning in the detail panes.

**`--watch [seconds]`**: live mode — with targets it re-runs the trace pipeline and re-renders every N seconds (default 2); without targets it refreshes the process table. Composes with `--recent`/`--json` etc.; Ctrl-C exits.

**Peer attribution (TUI detail page)**: each ESTABLISHED connection is reverse-matched against the peer socket's owner and the detail page shows `talking to: <process> (pid N) — k connection(s)`; when the peer lives elsewhere you get the remote address.

## TUI keys

Vim-style browsing (aligned with the Go witr):

| Key | Action |
|---|---|
| `j` `k` / `↑` `↓` | Move selection |
| `g` `G` | Jump to first / last row |
| `f` `b` `space` / PgUp PgDn | Page down / up |
| `h` `l` / `←` `→` | Switch tabs |
| `1`–`5` / Tab | Jump to tab / cycle focus (table ↔ details) |
| `/` | Search: Processes tab matches PID/user/name; Ports tab matches port/PID/process/address/proto/state (filters are per-tab; Enter applies, Esc clears) |
| `Enter` | Processes tab: full-screen process detail; Ports tab: port detail (all connections on that port + owning process); Containers tab: container detail; Locks tab: jump to the holder's detail page |
| `p` `n` `u` `c` `m` `t` | Processes tab: sort by PID / name / user / CPU / memory / start time; press again to flip direction |
| `p` `t` `n` `s` | Ports tab: sort by port / proto / address / state |
| `i` `n` `r` `g` `s` | Containers tab: sort by ID / name / runtime / image / status |
| `p` `n` `t` `m` `f` | Locks tab: sort by PID / process / type / mode / path |
| `t` `e` `p` `n` | Events tab: sort by time / event / PID / process (time defaults newest-first; press again to flip direction) |
| `a` | Ports tab: listening-only ↔ all socket states; Locks tab: locks ↔ all open files; Processes tab: actions bar (`k` kill / `t` term / `p` pause / `r` resume / `n` renice) |
| `z` | Zoom: the focused pane temporarily fills the row (tmux-style) |
| `x` | Kill the selected process (y/n confirm) |
| `r` | Refresh now |
| In detail pages | `j/k` scroll, `d/u` half page, `g/G` top/bottom, `b/f` page, `Tab` switch panes, `a` actions bar, `/` search env vars, `z` zoom, `c` copy pane text, `Esc/q` back |
| Mouse | Wheel scrolls the list / detail panes; click switches tabs, selects rows, focuses panes; double-click opens the detail |
| `q` / `Esc` | Quit |

Details of the selected process refresh 500ms after the cursor stops moving (debounced, so holding `j` doesn't fire a query per row) — same as the original's `selectionDebounce`.

**Port detail page**: select a port on the Ports tab and press `Enter` to see every socket on that port — the LISTEN entry plus **the requests happening right now** (each ESTABLISHED connection with its peer address, state and owning PID/process; a snapshot taken when the page opens). The Owner panel below shows the full trace of the listening process (attribution + ancestry + warnings). `Tab` switches focus between Connections and Owner, `j/k/d/u/g/G/b-f` scrolls, `Esc` returns.

**Process detail page**: left trace panel (identity, Started-by attribution, Ancestry Tree, Open Files, risk score, warnings), right environment variables pane; `c` copies the focused pane as plain text to the clipboard.

**Risk score**: each process aggregates 0–10 points of risk signals — binary running from a temp directory, deleted binary still running, `curl | sh`-style downloads piped into shells, LD_PRELOAD/DYLD injection, ESTABLISHED connections to public addresses. The CLI prints `risk N/10: signal list`; the TUI detail pages show the same.

**Crash-loop detection** (TUI): the same process identity reappearing under a new pid counts as one restart; the `Rst` column shows the total, and ≥2 restarts within 5 minutes raise a yellow warning in the detail panes — crash loops are visible at a glance (event details in the Events tab).

**Instantaneous CPU + Trend sparkline** (TUI): computed from the delta of cumulative CPU time between refreshes (not the lifetime average); the Trend column draws the last 8 samples as an 8-level sparkline, and the `c` sort key sorts on it.

**Binary fingerprint** (`--export` / TUI detail page): the target binary's sha256 plus a code-signature verdict (macOS `codesign`, Windows Authenticode; an invalid signature adds +3 to the risk score). Linux has no kernel-enforced signing story — the hash is the identity of record.

**GPU column** (TUI, optional): on machines with an NVIDIA driver, `nvidia-smi pmon` supplies per-process SM utilization and memory (`37% 2.3G`), with full values on the detail page. Without nvidia-smi the column hides itself; a failed probe is attempted only once per run.

**K8s pod attribution** (optional): with `kubectl` installed and a reachable cluster, containers are labeled with their owning pod (`docker: mongo-demo-2 (id 6838b8ba3c49) · pod data/mongo-0`) and the Containers tab gains a Pod column. Without kubectl this costs nothing.

**Container health**: the Containers tab colors the state cell (healthy/running green, unhealthy red, restarting/starting yellow); the container detail page and `-c` targets show the `inspect` RestartCount (annotated "restart policy fired" when > 0).

**`--export`**: `witr-rs --pid <N> --export` prints a paste-ready plain-text diagnostic report (including environment variable values, the open-files list, and the binary's sha256 + signature verdict).

**Containers tab**: enumerates containers via runtime CLIs on PATH (docker / podman / nerdctl), showing Runtime / ID / State / Status / (Pod) / Image / Name, with the state cell colored by health; `/` filters by name/image/ID/runtime/state, `i/n/r/g/s` sorts. Enumeration runs on a background thread (a hung runtime CLI never freezes the UI) and auto-refreshes every 3s; refreshes keep the stale table visible so nothing flashes — the loading placeholder only shows on first load. **`Enter` opens the container detail page**: container attributes on the left (Name/Runtime/ID/Image/State/Status/Ports/Restarts), in-container process list on the right (matched via cgroups on Linux; on macOS/Windows container processes live in a VM and a note is shown).

**Locks tab**: file locks plus an all-open-files view (Linux reads `/proc/locks`; macOS extracts lock flags from `lsof` with a lock-file-name heuristic); `a` toggles locks ↔ all open files (the open-files view caps the display at 100 rows until you search), and `Enter` on a row jumps straight to the holding process's detail page.

**Seeding the TUI from the CLI (`-i`)**: `witr-rs -i --pid 1234` / `witr-rs -i nginx` / `witr-rs -i --port 8080` / `witr-rs -c web -i` / `witr-rs -i --file /var/log/x.log` — the TUI opens on the right tab with the right filter (name prefills the search, pid selects the row, port/file/container switch tabs and prefill their filters). One target per type is used; extras are reported in the status line; exit 4 without a terminal.

## Platform support

| Capability | Linux | macOS | Windows |
|---|---|---|---|
| Process table | direct `/proc` reads | `ps` | ToolHelp32 snapshot |
| cmdline / cwd / exe | `/proc/<pid>/*` | `ps` + `lsof` | PowerShell (Get-CimInstance) |
| Port → process | `/proc/net/*` + fd inode matching | `lsof -i` | `netstat -ano` |
| File → process | `/proc/*/fd` | `lsof` | ✓ (Restart Manager API — no Sysinternals needed) |
| File locks (Locks tab) | `/proc/locks` + fdinfo | `lsof` lock flags + lock-file-name heuristic | ✗ |
| Service attribution | systemd (`systemctl status`) | launchd (`launchctl list` + plist probing) | SCM (`tasklist /svc`, recognizes services.exe descendants) |
| Container attribution | cgroups (docker/containerd/podman/lxc) | ✗ | ✗ |
| nohup/disown detection | ✓ (SIGHUP bit of `/proc/<pid>/status` SigIgn, surfaced as a warning) | ✗ | ✗ |
| Environment variables (`--env` / TUI detail page) | ✓ `/proc/<pid>/environ` (same user) | ✓ same-user processes via `ps -E` (the rest are SIP-limited; the pane says so) | ✗ |
| Start time | btime + starttime | `ps etime` | CIM CreationDate |

Optional cross-platform extras (identical on all three; silently skipped when the dependency is missing): `nvidia-smi` (GPU column), `kubectl` (K8s pod attribution), `docker`/`podman`/`nerdctl` (Containers tab).

External commands required: Linux — none strictly (systemctl/docker optional); macOS — `ps`/`lsof` (built in); Windows — `powershell`/`netstat`/`tasklist` (built in).

## Install

Grab the archive for your platform from [GitHub Releases](https://github.com/yaowenqiang/witr-rs/releases) (sha256 checksum files included). Pushing a `v*` tag makes CI build every target automatically:

| File | Platform |
|---|---|
| `witr-rs-x86_64-unknown-linux-musl.tar.gz` | Linux x86_64 (static) |
| `witr-rs-aarch64-unknown-linux-musl.tar.gz` | Linux ARM64 (static) |
| `witr-rs-x86_64-apple-darwin.tar.gz` | macOS Intel |
| `witr-rs-aarch64-apple-darwin.tar.gz` | macOS Apple Silicon |
| `witr-rs-x86_64-pc-windows-msvc.zip` | Windows x86_64 |

Or build from source:

```bash
cargo build --release          # host platform
cargo check --target x86_64-unknown-linux-gnu   # all three platforms type-check everywhere
cargo check --target x86_64-pc-windows-msvc
cargo test
```

## Usage

```bash
witr-rs                       # no args: interactive TUI on a terminal; static table when piped
witr-rs --tree                # no args + --tree: full system process tree (--list forces static too)
witr-rs --json                # no args + --json: every process as JSON
witr-rs nginx                 # by process name (substring match)
witr-rs python --exact        # exact match (case-insensitive)
witr-rs --pid 1234            # by PID
witr-rs --port 8080           # who owns this port
witr-rs --file /var/log/x.log # who holds this file open
witr-rs --file '/var/log/*.log' # globs: holders of every matching file at once
witr-rs -c web                # who runs this container (name/image/ID-prefix match)
witr-rs nginx --tree          # ancestry tree + children
witr-rs nginx --short         # one-line output (script-friendly)
witr-rs --port 8080 --json    # machine-readable JSON
witr-rs nginx --env           # only the command + environment variables (full on Linux; same-user on macOS)
witr-rs --watch               # keep refreshing the process table (default 2s, Ctrl-C to stop)
witr-rs --port 8080 --watch 5 # re-trace this target every 5 seconds
witr-rs --recent 5m           # only processes started within the last 5 minutes
witr-rs nginx --warnings      # only the warnings
witr-rs --pid 1234 --export   # paste-ready plain-text diagnostic report
witr-rs -i --port 8080        # TUI seeded to that port (-i, see above)
witr-rs nginx --pid 1         # mix multiple targets (divided per target)
NO_COLOR=1 witr-rs nginx      # disable colors (--no-color does the same)
```

### Exit codes

| Code | Meaning |
|---|---|
| 0 | OK, no warnings |
| 1 | Found, but with warnings (running as root, listening on all interfaces, deleted binary, LD_PRELOAD, …) |
| 2 | Target not found |
| 3 | Not enough permissions (e.g. a root-only query) |
| 4 | Invalid arguments |
| 5 | Internal error (e.g. process table unreadable) |
| 6 | Found, but the source could not be attributed (never on Windows, where ancestry routinely stops at an exited parent) |

Multi-target runs take the most severe exit code; the severity ranking matches the original (6 ranks below 1).

## Sample output (macOS)

```
== port 8919 ==
python3 — pid 57097 (user yaojack)
  started 2026-09-12 23:56:55 (3s ago)
  cwd /Users/yaojack/work
  exe /Users/yaojack/anaconda3/bin/python3.11
  cmd python3 -m http.server 8919

  started by:
    shell zsh — started from a zsh shell (pid 57095)

  chain (root → this):
    launchd            pid 1      root
    └─ zsh             pid 57095  yaojack
       └─ python3      pid 57097  yaojack  ← this

  sockets:
    tcp6  *:8919 LISTEN

  warnings:
  ⚠ pid 57097 listens on all interfaces (*:8919)
```

## Architecture

```
src/
├── cli.rs          clap argument definitions
├── model.rs        Process / Socket / Source / TargetReport data model
├── ancestry.rs     ppid chain walk (cycle guard, depth limit, missing-parent warnings)
├── pipeline.rs     target resolution (name/pid/port/file/container → pid), attribution priority, warnings
├── tui.rs          interactive UI (ratatui/crossterm): five tabs + detail panes + mouse + 3s auto-refresh
├── render.rs       standard / tree / short / json / env / warnings / export renderers
├── history.rs      sampling history: instantaneous cpu, sparklines, restart detection, event feed
├── risk.rs         0–10 risk scoring (temp-dir binary, curl|sh, injections, public peers, bad signatures …)
├── binary_id.rs    binary sha256 + code-signature verdict (codesign / Authenticode)
├── gpu.rs          nvidia-smi pmon sampling → per-process GPU column
├── k8s.rs          kubectl get pods → pod attribution for containers
├── util.rs          command execution with timeouts, time formatting, user-name resolution
│                    (negative-cached), host:port parsing
└── platform/
    ├── mod.rs      Platform trait (the only platform seam) + container enumeration / inspect
    ├── linux.rs    the /proc family
    ├── macos.rs    ps / lsof / launchctl
    └── windows.rs  ToolHelp32 / PowerShell / netstat / tasklist / Restart Manager
```

Attribution priority: container > ssh session > interactive shell > service manager (systemd/launchd/SCM) > keep-alive supervisor (supervisord/runc etc., incl. cmdline token matching) > cron > init catch-all (pid 1 with no shell in between — system daemons). When the Linux `service_source` falls back to "init" the pipeline drops it and tries the generic detectors instead.

## Known limitations (v0.4)

- TUI Ports/Containers/detail pages are snapshots from when they opened — `r` refreshes manually
- Windows process details rely on batched PowerShell queries (one call per target, 20s timeout guard)
- The CPU% column is empty for Windows in the TUI (tasklist doesn't provide it)
- Container attribution is Linux-only (container processes behind colima/Docker Desktop on macOS are not attributed, though `-c` targets get a runtime-side fallback view)
- Windows has `--file` (Restart Manager) but no Locks data
- macOS `launchctl list` only covers the current user domain; system daemons need sudo to be labeled. macOS file locks are approximated from `lsof` flags — the kernel exports no lock table there
- nohup/disown detection is Linux-only (no `/proc` on macOS/Windows, so no such warning there)
- The GPU column covers NVIDIA only (`nvidia-smi`); there is no per-process utilization source for Apple Silicon / AMD GPUs

## License

Apache-2.0. Design follows pranshuparmar/witr (also Apache-2.0).

# witr-rs

English | [简体中文](README.md)

**Why is this running?** — given a process name, PID, port or file, trace back who started it and how.

A Rust implementation of [pranshuparmar/witr](https://github.com/pranshuparmar/witr) (Go, Apache-2.0), aligned with its platform data-collection strategy.

**Run `witr-rs` with no arguments to enter the interactive TUI**, laid out like the original: five tabs at the top (1. Processes / 2. Ports / 3. Containers / 4. Locks / 5. Events), the process table on the left (PID / User / Name / CPU% / Trend / Mem / GPU / Age), a live trace summary of the selected process on the right, and key hints at the bottom — auto-refreshing every 3 seconds. Press `Enter` for the full-screen **process detail page** (70% details on the left + 30% environment variables on the right, each pane scrolls independently). Mouse works too (wheel scrolling, click tabs/rows/panes, double-click opens the detail page). With `-i`, targets seed the TUI so it opens right where the answer is (`witr-rs -i --port 8080` lands on the Ports tab filtered to that port). When stdout is piped it degrades to a static process table (`--list` forces that).

**Events tab (TUI)**: a 3-second sampler records processes appearing, exiting and restarting (last 500 events kept); `/` filters by event type / PID / process / detail, and `Enter` on an event jumps to that process's detail page (with a notice if it has exited). Together with the sampling history this drives the **crash-loop detection**: the same process identity reappearing under a new pid counts as one restart; the `Rst` column shows the total, and ≥2 restarts within 5 minutes raise a yellow warning in the detail panes.

**Tree view (`T`, Processes tab)**: flips the flat table into a parent→child tree (`└─` nesting, sort keys order the siblings); a live search falls back to the flat list. Press `T` again to go back.

**CPU history chart (detail page)**: the detail panes draw the last ~10 minutes of instantaneous CPU samples as a block-char chart normalized to the window peak — bursts and idle phases visible at a glance, no configuration.

**Disk I/O column (all platforms)**: the process table gains an IO column (read+write bytes per refresh interval) and the detail page shows cumulative read/write bytes and syscall counts. Sources: Linux `/proc/<pid>/io`, macOS `proc_pid_rusage`, Windows PowerShell `IO_COUNTERS` (protected system processes report nothing and show blanks).

**Memory trend + leak suspicion (detail page)**: the detail panel draws the last ~10 minutes of RSS samples as a green block-char chart on an absolute scale, annotated with the window peak; when RSS grows ≥20 MB over the window with ≥70% monotonically rising segments, a yellow "possible memory leak" warning appears — separating real leaks from sawtoothed allocate/free cycles.

**FD trend + leak suspicion (detail page)**: the same logic aimed at file descriptors — while the detail page is open, the fd count is sampled once per refresh (Linux reads `/proc/<pid>/fd`, macOS one `lsof -p`, Windows has no source), and an `Open fds (N)` history chart appears; growth ≥64 descriptors over the window with ≥70% monotonically rising segments raises a yellow "possible fd leak" — the socket-per-request service that never closes them gives itself away.

**Detail-page disk I/O chart**: two block-char sparklines for read/write rates (each annotated with its window peak), fed by the same cross-platform cumulative-byte deltas as the IO column (Linux `/proc/<pid>/io`; the section hides itself on macOS/Windows where per-process I/O is unavailable).

**Snapshot diff (`--snap` / `--diff`)**: `witr-rs --snap before.json` writes the whole process table as JSON; later `witr-rs --diff before.json` reports what changed — **new** processes, **gone** ones, **restarted** (same program identity back under a new pid, like the TUI's crash-loop detector — including a restart that happens to reuse the same pid: same pid, same identity, different start time counts as restarted) and **changed** (same pid, same identity, different command line). A pid taken over by an unrelated program no longer mis-reports as changed: the old process is **gone** (noted "pid taken over"), the new one **new** (noted "pid reused"). Snapshots taken with **`--sockets`** also record the current LISTEN ports, and `--diff` then reports **listen-new / listen-gone** — a first-pass canary for "something new started serving on :8080 after the snapshot" (an existing port merely changing owners is not reported). Exit code 1 when anything changed, 0 otherwise — script-friendly. Pathless `witr-rs --snap` **auto-rotates**: snapshots land in `snapshots/` next to the config dir, keeping the newest 10 by default (`--keep N`); `--diff last` compares against the newest auto snapshot and `--diff 30m` against "30 minutes ago" — what appeared and disappeared in the last half hour, one command. `--diff` with `--json` emits a machine-readable versioned envelope (`summary: {new, gone, restarted, changed, listen_new, listen_gone, total}` + `entries`, jq-ready); in the TUI, `D` opens the same comparison — newest auto snapshot vs the live table, color-grouped rows (listen changes in cyan/magenta), `j/k` to select, `Enter` to jump into that process's detail page, `r` to re-diff.

**Ranking (`--top`)**: `witr-rs --top cpu -n 30` skips the TUI and prints the top N processes ranked by CPU / memory / fd count / disk I/O / age / **disk I/O rate** (`--top fd` reads `/proc/<pid>/fd` on Linux and sweeps one `lsof -F pf` pass on macOS; Windows exits with a clear message since it has no source; `--top io` is Linux-only; `--top io-rate` ranks by read+write MB/s — the one-shot mode takes two samples 1 s apart, `--watch` uses the persistent sample history; all three platforms; `--top age` ranks oldest-first — pid 1 always wins, and the trailing column flips to the process state). Pair with `--watch N` for a live board: `--top cpu --watch 5` resamples, reranks and redraws every 5 seconds; Ctrl-C exits. "What's busiest right now" without opening a UI.

**Tabular output (`--csv` / `--markdown`)**: machine-readable forms of the process table — `--csv` escapes per RFC-4180 (commas, quotes and newlines inside command lines are safe), `--markdown` pastes straight into an issue or doc; both include NAME plus the full command line.

**CSV time series (`--watch` + `--record`)**: `witr-rs --watch 5 --record load.csv` appends the whole process table to a CSV every 5 seconds — timestamp / pid / user / name / cpu_pct / rss_mb / io read+write rates (columns left empty where the platform doesn't report them). Replay the load curve afterwards with Excel / pandas / SQLite; console output is untouched. A `.jsonl` path switches to **NDJSON mode**: one versioned JSON envelope per tick (`{schema_version, generated_at, process_count, processes}`), with ppid / state / age_secs riding along per process — `jq '.processes[] | select(.rss_mb > 500)'` and you're in.

**HTML report (`--report-html`)**: `witr-rs --report-html status.html` writes a self-contained single-file report (no JS, no dependencies): per-process CPU / memory bars, Top-CPU / Top-memory boards, and a nine-column table of every process, fully HTML-escaped — attach it, archive it, send it.

**Tree kill (`K`)**: the actions bar gains `K` — a BFS over ppid links collects every descendant of the selected process (grandchildren included, even if a parent is reaped mid-walk), prompts `kill pid N + M descendant(s)? y to confirm`, and SIGTERMs the whole tree on `y`. Killing a worker pool or a user session tree no longer means hunting pids one by one.

**Headless kill (`--kill` / `--kill-tree`)**: `witr-rs runaway --kill` signals the matched targets directly, no UI — `--signal KILL` (`SIGKILL` synonym, default `TERM`) picks the signal, `--kill-tree` BFS-collects all descendants first and kills children before their parents (the same collection logic as the TUI's `K`). Mutually exclusive with `-i`/`--watch`/`--follow`; exit code 2 when nothing matched, 1 when any kill failed — scripts can branch on the result. Each kill prints `killed <name> (pid N) [SIGKILL]`.

**Process notes (`N`)**: on the Processes tab, `N` opens a note prompt for the selected process (Enter saves, Esc discards, empty text removes), persisted by identity into the config file's `notes` key — the note follows the program across restarts and new pids; the table row shows a ✎ marker and the detail page gains a Note section. Leave the answer to "what is this python actually doing".

**Help overlay (`?`)**: from any page, `?` opens a full keymap for the current tab (global keys + per-tab sections), `j/k` scrolls; Esc / q / Backspace / `?` again returns to the page it was opened **from** (open it on a detail page, land back on that detail page). No key left unmemorized.

**JSON schema**: `--json` output is now a versioned envelope `{schema_version, generated_at, process_count, processes}` so downstream parsers can check the version before trusting the shape; `--tree --json` turns the no-target listing into a **nested forest** (children nest under their parent's `children`, same rules as the text tree: orphans and ppid cycles become roots, pid-ascending); `--diff --json` adds the same envelope plus a `summary` of counts.

**Follow across restarts (`--follow`)**: `witr-rs --pid 1234 --follow` keeps tracing the target after it dies — when the pid exits, the process table is re-scanned for the same program identity (name+exe+user) and the trace continues under the new pid (implies `--watch`; gives up after the identity stays missing for 3 refreshes). Multi-instance ambiguity resolves to the most recently started match.

**`--watch [seconds]`**: live mode — with targets it re-runs the trace pipeline and re-renders every N seconds (default 2); without targets it refreshes the process table. Composes with `--recent`/`--json` etc. **`--times N`** bounds the loop for CI/cron — `--watch 5 --times 12` samples for a minute and exits (code 0; 130 when interrupted by SIGINT). The target-less watch ends with a **summary**: on Ctrl-C (unix) or `--times` it prints what happened during the run (activity counts + restart chains, same data as the TUI's `S` page; `--json` wraps it in a JSON envelope with `ticks` / `interrupted` / `summary`). Three shapes for the target-less watch: default redraws the whole table; **`--quiet`** skips the redraw and prints only alerts/hooks (a headless watchdog can run for days without filling the scrollback); **`--watch --json`** emits one JSON envelope per tick on stdout (alerts go to stderr so a `| jq` pipe stays clean).

**Event hooks (`--on-start` / `--on-exit`)**: while watching/following a target, run a command once on the appear/disappear edge — `--watch 2 --on-start 'say up'` is a wait-for-deploy script (it also fires on the first tick if the target is already up), `--follow --on-exit 'say gone'` is a departure sentinel. Commands run via `sh -c`; their exit codes don't affect the watch loop.

**Command audit (`--audit CMD`)**: `witr-rs --audit 'cargo build --release'` wraps a command, samples its process subtree every 500 ms while it runs, and prints a report when it exits — wall duration, exit code, spawned process count and peak alive count, subtree peak CPU / peak RSS, total disk read+write, plus the full process tree (each member at its last sighting). Two deliberate approximations (both documented in the code): a child that exits mid-run keeps its contribution (cumulative I/O and identity are remembered at last sighting); a child whose parent exited reparents and breaks the ppid walk, so one generation of catch-up adopts processes whose parent was in the previous tick's subtree (deeper reparent chains can still slip away — rare in build trees, where the chain dies root-first). "How much did this build actually eat, and how many processes did it spawn" in one command; the command's exit code passes straight through for CI.

**Dead-target hints**: when a trace comes up empty, witr-rs suggests the next step — a missing `--pid 999999` hints that "`--follow` keeps tracing across restarts"; a mistyped name gets the three closest candidates by edit distance (`witr-rs nginxx` → `closest: nginx, ...`), so a typo doesn't cost a whole investigation round.

**Peer attribution (TUI detail page)**: each ESTABLISHED connection is reverse-matched against the peer socket's owner and the detail page shows `talking to: <process> (pid N) — k connection(s)`; when the peer lives elsewhere you get the remote address.

**Ports overview (`o`, Ports tab)**: flips the per-socket table into an aggregate keyed by (port, owning process) — columns Port / Proto(s) / Process / PID / User / Addrs (how many addresses the port is bound on; tcp+tcp6 merge into one row), sorted by port, with `/` search and `Enter` jumping to the owner's process detail page. "Who is serving what on this machine" at a glance.

**Crash forensics (exit-time capture)**: the moment an exit event fires, the TUI grabs the dying process's last log lines in the background (macOS unified log by process name / Linux journald by `_PID=`, up to 25 lines, the most recent 50 cached); `l` on an exited/restarted Events row shows these "last words" **instantly** — no racing the log rotation, the crash scene is frozen at exit time.

**Desktop notifications (`--notify` / `!`)**: the TUI fires a system notification whenever a target process restarts; once the same name has restarted ≥2 times this session, its plain exits notify too (crash-loop alerts). macOS uses `osascript`, Linux `notify-send`, Windows a native WinRT toast via PowerShell (no extra module) — sent from a background thread so sampling never stalls; `--notify` pre-enables it and `!` toggles live (footer shows the state).

**Pause sampling (`P`)**: freezes TUI sampling — no refresh, no new events, no notifications, footer shows `⏸ paused`; press again to resume. Read the list or copy a scene without the data flowing past you.

**Session digest (`--since` / `S`)**: `witr-rs --replay ev.jsonl --since 1h` skips the UI — it prints a "what happened" digest of the recorded window and exits (pipe-friendly): started / exited / restarted counts plus restart chains (which program restarted how many times). In the TUI, `S` opens the same digest as a full page: activity counts, restart chains, and two boards — **CPU spikes** (highest instantaneous peak per process in the window) and **memory climbers** (fastest RSS growth); `--since` presets the window (30, 30s, 5m, 2h, 1d — default: whole session), `r` recomputes. Answers "what has this machine been busy with for the last half hour".

**Threshold alerts (`--alert-cpu` / `--alert-mem` / `--alert-fd` / `--alert-io` / `--alert-conn`)**: `witr-rs --alert-cpu 90 --alert-mem 2048` — when a process exceeds the threshold for 5 consecutive samples (~15 seconds): a desktop notification fires, the Events tab records an alert, and the row highlights red. One notification per excursion, re-armed once usage drops back under — no alert storms. `--alert-fd 4096` watches open-file counts (Linux reads `/proc` directly; macOS sweeps one `lsof` pass per cycle — only while the alert is armed); `--alert-io 100` watches disk I/O rate (read+write MB/s, from Linux `/proc/<pid>/io` deltas); `--alert-conn 200` watches per-process ESTABLISHED connection counts. With **`--alert-exec`** a custom command runs on every firing (webhook: `--alert-exec 'curl -s $SLACK_HOOK -d "$WITR_ALERT_NAME: $WITR_ALERT_DETAIL"'`); the context rides in as `WITR_ALERT_PID` / `WITR_ALERT_NAME` / `WITR_ALERT_DETAIL` environment variables. Alerts don't live in the TUI alone: **`--alert-*` under `--watch` is a headless watchdog** — `witr-rs --watch 5 --alert-cpu 90` checks thresholds every tick and prints a `⚠ alert: <name> (pid N) — detail` line on each firing (same 5-samples-and-latch machinery as the TUI, `--alert-exec` still runs), so the machine can be watched with no UI at all; add `--events-log` and alerts land in the same JSONL stream as started/exited/restarted events (replayable via `--replay`).

**Port canary (`--alert-port`) + repeat nagging (`--alert-repeat`)**: `--alert-port 9090` watches LISTEN ports for an **edge** — the moment something starts listening on :9090 it alerts `listener appeared on :9090 (<owner>)` (the first observation only arms: a port already bound at startup is the status quo, not an event — the same edge semantics as `--on-start`/`--on-exit`). Prefix `!` to invert into a gone-sentinel: `--alert-port '!8080'` alerts `listener gone from :8080 (was <owner>)` when the listener disappears. Repeatable, so several ports can be watched at once. **`--alert-repeat 60`** re-sends a sustained alert about every 60 seconds (the clock resets on first fire and on re-arming after a drop back under; unset keeps the classic once-per-excursion) — a watchdog that keeps nagging until someone looks. TUI and `--watch` alike; `--alert-exec` and `--events-log` work as usual.

**Prometheus endpoint (`--serve`)**: `witr-rs --serve :9100` starts a `/metrics` scrape endpoint in the Prometheus text format (zero new dependencies) — no background sampler; **every scrape samples the process table fresh**, so scrape frequency IS the sample rate. It exports machine totals (`witr_process_count`, `witr_rss_total_mb`) plus per-process gauges for the union of the top-20 CPU and top-20 RSS processes (`witr_process_cpu_percent` / `witr_process_rss_bytes` / `witr_process_open_fds`, labeled pid / name / user — bounded cardinality); each process also carries **`witr_process_start_time_seconds`** (start time as a unix-seconds gauge — a series reset to "now" is the standard Prometheus restart signal; `changes()` alerts on it directly); and the port side gains **`witr_port_listeners{proto,port,owner}`** — one series per listening (proto, port), the `owner` label carrying the "name (pid N)" owner list, so unexpected listeners stand out. Beyond `/metrics` there is **`/api/ps`**: the whole process table as the same versioned envelope `--json` prints (with enriched user / start time and friends) — `curl -s localhost:9100/api/ps | jq` and you're in. The endpoint self-monitors with three series: `witr_scrapes_total`, `witr_scrape_duration_seconds`, `witr_scrape_timestamp_unix`. A bare port binds `127.0.0.1` (the metrics name your processes; don't broadcast them), `[HOST]:PORT` overrides; your Prometheus `scrape_interval` doubles as the sampling interval.

**Man page (`--man`)**: `witr-rs --man [FILE]` renders the full man page (roff, via clap_mangen) — with no argument it prints to stdout (`witr-rs --man | gzip > /usr/local/share/man/man1/witr-rs.1.gz` installs it), with FILE it writes there (creating missing directories).

**Config file**: `~/.config/witr-rs/config.toml` (macOS: `~/Library/Application Support/witr-rs/`, Windows: `%APPDATA%\witr-rs\`) — six keys, `refresh_secs` (sampling interval) / `sort` (default sort) / `notify` / `paused` / `watch` (watchlist) / `notes` (process annotations), acting as defaults for the CLI flags: the file loads first, the command line always wins. Bad lines are skipped with a warning; no file changes nothing.

**Watchlist (`w`)**: on the Processes tab, `w` stars the selected row and pins it to the top (your chosen sort still applies inside the pinned block); press again to unwatch. Entries persist by identity (name + exe basename + user) into the config file's `watch` key — no pid in the key, so the ★ follows the program across restarts. Tree mode skips pinning (it would tear children from parents); search filters still apply.

**System resources page (`y`)**: a whole-machine dashboard — CPU history chart (fixed 0–100 scale, current value + window peak annotated), memory history chart (absolute scale + peak), load average (1/5/15 min), swap usage, a per-core grid (cores ≥90% render red), and **disk mounts** (one usage bar per device-backed filesystem, ≥90% full renders red; local disks only, network mounts stay hidden). Linux reads `/proc` directly (microsecond-cheap, sampled every cycle so history is already there when the page opens); macOS uses Mach `host_processor_info` + `vm_stat`, Windows a single PowerShell CIM query (those two sample only while the page is open; the disk section sweeps df/CIM once per refresh while open on all platforms). Answers "how busy is this machine, how much memory is left, and which disk is nearly full".

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
| `T` | Processes tab: tree view ↔ flat table (children nest under their parent; a live search shows flat) |
| `F` | Logs page: toggle the live log stream (container `logs -f` / journald `journalctl -f` / macOS `log stream` — the command follows the source) |
| `a` | Ports tab: listening-only ↔ all socket states; Locks tab: locks ↔ all open files; Processes tab: actions bar (`k` kill / `K` tree-kill / `t` term / `p` pause / `r` resume / `n` renice) |
| `w` | Processes tab: watch the selected process (★ pins it to the top, persists to the config file across sessions, matched by identity so restarts under a new pid keep it); press again to unwatch |
| `N` | Processes tab: annotate the selected process (Enter saves / Esc discards / empty removes; identity-persisted, ✎ marker on the row, survives restarts) |
| `o` | Ports tab: per-socket detail ↔ aggregate overview keyed by (port, owner) (`Enter` opens the owner's process detail) |
| `l` | Detail page / Events tab: pull the process's recent logs (container logs / journalctl / macOS unified log) into a full-screen scrollable Logs page; on exited Events rows the auto-captured last words appear instantly |
| `S` | Open the session summary page (activity counts / restart chains / CPU-spike board / memory climbers; window from `--since`), `r` recompute, `Esc` back |
| `y` | Open the system resources page: machine-wide CPU/memory history charts, load, swap, per-core grid; `r` sample now, `Esc` back |
| `D` | Open the snapshot diff page: newest auto snapshot vs the live table (color-grouped new/gone/restarted/changed/listen rows + counts), `j/k` select, `Enter` jump into that process's detail page, `r` re-diff, `Esc` back |
| `P` | Pause / resume sampling (global freeze, footer shows `⏸ paused`; on Events, pid-descending sort is now `p` twice) |
| `!` | Toggle desktop notifications (`--notify` pre-enables; footer shows the state) |
| `z` | Zoom: the focused pane temporarily fills the row (tmux-style) |
| `x` | Kill the selected process (y/n confirm) |
| `?` | Keymap overlay: global keys + sections for the current tab, `j/k` scrolls, Esc/q/Backspace returns to the page it was opened from |
| `r` | Refresh now |
| In detail pages | `j/k` scroll, `d/u` half page, `g/G` top/bottom, `b/f` page, `Tab` switch panes, `a` actions bar, `l` recent logs, `/` search env vars, `z` zoom, `c` copy pane text, `Esc/q` back |
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

**Crash log correlation**: `l` on the detail page or the Events tab pulls the process's recent logs (container logs via `docker/podman/nerdctl logs`, `journalctl _PID=<pid>` on Linux, the unified log via `log show --predicate` on macOS) — after the Events tab flags a crash loop, `l` is where "why does it keep restarting" usually answers itself. Fetching runs on a background thread (`log show` can take seconds; the UI never freezes) and lands on a full-screen, scrollable Logs page. `F` toggles a **live stream** rendered into the same page, the command following the source (container `logs -f`, Linux `journalctl -f _PID=`, macOS `log stream --predicate`) — autoscrolling while you're at the bottom, capped at the last 500 lines, and the child CLI is killed when you leave the page or quit. CLI twin: `witr-rs --pid 1234 --logs [N]` (100 lines by default).

**Event persistence + replay**: `witr-rs --events-log events.jsonl` makes the TUI append every started/exited/restarted event the sampler produces as JSONL — the record survives the TUI, answering "what happened while I was away"; a **target-less `--watch` honors the flag too** — run headless in cron/systemd and events plus threshold alerts still land in the file. `witr-rs --replay events.jsonl` reads it back and opens straight onto the Events tab (imported history + live sampling layered on top, original timestamps preserved).

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
| Per-process disk I/O (TUI IO column + detail totals) | ✓ `/proc/<pid>/io` (byte deltas → rate) | ✓ `proc_pid_rusage` | ✓ PowerShell IO_COUNTERS |
| Per-process fd count (`--top fd` / `--alert-fd`) | ✓ direct `/proc/<pid>/fd` reads | ✓ single `lsof -F pf` sweep | ✗ |
| Start time | btime + starttime | `ps etime` | CIM CreationDate |

Optional cross-platform extras (identical on all three; silently skipped when the dependency is missing): `nvidia-smi` (GPU column), `kubectl` (K8s pod attribution), `docker`/`podman`/`nerdctl` (Containers tab).

External commands required: Linux — none strictly (systemctl/docker optional); macOS — `ps`/`lsof` (built in); Windows — `powershell`/`netstat`/`tasklist` (built in).

## Install

One-liner (macOS / Linux — downloads the release archive for your platform, verifies its sha256 and installs to `~/.local/bin`, override with `WITR_INSTALL_DIR`):

```bash
curl -fsSL https://raw.githubusercontent.com/yaowenqiang/witr-rs/main/install.sh | sh
```

Or grab the archive for your platform from [GitHub Releases](https://github.com/yaowenqiang/witr-rs/releases) (sha256 checksums in `sha256sums.txt`). Pushing a `v*` tag makes CI build every target automatically:

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
witr-rs --pid 1234 --logs 50  # the process's last 50 log lines (container/journal/unified log)
witr-rs --events-log ev.jsonl # record TUI events to disk (JSONL, append)
witr-rs --watch 5 --events-log ev.jsonl # record headless: live event + alert log with no UI (cron/systemd friendly)
witr-rs --replay ev.jsonl     # replay a recording, opening on the Events tab
witr-rs --replay ev.jsonl --since 1h # "what happened" digest of the recording: counts + restart chains, printed and exit
witr-rs --top cpu -n 30       # top 30 by CPU (--top mem|fd|io|io-rate|age likewise; no TUI)
witr-rs --top io-rate -n 10   # disk I/O rate board (read+write MB/s; persistent history under --watch)
witr-rs --top age -n 10       # top 10 oldest processes (age ranking; pid 1 always wins)
witr-rs --top cpu --watch 5   # live CPU board, reranked every 5s (Ctrl-C exits)
witr-rs --csv                 # whole table as CSV (RFC-4180 escaping; --markdown for docs)
witr-rs --watch 5 --record load.csv # append the whole table to a CSV every 5s
witr-rs --watch 5 --record load.jsonl # same time series, NDJSON envelopes (ppid/state/age included)
witr-rs --tree --json         # whole table as nested JSON (children under parents)
witr-rs --report-html status.html   # self-contained HTML report (bars + top boards + full table)
witr-rs --alert-fd 4096 --alert-io 100 # fd-count / disk-IO-rate threshold alerts (same mechanism as CPU)
witr-rs --alert-conn 200      # per-process ESTABLISHED connection-count alerts (TUI and --watch)
witr-rs --watch 5 --alert-cpu 90 # headless watchdog: prints a ⚠ alert line on each firing, no TUI
witr-rs --watch 5 --quiet --alert-mem 2048 # even quieter watchdog: no per-tick redraw, alerts/hooks only
witr-rs --watch 5 --times 12  # sample for one minute, print the summary and exit (--json: the summary is a JSON envelope too)
witr-rs --port 8080 --watch 2 --on-start 'say up' # run a command once on the target-appears edge (wait-for-deploy)
witr-rs --alert-cpu 90 --alert-exec 'curl -s $SLACK_HOOK -d "$WITR_ALERT_NAME: $WITR_ALERT_DETAIL"' # run a command on every alert firing (webhook)
witr-rs --watch 2 --alert-port 9090 # port canary: alert when something starts listening on :9090 (TUI works too)
witr-rs --watch 2 --alert-port '!8080' --alert-repeat 60 # alert when :8080's listener disappears; re-nag every 60s while down
witr-rs --audit 'cargo build --release' # run a wrapped command, then print its subtree report (duration/exit code/peak CPU/RSS/disk IO + tree)
witr-rs runaway --kill        # headless kill of matched targets (--signal KILL picks the signal; --kill-tree takes the descendants first)
witr-rs --pid 1234 --logs 200 --grep ERROR # show only matching log lines (needs --logs)
witr-rs --snap before.json    # write the process table as JSON and exit
witr-rs --snap                # auto snapshot: stored next to the config dir, rotating (keeps 10; --keep N)
witr-rs --snap=now.json --sockets # also record LISTEN ports (for --diff to report listener changes)
witr-rs --diff before.json    # new / gone / restarted / changed / listen-new / listen-gone vs a snapshot (identity-based; pid reuse doesn't fool it; exit 1 on change)
witr-rs --diff last           # diff against the newest auto snapshot (--diff 30m = the one from 30 minutes ago)
witr-rs --diff last --json    # machine-readable diff envelope (summary counts + entries)
witr-rs --serve :9100         # Prometheus /metrics + /api/ps JSON process-table endpoint (samples on every scrape; binds 127.0.0.1 by default; includes port gauges, the restart-signal start_time and self-monitoring metrics)
witr-rs --man                 # render the man page (stdout; --man FILE writes a file, creating the directory)
witr-rs --pid 1234 --follow   # keep tracing across restarts (new pid, same program; hinted when a --pid comes up empty)
witr-rs --pid 1234 --follow --on-exit 'say gone'  # run a command once when a watched target disappears (follow then exits 2 when truly gone)
witr-rs --notify              # TUI desktop notifications: restarts always, crash-loop exits too
witr-rs --completions zsh     # shell completion script (bash|zsh|fish|powershell)
witr-rs -i --port 8080        # TUI seeded to that port (-i, see above)
witr-rs nginx --pid 1         # mix multiple targets (divided per target)
NO_COLOR=1 witr-rs nginx      # disable colors (--no-color does the same)
```

Shell completions (pick your shell):

```bash
witr-rs --completions bash >> ~/.bashrc      # or zsh → ~/.zshrc, fish → ~/.config/fish/completions/witr-rs.fish
```

### Exit codes

| Code | Meaning |
|---|---|
| 0 | OK, no warnings |
| 1 | Found, but with warnings (running as root, listening on all interfaces, deleted binary, LD_PRELOAD, zombie, …) |
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
├── render.rs       standard / tree / short / json / env / warnings / export / csv / markdown / top / html renderers
├── history.rs      sampling history: instantaneous cpu, sparklines, memory trend + leak suspicion, restart detection, event feed, session summary
├── config.rs       user config file (flat toml subset: refresh_secs/sort/notify/paused/watch/notes; CLI overrides)
├── snapshot.rs     --snap / --diff: full-table snapshots (with auto-rotation) + new/gone/restarted/changed comparison
├── serve.rs        --serve: Prometheus text-format endpoint (hand-rolled HTTP on std::net, scrape-driven sampling, bounded cardinality)
├── logs.rs         crash log correlation: container logs / journalctl / macOS unified log
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

## Known limitations

- TUI Ports/Containers/detail pages are snapshots from when they opened — `r` refreshes manually
- Windows process details rely on batched PowerShell queries (one call per target, 20s timeout guard); the Windows CPU% column comes from `Get-Process` sampling deltas between refreshes (empty when PowerShell is unavailable)
- Log correlation (`l` / `--logs`) covers container logs / Linux journald / the macOS unified log; Windows has no equivalent single log source yet (crash forensics is likewise absent on Windows). The live `F` stream covers container / journald / unified log; the Windows event log has no streaming equivalent
- Desktop notifications work on all three platforms (macOS osascript / Linux notify-send / Windows WinRT toast); Windows still has no per-process I/O — the IO column and the detail-page I/O chart are absent there
- Event persistence (`--events-log`): both the TUI and a target-less `--watch` can record, and `--replay` replays either; the watch sampling granularity is the `--watch` interval (default 2s) — processes born and gone inside one window are invisible
- The `--watch` Ctrl-C summary relies on a SIGINT hook (unix); on Windows use `--times N` to end a run (the summary is there in the `--times` exit and the `--json` envelope)
- The session-digest (`--since`/`S`) CPU-spike and memory-climber boards only cover processes alive at the last refresh (dead pids are pruned) — a spike-then-exit shows up in the activity counts, not on the boards; the `--replay` file digest carries activity counts and restart chains only (recordings hold no samples)
- `--follow` matches by program identity (name+exe+user): a restart of a script that runs under several parallel instances may attach to a sibling rather than "the" successor (the most recently started instance wins)
- FD trend sampling happens only while the detail page is open (macOS pays one `lsof -p` per tick, ~100ms); Windows has no fd source, so the section is absent there
- Container attribution is Linux-only (container processes behind colima/Docker Desktop on macOS are not attributed, though `-c` targets get a runtime-side fallback view)
- Windows has `--file` (Restart Manager) but no Locks data
- macOS `launchctl list` only covers the current user domain; system daemons need sudo to be labeled. macOS file locks are approximated from `lsof` flags — the kernel exports no lock table there
- nohup/disown detection is Linux-only (no `/proc` on macOS/Windows, so no such warning there)
- The GPU column covers NVIDIA only (`nvidia-smi`); there is no per-process utilization source for Apple Silicon / AMD GPUs
- `--top fd` / `--alert-fd` are absent on Windows (no per-process fd source); `--top io` / `--alert-io` and the `--record` io-rate columns are Linux-only (`/proc/<pid>/io`)
- `--serve`'s per-process fd gauge (`witr_process_open_fds`) is emitted only where fd counts exist (Linux/macOS, same limits as `--top fd`); the other metrics export everywhere

## License

Apache-2.0. Design follows pranshuparmar/witr (also Apache-2.0).

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

**FD trend + leak suspicion (detail page)**: the same logic aimed at file descriptors — while the detail page is open, the fd count is sampled once per refresh (Linux reads `/proc/<pid>/fd`, macOS asks libproc's `proc_pidinfo` natively — a microsecond syscall, no subprocess; Windows falls back to a full-table handle sweep — likewise paid only while the page is open), and an `Open fds (N)` history chart appears; growth ≥64 descriptors over the window with ≥70% monotonically rising segments raises a yellow "possible fd leak" — the socket-per-request service that never closes them gives itself away.

**Thread trend + leak suspicion (detail page)**: the fd chart's twin aimed at kernel thread counts. Threads ride the whole-table listing (Linux `/proc/<pid>/stat` nlwp, the Windows ToolHelp thread snapshot, macOS one `ps -axo pid=,nlwp=` sweep — all three platforms), and a `Threads (N)` history chart appears; growth ≥16 threads over the window with ≥70% monotonically rising segments raises a yellow "possible thread leak" — the service that spawns a thread per request and never reaps it surfaces here. Paired with the **`--top threads`** board, the **`--alert-threads N`** threshold and the `thr>N` numeric filter.

**Swap column + `--top swap` (Linux)**: the process table grows a SWAP column only when someone is actually sitting in swap (zero dead width on machines that never swap), showing each process's paged-out bytes (`/proc/<pid>/status` VmSwap); the detail page adds an "In swap" line. The machine-level swap percent answers "how much got paged out" — `--top swap -n 10` names the pid, the first question worth asking when memory runs tight.

**Detail-page disk I/O chart**: two block-char sparklines for read/write rates (each annotated with its window peak), fed by the same cross-platform cumulative-byte deltas as the IO column (Linux `/proc/<pid>/io`, macOS `proc_pid_rusage`, Windows PowerShell `IO_COUNTERS`).

**Snapshot diff (`--snap` / `--diff`)**: `witr-rs --snap before.json` writes the whole process table as JSON; later `witr-rs --diff before.json` reports what changed — **new** processes, **gone** ones, **restarted** (same program identity back under a new pid, like the TUI's crash-loop detector — including a restart that happens to reuse the same pid: same pid, same identity, different start time counts as restarted) and **changed** (same pid, same identity, different command line). A pid taken over by an unrelated program no longer mis-reports as changed: the old process is **gone** (noted "pid taken over"), the new one **new** (noted "pid reused"). Snapshots taken with **`--sockets`** also record the current LISTEN ports, and `--diff` then reports **listen-new / listen-gone** — a first-pass canary for "something new started serving on :8080 after the snapshot" (an existing port merely changing owners is not reported). Exit code 1 when anything changed, 0 otherwise — script-friendly. Pathless `witr-rs --snap` **auto-rotates**: snapshots land in `snapshots/` next to the config dir, keeping the newest 10 by default (`--keep N`); `--diff last` compares against the newest auto snapshot and `--diff 30m` against "30 minutes ago" — what appeared and disappeared in the last half hour, one command. `--diff` with `--json` emits a machine-readable versioned envelope (`summary: {new, gone, restarted, changed, listen_new, listen_gone, total}` + `entries`, jq-ready); in the TUI, `D` opens the same comparison — newest auto snapshot vs the live table, color-grouped rows (listen changes in cyan/magenta), `j/k` to select, `Enter` to jump into that process's detail page, `r` to re-diff.

**Ranking (`--top`)**: `witr-rs --top cpu -n 30` skips the TUI and prints the top N processes ranked by CPU / memory / fd count / disk I/O / age / **disk I/O rate** / **GPU SM utilization** (`--top gpu`, when an NVIDIA driver is present) / **kernel thread count** (`--top threads` — the thread-leak ranking, carried with the whole table on all three platforms: Linux `/proc stat`, the Windows thread snapshot, macOS `ps nlwp`) / **ESTABLISHED connection count** (`--top conn` — the ranking twin of `--alert-conn`: who holds the most live connections) / **TCP throughput** (`--top net` — the ranking twin of `--alert-net-per-proc`, sent+received bytes/s diffed from two `ss(8)` sweeps: who is eating the NIC, at a glance) (`--top fd` reads `/proc/<pid>/fd` on Linux, sweeps the table natively via libproc on macOS (one `proc_pidinfo` query per pid, no subprocess) and uses PowerShell `Get-Process` handle counts on Windows; `--top io` and `--top io-rate` work on all three platforms — io-rate ranks by read+write MB/s, the one-shot mode takes two samples 1 s apart and `--watch` uses the persistent sample history; `--top age` ranks oldest-first — pid 1 always wins, and the trailing column flips to the process state). Pair with `--watch N` for a live board: `--top cpu --watch 5` resamples, reranks and redraws every 5 seconds; Ctrl-C exits. "What's busiest right now" without opening a UI. The boards themselves take the tabular outputs too: `--top cpu --csv` / `--top cpu --markdown` hand the ranking straight to scripts and docs (`--json` was already supported; `--top` with `--report-html` is still rejected).

**Tabular output (`--csv` / `--markdown`)**: machine-readable forms of the process table — `--csv` escapes per RFC-4180 (commas, quotes and newlines inside command lines are safe), `--markdown` pastes straight into an issue or doc; both include NAME plus the full command line.

**Aggregate by name (`--by-name`)**: `witr-rs --by-name` folds the whole process table by (name, user) — columns NAME / USER / N (instance count) / ΣCPU% / ΣRSS MB / ΣCPUTIME / AGE(OLDEST), sorted by ΣRSS descending. "What do those 34 renderer processes cost **combined**" on one screen. Pairs with `--csv` / `--markdown` / `--json` (versioned envelope: `group_count` + `groups`) and `--watch N` for a live view. ΣCPU% is the sum of the platform's lifetime averages (same source as the table column); ΣCPUTIME is the honest cumulative CPU time.

**CSV time series (`--watch` + `--record`)**: `witr-rs --watch 5 --record load.csv` appends the whole process table to a CSV every 5 seconds — timestamp / pid / user / name / cpu_pct / rss_mb / io read+write rates / gpu_sm (columns left empty where the platform doesn't report them), plus four machine columns `sys_load1` / `sys_mem_pct` / `sys_procs` / `sys_net_bps` (recorded on a single `pid=_system` summary row — load, memory percent, process count and combined NIC receive+transmit bytes/s, same file same cadence as the process rows). Replay the load curve afterwards with Excel / pandas / SQLite; console output is untouched. A `.jsonl` path switches to **NDJSON mode**: one versioned JSON envelope per tick (`{schema_version, generated_at, process_count, processes}`), with ppid / state / age_secs riding along per process — `jq '.processes[] | select(.rss_mb > 500)'` and you're in; the machine snapshot rides in the same envelope's `system` key (`load1` / `cpu_pct` / `mem_used_mb` / `mem_pct` / `proc_count` / `net_bps`, null where the platform can't measure). **Long-run hygiene (`--record-max-mb MB`)**: when the `--record` or `--events-log` file passes this size it rotates to `<file>.1` (the previous .1 is dropped) and starts fresh — CSV mode re-writes the header after a rotation, so `--plot` / `--samples` read rotated output without special cases; disk use stays bounded (2× the cap) however many months the watchdog runs. The knob also lives in the config file (`record_max_mb = 200`).

**Time-series chart (`--plot`)**: `witr-rs --plot load.csv` renders a `--record` sample file (both .csv and .jsonl are accepted) into a self-contained HTML time-series chart, written to `load.csv.html`, then exits — five inline-SVG charts (machine cpu% / memory% / 1-minute load / network rate MB/s / process count), no JS, no external assets, double-clickable offline. **Multiple files** overlay their curves — `--plot before.jsonl after.jsonl` records once before and once after a release, and one chart shows the difference (output `witr-plot.html`). "Record now, look at the load curve later" without opening Excel.

**Grafana dashboard export (`--export-grafana FILE`)**: writes a ready-made Grafana dashboard JSON — 16 panels spreading the whole `/metrics` vocabulary across one screen: machine cpu / memory / swap / load / process count, PSI stalls, NIC throughput and drops, TCP retransmit rate, container cpu / memory / throttle rate / OOM kills / disk I/O, and top-CPU / top-RSS process boards (`topk(5, …)`); every PromQL expression is pre-filled — import into Grafana, pick the Prometheus datasource, done. Building panels was the only toil left after the exporter; one command retires it.

**HTML report (`--report-html`)**: `witr-rs --report-html status.html` writes a self-contained single-file report (no JS, no dependencies): per-process CPU / memory bars, Top-CPU / Top-memory boards, and a nine-column table of every process, fully HTML-escaped — attach it, archive it, send it.

**Tree kill (`K`)**: the actions bar gains `K` — a BFS over ppid links collects every descendant of the selected process (grandchildren included, even if a parent is reaped mid-walk), prompts `kill pid N + M descendant(s)? y to confirm`, and SIGTERMs the whole tree on `y`. Killing a worker pool or a user session tree no longer means hunting pids one by one.

**Headless kill (`--kill` / `--kill-tree`)**: `witr-rs runaway --kill` signals the matched targets directly, no UI — `--signal KILL` (`SIGKILL` synonym, default `TERM`) picks the signal, `--kill-tree` BFS-collects all descendants first and kills children before their parents (the same collection logic as the TUI's `K`). Mutually exclusive with `-i`/`--watch`/`--follow`; exit code 2 when nothing matched, 1 when any kill failed — scripts can branch on the result. Each kill prints `killed <name> (pid N) [SIGKILL]`. **`--dry-run`** prints the kill plan only (`would kill …`, including --kill-tree's collected descendants, in the exact order the real run would use) without signaling anything; exit codes unchanged — inspect first, kill second.

**Scripting primitives (`--pids-only` / `--wait`)**: `witr-rs nginx --pids-only` prints just the space-separated matched pids (exit code 2 when nothing matches) — `witr-rs nginx --pids-only | xargs kill` is a one-line kill. `witr-rs --port 8080 --wait` blocks until the target exists (`--wait gone` waits for it to disappear instead), polling once per second, printing the result and exiting 0 once the condition holds; **`--timeout N`** bounds the wait, exiting 124 on timeout (the GNU timeout convention) or 130 on SIGINT — `--pid 1234 --wait gone --timeout 60` is the "wait for the deploy script to retire the old process" primitive.

**Process notes (`N`)**: on the Processes tab, `N` opens a note prompt for the selected process (Enter saves, Esc discards, empty text removes), persisted by identity into the config file's `notes` key — the note follows the program across restarts and new pids; the table row shows a ✎ marker and the detail page gains a Note section. Leave the answer to "what is this python actually doing".

**Help overlay (`?`)**: from any page, `?` opens a full keymap for the current tab (global keys + per-tab sections), `j/k` scrolls; Esc / q / Backspace / `?` again returns to the page it was opened **from** (open it on a detail page, land back on that detail page). No key left unmemorized.

**JSON schema**: `--json` output is now a versioned envelope `{schema_version, generated_at, process_count, processes}` so downstream parsers can check the version before trusting the shape; `--tree --json` turns the no-target listing into a **nested forest** (children nest under their parent's `children`, same rules as the text tree: orphans and ppid cycles become roots, pid-ascending); `--diff --json` adds the same envelope plus a `summary` of counts.

**Follow across restarts (`--follow`)**: `witr-rs --pid 1234 --follow` keeps tracing the target after it dies — when the pid exits, the process table is re-scanned for the same program identity (name+exe+user) and the trace continues under the new pid (implies `--watch`; gives up after the identity stays missing for 3 refreshes). Multi-instance ambiguity resolves to the most recently started match.

**`--watch [seconds]`**: live mode — with targets it re-runs the trace pipeline and re-renders every N seconds (default 2); without targets it refreshes the process table. Composes with `--recent`/`--json` etc. **`--times N`** bounds the loop for CI/cron — `--watch 5 --times 12` samples for a minute and exits (code 0; 130 when interrupted by SIGINT). The target-less watch ends with a **summary**: on Ctrl-C (unix) or `--times` it prints what happened during the run (activity counts + restart chains, same data as the TUI's `S` page; `--json` wraps it in a JSON envelope with `ticks` / `interrupted` / `summary`). Three shapes for the target-less watch: default redraws the whole table; **`--quiet`** skips the redraw and prints only alerts/hooks (a headless watchdog can run for days without filling the scrollback); **`--watch --json`** emits one JSON envelope per tick on stdout (alerts go to stderr so a `| jq` pipe stays clean).

**Event hooks (`--on-start` / `--on-exit`)**: while watching/following a target, run a command once on the appear/disappear edge — `--watch 2 --on-start 'say up'` is a wait-for-deploy script (it also fires on the first tick if the target is already up), `--follow --on-exit 'say gone'` is a departure sentinel. Commands run via `sh -c`; their exit codes don't affect the watch loop.

**Command audit (`--audit CMD`)**: `witr-rs --audit 'cargo build --release'` wraps a command, samples its process subtree every 500 ms while it runs, and prints a report when it exits — wall duration, exit code, spawned process count and peak alive count, subtree peak CPU / peak RSS, total disk read+write, plus the full process tree (each member at its last sighting). Two deliberate approximations (both documented in the code): a child that exits mid-run keeps its contribution (cumulative I/O and identity are remembered at last sighting); a child whose parent exited reparents and breaks the ppid walk, so one generation of catch-up adopts processes whose parent was in the previous tick's subtree (deeper reparent chains can still slip away — rare in build trees, where the chain dies root-first). "How much did this build actually eat, and how many processes did it spawn" in one command; the command's exit code passes straight through for CI. With **`--json`** the same report comes out as a versioned envelope (`duration_secs` / `exit_code` / `killed_by_signal` / `spawned` / `peak_alive` / `peak_cpu_pct` / `peak_rss_bytes` / `io_read_bytes` / `io_write_bytes` + `tree`) — jq-ready in CI.

**Dead-target hints**: when a trace comes up empty, witr-rs suggests the next step — a missing `--pid 999999` hints that "`--follow` keeps tracing across restarts"; a mistyped name gets the three closest candidates by edit distance (`witr-rs nginxx` → `closest: nginx, ...`), so a typo doesn't cost a whole investigation round.

**Peer attribution (TUI detail page)**: each ESTABLISHED connection is reverse-matched against the peer socket's owner and the detail page shows `talking to: <process> (pid N) — k connection(s)`; when the peer lives elsewhere you get the remote address.

**Controlling-terminal attribution (tty)**: every process carries its controlling terminal (`ttys004` / `pts/3`); daemons and nohup'd processes with none show **detached (`-`)** — "which terminal started this, or does it answer to no one" at a glance. The CLI identity block (dimmed `detached (no controlling terminal)`), the `--export` report and the TUI detail page all show the line; `--json` carries an optional `tty` field. The same identity block also carries the **process group and session** (`pgid` / `sid`, from Linux `/proc/<pid>/stat` and macOS `ps`) — signal the group leader or the whole group, or tell which session a process belongs to, without a separate `ps -o pgid -o sid`.

**cgroup resource panel (Linux detail page)**: on Linux, opening a process detail reads the `0::` line of `/proc/<pid>/cgroup` for the cgroup v2 path, then reads that group's `memory.current` and `cpu.stat`'s `usage_usec` back from `/sys/fs/cgroup` — the CLI detail block, `--export` and the TUI detail page all show `cgroup <path> · mem <usage> · cpu <total seconds>`. This is the group-level view for containers/services: RSS answers "how much does this process eat", the cgroup answers "how much does its whole container/service eat". The root group (the whole machine) is not shown. The path is also **classified**: docker / containerd / podman / kubepods / lxc / colima scopes identify as containers (annotated with the container id, resolved to its owning Pod via kubectl in k8s setups — `kubernetes pod ns/name · container <id12>`), while a `.slice` leaf ending in `.service` / `.socket` / `.timer` &c. identifies as a systemd unit (system or `user@` user level) — the Started-by attribution climbs from "who is this process's parent" to "which service unit / container runtime pulled it up".

**Ports overview (`o`, Ports tab)**: flips the per-socket table into an aggregate keyed by (port, owning process) — columns Port / Proto(s) / Process / PID / User / Addrs (how many addresses the port is bound on; tcp+tcp6 merge into one row), sorted by port, with `/` search and `Enter` jumping to the owner's process detail page. "Who is serving what on this machine" at a glance.

**Crash forensics (exit-time capture)**: the moment an exit event fires, the TUI grabs the dying process's last log lines in the background (macOS unified log by process name / Linux journald by `_PID=`, up to 25 lines, the most recent 50 cached); `l` on an exited/restarted Events row shows these "last words" **instantly** — no racing the log rotation, the crash scene is frozen at exit time.

**Desktop notifications (`--notify` / `!`)**: the TUI fires a system notification whenever a target process restarts; once the same name has restarted ≥2 times this session, its plain exits notify too (crash-loop alerts). macOS uses `osascript`, Linux `notify-send`, Windows a native WinRT toast via PowerShell (no extra module) — sent from a background thread so sampling never stalls; `--notify` pre-enables it and `!` toggles live (footer shows the state).

**Pause sampling (`P`)**: freezes TUI sampling — no refresh, no new events, no notifications, footer shows `⏸ paused`; press again to resume. Read the list or copy a scene without the data flowing past you.

**Session digest (`--since` / `S`)**: `witr-rs --replay ev.jsonl --since 1h` skips the UI — it prints a "what happened" digest of the recorded window and exits (pipe-friendly): started / exited / restarted counts plus restart chains (which program restarted how many times). In the TUI, `S` opens the same digest as a full page: activity counts, restart chains, and two boards — **CPU spikes** (highest instantaneous peak per process in the window) and **memory climbers** (fastest RSS growth); `--since` presets the window (30, 30s, 5m, 2h, 1d — default: whole session), `r` recomputes. Answers "what has this machine been busy with for the last half hour".

**Threshold alerts (`--alert-cpu` / `--alert-mem` / `--alert-fd` / `--alert-io` / `--alert-conn` / `--alert-threads`)**: `witr-rs --alert-cpu 90 --alert-mem 2048` — when a process exceeds the threshold for 5 consecutive samples (~15 seconds): a desktop notification fires, the Events tab records an alert, and the row highlights red. One notification per excursion; when usage drops back under, a **recovery event** is recorded (`✔ recovered: <name> (pid N) — detail`, kind=recovered) — the alert's full lifecycle (fired → recovered) leaves traces on the Events tab, in `--events-log` and on a headless watch's stdout, and the detector re-arms automatically. `M` in the TUI is a global mute: alert evaluation keeps running but no side effects fire, and muted entries land in the ring as kind=silenced (there's an accounting of "why didn't anything ring during that window"). `--alert-fd 4096` watches open-file counts (Linux reads `/proc` directly; macOS sweeps one `lsof` pass per cycle — only while the alert is armed); `--alert-io 100` watches disk I/O rate (read+write MB/s, from Linux `/proc/<pid>/io` deltas); `--alert-conn 200` watches per-process ESTABLISHED connection counts; `--alert-threads 400` watches kernel thread counts (Linux `/proc stat` and the Windows thread snapshot carry them with the whole table — services whose threads only ever climb give themselves away); `--alert-net-per-proc 5` watches per-process TCP throughput (sent+received MB/s, diffed from `ss(8)` sweeps — quietly exfiltrating data and services saturating the uplink get named by pid; Linux with ss(8) on PATH); `--alert-deviation 10` watches **self-baseline deviation** — fire when a process's instantaneous CPU exceeds its own trailing ~2-minute median by X times (and clears the absolute 5% floor) for 5 consecutive samples: "the quiet daemon suddenly busy" needs no per-process threshold to exist, and the baseline adapts to the process (armed after ~36s of history; the median can't be dragged by the burst itself until half the window turns over). Ten machine-wide thresholds: **`--alert-load N`** (1-minute load average over N for 5 consecutive samples), **`--alert-mem-pct PCT`** (whole-machine memory percentage over PCT for 5 consecutive samples), **`--alert-count N`** (visible process count over N for 5 consecutive samples — a sentinel for table explosions like fork bombs and runaway task spawners), **`--alert-disk PCT`** (any local disk's used percent over PCT for 5 consecutive samples — a shout before the disk fills, the detail naming the fullest mounts; the df sweep is paid only while the alert is armed), **`--alert-net MB/S`** (combined receive+transmit rate across all non-loopback NICs over MB/S for 5 consecutive samples — the sentinel for a saturated uplink or a process quietly exfiltrating; NIC counters are sampled only while the alert is armed or the system resources page is open) **`--alert-psi PCT`** (Linux PSI pressure — any resource's "full" stall percentage over PCT for 5 consecutive samples, the detail naming the resource and the reading; when the machine is stalled so hard the scheduler can't even run, load average hasn't caught up yet but PSI is already shouting), **`--alert-mem-avail-mb MB`** (reclaimable memory (MemAvailable) below this absolute floor in MB for 5 consecutive samples — the last sentinel before the OOM killer; percentage thresholds lie on big-RAM machines, "MB left" doesn't), **`--alert-swap-pct PCT`** (swap used percent over PCT for 5 consecutive samples — memory pressure spilling onto disk), **`--alert-retrans SEG/S`** (TCP retransmit rate over this many segments/s for 5 consecutive samples — the top cause of "the network got slow", invisible to load and PSI; counters diffed from Linux `/proc/net/snmp`) and **`--alert-nic-drop PKT/S`** (combined rx+tx drop/error counters across non-loopback NICs over this many packets/s for 5 consecutive samples — throughput can look fine while packets never arrive; `/proc/net/dev` counter deltas) — the same "5 samples + latch" machinery, working in the TUI and under `--watch` alike, logged as `(system)` entries on the Events tab, with `--alert-repeat` / `--alert-exec` applying as usual. With **`--alert-exec`** a custom command runs on every firing (the context rides in as `WITR_ALERT_PID` / `WITR_ALERT_NAME` / `WITR_ALERT_DETAIL` environment variables), or use **`--alert-webhook URL`** to POST each firing as JSON (`{schema_version, kind:"alert", at_unix, pid, name, detail}`) to any http:// receiver — sent from a background thread with a 3-second timeout, never stalling sampling or the watch loop (https wants a reverse proxy or gateway in front; it only fires when you set it, zero default traffic). Alerts don't live in the TUI alone: **`--alert-*` under `--watch` is a headless watchdog** — `witr-rs --watch 5 --alert-cpu 90` checks thresholds every tick and prints a `⚠ alert: <name> (pid N) — detail` line on each firing (same 5-samples-and-latch machinery as the TUI, `--alert-exec` / `--alert-webhook` still apply), so the machine can be watched with no UI at all; add `--events-log` and alerts land in the same JSONL stream as started/exited/restarted events (replayable via `--replay`). All of these thresholds can also live in the **config file** (`alert_cpu = 90` / `alert_webhook = "http://..."`, key names matching the flags one for one) — a watchdog deployed as a systemd service keeps its thresholds in config.toml and the command line stays just `--watch`.

**Port canary (`--alert-port`) + repeat nagging (`--alert-repeat`)**: `--alert-port 9090` watches LISTEN ports for an **edge** — the moment something starts listening on :9090 it alerts `listener appeared on :9090 (<owner>)` (the first observation only arms: a port already bound at startup is the status quo, not an event — the same edge semantics as `--on-start`/`--on-exit`). Prefix `!` to invert into a gone-sentinel: `--alert-port '!8080'` alerts `listener gone from :8080 (was <owner>)` when the listener disappears. Repeatable, so several ports can be watched at once. **`--alert-repeat 60`** re-sends a sustained alert about every 60 seconds (the clock resets on first fire and on re-arming after a drop back under; unset keeps the classic once-per-excursion) — a watchdog that keeps nagging until someone looks. TUI and `--watch` alike; `--alert-exec` and `--events-log` work as usual.

**Alert silence windows (`--alert-silence`)**: `--alert-silence backup=30m db=1h` — processes whose name contains backup stop raising alerts for the first 30 minutes of the session, db-names for one hour (a **maintenance window**: nightly backups and batch jobs don't wake you); without `=DUR` the whole session is silenced; `!NAME` inverts (silence names **not** matching — the reverse allowlist). Several at once, TUI and `--watch` alike. Silenced processes are still evaluated; the firing is just replaced by a kind=silenced event (`--events-log` still records it — there's an audit trail of what happened while silenced), and `--alert-exec` / `--alert-webhook` / desktop notifications all stay quiet. Also lives in the config file (`alert_silence = ["backup=30m", "db"]`).

**First-sighting alerts (`--alert-new-proc`)**: `--alert-new-proc xmrig miner` — the first time a process whose name contains any pattern appears this session, it alerts (a **miner/backdoor sentinel**: new faces a normal machine shouldn't see). The `!NAME` prefix switches to **whitelist mode** — `--alert-new-proc '!nginx' '!cron'` alerts only on names matching no pattern ("only these should ever run here"); the two forms can't be mixed. Each name fires once per session (a HashSet keeps the books), TUI and `--watch` alike, with `--alert-exec` / `--alert-webhook` / `--events-log` applying as usual. Also lives in the config file (`alert_new_proc = ["xmrig", "!nginx"]`).

**Service installer (`--install-service`)**: `witr-rs --watch 5 --alert-cpu 90 --install-service` bakes **the exact flags you just proved out** into a system service and registers it — Linux writes a systemd user unit (`~/.config/systemd/user/witr-rs.service`, `enable --now`), macOS a launchd plist (`~/Library/LaunchAgents/`, `launchctl load`), Windows a schtasks XML plus the registration command. Prove the thresholds with `--watch` interactively, then one command turns them into a boot-persistent watchdog (targets, every `--alert-*`, the silence/first-sighting lists, `--events-log`, `--record` all ride into the service definition). A custom path (`--install-service /tmp/w.service`) only writes the file and prints the manual registration hint — no system-level side effects; only the default path auto-registers. **The systemd unit carries `WatchdogSec`** (sampling interval × 3, 60s floor): the service process sends a WATCHDOG=1 sd_notify heartbeat every sampling tick — if witr-rs itself hangs (blocked IO, deadlock) systemd kills and restarts it, so the watchdog is no longer an unsupervised single point; READY=1 goes out at startup. Non-systemd platforms keep their own keep-alive mechanisms (launchd KeepAlive, schtasks).

**Short-lived process capture (brief)**: processes that spawn and die inside one sampling tick (port scans, the first wave of a fork bomb, every-minute crontab jobs) are invisible to a 3-second sampler — the TUI and a target-less `--watch` automatically start a **250ms high-frequency poller** (Linux readdir `/proc`, macOS native `proc_listallpids` — no subprocess on either; Windows has no equivalently cheap sweep and skips it) catching processes that live ≤5 seconds, recorded as kind=brief events (the name resolves at first sighting — after death it's too late to ask; unresolved ones report `pid N`), one `>> brief: sleep (pid 7965) — spawned and exited within ~1292ms` line on stdout, `--events-log` as usual, visible on the Events tab.

**Time scrubbing (`<` / `>`)**: the TUI keeps a rolling buffer of the last 30 process-table frames — on the Processes tab, `<` steps back through history (the table returns to that moment: who was alive then, what their CPU was; the tab bar lights a yellow REPLAY badge), `>` steps forward, and reaching the end returns to live. Alert machinery pauses while scrubbing (replayed frames raise nothing) but the buffer **keeps recording** — step back, look around, step forward to now, nothing was missed. "The machine was fine ten minutes ago — where exactly did it turn" without snapshots or recordings: hold `<` and walk back.

**Remote mode (`--remote URL`, repeatable)**: `witr-rs --remote http://10.0.0.7:9100` doesn't look at this machine — it pulls `/api/ps` from a remote `witr-rs --serve` endpoint (under `--tree` it still pulls the flat table and rebuilds the forest locally) and renders it with the exact same renderers as the local listing — table / `--json` / `--csv` / `--markdown`; `--watch N` re-fetches on an interval (clear-and-redraw, `--times N` bounds it). **`--remote` is repeatable** — a whole fleet at once: one divider-labeled section per host (`----- [host] -----`), an unreachable host prints a ⚠ line without sinking the rest (exit 5 only when every host is down); multi-host `--json` emits the fleet envelope (`host_count` + `hosts[]`, each entry carrying `host` / `process_count` / `processes`, failures recorded as `error`). One witr-rs binary on the jump host and a few SSH tunnels is all it takes — "the neighbor machines' process tables" without Prometheus or a web page: one `--serve` per far side, `--remote` whenever you like. Zero new dependencies (hand-rolled HTTP GET on std::net, http:// only — TLS via a reverse proxy).

**Config hot reload (SIGHUP)**: `kill -HUP $(pidof witr-rs)` re-reads the config without a restart — the TUI immediately re-folds every knob (sampling interval, sort, alert thresholds, silence/first-sighting lists, notifications; the **watchlist and alert state stay** — retuning thresholds doesn't lose fired latches), and a headless `--watch` picks it up on the next tick. Semantics match startup: command-line flags always beat the file, and a reload only moves what the file changed. Tweak config.toml without killing anything.

**Ports overview (`--ports`)**: skip the UI and print every current LISTEN port — columns port / proto / owners (multiple owners of a shared port are comma-joined, both processes visible at a glance), sorted by port. The CLI twin of the TUI's Ports overview (`o`): `--json` emits the versioned envelope (`listener_count` + `listeners`), `--csv` gives a port,proto,owners table — "who is serving on this machine right now" in one command. **`--watch N`** turns it into a live board (clear-and-redraw, Ctrl-C to stop, `--times N` bounds the run; the machine-readable formats stay one-shot — the polling consumer owns its own cadence).

**Connections overview (`--conns`)**: skip the UI and print every network connection on the machine outside LISTEN — columns PROTO / LOCAL / PEER / STATE / OWNER (ESTABLISHED / TIME_WAIT / …, every state), owners resolved against the process table; when the peer is also local (loopback traffic) the OWNER cell appends `↔ <other end>` — "who owns both ends of this connection" at a glance, the mirror of `--ports`. `--json` emits the versioned envelope (`connection_count` + `connections`, loopback attribution in the `peer_pid` / `peer_owner` fields), `--csv` / `--markdown` give machine-readable tables, and **`--watch N`** turns it into a live board (the machine-readable formats stay one-shot). Add **`--by-peer`** for the **peer-aggregated** view: rows fold by (proto, remote address, remote port) — columns PEER / CONNS / STATES / OWNERS / LOCAL PORTS, busiest first — "who is this machine actually talking to, and which link is hottest" on one screen (database connection pools, crawler targets, whatever is connected to you; `--json` / `--csv` / `--markdown` supported all the same).

**File-lock overview (`--locks`)**: skip the UI and print every file lock on the system — columns PID / OWNER / MODE / TYPE / PATH (sorted by pid then path, owners dimmed). The CLI twin of the TUI's Locks tab; `--json` emits the versioned envelope (`lock_count` + `locks`), with `--csv` / `--markdown` working too. Same data sources as the tab (Linux `/proc/locks`, macOS `lsof` lock flags) — "who is holding this file" is now also a scripting question.

**Zombie quick list (`--zombies`)**: `witr-rs --zombies` lists every `<defunct>` zombie in the table — columns PID / NAME / PARENT (`(gone)` when the parent has exited) / AGE (oldest first). Zombies cost nothing themselves, but a field of them is the signature of a parent that never `wait()`s. `--json` emits the versioned envelope (`zombie_count` + `zombies`), with `--csv` / `--markdown` working too; the **exit code is 1 when zombies are found**, 0 otherwise — `witr-rs --zombies || alert` is a ready-made patrol probe.

**Service-unit overview (`--services`)**: skip the UI and list the service manager's current units — columns MANAGER / NAME / STATE / PID / DESCRIPTION (Linux systemd / macOS launchd / Windows SCM), running units (a main pid in hand) floating to the top. The CLI twin of the TUI's Services tab (6): `--json` emits the versioned envelope (`service_count` + `services`), with `--csv` / `--markdown` working too — "which services run on this machine, and are they alive" in one command.

**Drift watchdog (`--diff-auto`)**: `witr-rs --watch 30 --diff-auto 30` — while watching, an in-memory frame is taken and compared against the previous one every N seconds; anything changed prints `== drift · N new / M gone / K restarted / J changed ==` plus the color-coded change rows. Where `--alert-port` watches one port's edges, `--diff-auto` watches the whole table — "what appeared on this machine in the last half hour" without anyone remembering to run `--diff`; the watchdog shouts on its own. Requires `--watch`; with **`--json`** every drift check emits a versioned envelope frame (`summary: {new, gone, restarted, changed, listen_new, listen_gone, total}` + `entries`, shaped exactly like `--diff --json` — `| jq '.summary'` watches the counts), and a check with no changes prints nothing. Frames never touch disk — pure in-memory comparison, zero writes.

**Prometheus endpoint (`--serve`)**: `witr-rs --serve :9100` starts a `/metrics` scrape endpoint in the Prometheus text format (zero new dependencies) — no background sampler; **every scrape samples the process table fresh**, so scrape frequency IS the sample rate. **`--serve-token TOKEN`** puts every endpoint behind Bearer auth (`Authorization: Bearer TOKEN`; missing or wrong token gets a 401) — for the few times metrics must leave localhost. It exports machine totals (`witr_process_count`, `witr_rss_total_mb`), **machine resource gauges** (`witr_machine_cpu_percent` — a true instantaneous figure from refresh-to-refresh deltas, `witr_machine_mem_used_bytes` / `witr_machine_mem_total_bytes`, `witr_machine_mem_available_bytes`, `witr_machine_swap_used/total_bytes`, `witr_machine_load1`) — what the built-in sentinels watch, a Prometheus rule can watch too and **per-NIC traffic counters** (`witr_machine_net_rx_bytes_total{nic}` / `witr_machine_net_tx_bytes_total{nic}` — `rate()` them in PromQL for per-interface throughput, loopback excluded), plus **PSI pressure** (`witr_machine_psi_stall_percent{resource,kind}` — cpu/mem/io some/full 10-second stall shares, Linux), per-NIC drop counters (`witr_machine_nic_drop_total{nic,direction}`), and per-process gauges for the union of the top-20 CPU and top-20 RSS processes (`witr_process_cpu_percent` / `witr_process_rss_bytes` / `witr_process_open_fds`, labeled pid / name / user — bounded cardinality); each process also carries **cumulative disk-I/O counters** (`witr_process_io_read_bytes_total` / `witr_process_io_write_bytes_total` — `rate()` them in PromQL for per-process read/write throughput) and **`witr_process_start_time_seconds`** (start time as a unix-seconds gauge — a series reset to "now" is the standard Prometheus restart signal; `changes()` alerts on it directly); and the port side gains **`witr_port_listeners{proto,port,owner}`** — one series per listening (proto, port), the `owner` label carrying the "name (pid N)" owner list, so unexpected listeners stand out. Beyond `/metrics` there are seven JSON endpoints: **`/api/ps`** (the whole process table as the same versioned envelope `--json` prints, with enriched user / start time and friends), **`/api/ports`** (the LISTEN table, same envelope as `--ports --json`), **`/api/conns`** (the non-LISTEN connection table, same envelope as `--conns --json`, loopback peer attribution included), **`/api/tree`** (the nested process forest, the HTTP form of `--tree --json`), **`/api/services`** (the service-unit table, same envelope as `--services --json`) and **`/api/containers`** (the container table: runtime/id/name/image/state/cpu/mem/throttle/OOM/disk I/O — the same background snapshot the `/metrics` container series ride), **`/api/top?metric=cpu|mem|fd|age|io|io-rate|threads|conn|net&n=N`** (the `--top` ranking over HTTP; `value`'s unit follows the metric — percent / bytes / count / seconds, the io pair and net in bytes and bytes-per-second, threads/conn as counts, unknown metrics get a 400) — `curl -s localhost:9100/api/ports | jq` and you're in. There is also a seventh, non-JSON endpoint, **`/api/events`** (a **Server-Sent Events** live event stream): the first hit arms a 5-second differential sampler that keeps pushing started/exited/restarted edges to subscribers as `data: {...}` frames (the same TuiEvent JSON the TUI event ring / `--events-log` writes), with a `: ping` keepalive every 15 silent seconds — `curl -N localhost:9100/api/events` is this machine's live event broadcast; pure `/metrics` deployments pay no sampling cost (the sampler starts lazily). The endpoint self-monitors with three series: `witr_scrapes_total`, `witr_scrape_duration_seconds`, `witr_scrape_timestamp_unix`. When containers are running, `/metrics` also exports **per-container metrics** (`witr_container_cpu_percent` / `witr_container_mem_used_bytes` / `witr_container_mem_total_bytes`, labeled runtime/id/name/image/state — container cpu/mem on the same screen as the processes; sampling rides a 30-second background cache so scrapes never block on the runtime CLI). A bare port binds `127.0.0.1` (the metrics name your processes; don't broadcast them), `[HOST]:PORT` overrides; your Prometheus `scrape_interval` doubles as the sampling interval. When containers run, `/metrics`' container series extend to the full cgroup pressure picture: `witr_container_throttled_seconds_total` (accumulated CFS throttle time — `rate()` it for throttle velocity), `witr_container_oom_kills_total` (kernel OOM kills), `witr_container_io_read/write_bytes_total` (container disk I/O, read on the same cgroup sweep as THR%/OOM) — containers on the same screen as processes and the host in PromQL. Opening `/` in a browser serves a **zero-JS dashboard** (a `meta refresh` re-renders every 5 s: cpu / memory / load / process-count gauge tiles, temperature and PSI where the platform reports them, top-CPU and top-memory tables, the **container table** (name/state/cpu/memory/limit/OOM count), the listeners table — internet-wide binds painted red; every view samples fresh, the same machinery as `/metrics`, no external assets, no scripts).

**Bilingual help (`--en`)**: help text is Chinese by default — `--help`, the `--man` page and the `--completions` scripts all follow the language, and `--en` switches back to English. The language is resolved by pre-scanning argv for `--en` before the clap parse (every help string is fixed while the Command is built); clap's own "Usage:"/"Options:" scaffolding and parse errors stay English either way (clap has no i18n layer to hook).

**Man page (`--man`)**: `witr-rs --man [FILE]` renders the full man page (roff, via clap_mangen) — with no argument it prints to stdout (`witr-rs --man | gzip > /usr/local/share/man/man1/witr-rs.1.gz` installs it), with FILE it writes there (creating missing directories).

**Config file**: `~/.config/witr-rs/config.toml` (macOS: `~/Library/Application Support/witr-rs/`, Windows: `%APPDATA%\witr-rs\`) — six TUI keys, `refresh_secs` (sampling interval) / `sort` (default sort) / `notify` / `paused` / `watch` (watchlist) / `notes` (process annotations), plus every **`alert_*` key** matching a flag one for one (`alert_cpu` / `alert_mem` / `alert_fd` / `alert_io` / `alert_conn` / `alert_load` / `alert_mem_pct` / `alert_count` / `alert_disk` / `alert_net` / `alert_psi` / `alert_repeat` numeric, `alert_exec` / `alert_webhook` strings, `alert_silence` / `alert_new_proc` string arrays) and `serve_token` (the Bearer token for `--serve`) — a watchdog deployed as a service keeps its thresholds in the file and the command line stays just `--watch`. All keys act as defaults for the CLI flags: the file loads first, the command line always wins; a `kill -HUP` hot-reloads it mid-run (see above). Bad lines are skipped with a warning; no file changes nothing.

**Watchlist (`w`)**: on the Processes tab, `w` stars the selected row and pins it to the top (your chosen sort still applies inside the pinned block); press again to unwatch. Entries persist by identity (name + exe basename + user) into the config file's `watch` key — no pid in the key, so the ★ follows the program across restarts. Tree mode skips pinning (it would tear children from parents); search filters still apply.

**System resources page (`y`)**: a whole-machine dashboard — CPU history chart (fixed 0–100 scale, current value + window peak annotated), memory history chart (absolute scale + peak), load average (1/5/15 min), swap usage, a per-core grid (cores ≥90% render red) plus **per-core history rows** (one 0–100-scale sparkline per core with its window peak — a single core pegged while the rest idle is the classic single-thread bottleneck, invisible in the total), **disk mounts** (one usage bar per device-backed filesystem, ≥90% full renders red; local disks only, network mounts stay hidden), **NIC rates** (per-interface ↓rx ↑tx MB/s plus a total-rate sparkline with peak, the top 8 interfaces sorted by throughput; counters start sampling when the page opens, rates are diffs between sweeps — Linux `/proc/net/dev`, macOS `netstat -ib`, Windows `Get-NetAdapterStatistics`), **temperature** (Linux reads the hottest hwmon sensor; ≥80°C red, ≥65°C yellow) and **PSI pressure** (Linux `/proc/pressure/*` per-resource some/full stall percentages, the worst full ≥10% painted red — full stall is the "machine is dying" signature). Linux reads `/proc` directly (microsecond-cheap, sampled every cycle so history is already there when the page opens); macOS uses Mach `host_processor_info` + `vm_stat`, Windows a single PowerShell CIM query (those two sample only while the page is open; the disk section sweeps df/CIM once per refresh while open on all platforms). Answers "how busy is this machine, how much memory is left, which disk is nearly full, and which NIC is carrying the traffic". Its CLI twin **`--sys`** prints the same machine numbers without the TUI (cpu / memory / swap / load / process count / fullest disk / NIC rates / temperature / PSI; sections the platform can't measure just don't appear; `--watch N` keeps it refreshed, `--json` / `--csv` / `--markdown` are one-shot outputs from the same frame).

## TUI keys

Vim-style browsing (aligned with the Go witr):

| Key | Action |
|---|---|
| `j` `k` / `↑` `↓` | Move selection |
| `g` `G` | Jump to first / last row |
| `f` `b` `space` / PgUp PgDn | Page down / up |
| `h` `l` / `←` `→` | Switch tabs |
| `1`–`6` / Tab | Jump to tab / cycle focus (table ↔ details) |
| `/` | Search: Processes tab matches PID/user/name, or **comparison expressions** (`cpu>50`, `mem>1g`, `fd>100`, `age<30m`, `io>10m`, `thr>200` — `> < >= <= =`, byte values take k/m/g suffixes, ages take s/m/h/d); Ports tab matches port/PID/process/address/proto/state (filters are per-tab; Enter applies, Esc clears; a non-expression falls back to plain substring search) |
| `Enter` | Processes tab: full-screen process detail; Ports tab: port detail (all connections on that port + owning process); Containers tab: container detail; Locks tab: jump to the holder's detail page |
| `p` `n` `u` `c` `m` `i` `t` | Processes tab: sort by PID / name / user / CPU / memory / disk I/O rate / start time; press again to flip direction (`i` ranks by read+write bytes per second, needs two samples a second apart) |
| `p` `t` `n` `s` | Ports tab: sort by port / proto / address / state |
| `i` `n` `r` `g` `s` `p` | Containers tab: sort by ID / name / runtime / image / status / compose project |
| `p` `n` `t` `m` `f` | Locks tab: sort by PID / process / type / mode / path |
| `n` `m` `s` `p` | Services tab: sort by name / manager / state / main pid |
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
| `M` | Global mute toggle: alert evaluation keeps running but notifications / hooks / alert lines stop firing; muted entries enter the event ring as `silenced` (footer shows an indicator) |
| `<` `>` | Processes tab: scrub backward / forward through the last 30 process-table snapshots frame by frame (REPLAY badge on the tab bar; scrubbing to the end returns to live automatically; alerts pause during replay, recording continues) |
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

**Crash-loop detection** (TUI): the same process identity reappearing under a new pid counts as one restart; the `Rst` column shows the total, and ≥2 restarts within 5 minutes raise a yellow warning in the detail panes — crash loops are visible at a glance (event details in the Events tab). Restart events also **compare the previous life's command line and environment** with the new one: a changed argv is annotated with the new command line in the restart detail (catching "config changed but the service came up with the wrong arguments"), a changed env gets an "env changed" note — restarts are not just a count, they answer "why is this life different".

**Instantaneous CPU + Trend sparkline** (TUI): computed from the delta of cumulative CPU time between refreshes (not the lifetime average); the Trend column draws the last 8 samples as an 8-level sparkline, and the `c` sort key sorts on it.

**Binary fingerprint** (`--export` / TUI detail page): the target binary's sha256 plus a code-signature verdict (macOS `codesign`, Windows Authenticode; an invalid signature adds +3 to the risk score). Linux has no kernel-enforced signing story — the hash is the identity of record.

**GPU column** (TUI, optional): on machines with an NVIDIA driver, `nvidia-smi pmon` supplies per-process SM utilization and memory (`37% 2.3G`), with full values on the detail page. Without nvidia-smi the column hides itself; a failed probe is attempted only once per run. The same data feeds the **`--top gpu`** board and the `gpu_sm` column of **`--record`**.

**K8s pod attribution** (optional): with `kubectl` installed and a reachable cluster, containers are labeled with their owning pod (`docker: mongo-demo-2 (id 6838b8ba3c49) · pod data/mongo-0`) and the Containers tab gains a Pod column; the single `kubectl get pods -A -o json` call also extracts each pod's phase / total restart count / first non-routine waiting reason (CrashLoopBackOff, ImagePullBackOff, …), feeding the container/pod alert edges. Without kubectl this costs nothing.

**Container health**: the Containers tab colors the state cell (healthy/running green, unhealthy red, restarting/starting yellow); the container detail page and `-c` targets show the `inspect` RestartCount (annotated "restart policy fired" when > 0). The tab also **watches container edges** (active once the Containers tab has been opened): when a runtime CLI exists, a **`docker/podman/nerdctl events` stream** is spawned automatically — a container's die / OOM / health-check-flips-red arrives in **milliseconds** (`>> container: web — exited (exit code 137)`), no waiting for the next enumeration; when the stream isn't available (no runtime) it falls back to **enumeration diffing**: a running container exiting/dying fetches the cause from `inspect` — `exited — OOMKilled (exit 137)` names the OOM, `exit N: <error>` names the runtime error; a climbing RestartCount (old → new) hints at a crash loop; a climbing cgroup `memory.events` oom_kill count — the kernel genuinely OOM-killed inside the container, however fast a restart policy hides the exit — raises one too; with a reachable cluster the **pod states are watched too**: a container waiting on a non-routine reason (CrashLoopBackOff / ImagePullBackOff… — deploy-time ContainerCreating / PodInitializing don't count), a pod falling from Running back to Pending, entering Failed, and a climbing pod-level restart count each raise an alert. The same "edge-triggered + fire once" machinery: desktop notifications, `--alert-exec`, `--alert-webhook` and `--events-log` all apply. The TUI needs no flag; a headless `--watch` arms the same edges into the alert pipeline with **`--alert-container`** (container and pod enumeration runs on a background thread, one sweep every ≥10 s, never on the sampling tick; while the events stream is live it owns death edges — the millisecond `>>` line lands first and the sweep only backstops) — in cron/systemd, container OOMs and Pod CrashLoopBackOffs shout all the same.

**Crash log correlation**: `l` on the detail page or the Events tab pulls the process's recent logs (container logs via `docker/podman/nerdctl logs`, `journalctl _PID=<pid>` on Linux, the unified log via `log show --predicate` on macOS) — after the Events tab flags a crash loop, `l` is where "why does it keep restarting" usually answers itself. Fetching runs on a background thread (`log show` can take seconds; the UI never freezes) and lands on a full-screen, scrollable Logs page. `F` toggles a **live stream** rendered into the same page, the command following the source (container `logs -f`, Linux `journalctl -f _PID=`, macOS `log stream --predicate`) — autoscrolling while you're at the bottom, capped at the last 500 lines, and the child CLI is killed when you leave the page or quit. CLI twin: `witr-rs --pid 1234 --logs [N]` (100 lines by default).

**Event persistence + replay**: `witr-rs --events-log events.jsonl` makes the TUI append every started/exited/restarted event the sampler produces as JSONL — the record survives the TUI, answering "what happened while I was away"; a **target-less `--watch` honors the flag too** — run headless in cron/systemd and events plus threshold alerts still land in the file. `witr-rs --replay events.jsonl` reads it back and opens straight onto the Events tab (imported history + live sampling layered on top, original timestamps preserved). With **`--follow`** it becomes a tail: `--replay ev.jsonl --follow` loads the history, then keeps watching the end of the file — events the recording side appends stream into the ring live (record on one machine, open a live window onto it from another machine or session). Torn lines wait for their newline; a truncated/rotated file restarts the tail from the top.

**Samples replay page (`--samples`)**: `witr-rs --samples load.csv` imports a `--record` sample file (both .csv and .jsonl are accepted) into the TUI's **Samples page** — five machine series (cpu% / memory% / 1-minute load / network MB/s / process count) drawn as sparklines; `←/→` (h/l) moves the cursor to read individual instants (the readout line lists every series' value at the cursor), `↑/↓` (j/k) switches the charted series, `g/G` jump to the ends, `Esc` back to the table, `c` copies the page text. Live sampling continues underneath — "debug today's machine against last night's recorded curve" with both time planes on one screen.

**Containers tab**: enumerates containers via runtime CLIs on PATH (docker / podman / nerdctl), showing Runtime / ID / State / Status / (Pod) / (Compose) / Image / Name, with the state cell colored by health; **CPU% / MEM columns** appear once the first resource sweep lands — a background `stats --no-stream` runs about every 10s (~2s per runtime CLI, costlier than the listing itself) and merges into the table by container id, with the MEM cell colored by how much of the container's own limit it occupies (≥70% yellow, ≥90% red — a container bumping its cap is the usual OOM prologue); **THR% / OOM columns** come from the container cgroup's throttle time and oom_kill count (Linux cgroup v2, a few file reads alongside each sweep — no runtime CLI cost): THR% is the share of the last sweep interval the cgroup spent throttled by its CFS quota (≥50% red — the top reason a "slow container" shows idle CPU), and a non-zero OOM cell means the kernel OOM-killed inside that container; the **Compose column** carries the container's `com.docker.compose.project` label (parsing both docker's packed `k=v,k2=v2` string and podman/nerdctl's JSON object label shapes; the column hides itself on non-compose hosts) — which stack owns this row of containers, at a glance; `/` filters by name/image/ID/runtime/state/compose project, `i/n/r/g/s` sorts, `p` sorts by compose project. Enumeration runs on a background thread (a hung runtime CLI never freezes the UI) and auto-refreshes every 3s; refreshes keep the stale table visible so nothing flashes — the loading placeholder only shows on first load. **`Enter` opens the container detail page**: container attributes on the left (Name/Runtime/Compose/ID/Image/State/Status/Ports/Restarts), in-container process list on the right (matched via cgroups on Linux; on macOS/Windows container processes live in a VM and a note is shown).

**Locks tab**: file locks plus an all-open-files view (Linux reads `/proc/locks`; macOS extracts lock flags from `lsof` with a lock-file-name heuristic); `a` toggles locks ↔ all open files (the open-files view caps the display at 100 rows until you search), and `Enter` on a row jumps straight to the holding process's detail page.

**Services tab (6)**: the service manager's units (Linux systemd / macOS launchd / Windows SCM) — columns Name / Manager / State / PID / Description, running units first, `n/m/s/p` to sort, `/` to filter by name/manager/state/description; `Enter` jumps into the unit's main process's detail page (launchd units recover the program identity via plist probing). CLI twin: `--services`.

**Seeding the TUI from the CLI (`-i`)**: `witr-rs -i --pid 1234` / `witr-rs -i nginx` / `witr-rs -i --port 8080` / `witr-rs -c web -i` / `witr-rs -i --file /var/log/x.log` — the TUI opens on the right tab with the right filter (name prefills the search, pid selects the row, port/file/container switch tabs and prefill their filters). One target per type is used; extras are reported in the status line; exit 4 without a terminal.

## Platform support

| Capability | Linux | macOS | Windows |
|---|---|---|---|
| Process table | direct `/proc` reads | `ps` | ToolHelp32 snapshot |
| cmdline / cwd / exe | `/proc/<pid>/*` | `ps` + `lsof` | PowerShell (Get-CimInstance) |
| Port → process | `/proc/net/*` + fd inode matching | `lsof -i` | `netstat -ano` |
| File → process | `/proc/*/fd` | `lsof` | ✓ (Restart Manager API — no Sysinternals needed) |
| File locks (Locks tab / `--locks`) | `/proc/locks` + fdinfo | `lsof` lock flags + lock-file-name heuristic | ✗ |
| Process group / session (pgid / sid) | ✓ `/proc/<pid>/stat` | ✓ `ps pgid=,sess=` | ✗ |
| cgroup v2 resource panel (detail page) | ✓ `/proc/<pid>/cgroup` + `/sys/fs/cgroup` | ✗ | ✗ |
| Service attribution | systemd (`systemctl status`) | launchd (`launchctl list` + plist probing) | SCM (`tasklist /svc`, recognizes services.exe descendants) |
| Container attribution | cgroups (docker/containerd/podman/lxc) | ✗ | ✗ |
| nohup/disown detection | ✓ (SIGHUP bit of `/proc/<pid>/status` SigIgn, surfaced as a warning) | ✗ | ✗ |
| Controlling-terminal (tty) attribution | ✓ `/proc/<pid>/stat` tty_nr | ✓ `ps tty=` (`??` means detached) | ✗ |
| Environment variables (`--env` / TUI detail page) | ✓ `/proc/<pid>/environ` (same user) | ✓ same-user processes via `ps -E` (the rest are SIP-limited; the pane says so) | ✗ |
| Per-process disk I/O (TUI IO column + detail totals) | ✓ `/proc/<pid>/io` (byte deltas → rate) | ✓ `proc_pid_rusage` | ✓ PowerShell IO_COUNTERS |
| Per-process fd count (`--top fd` / `--alert-fd`) | ✓ direct `/proc/<pid>/fd` reads | ✓ native libproc `proc_pidinfo` sweep (no subprocess) | ✓ PowerShell `Get-Process` HandleCount |
| Per-process kernel thread count (`--top threads` / `--alert-threads` / detail thread chart) | ✓ `/proc/<pid>/stat` nlwp | ✓ `ps nlwp` with the listing | ✓ ToolHelp thread snapshot |
| Reclaimable-memory floor (`--alert-mem-avail-mb`) | ✓ MemAvailable | ✗ | ✗ |
| TCP retransmit counters (`--alert-retrans`) | ✓ `/proc/net/snmp` | ✗ | ✗ |
| Per-NIC drop/error counters (`--alert-nic-drop`) | ✓ `/proc/net/dev` | ✗ | ✗ |
| Per-process network throughput (`--top net` / `--alert-net-per-proc`) | ✓ `ss(8)` tcp_info deltas | ✗ | ✗ |
| Start time | btime + starttime | `ps etime` | CIM CreationDate |
| Temperature (system resources page) | ✓ hottest hwmon sensor | ✗ | ✗ |
| PSI pressure (system resources page / `--alert-psi`) | ✓ `/proc/pressure/*` | ✗ | ✗ |

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
witr-rs --replay ev.jsonl --follow # tail the recording: appended events stream in live (a live window onto another session/machine)
witr-rs --replay ev.jsonl --since 1h # "what happened" digest of the recording: counts + restart chains, printed and exit
witr-rs --top cpu -n 30       # top 30 by CPU (--top mem|fd|io|io-rate|age likewise; no TUI)
witr-rs --top io-rate -n 10   # disk I/O rate board (read+write MB/s; persistent history under --watch)
witr-rs --top age -n 10       # top 10 oldest processes (age ranking; pid 1 always wins)
witr-rs --top threads -n 10   # most-threaded processes (--top conn for connections, --top net for who is eating the NIC)
witr-rs --top cpu --watch 5   # live CPU board, reranked every 5s (Ctrl-C exits)
witr-rs --csv                 # whole table as CSV (RFC-4180 escaping; --markdown for docs)
witr-rs --watch 5 --record load.csv # append the whole table to a CSV every 5s
witr-rs --watch 5 --record load.csv --record-max-mb 200 # same, rotating to load.csv.1 past 200MB (a months-long watchdog stays disk-bounded)
witr-rs --watch 5 --record load.jsonl # same time series, NDJSON envelopes (ppid/state/age included)
witr-rs --plot load.csv        # render the recording into a self-contained HTML time-series chart (five offline SVG curves)
witr-rs --samples load.csv     # import the recording into the TUI Samples page (sparklines + ←→ cursor readout)
witr-rs --tree --json         # whole table as nested JSON (children under parents)
witr-rs --export-grafana dash.json  # 16-panel Grafana dashboard: the /metrics vocabulary as pre-filled PromQL, import and go
witr-rs --report-html status.html   # self-contained HTML report (bars + top boards + full table)
witr-rs --alert-fd 4096 --alert-io 100 # fd-count / disk-IO-rate threshold alerts (same mechanism as CPU)
witr-rs --alert-conn 200      # per-process ESTABLISHED connection-count alerts (TUI and --watch)
witr-rs --alert-threads 400   # per-process kernel-thread-count alerts (the thread-leak sentinel, TUI and --watch)
witr-rs --alert-net-per-proc 5 # per-process TCP-throughput alerts (MB/s; quiet exfiltration gets named, ss(8) diffs)
witr-rs --watch 5 --alert-deviation 10 # self-baseline sentinel: a quiet process suddenly staying busy shouts (no threshold to preset)
witr-rs --watch 5 --alert-mem-avail-mb 500 # the last sentinel before OOM: shout when available memory drops under 500MB
witr-rs --watch 5 --alert-retrans 100 --alert-nic-drop 50 # network-quality sentinels: TCP retransmits / NIC drops over rate (--alert-swap-pct 90 is of the same family)
witr-rs --watch 5 --alert-cpu 90 # headless watchdog: prints a ⚠ alert line on each firing, no TUI
witr-rs --watch 5 --quiet --alert-mem 2048 # even quieter watchdog: no per-tick redraw, alerts/hooks only
witr-rs --watch 5 --times 12  # sample for one minute, print the summary and exit (--json: the summary is a JSON envelope too)
witr-rs --port 8080 --watch 2 --on-start 'say up' # run a command once on the target-appears edge (wait-for-deploy)
witr-rs --alert-cpu 90 --alert-exec 'curl -s $SLACK_HOOK -d "$WITR_ALERT_NAME: $WITR_ALERT_DETAIL"' # run a command on every alert firing (webhook)
witr-rs --watch 2 --alert-port 9090 # port canary: alert when something starts listening on :9090 (TUI works too)
witr-rs --watch 2 --alert-port '!8080' --alert-repeat 60 # alert when :8080's listener disappears; re-nag every 60s while down
witr-rs --audit 'cargo build --release' # run a wrapped command, then print its subtree report (duration/exit code/peak CPU/RSS/disk IO + tree)
witr-rs --audit 'cargo build --release' --json # same, as a machine-readable envelope (jq-ready in CI)
witr-rs --ports               # current LISTEN port overview (--json / --csv machine-readable)
witr-rs --locks               # system-wide file-lock listing (--json / --csv / --markdown)
witr-rs --zombies             # zombie process quick list (oldest first; exit 1 when found — a patrol probe)
witr-rs --conns               # every non-LISTEN connection: local/peer/state/owner (loopback peers attributed; --watch N for a live board)
witr-rs --services            # the service manager's units (systemd/launchd/SCM; running ones first)
witr-rs --watch 5 --alert-load 8 --alert-mem-pct 90 # machine-wide watchdog: load / memory-percent threshold alerts
witr-rs --watch 5 --alert-count 800 # machine-wide watchdog: alert when the visible process count tops 800 (fork-bomb sentinel)
witr-rs --watch 5 --alert-disk 90 # machine-wide watchdog: alert when any disk's used percent crosses the line (disk-full sentinel)
witr-rs --watch 5 --alert-psi 10 --alert-webhook http://127.0.0.1:9000/hook # Linux PSI full-stall alert + JSON webhook push
witr-rs --watch 5 --alert-new-proc xmrig miner # first-sighting alerts: any new face reports (miner/backdoor sentinel; '!nginx' is the inverse whitelist mode)
witr-rs --watch 5 --alert-cpu 90 --alert-silence backup=30m # maintenance window: names starting backup stay silent for 30 min ('!NAME' inverts)
witr-rs --watch 5 --alert-cpu 90 --install-service # one command turns it into a systemd user unit / launchd plist / schtasks service
kill -HUP $(pgrep -f 'witr-rs --watch') # config hot reload: change thresholds / silence lists without restarting (alert state preserved)
witr-rs --plot before.jsonl after.jsonl # overlay two recordings' machine curves for comparison (writes witr-plot.html)
witr-rs --remote http://a:9100 --remote http://b:9100 # a fleet, one section per host (--json emits the fleet envelope; a dead host warns without sinking the rest)
witr-rs --remote http://10.0.0.7:9100    # render a remote --serve's process table (--watch N re-fetches; --tree/--csv/--json work like local)
witr-rs --remote http://10.0.0.7:9100 --watch 2 # live refreshing remote board
witr-rs --watch 10 --alert-container # headless container sentinel: exit/OOM and Pod CrashLoopBackOff shout once per edge
witr-rs --sys                 # machine dashboard: cpu/mem/load/disk/nic/temp/psi (--watch 2 to keep it live; --csv/--markdown/--json from the same frame)
witr-rs --conns --by-peer      # connections folded by peer: who talks most, which link is hottest (--json/--csv/--markdown alike)
witr-rs --watch 30 --diff-auto 30 # drift watchdog: auto-frame comparison every 30s, prints only on change
witr-rs --top cpu --csv       # CPU board straight to CSV (--markdown likewise)
witr-rs --by-name             # fold the table by (name, user): N / ΣCPU / ΣRSS / ΣCPUTIME (--csv/--markdown/--json alike)
witr-rs --by-name --watch 5   # live aggregate view
witr-rs nginx --pids-only     # print only the matched pids (pipe into xargs kill; exit 2 on no match)
witr-rs --port 8080 --wait    # block until the target exists (--wait gone waits for exit; --timeout N exits 124)
witr-rs --pid 1234 --wait gone --timeout 60 # wait for the old process to retire (deploy-script primitive)
witr-rs --ports --watch 2     # live LISTEN board (--times N bounds it)
witr-rs --watch 30 --diff-auto 30 --json # machine-readable drift frames (summary + entries, jq the counts)
curl -s 'localhost:9100/api/top?metric=mem&n=5' # the --top ranking over HTTP (cpu|mem|fd|age|io|io-rate|threads|conn|net)
witr-rs runaway --kill        # headless kill of matched targets (--signal KILL picks the signal; --kill-tree takes the descendants first)
witr-rs --pid 1234 --logs 200 --grep ERROR # show only matching log lines (needs --logs)
witr-rs --snap before.json    # write the process table as JSON and exit
witr-rs --snap                # auto snapshot: stored next to the config dir, rotating (keeps 10; --keep N)
witr-rs --snap=now.json --sockets # also record LISTEN ports (for --diff to report listener changes)
witr-rs --diff before.json    # new / gone / restarted / changed / listen-new / listen-gone vs a snapshot (identity-based; pid reuse doesn't fool it; exit 1 on change)
witr-rs --diff last           # diff against the newest auto snapshot (--diff 30m = the one from 30 minutes ago)
witr-rs --diff last --json    # machine-readable diff envelope (summary counts + entries)
witr-rs --serve :9100         # Prometheus /metrics + zero-JS dashboard (/) + /api/ps JSON process-table endpoint (samples on every scrape; binds 127.0.0.1 by default; includes port gauges, the restart-signal start_time and self-monitoring metrics)
witr-rs --serve :9100 --serve-token s3cret # same + Bearer auth on every endpoint (Prometheus's authorization credential plugs straight in)
curl -N localhost:9100/api/events # SSE live event stream: started/exited/restarted pushed frame by frame (15s keepalive ping when idle)
witr-rs --man                 # render the man page (stdout; --man FILE writes a file, creating the directory)
witr-rs --en --help           # English help (--man / --completions follow --en too)
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
| 1 | Found, but with warnings (running as root, listening on all interfaces, deleted binary, LD_PRELOAD, zombie, …); `--zombies` also exits 1 when zombies are found |
| 2 | Target not found |
| 3 | Not enough permissions (e.g. a root-only query) |
| 4 | Invalid arguments |
| 5 | Internal error (e.g. process table unreadable) |
| 6 | Found, but the source could not be attributed (never on Windows, where ancestry routinely stops at an exited parent) |
| 124 | `--wait` timed out (GNU timeout convention; 130 when interrupted by SIGINT) |

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
├── history.rs      sampling history: instantaneous cpu, sparklines, memory trend + leak suspicion, restart detection, event feed, session summary, alert silence/first-sighting lists, short-lived process capture, container event parsing
├── config.rs       user config file (flat toml subset: refresh_secs/sort/notify/paused/watch/notes; CLI overrides)
├── snapshot.rs     --snap / --diff: full-table snapshots (with auto-rotation) + new/gone/restarted/changed comparison
├── serve.rs        --serve: Prometheus text-format endpoint (hand-rolled HTTP on std::net, scrape-driven sampling, bounded cardinality; /api/events lazy SSE differential sampler)
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
- Event persistence (`--events-log`): both the TUI and a target-less `--watch` can record, and `--replay` replays either; the watch sampling granularity is the `--watch` interval (default 2s) — processes born and gone inside one window are covered by the short-lived capture instead (a 250ms poller surfaces anything alive ≤5s; longer-lived ones take the regular started/exited path)
- The `--watch` Ctrl-C summary relies on a SIGINT hook (unix); on Windows use `--times N` to end a run (the summary is there in the `--times` exit and the `--json` envelope)
- The session-digest (`--since`/`S`) CPU-spike and memory-climber boards only cover processes alive at the last refresh (dead pids are pruned) — a spike-then-exit shows up in the activity counts, not on the boards; the `--replay` file digest carries activity counts and restart chains only (recordings hold no samples)
- `--follow` matches by program identity (name+exe+user): a restart of a script that runs under several parallel instances may attach to a sibling rather than "the" successor (the most recently started instance wins)
- FD trend sampling happens only while the detail page is open (Linux/macOS both use native microsecond queries; Windows has the whole-table handle sweep but no per-pid fd query, so the section is absent there)
- Container attribution is Linux-only (container processes behind colima/Docker Desktop on macOS are not attributed, though `-c` targets get a runtime-side fallback view)
- Windows has `--file` (Restart Manager) but no Locks data
- macOS `launchctl list` only covers the current user domain; system daemons need sudo to be labeled. macOS file locks are approximated from `lsof` flags — the kernel exports no lock table there
- nohup/disown detection is Linux-only (no `/proc` on macOS/Windows, so no such warning there)
- The GPU column covers NVIDIA only (`nvidia-smi`); there is no per-process utilization source for Apple Silicon / AMD GPUs
- On Windows `--top fd` / `--alert-fd` count kernel handles (PowerShell `Get-Process` HandleCount, the same counter Sysinternals surfaces as Handles)
- The cgroup resource panel and `--locks` have data on Linux/macOS only (both absent on Windows); when the cgroup numbers can't be read (e.g. a container namespace where the path doesn't match the host mount) only the path is shown
- `--replay --follow` tails at the recording side's write cadence — no new lines means nothing flows in, and when the recorder exits the TUI keeps waiting (Ctrl-C to leave)

## License

Apache-2.0. Design follows pranshuparmar/witr (also Apache-2.0).

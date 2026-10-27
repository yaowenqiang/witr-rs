use clap::{Parser, ValueEnum};
use std::sync::atomic::{AtomicBool, Ordering};

// --- UI language -----------------------------------------------------------------
// Help text is bilingual: Chinese by default, English under `--en`. Every
// string below is resolved while the clap Command is being built, and
// `init_language()` runs at the very top of main() — before the parse — so
// `--help`, the `--man` page and the `--completions` scripts all come out in
// the chosen language. clap's own scaffolding ("Usage:", "Options:", parse
// errors) stays English either way; clap has no i18n layer to hook.

static ENGLISH: AtomicBool = AtomicBool::new(false);

/// Pick between the Chinese (default) and English variant of a help string.
pub fn t<'a>(zh: &'a str, en: &'a str) -> &'a str {
    if ENGLISH.load(Ordering::Relaxed) {
        en
    } else {
        zh
    }
}

/// Pre-scan the raw argv for `--en` before the clap parse — the language has
/// to be known while the Command (and every help string in it) is built.
pub fn init_language() {
    if std::env::args_os().any(|a| a == "--en") {
        ENGLISH.store(true, Ordering::Relaxed);
    }
}

// Shell for `--completions`.
#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum Shell {
    Bash,
    Zsh,
    Fish,
    Powershell,
}

// Metric for `--top`.
#[derive(Clone, Copy, Debug, ValueEnum, PartialEq)]
pub enum TopMetric {
    #[value(help = t("进程生命周期内的平均 CPU 占用率", "Lifetime average CPU percent"))]
    Cpu,
    #[value(help = t("常驻内存大小（RSS）", "Resident set size"))]
    Mem,
    #[value(help = t(
        "打开的描述符数（Linux 开销小；macOS 一次 lsof 扫描；Windows 一次 PowerShell 句柄扫描）",
        "Open descriptor count (Linux cheap; one lsof scan on macOS; one PowerShell handle sweep on Windows)"
    ))]
    Fd,
    #[value(help = t("累计磁盘 I/O 字节数（读 + 写；Linux /proc）", "Cumulative disk I/O bytes (read + write; Linux /proc)"))]
    Io,
    #[value(help = t(
        "磁盘 I/O 速率（字节/秒，读 + 写；需要相隔一秒的两次采样——或一次正在运行的 --watch——才能做差分）",
        "Disk I/O rate in bytes/s (read + write; needs two samples one second apart — or a running --watch — to take the delta)"
    ))]
    IoRate,
    #[value(help = t(
        "启动至今的时长——最旧的在前（“开机以来一直跑着的是什么”）",
        "Time since start — oldest first (\"what has been running since boot\")"
    ))]
    Age,
    #[value(help = t(
        "GPU SM 占用率（NVIDIA，需要 nvidia-smi；无 GPU 或非 NVIDIA 时没有该指标）",
        "GPU SM utilization (NVIDIA, needs nvidia-smi; absent without an NVIDIA GPU)"
    ))]
    Gpu,
    #[value(help = t(
        "内核线程数（Linux /proc stat、Windows 线程快照；macOS 仅详情页可查）——线程泄漏的进程榜",
        "Kernel thread count (Linux /proc stat, Windows thread snapshot; macOS detail page only) — the thread-leak ranking"
    ))]
    Threads,
    #[value(help = t(
        "ESTABLISHED 连接数（--alert-conn 的排行版——谁攥着最多的活动连接）",
        "ESTABLISHED connection count (the ranking twin of --alert-conn — who holds the most live connections)"
    ))]
    Conn,
}

impl TopMetric {
    pub fn header(&self) -> &'static str {
        match self {
            TopMetric::Cpu => "CPU%",
            TopMetric::Mem => "RSS",
            TopMetric::Fd => "FDS",
            TopMetric::Io => "IO",
            TopMetric::IoRate => "IO/S",
            TopMetric::Age => "AGE",
            TopMetric::Gpu => "GPU%",
            TopMetric::Threads => "THR",
            TopMetric::Conn => "CONNS",
        }
    }
}

// Worked examples at the bottom of --help — kept out of the attribute so the
// bilingual block stays readable.
const EXAMPLES_ZH: &str = "示例：
  witr-rs                  列出所有进程
  witr-rs --tree           完整进程树
  witr-rs nginx            nginx 为什么在运行？
  witr-rs --pid 1234       检查一个 pid
  witr-rs --port 8080      谁占着这个端口？
  witr-rs --file /var/log/x.log   谁打开着这个文件？
  witr-rs -c web           容器 \"web\" 为什么在运行？
  witr-rs nginx --warnings 只看告警
  witr-rs nginx --env      打印进程命令行与环境变量
  witr-rs nginx --tree     完整祖先树
  witr-rs -i --port 8080   在 TUI 中打开该端口
  witr-rs --top cpu        最忙的 15 个进程，不进 TUI
  witr-rs --top age        什么进程跑得最久
  witr-rs --top cpu --watch 5   每 5 秒刷新排行
  witr-rs --top mem -n 30 --csv   内存前 30 名，CSV 格式
  witr-rs --watch 5 --record load.csv   每 5 秒记录一行 csv 样本
  witr-rs --watch 5 --record samples.jsonl   ……每帧一条 json 信封
  witr-rs --watch 5 --alert-cpu 90 --alert-exec 'curl -s $HOOK -d \"$WITR_ALERT_NAME\"'   无头看门狗
  witr-rs --watch 5 --times 12   有界 watch：采样一分钟，打印摘要后退出
  witr-rs --snap           自动快照（自动轮换，保留 10 份）
  witr-rs --snap=now.json --sockets   同时记录 LISTEN 端口，供之后 --diff
  witr-rs --diff last      距上次自动快照有什么变化
  witr-rs --diff last --json   ……JSON 格式
  witr-rs --report-html status.html   自包含 HTML 报告
  witr-rs --audit 'make build'   运行命令并报告其子树的资源足迹
  witr-rs node --kill            杀掉所有匹配的进程
  witr-rs node --kill-tree --signal KILL   ……连同所有后代
  witr-rs --watch 2 --alert-port 9090        :9090 出现新监听时告警
  witr-rs --watch 2 --alert-port '!8080' --alert-repeat 60   ……:8080 一直不在就反复催
  witr-rs --top io-rate          按磁盘 I/O 速率排最忙
  witr-rs nginx --logs --grep error   最近 100 行日志，过滤后
  witr-rs --ports          所有监听端口及其归属进程，一张表
  witr-rs --ports --watch 2   端口表常驻刷新（Ctrl-C 退出）
  witr-rs --by-name        按程序身份聚合：几个实例、共吃多少 CPU/内存
  witr-rs --port 8080 --wait          阻塞到有人监听 :8080（wait-for-deploy）
  witr-rs --pid 1234 --wait gone --timeout 60   阻塞到 1234 退出，最多等一分钟
  witr-rs nginx --pids-only | xargs kill   只打印匹配 pid，接管道
  witr-rs --watch 5 --alert-load 8 --alert-mem-pct 90   整机看门狗
  witr-rs --watch 30 --diff-auto 30   每 30 秒打印一次进程表漂移
  witr-rs --serve :9100    在 :9100 暴露 Prometheus 指标（curl :9100/api/ps 取 JSON）
  witr-rs --sys            整机仪表盘：CPU/内存/负载/磁盘/网卡/温度/PSI（--watch 2 常驻）
  witr-rs --top threads    线程数最多的进程（--top conn 看谁攥着最多连接）
  witr-rs --watch 10 --alert-container   无头容器哨兵：容器退出/OOM/crash loop 即喊
  witr-rs --man witr-rs.1  写出 man 手册页";

const EXAMPLES_EN: &str = "Examples:
  witr-rs                  list all processes
  witr-rs --tree           full process tree
  witr-rs nginx            why is nginx running?
  witr-rs --pid 1234       inspect one pid
  witr-rs --port 8080      who owns this port?
  witr-rs --file /var/log/x.log   who holds this file open?
  witr-rs -c web           why is container \"web\" running?
  witr-rs nginx --warnings show only the warnings
  witr-rs nginx --env      print the process environment
  witr-rs nginx --tree     full ancestry tree
  witr-rs -i --port 8080   TUI opened on this port
  witr-rs --top cpu        hottest 15 processes, no TUI
  witr-rs --top age        what has been running the longest
  witr-rs --top cpu --watch 5   refresh the top ranking every 5s
  witr-rs --top mem -n 30 --csv   top-30 memory as CSV
  witr-rs --watch 5 --record load.csv   record a csv sample every 5s
  witr-rs --watch 5 --record samples.jsonl   ...as one json envelope per tick
  witr-rs --watch 5 --alert-cpu 90 --alert-exec 'curl -s $HOOK -d \"$WITR_ALERT_NAME\"'   headless watchdog
  witr-rs --watch 5 --times 12   bounded watch: sample a minute, print the digest, exit
  witr-rs --snap           auto snapshot (rotates, keeps 10)
  witr-rs --snap=now.json --sockets   also record LISTEN ports for a later --diff
  witr-rs --diff last      what changed since the last auto snapshot
  witr-rs --diff last --json   ...as JSON
  witr-rs --report-html status.html   self-contained html report
  witr-rs --audit 'make build'   run a command, report its subtree resource footprint
  witr-rs node --kill            kill every matching process
  witr-rs node --kill-tree --signal KILL   ...and every descendant
  witr-rs --watch 2 --alert-port 9090        alert when something starts listening on :9090
  witr-rs --watch 2 --alert-port '!8080' --alert-repeat 60   ...and keep nagging while :8080 is down
  witr-rs --top io-rate          hottest processes by disk-I/O rate
  witr-rs nginx --logs --grep error   last 100 log lines, filtered
  witr-rs --ports          every listening port and its owner, one table
  witr-rs --ports --watch 2   keep the port table refreshed (Ctrl-C to stop)
  witr-rs --by-name        aggregate by identity: how many instances, total cpu/memory
  witr-rs --port 8080 --wait          block until something listens on :8080 (wait-for-deploy)
  witr-rs --pid 1234 --wait gone --timeout 60   block until 1234 exits, at most a minute
  witr-rs nginx --pids-only | xargs kill   print matching pids only, feed a pipe
  witr-rs --watch 5 --alert-load 8 --alert-mem-pct 90   machine-wide watchdog
  witr-rs --watch 30 --diff-auto 30   print process-table drift every 30s
  witr-rs --serve :9100    expose Prometheus metrics on :9100 (curl :9100/api/ps for JSON)
  witr-rs --sys            the machine dashboard: cpu/mem/load/disk/nic/temp/psi (--watch 2 to keep it live)
  witr-rs --top threads    most-threaded processes (--top conn for who holds the most connections)
  witr-rs --watch 10 --alert-container   headless container sentinel: exit/OOM/crash loop shouts
  witr-rs --man witr-rs.1  write the man page";

fn examples() -> &'static str {
    if ENGLISH.load(Ordering::Relaxed) {
        EXAMPLES_EN
    } else {
        EXAMPLES_ZH
    }
}

impl Cli {
    /// Fold the user config under the CLI flags: the file holds defaults,
    /// an explicit flag wins. Applied once right after load so every
    /// downstream consumer (validation, watch loop, TUI seeds) sees the
    /// resolved value. Only the alert knobs participate — the TUI keys
    /// (refresh_secs/sort/notify/paused/watch/notes) are read at their own
    /// use sites.
    pub fn apply_config(&mut self, cfg: &crate::config::Config) {
        self.alert_cpu = self.alert_cpu.or(cfg.alert_cpu);
        self.alert_mem = self.alert_mem.or(cfg.alert_mem);
        self.alert_fd = self.alert_fd.or(cfg.alert_fd);
        self.alert_io = self.alert_io.or(cfg.alert_io);
        self.alert_conn = self.alert_conn.or(cfg.alert_conn);
        self.alert_threads = self.alert_threads.or(cfg.alert_threads);
        self.alert_container = self.alert_container || cfg.alert_container.unwrap_or(false);
        self.alert_load = self.alert_load.or(cfg.alert_load);
        self.alert_mem_pct = self.alert_mem_pct.or(cfg.alert_mem_pct);
        self.alert_count = self.alert_count.or(cfg.alert_count);
        self.alert_disk = self.alert_disk.or(cfg.alert_disk);
        self.alert_net = self.alert_net.or(cfg.alert_net);
        self.alert_psi = self.alert_psi.or(cfg.alert_psi);
        self.alert_repeat = self.alert_repeat.or(cfg.alert_repeat);
        if self.alert_exec.is_none() {
            self.alert_exec = cfg.alert_exec.clone();
        }
        if self.alert_webhook.is_none() {
            self.alert_webhook = cfg.alert_webhook.clone();
        }
        if self.serve_token.is_none() {
            self.serve_token = cfg.serve_token.clone();
        }
        if self.alert_silence.is_empty() {
            self.alert_silence = cfg.alert_silence.clone();
        }
        if self.alert_new_proc.is_empty() {
            self.alert_new_proc = cfg.alert_new_proc.clone();
        }
    }
}

// witr-rs 的命令行定义。帮助文本双语：默认中文，`--en` 切换英文——每个
// 帮助串都经 t() 在 Command 构建时定稿，语言由 init_language() 预扫描决定。
#[derive(Parser, Debug, Clone)]
#[command(
    name = "witr-rs",
    version,
    about = t(
        "Why is this running? —— 给出进程名、PID、端口或文件，一路追溯它是被谁、以何种方式拉起来的。pranshuparmar/witr 的 Rust 重写版",
        "Why is this running? — trace processes, ports and files back to what started them. A Rust rewrite inspired by pranshuparmar/witr"
    ),
    after_help = examples()
)]
pub struct Cli {
    #[arg(
        value_name = "NAMES",
        help = t(
            "要溯源的进程名，可给多个（子串匹配；配合 --exact 精确匹配）。完全不带目标时，witr-rs 列出所有进程",
            "Process name(s) to trace (substring match; combine with --exact). With no target at all, witr-rs lists every process"
        )
    )]
    pub names: Vec<String>,

    #[arg(
        short = 'p',
        long = "pid",
        value_name = "PID",
        help = t("按 PID 溯源（可重复）", "Trace by pid (repeatable)")
    )]
    pub pids: Vec<i32>,

    #[arg(
        long = "port",
        value_name = "PORT",
        help = t("按本地端口溯源（可重复）", "Trace by local port (repeatable)")
    )]
    pub ports: Vec<u16>,

    #[arg(
        short = 'f',
        long = "file",
        value_name = "PATH",
        help = t(
            "按打开的文件路径溯源（可重复；支持 /var/log/*.log 这类通配符，匹配所有已存在的文件）",
            "Trace by open file path (repeatable; globs like /var/log/*.log match every existing file)"
        )
    )]
    pub files: Vec<String>,

    #[arg(
        short = 'c',
        long = "container",
        value_name = "QUERY",
        help = t(
            "按容器溯源（名称、镜像、ID 前缀；可重复）",
            "Trace by container (name, image, id prefix; repeatable)"
        )
    )]
    pub containers: Vec<String>,

    #[arg(
        short = 'x',
        long,
        help = t("进程名按精确匹配，而非子串匹配", "Match names exactly instead of by substring")
    )]
    pub exact: bool,

    #[arg(
        short = 't',
        long,
        help = t("把祖先链显示为进程树", "Show the ancestry as a tree")
    )]
    pub tree: bool,

    #[arg(
        short = 's',
        long,
        help = t("每个匹配结果只输出一行（便于脚本处理）", "Single-line output per match (for scripts)")
    )]
    pub short: bool,

    #[arg(short = 'j', long, help = t("输出机器可读的 JSON", "Machine-readable JSON"))]
    pub json: bool,

    #[arg(
        long = "warnings",
        help = t("只显示为匹配进程采集到的告警", "Show only the collected warnings for the matched process(es)")
    )]
    pub warnings: bool,

    #[arg(
        long = "env",
        help = t(
            "只打印进程的命令行与环境变量，不输出其他内容",
            "Print the process command and environment variables, nothing else"
        )
    )]
    pub env: bool,

    #[arg(
        long = "no-color",
        help = t(
            "关闭彩色输出（同时遵循 NO_COLOR 环境变量）",
            "Disable colored output (also honors the NO_COLOR environment variable)"
        )
    )]
    pub no_color: bool,

    #[arg(
        long = "list",
        help = t(
            "即使在终端下也强制输出静态进程列表（无参数时默认进 TUI）",
            "Force the static process listing even on a terminal (no args = TUI)"
        )
    )]
    pub list: bool,

    #[arg(
        long = "ports",
        help = t(
            "列出所有 LISTEN 套接字及其归属进程——一次性表格版的端口总览（端口、协议、暴露范围、归属进程；SCOPE：internet=0.0.0.0/:: 通配绑定、外网可达，loopback=仅本机，iface=具体地址）。可搭配 --csv / --json。属于无目标操作：不能与目标同时使用",
            "List every LISTEN socket with its owning processes — the Ports overview as a one-shot table (port, proto, exposure scope, owners; SCOPE: internet = wildcard 0.0.0.0/:: bind, reachable from anywhere; loopback = this host only; iface = specific addresses). Pairs with --csv / --json. A no-target operation: cannot be combined with targets"
        )
    )]
    pub ports_list: bool,

    #[arg(
        short = 'i',
        long = "interactive",
        help = t(
            "即使带了目标也打开交互式 TUI，并直接定位到目标（每类目标限一个：进程名、PID、端口、文件、容器）",
            "Open the interactive TUI even with targets, seeded from them (one target per type: name, pid, port, file, container)"
        )
    )]
    pub interactive: bool,

    #[arg(
        long = "export",
        help = t(
            "输出纯文本诊断报告（进程身份、来源、祖先链、环境变量取值、打开的文件）——可与任意目标搭配",
            "Plain-text diagnostic report (identity, source, chain, env values, open files) — combine with any target"
        )
    )]
    pub export: bool,

    #[arg(
        long = "pids-only",
        help = t(
            "只打印目标匹配到的 pid（空格分隔一行）——`witr-rs nginx --pids-only | xargs kill` 的管道用法；无匹配退出码 2",
            "Print only the pids the targets matched (space-separated, one line) — the `witr-rs nginx --pids-only | xargs kill` pipe; exit 2 when nothing matched"
        )
    )]
    pub pids_only: bool,

    #[arg(
        long = "recent",
        value_name = "DURATION",
        help = t(
            "只列出在该时间窗内启动的进程（30、30s、5m、2h、1d、1h30m）。过滤列表输出；不能与目标同时使用",
            "Only list processes started within this window (30, 30s, 5m, 2h, 1d, 1h30m). Filters the listing; cannot be combined with targets"
        )
    )]
    pub recent: Option<String>,

    #[arg(
        long = "top",
        value_name = "METRIC",
        help = t(
            "按该指标输出前 N 名进程，代替完整列表（默认 N = 15，可用 --count 覆盖）。属于无目标操作：不能与目标同时使用",
            "Print the top N processes by this metric instead of a full listing (default N = 15, override with --count). A no-target operation: cannot be combined with targets"
        )
    )]
    pub top: Option<TopMetric>,

    #[arg(
        short = 'n',
        long = "count",
        value_name = "N",
        help = t("--top 的行数（默认 15）", "Row count for --top (default 15)")
    )]
    pub count: Option<usize>,

    #[arg(
        long = "by-name",
        help = t(
            "按程序身份（名字 + 用户）聚合整张进程表：实例数 / ΣCPU / Σ内存 / Σ累计 CPU 时间——回答“8 个 node 进程一共吃了多少”。属于无目标操作；可搭配 --csv / --markdown / --json / --watch",
            "Aggregate the whole table by program identity (name + user): instance count / ΣCPU / Σmemory / Σlifetime CPU time — \"what do the 8 node processes cost together\". A no-target operation; pairs with --csv / --markdown / --json / --watch"
        )
    )]
    pub by_name: bool,

    #[arg(
        long,
        help = t(
            "列出全部僵尸进程（state Z）及其父进程——谁的锅一眼可见。发现僵尸退出码 1，干净则 0，脚本可直接判断。属于无目标操作；--csv / --markdown / --json 同样支持",
            "List every zombie process (state Z) with its parent — whose fault it is, at a glance. Exit 1 when any zombie exists, 0 when clean, so scripts can branch. A no-target operation; --csv / --markdown / --json work too"
        )
    )]
    pub zombies: bool,

    #[arg(
        long,
        help = t(
            "列出全系统当前持有的文件锁（持锁进程 / 模式 / 文件路径）——“哪个进程锁着这个文件”一条命令。属于无目标操作；--csv / --markdown / --json 同样支持",
            "List every file lock currently held system-wide (holder / mode / file path) — \"which process locks this file\" in one command. A no-target operation; --csv / --markdown / --json work too"
        )
    )]
    pub locks: bool,

    #[arg(
        long,
        help = t(
            "列出服务管理器当前的单元（Linux systemd / macOS launchd / Windows SCM 服务）：管理器 / 名称 / 状态 / 主 pid / 描述。Services 页（6）的 CLI 孪生。属于无目标操作；--csv / --markdown / --json 同样支持",
            "List the service manager's current units (Linux systemd / macOS launchd / Windows SCM services): manager / name / state / main pid / description. The Services tab's (6) CLI twin. A no-target operation; --csv / --markdown / --json work too"
        )
    )]
    pub services: bool,

    #[arg(
        long = "sys",
        help = t(
            "整机仪表盘：CPU 占用（含每核）、内存/swap、load average、磁盘挂载点用量、网卡速率、温度与 PSI 压力（平台支持时）——系统资源页（y）的 CLI 孪生。属于无目标操作；--json / --csv / --markdown 一次性输出，--watch 常驻刷新",
            "The machine dashboard: CPU usage (per-core included), memory/swap, load average, disk mount usage, NIC rates, temperature and PSI pressure (where the platform reports them) — the system page's (y) CLI twin. A no-target operation; --json / --csv / --markdown are one-shot, --watch keeps it refreshed"
        )
    )]
    pub sys: bool,

    #[arg(
        long,
        help = t(
            "列出全机的网络连接（LISTEN 之外的所有状态：ESTABLISHED / TIME_WAIT / …）——本地地址 / 对端 / 状态 / 属主进程；回环对端自动归因到本机另一端的进程。--ports 的镜像面。属于无目标操作；--csv / --markdown / --json / --watch 同样支持",
            "List the machine's network connections (every state except LISTEN: ESTABLISHED / TIME_WAIT / ...) — local / peer / state / owning process; loopback peers are attributed to the local process on the other end. The mirror of --ports. A no-target operation; --csv / --markdown / --json / --watch work too"
        )
    )]
    pub conns: bool,

    #[arg(
        long = "by-peer",
        requires = "conns",
        help = t(
            "把 --conns 的连接按远端地址聚合（本地属主）：每个对端一行，连接数 / ESTABLISHED 数 / 其余状态 / 本地属主列表——回答“这台机器在和谁说话”。可搭配 --csv / --markdown / --json / --watch",
            "Aggregate --conns by remote address: one row per peer with connection count / ESTABLISHED count / remaining states / local owners — \"who is this machine talking to\". Pairs with --csv / --markdown / --json / --watch"
        )
    )]
    pub by_peer: bool,

    #[arg(
        long,
        help = t(
            "把列表 / --top 行输出为 CSV（一行表头 + 每个进程一行）。属于无目标格式：不能与目标同时使用——目标查询请用 --json",
            "Emit the listing / --top rows as CSV (one header row + one row per process). A no-target format: cannot be combined with targets — use --json there"
        )
    )]
    pub csv: bool,

    #[arg(
        long,
        help = t(
            "把列表 / --top 行输出为 Markdown 表格（可直接粘贴到 issue 和 PR）。规则与 --csv 相同",
            "Emit the listing / --top rows as a Markdown table (pastes into issues and PRs). Same rules as --csv"
        )
    )]
    pub markdown: bool,

    #[arg(
        long = "record",
        value_name = "FILE",
        help = t(
            "配合 --watch（无目标——记录整个进程表）：每刷新一次，把每个可见进程追加一行 CSV 到该文件（timestamp、pid、user、name、cpu_pct、rss_mb，平台支持时还有每秒 io 读/写字节）。不影响控制台输出",
            "With --watch (no targets — it records the whole table): append one CSV row per visible process per refresh tick to this file (timestamp, pid, user, name, cpu_pct, rss_mb, io read/write bytes-per-second where the platform reports them). Leaves the console output untouched"
        )
    )]
    pub record: Option<String>,

    #[arg(
        long = "watch",
        value_name = "SECONDS",
        num_args = 0..=1,
        default_missing_value = "2",
        help = t(
            "每 N 秒重新执行一次当前查询（默认 2），直到 Ctrl-C。可用于目标查询、普通列表和 --recent",
            "Re-run the current query every N seconds (default 2) until Ctrl-C. Works with targets, the plain listing and --recent"
        )
    )]
    pub watch: Option<u64>,

    #[arg(
        long = "times",
        value_name = "N",
        help = t(
            "--watch 达到该刷新次数后停止并退出（给 CI 和 cron 的时长上限：`--watch 5 --times 12` 采样一分钟，打印摘要后退出）。需要 --watch",
            "Stop --watch after this many refresh ticks and exit (a duration bound for CI and cron: `--watch 5 --times 12` samples for a minute, then prints the summary and exits). Needs --watch"
        )
    )]
    pub times: Option<u64>,

    #[arg(
        long = "quiet",
        help = t(
            "静默版 --watch：完全跳过每次刷新的表格重绘——只打印告警、follow 提示和钩子输出，无头看门狗可以连跑几天而不撑爆回滚缓冲或管道。需要 --watch",
            "Quiet --watch: skip the per-tick table redraw entirely — only alerts, follow notes and hook output are printed, so a headless watchdog can run for days without filling the scrollback or a pipeline. Needs --watch"
        )
    )]
    pub quiet: bool,

    #[arg(
        long = "wait",
        value_name = "WHAT",
        num_args = 0..=1,
        default_missing_value = "here",
        help = t(
            "阻塞等待目标出现（--wait 或 --wait here）或消失（--wait gone）：每秒轮询一次，条件满足即退出——here 打印正常溯源结果，gone 打印一行 gone: 确认，两者退出码都是 0。配 --timeout 限时（超时退出码 124，GNU timeout 惯例）。需要目标",
            "Block until the target appears (--wait or --wait here) or disappears (--wait gone): poll once a second; when the condition holds, exit 0 — `here` prints the normal trace, `gone` prints a one-line gone: confirmation. Add --timeout to bound it (exit 124 on timeout, the GNU timeout convention). Needs a target"
        )
    )]
    pub wait: Option<String>,

    #[arg(
        long = "timeout",
        value_name = "SECONDS",
        help = t(
            "--wait 的时间上界（秒）：超时以 124 退出。0 或缺省 = 一直等",
            "Time bound for --wait in seconds: timeout exits 124. 0 or unset = wait forever"
        )
    )]
    pub timeout: Option<u64>,

    #[arg(
        long = "logs",
        value_name = "N",
        num_args = 0..=1,
        default_missing_value = "100",
        help = t(
            "打印匹配进程的最后 N 行日志（默认 100）：归属到容器时取容器日志，否则取 journald（Linux）或统一日志（macOS）。加 --grep PATTERN 只保留匹配行",
            "Print the last N log lines (default 100) of the matched process: container logs when attributed to one, else journald (Linux) or the unified log (macOS). Add --grep PATTERN to keep only matching lines"
        )
    )]
    pub logs: Option<u64>,

    #[arg(
        long = "grep",
        value_name = "PATTERN",
        help = t("配合 --logs：只保留包含该子串的日志行", "With --logs: keep only log lines containing this substring")
    )]
    pub grep: Option<String>,

    #[arg(
        long = "events-log",
        value_name = "FILE",
        help = t(
            "把每个事件（出现/退出/重启）以 JSON lines 追加到该文件——持久记录，之后可用 --replay 回放。无目标时也能在 `--watch` 下无头运行（阈值告警写入同一数据流）；TUI 下则记录采样器",
            "Append every event (started/exited/restarted) as JSON lines to this file — a durable record you can --replay later. Without targets this works headless under `--watch` too (threshold alerts land in the same stream); with the TUI it records the sampler"
        )
    )]
    pub events_log: Option<String>,

    #[arg(
        long = "replay",
        value_name = "FILE",
        help = t(
            "打开 TUI 的 Events 页，回放 --events-log 录制的文件；在导入的历史之上继续实时采样。加 --follow 持续跟随文件末尾——录制侧追加的事件实时流入（把 TUI 变成另一台机器/另一个会话的直播窗口）",
            "Open the TUI on the Events tab replaying a recorded --events-log file; live sampling continues on top of the imported history. Add --follow to keep tailing the file — events the recording side appends stream in live (turns the TUI into a live window onto another session or machine)"
        )
    )]
    pub replay: Option<String>,

    #[arg(
        long = "since",
        value_name = "DURATION",
        help = t(
            "会话摘要时间窗（30、30s、5m、2h、1d）：配合 --replay FILE，打印已录事件的“发生了什么”摘要后退出；TUI 下则设定 'S' 摘要页的时间窗",
            "Session digest window (30, 30s, 5m, 2h, 1d): with --replay FILE, print a \"what happened\" digest of the recorded events and exit; with the TUI it sets the 'S' summary-page window"
        )
    )]
    pub since: Option<String>,

    #[arg(
        long = "notify",
        help = t(
            "进程重启或反复退出（崩溃循环）时发桌面通知：macOS osascript / Linux notify-send。仅 TUI；'!' 键可实时开关",
            "Desktop notifications when a process restarts, or exits repeatedly (crash loop): macOS osascript / Linux notify-send. TUI only; the '!' key toggles it live"
        )
    )]
    pub notify: bool,

    #[arg(
        long = "alert-cpu",
        value_name = "PCT",
        help = t(
            "进程 CPU 占用率连续 5 次采样（约 15s）超过该百分比时告警：桌面通知 + Events 页记录 + 红色行高亮。一次超标只告警一次——回落后重新武装。TUI 和 --watch 下均可用",
            "Alert when a process exceeds this CPU% for 5 consecutive samples (~15s): desktop notification + Events-tab record + red row highlight. One alert per excursion — re-arms when usage drops back under. Works in the TUI and under --watch"
        )
    )]
    pub alert_cpu: Option<f64>,

    #[arg(
        long = "alert-mem",
        value_name = "MB",
        help = t(
            "进程 RSS 连续 5 次采样（约 15s）超过该 MB 数时告警——行为与 --alert-cpu 相同。TUI 和 --watch",
            "Alert when a process exceeds this RSS in MB for 5 consecutive samples (~15s) — same behavior as --alert-cpu. TUI and --watch"
        )
    )]
    pub alert_mem: Option<u64>,

    #[arg(
        long = "alert-fd",
        value_name = "N",
        help = t(
            "进程打开的描述符数连续 5 次采样（约 15s）超过该值时告警——--alert-cpu/--alert-mem 的阈值告警姊妹版，用于 fd 泄漏。每次刷新多一次 fd 扫描（Linux 开销小，macOS 一次 lsof，Windows 一次 PowerShell 扫描）。TUI 和 --watch",
            "Alert when a process exceeds this open-descriptor count for 5 consecutive samples (~15s) — the threshold-alert twin of --alert-cpu/--alert-mem, for fd leaks. Costs one fd sweep per refresh (cheap on Linux, one lsof scan on macOS, one PowerShell sweep on Windows). TUI and --watch"
        )
    )]
    pub alert_fd: Option<u64>,

    #[arg(
        long = "alert-io",
        value_name = "MB/S",
        help = t(
            "进程磁盘 I/O 速率连续 5 次采样（约 15s）超过该 MB/s（读 + 写合计）时告警。TUI 和 --watch",
            "Alert when a process exceeds this disk-I/O rate in MB/s (read + write combined) for 5 consecutive samples (~15s). TUI and --watch"
        )
    )]
    pub alert_io: Option<f64>,

    #[arg(
        long = "alert-conn",
        value_name = "N",
        help = t(
            "进程持有的 ESTABLISHED 连接数连续 5 次采样（约 15s）超过该值时告警——--alert-fd 的网络版，用于连接泄漏。TUI 和 --watch",
            "Alert when a process holds more than this many ESTABLISHED connections for 5 consecutive samples (~15s) — the network twin of --alert-fd, for connection leaks. TUI and --watch"
        )
    )]
    pub alert_conn: Option<u64>,

    #[arg(
        long = "alert-threads",
        value_name = "N",
        help = t(
            "进程内核线程数连续 5 次采样（约 15s）超过该值时告警——内存/fd 泄漏哨兵的线程版：线程只增不减的服务（每次请求 spawn 线程却不回收）在这里现形。TUI 和 --watch",
            "Alert when a process exceeds this kernel thread count for 5 consecutive samples (~15s) — the thread twin of the memory/fd leak sentinels: services that spawn threads per request and never reap them surface here. TUI and --watch"
        )
    )]
    pub alert_threads: Option<u64>,

    #[arg(
        long = "alert-container",
        help = t(
            "配合 --watch 的容器与 Pod 边缘哨兵：运行中的容器退出时取死因（OOMKilled 点名 OOM）、RestartCount 攀升提示 crash loop；集群可达时 Pod 的 CrashLoopBackOff / 回退 Pending / Failed / 重启数攀升各报一条。边缘触发、只报一次——⚠ 行、--alert-exec / --alert-webhook / --events-log 照常生效（TUI 的 Containers 页无需此旗标即已盯边缘）",
            "Container & pod edge sentinel for a headless --watch: a running container exiting names its cause of death (OOMKilled calls out OOM), a climbing RestartCount flags a crash loop; with a reachable cluster, pod CrashLoopBackOff / back-to-Pending / Failed / restart climbs each report once. Edge-triggered, one alert per edge — the ⚠ line, --alert-exec / --alert-webhook / --events-log all apply (the TUI's Containers page watches these edges without the flag)"
        )
    )]
    pub alert_container: bool,

    #[arg(
        long = "alert-load",
        value_name = "N",
        help = t(
            "整机告警：1 分钟负载均值连续 5 次采样（约 15s）超过该值时触发。与按进程的 --alert-* 阈值不同，它盯着整台机器——失控进程、内存颠簸、超载主机。TUI 和 --watch",
            "Machine-wide alert: fire when the 1-minute load average exceeds this value for 5 consecutive samples (~15s). Unlike the per-process --alert-* thresholds this watches the whole machine — runaways, thrashing, an overloaded box. TUI and --watch"
        )
    )]
    pub alert_load: Option<f64>,

    #[arg(
        long = "alert-mem-pct",
        value_name = "PCT",
        help = t(
            "整机告警：已用内存占物理内存的百分比连续 5 次采样（约 15s）超过该值时触发。TUI 和 --watch",
            "Machine-wide alert: fire when used RAM exceeds this percent of physical memory for 5 consecutive samples (~15s). TUI and --watch"
        )
    )]
    pub alert_mem_pct: Option<u64>,

    #[arg(
        long = "alert-count",
        value_name = "N",
        help = t(
            "整机告警：可见进程数连续 5 次采样（约 15s）超过该值时触发——fork 炸弹、失控任务生成器把进程表撑爆的哨兵。TUI 和 --watch",
            "Machine-wide alert: fire when the visible process count exceeds this value for 5 consecutive samples (~15s) — a sentinel for table explosions (fork bombs, runaway task spawners). TUI and --watch"
        )
    )]
    pub alert_count: Option<u32>,

    #[arg(
        long = "alert-disk",
        value_name = "PCT",
        help = t(
            "整机告警：任一本地磁盘的已用百分比连续 5 次采样（约 15s）超过该值时触发——磁盘写满之前喊一嗓子，详情列出最满的挂载点。TUI 和 --watch",
            "Machine-wide alert: fire when any local disk's used percent exceeds this value for 5 consecutive samples (~15s) — a shout before the disk fills; the detail names the fullest mounts. TUI and --watch"
        )
    )]
    pub alert_disk: Option<u64>,

    #[arg(
        long = "alert-net",
        value_name = "MB/S",
        help = t(
            "整机告警：全部非回环网卡的收发合计速率连续 5 次采样（约 15s）超过该值（MB/s）时触发——流量打满出口、进程偷偷外传数据的哨兵。TUI 和 --watch",
            "Machine-wide alert: fire when the combined rx+tx rate across all non-loopback NICs exceeds this value (MB/s) for 5 consecutive samples (~15s) — a sentinel for saturated uplinks and processes quietly exfiltrating data. TUI and --watch"
        )
    )]
    pub alert_net: Option<u64>,

    #[arg(
        long = "alert-psi",
        value_name = "PCT",
        help = t(
            "整机告警：任一资源的 PSI full 停滞（10 秒窗）连续 5 次采样（约 15s）超过该百分比时触发——所有任务都卡在 cpu/memory/io 上的“机器喘不过气”信号（Linux，内核需开 PSI）。TUI 和 --watch",
            "Machine-wide alert: fire when any resource's PSI full stall (10s window) exceeds this percent for 5 consecutive samples (~15s) — every task stuck on cpu/memory/io at once, the machine-gasping signal (Linux, kernel PSI required). TUI and --watch"
        )
    )]
    pub alert_psi: Option<f64>,

    #[arg(
        long = "alert-port",
        value_name = "PORT|!PORT",
        help = t(
            "监听金丝雀，可重复：有进程开始 LISTEN 该端口时告警（只报边沿——启动时就已绑定的端口属于现状，不算事件）。加 ! 前缀反转：`--alert-port '!8080'` 在原本存在的监听消失时告警。TUI 和 --watch",
            "Listener canary, repeatable: alert when something starts LISTENing on this port (an edge — a port already bound at startup is the status quo, not an event). Prefix with ! to invert: `--alert-port '!8080'` alerts when a listener that was up disappears. TUI and --watch"
        )
    )]
    pub alert_port: Vec<String>,

    #[arg(
        long = "alert-repeat",
        value_name = "SECONDS",
        help = t(
            "阈值告警持续命中时，改为约每 N 秒重发一次而不是每次超标只报一次——适合一直催到有人来看的看门狗。需要某个 --alert-* 阈值",
            "While a threshold alert keeps firing, re-send it about every N seconds instead of once per excursion — a watchdog that nags until someone looks. Needs one of the --alert-* thresholds"
        )
    )]
    pub alert_repeat: Option<u64>,

    #[arg(
        long = "alert-exec",
        value_name = "CMD",
        help = t(
            "每次阈值告警触发时执行该 shell 命令（需要 --alert-cpu/--alert-mem/--alert-fd/--alert-io/--alert-conn/--alert-port/--alert-load/--alert-mem-pct 之一；每次超标执行一次）。告警上下文以 WITR_ALERT_PID / WITR_ALERT_NAME / WITR_ALERT_DETAIL 导出——例如 `--alert-exec 'curl -s $SLACK_HOOK -d \"$WITR_ALERT_NAME: $WITR_ALERT_DETAIL\"'`。TUI 和 --watch",
            "Run this shell command each time a threshold alert fires (needs one of --alert-cpu/--alert-mem/--alert-fd/--alert-io/--alert-conn/--alert-port/--alert-load/--alert-mem-pct; one run per excursion). The alert context is exported as WITR_ALERT_PID / WITR_ALERT_NAME / WITR_ALERT_DETAIL — e.g. `--alert-exec 'curl -s $SLACK_HOOK -d \"$WITR_ALERT_NAME: $WITR_ALERT_DETAIL\"'`. TUI and --watch"
        )
    )]
    pub alert_exec: Option<String>,

    #[arg(
        long = "alert-webhook",
        value_name = "URL",
        help = t(
            "每次阈值告警触发时向该 URL POST 一条 JSON 告警（与 --events-log 信封同构；仅支持 http://——标准库无 TLS，https:// 会被拒绝并提示）。发送在后台线程进行（3 秒超时），失败只打一行 stderr，绝不拖慢采样。TUI 和 --watch",
            "POST one JSON alert to this URL each time a threshold alert fires (same shape as the --events-log envelope; http:// only — std has no TLS, https:// is refused with a note). Sending runs on a background thread (3s timeout); failures print one stderr line and never stall the sampler. TUI and --watch"
        )
    )]
    pub alert_webhook: Option<String>,

    #[arg(
        long = "alert-silence",
        value_name = "NAME[=DUR]",
        num_args = 1..,
        help = t(
            "告警静默窗口：名字包含 NAME 的进程不再触发告警（维护窗口）。NAME=30m 只静默 30 分钟（从会话开始计），不带 =DUR 则整个会话静默；!NAME 反选（只静默名字不含 NAME 的）。可重复/可一次给多个，如 --alert-silence backup=30m db=1h。TUI 和 --watch",
            "Alert silence window: processes whose name contains NAME stop raising alerts (a maintenance window). NAME=30m silences for 30 minutes from session start; without =DUR the whole session is silenced; !NAME inverts (silence names NOT matching). Repeatable / several at once: --alert-silence backup=30m db=1h. TUI and --watch"
        )
    )]
    pub alert_silence: Vec<String>,

    #[arg(
        long = "alert-new-proc",
        value_name = "NAME",
        num_args = 1..,
        help = t(
            "首见进程告警：会话内第一次出现名字包含 NAME 的进程就告警（挖矿/后门检测）。!NAME 反选为白名单模式——只对名字不含任何模式的进程告警；两种形态不能混用。每个名字每次会话只报一次。可一次给多个：--alert-new-proc xmrig miner。TUI 和 --watch",
            "First-sighting alerts: fire once the first time a process whose name contains NAME appears in the session (miner/backdoor detection). !NAME switches to whitelist mode — alert only on names matching NO pattern; the two forms can't be mixed. Once per name per session. Several at once: --alert-new-proc xmrig miner. TUI and --watch"
        )
    )]
    pub alert_new_proc: Vec<String>,

    #[arg(
        long = "install-service",
        value_name = "PATH",
        num_args = 0..=1,
        default_missing_value = "",
        help = t(
            "把当前这组 watch/alert 参数固化成系统服务并注册：Linux 写 systemd 用户单元（~/.config/systemd/user/witr-rs.service 并 enable --now），macOS 写 launchd plist（~/Library/LaunchAgents 并 launchctl load），Windows 写 schtasks XML 并提示注册命令。可给自定义路径 --install-service /tmp/w.service。至少要给一个 --watch 或 --alert-* 参数",
            "Bake the current watch/alert flags into a system service and register it: Linux writes a systemd user unit (~/.config/systemd/user/witr-rs.service, enabled --now), macOS a launchd plist (~/Library/LaunchAgents, launchctl load), Windows a schtasks XML plus the registration command. Custom path: --install-service /tmp/w.service. Needs at least one --watch or --alert-* flag"
        )
    )]
    pub install_service: Option<String>,

    #[arg(
        long = "audit",
        value_name = "CMD",
        help = t(
            "在 shell 下运行 CMD，只盯它的进程子树，退出时打印审计报告：实际耗时、退出码、派生了多少进程、子树峰值 CPU/RSS、磁盘 I/O 和进程树。加 --json 得到机器可读的信封（CI 可对峰值 RSS、派生进程数等做断言）。独立模式：不能与目标同时使用",
            "Run CMD under a shell, watch only its process subtree, and on exit print the audit report: wall duration, exit code, how many processes it spawned, peak subtree CPU/RSS, disk I/O and the process tree. Add --json for the machine-readable envelope (CI can assert on peak RSS, spawned counts and the like). A standalone mode: cannot be combined with targets"
        )
    )]
    pub audit: Option<String>,

    #[arg(
        long = "kill",
        help = t(
            "杀掉所有匹配目标的进程（进程名、--pid、--port、--file、--container），而不是只做报告。默认发 SIGTERM，除非 --signal 另有指定。需要目标",
            "Kill every process matching the targets (name, --pid, --port, --file, --container) instead of reporting on them. Sends SIGTERM unless --signal says otherwise. Needs targets"
        )
    )]
    pub kill: bool,

    #[arg(
        long = "kill-tree",
        help = t(
            "同 --kill，但还会杀掉每个匹配的所有后代（先杀子进程，再杀匹配本身）。需要目标",
            "Like --kill, but also kills every descendant of each match (children first, then the match). Needs targets"
        )
    )]
    pub kill_tree: bool,

    #[arg(
        long = "signal",
        value_name = "SIG",
        help = t(
            "--kill/--kill-tree 使用的信号名（默认 TERM；如 KILL、INT、HUP——Unix 下传给 `kill -s`，Windows 下 KILL 映射为 taskkill /F）",
            "Signal name for --kill/--kill-tree (default TERM; e.g. KILL, INT, HUP — passed to `kill -s` on Unix, mapped to taskkill /F for KILL on Windows)"
        )
    )]
    pub signal: Option<String>,

    #[arg(
        long = "report-html",
        value_name = "FILE",
        help = t(
            "把当前进程表生成自包含的 HTML 报告（摘要 + 带 CPU/内存条的完整表格）写入该文件后退出。属于无目标操作：不能与目标同时使用",
            "Self-contained HTML report of the current process table (a summary plus the full table with cpu/mem bars) written to this file, then exit. A no-target operation: cannot be combined with targets"
        )
    )]
    pub report_html: Option<String>,

    #[arg(
        long = "plot",
        value_name = "FILE",
        num_args = 1..,
        help = t(
            "把 --record 产出的样本文件（.csv 或 .jsonl）画成自包含 HTML 时序图（内联 SVG：整机 cpu%、内存%、负载、进程数、网络速率），写入 FILE.html 后退出——无 JS、无外部资源，离线可看。给多个文件则曲线叠加对比（发布前后各录一份，一图看清差异），输出 witr-plot.html。属于无目标操作：不能与目标同时使用",
            "Render a --record sample file (.csv or .jsonl) into a self-contained HTML time-series chart (inline SVG: machine cpu%, memory%, load, process count, network rate), written to FILE.html, then exit — no JS, no external assets, viewable offline. Multiple files overlay their curves for before/after comparison (output witr-plot.html). A no-target operation: cannot be combined with targets"
        )
    )]
    pub plot: Vec<String>,

    #[arg(
        long = "samples",
        value_name = "FILE",
        help = t(
            "把 --record 产出的样本文件（.csv 或 .jsonl）导入 TUI 的 Samples 页做时序浏览：五条曲线（cpu%/内存%/负载/网络/进程数）sparkline，←→ 移动光标逐时刻读数，实时采样继续。属于无目标操作：不能与目标同时使用",
            "Import a --record sample file (.csv or .jsonl) into the TUI's Samples page for time-series browsing: five sparkline series (cpu%/memory%/load/network/process count), ←→ move the cursor to read individual instants; live sampling continues. A no-target operation: cannot be combined with targets"
        )
    )]
    pub samples: Option<String>,

    #[arg(
        long = "on-exit",
        value_name = "CMD",
        help = t(
            "被 watch/follow 的目标消失时执行一次该 shell 命令（仅 watch/follow 模式）——例如 `--on-exit 'say gone'`。--follow 模式下，若程序再也没以新 pid 回来，循环仍以退出码 2 结束",
            "Run this shell command once whenever a watched/followed target disappears (watch/follow mode only) — e.g. `--on-exit 'say gone'`. In --follow mode the loop still exits 2 when the program never comes back under a new pid"
        )
    )]
    pub on_exit: Option<String>,

    #[arg(
        long = "on-start",
        value_name = "CMD",
        help = t(
            "被 watch 的目标出现时执行一次该 shell 命令——若第一个采样点它已在运行也会触发。--on-exit 的镜像版，用于等待部署的脚本：`--watch 2 --on-start 'say up'`。需要目标且搭配 --watch（或 --follow）",
            "Run this shell command once whenever a watched target appears — including on the very first tick if it is already up. The mirror of --on-exit, for wait-for-deploy scripts: `--watch 2 --on-start 'say up'`. Needs a target and --watch (or --follow)"
        )
    )]
    pub on_start: Option<String>,

    #[arg(
        long = "snap",
        value_name = "FILE",
        num_args = 0..=1,
        default_missing_value = "",
        help = t(
            "把所有可见进程写成 JSON 后退出——一份快照，供之后 --diff 对比。不给 FILE 时，快照落入配置目录下的自动轮换目录（保留最近 10 份）并打印所选路径，`--snap` / `--diff last` 无需手工管理文件",
            "Write every visible process as JSON and exit — a snapshot to --diff against later. Without a FILE the snapshot lands in the auto-rotate directory under the config dir (the 10 most recent are kept) and the chosen path is printed, so `--snap` / `--diff last` work without managing files by hand"
        )
    )]
    pub snap: Option<String>,

    #[arg(
        long = "diff",
        value_name = "FILE|last|DURATION",
        help = t(
            "把当前进程表与 --snap 快照文件对比：新增 / 消失 / 重启（同程序换了新 pid）/ 变化（cmdline）。FILE 还可以是 `last`（最新的自动快照）或时长（`1h`——满足该年龄的最新快照）",
            "Compare the current process table against a --snap file: new / gone / restarted (same program, new pid) / changed (cmdline). FILE can also be `last` (the newest auto snapshot) or a duration (`1h` — the newest snapshot at least that old)"
        )
    )]
    pub diff: Option<String>,

    #[arg(
        long = "keep",
        value_name = "N",
        help = t(
            "--snap（不给 FILE）保留多少份自动快照后才删最旧的（默认 10）",
            "How many auto snapshots --snap (without a FILE) keeps before pruning the oldest (default 10)"
        )
    )]
    pub keep: Option<usize>,

    #[arg(
        long = "sockets",
        help = t(
            "配合 --snap：同时记录当前 LISTEN 端口，之后的 --diff 就能报告出现或消失的监听（“有新进程开始在 :8080 上服务”）——意外服务的初级金丝雀",
            "With --snap: also record the current LISTEN ports, so a later --diff can report listeners that appeared or disappeared (\"a new process started serving on :8080\") — a first-pass canary for unexpected services"
        )
    )]
    pub sockets: bool,

    #[arg(
        long = "diff-auto",
        value_name = "SECONDS",
        help = t(
            "配合无目标的 --watch：每 N 秒把实时进程表与上一次检查对比并打印漂移——新增 / 消失 / 重启 / 变化，外加监听边沿事件（每个周期在内存里做快照+对比，不写文件）。--alert-port 金丝雀的进程侧孪生版",
            "With a target-less --watch: every N seconds compare the live table against the previous check and print what drifted — new / gone / restarted / changed, plus listen edges (an in-memory snapshot+diff each interval, no files written). The process-side twin of --alert-port's canary"
        )
    )]
    pub diff_auto: Option<u64>,

    #[arg(
        short = 'o',
        long = "follow",
        help = t(
            "配合单个 --pid 目标：被追踪的 pid 退出后继续——以相同程序身份（名称+exe+user）在新 pid 上重新接续。隐含 --watch；身份连续 3 次刷新都不存在才停止",
            "With one --pid target: when the traced pid exits, keep going — re-acquire the same program (name+exe+user) under its new pid. Implies --watch; stops once the identity stays gone for 3 consecutive refreshes"
        )
    )]
    pub follow: bool,

    #[arg(
        long = "completions",
        value_name = "SHELL",
        help = t(
            "打印指定 shell 的补全脚本后退出：在你的 rc 文件里 source 它，例如 `witr-rs --completions zsh >> ~/.zshrc`",
            "Print the shell completion script for the given shell and exit: source it from your rc file, e.g. `witr-rs --completions zsh >> ~/.zshrc`"
        )
    )]
    pub completions: Option<Shell>,

    #[arg(
        long = "man",
        value_name = "FILE",
        num_args = 0..=1,
        default_missing_value = "",
        help = t(
            "打印 roff man 手册页（供 `man witr-rs` 使用）后退出——给了 FILE 则写入文件，例如 `witr-rs --man ~/.local/share/man/man1/witr-rs.1`",
            "Print a roff man page (for `man witr-rs`) and exit — write it to FILE instead when given, e.g. `witr-rs --man ~/.local/share/man/man1/witr-rs.1`"
        )
    )]
    pub man: Option<String>,

    #[arg(
        long = "serve",
        value_name = "[HOST]:PORT",
        help = t(
            "在该地址上提供 Prometheus 指标（[HOST]:PORT 或裸端口，默认主机 127.0.0.1），直到 Ctrl-C：每个进程的 cpu/rss/fd 指标（Prometheus 文本格式），每次 /metrics 抓取都实时重新采样。属于无目标操作",
            "Serve Prometheus metrics on this address ([HOST]:PORT or bare PORT, default host 127.0.0.1) until Ctrl-C: per-process cpu/rss/fd gauges (Prometheus text format) sampled fresh on every /metrics scrape. A no-target operation"
        )
    )]
    pub serve: Option<String>,

    #[arg(
        long = "serve-token",
        value_name = "TOKEN",
        help = t(
            "给 --serve 端点启用 Bearer 认证：所有请求须带 `Authorization: Bearer TOKEN` 头（Prometheus 的 authorization 凭据配置可直接对接），否则一律 401——指标里带进程名，绑到非回环地址前先用它把门",
            "Require `Authorization: Bearer TOKEN` on every --serve request (Prometheus's authorization credentials plug right in); anything else gets 401 — the metrics name processes, so gate them before binding past localhost"
        )
    )]
    pub serve_token: Option<String>,

    #[arg(
        long = "remote",
        value_name = "URL",
        help = t(
            "查询远端 witr-rs --serve 端点而不是本机：给定 http://host:port（不带 TLS），拉取 /api/ps（--tree 时拉 /api/tree）并按本地同样的表格/JSON/CSV 渲染；配合 --watch 周期重拉。属于无目标操作",
            "Query a remote witr-rs --serve endpoint instead of this machine: give http://host:port (no TLS); /api/ps is fetched (or /api/tree under --tree) and rendered with the same table/JSON/CSV as local; --watch re-fetches on an interval. A no-target operation"
        )
    )]
    pub remote: Option<String>,

    #[arg(
        long = "en",
        help = t(
            "以英文输出帮助说明（默认中文）",
            "Print the help text in English (Chinese is the default)"
        )
    )]
    pub en: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn help_language_defaults_to_chinese_and_flips_on_english() {
        ENGLISH.store(false, Ordering::Relaxed);
        assert_eq!(t("中文", "english"), "中文");
        ENGLISH.store(true, Ordering::Relaxed);
        assert_eq!(t("中文", "english"), "english");
        ENGLISH.store(false, Ordering::Relaxed);
    }

    #[test]
    fn apply_config_fills_defaults_flags_win() {
        let (cfg, _) = crate::config::Config::parse(
            "alert_cpu = 80\nalert_webhook = \"http://cfg/hook\"\nalert_exec = cfg-cmd\nalert_silence = [\"backup=30m\"]\nalert_threads = 400\nalert_container = true\n",
        );
        // flag wins over the file, file fills the rest
        let mut cli = Cli::parse_from(["witr-rs", "--alert-cpu", "95"]);
        cli.apply_config(&cfg);
        assert_eq!(cli.alert_cpu, Some(95.0));
        assert_eq!(cli.alert_webhook.as_deref(), Some("http://cfg/hook"));
        assert_eq!(cli.alert_exec.as_deref(), Some("cfg-cmd"));
        assert_eq!(cli.alert_silence, vec!["backup=30m"]);
        assert_eq!(cli.alert_threads, Some(400));
        assert!(cli.alert_container, "file bool folds in");
        // explicit flags beat the file on every knob, silence included
        let mut cli = Cli::parse_from(["witr-rs", "--alert-silence", "db=1h", "--alert-new-proc", "miner"]);
        cli.apply_config(&cfg);
        assert_eq!(cli.alert_silence, vec!["db=1h"]);
        assert_eq!(cli.alert_new_proc, vec!["miner"]);
        // nothing set anywhere stays unset
        let mut cli = Cli::parse_from(["witr-rs"]);
        cli.apply_config(&crate::config::Config::default());
        assert!(cli.alert_cpu.is_none() && cli.alert_webhook.is_none());
        assert!(cli.alert_silence.is_empty());
        assert!(cli.alert_new_proc.is_empty());
        assert!(!cli.alert_container);
    }
}

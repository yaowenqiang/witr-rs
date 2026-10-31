# witr-rs

[English](README.en.md) | **简体中文**

**Why is this running?** — 给出进程名、PID、端口或文件，一路追溯它是被谁、以何种方式拉起来的。

Rust 实现的 [pranshuparmar/witr](https://github.com/pranshuparmar/witr)（Go，Apache-2.0）同类工具，平台采集策略与其对齐。

**直接运行 `witr-rs`（无参数）进入交互式 TUI**，布局与原版一致：顶部五个标签页（1. Processes / 2. Ports / 3. Containers / 4. Locks / 5. Events），左侧进程表（PID / User / Name / CPU% / Trend / Mem / GPU / Age），右侧实时显示选中进程的溯源摘要，按 `Enter` 进入全屏**进程详情页**（左 70% 详情 + 右 30% 环境变量，双面板独立滚动），底部快捷键提示，每 3 秒自动刷新。支持鼠标（滚轮滚动、点击标签/行/面板、双击打开详情）。带目标时用 `-i` 也能进 TUI 并直接定位到目标（`witr-rs -i --port 8080` 打开即落在 Ports 页的该端口上）。管道输出时自动退化为静态进程表（`--list` 可强制）。

**Events 事件页（TUI）**：以 3 秒采样记录进程的 出现 / 退出 / 重启 事件流（保留最近 500 条），`/` 可按 事件类型/PID/进程名/详情 过滤，选中事件按 `Enter` 直接跳到对应进程的详情页（已退出则提示）。配合采样历史实现 **崩溃重启检测**：同一进程身份换新 pid 即记一次重启，`Rst` 列显示总次数，5 分钟内 ≥2 次时详情页黄色告警。

**树形视图（`T`，Processes 页）**：一键把平铺进程表变成 父→子 树（`└─` 缩进嵌套，排序键决定同级顺序）；搜索时自动回退平铺视图，再按 `T` 切回。

**CPU 历史大图（详情页）**：详情面板把最近约 10 分钟的瞬时 CPU 采样画成块字符图（按窗口峰值归一化）——突发负载和空闲段一眼可见。

**磁盘 I/O 列（三平台）**：进程表新增 IO 列（由每秒读写字节差分算出的速率），详情页显示累计读写字节数与系统调用次数。数据源：Linux `/proc/<pid>/io`、macOS `proc_pid_rusage`、Windows PowerShell `IO_COUNTERS`（受保护的系统进程取不到时该行留空）。

**内存趋势 + 泄漏嫌疑（详情页）**：详情面板把最近约 10 分钟的 RSS 采样画成绿色块字符图（绝对刻度，标注窗口峰值）；当 RSS 在窗口内增长 ≥20MB 且 ≥70% 的采样段单调上升时，追加黄色"疑似内存泄漏"告警——区分真实泄漏与锯齿状的正常分配回收。

**FD 趋势 + 泄漏嫌疑（详情页）**：同款逻辑盯文件描述符——打开详情页期间每次刷新采样一次 fd 数（Linux 读 `/proc/<pid>/fd`，macOS 走 libproc `proc_pidinfo` 原生查询——微秒级系统调用，无子进程，Windows 退化为全表句柄扫描——同样只在详情页打开时付出），显示 `Open fds (N)` 历史图；窗口内增长 ≥64 个且 ≥70% 单调上升时标黄色"疑似 fd 泄漏"——socket-per-request 却不关闭的服务一眼现形。

**线程趋势 + 泄漏嫌疑（详情页）**：fd 历史图的同款孪生盯内核线程数。线程数随整表采样（Linux `/proc/<pid>/stat` 的 nlwp、Windows ToolHelp 线程快照、macOS 一条 `ps -axo pid=,nlwp=` 扫描——三平台齐备），详情页显示 `Threads (N)` 历史图；窗口内增长 ≥16 个且 ≥70% 采样段单调上升时标黄色"疑似线程泄漏"——每次请求 spawn 线程却不回收的服务在这里现形。配套 **`--top threads`** 榜与 **`--alert-threads N`** 阈值告警、`thr>N` 数值过滤。

**详情页磁盘 I/O 历史图**：读/写速率两条块字符图（各标注窗口峰值速率），来自与 IO 列同一套跨平台累计字节差值（Linux `/proc/<pid>/io`、macOS `proc_pid_rusage`、Windows PowerShell `IO_COUNTERS`）。

**快照 diff（`--snap` / `--diff`）**：`witr-rs --snap before.json` 把整张进程表落成 JSON；之后 `witr-rs --diff before.json` 报告变化——**new**（新出现）、**gone**（消失）、**restarted**（同一程序身份换了新 pid 回来，与 TUI 崩溃重启检测同一套身份判定；含"重启后恰好复用原 pid"——同 pid 同身份但启动时间变了也识别为 restarted）、**changed**（同 pid 同身份但命令行变了）。pid 被无关进程复用时不再误报为 changed：旧进程报 gone（标注 pid taken over）、新进程报 new（标注 pid reused）。快照加 **`--sockets`** 还会记录当前 LISTEN 端口，`--diff` 据此报告 **listen-new / listen-gone**——"快照之后有新进程开始监听 ：8080"这类意外服务的第一道金丝雀（已有端口只是换属主不算变化）。有变化时退出码 1，无变化 0，适合脚本。不带路径的 `witr-rs --snap` 走**自动轮转**：快照存到配置目录旁的 `snapshots/`，默认保留 10 份（`--keep N` 可调）；`--diff last` 直接对比最近一份自动快照，`--diff 30m` 对比"半小时前"那一份——"这半小时机器上多了什么、少了什么"一条命令。`--diff` 配 `--json` 输出带版本信封的机器可读结果（`summary: {new, gone, restarted, changed, listen_new, listen_gone, total}` + `entries`，jq 直接取数）；TUI 里按 `D` 看同一份对比——最新自动快照 vs 实时表，着色分组行（listen 变化青/品红色），`j/k` 选中、`Enter` 跳进该进程详情页、`r` 重算。

**排行榜（`--top`）**：`witr-rs --top cpu -n 30` 不进 TUI，直接打印按 CPU / 内存 / fd 数 / 磁盘 I/O / 存活时长 / **磁盘 I/O 速率** / **GPU SM 占用**（`--top gpu`，装有 NVIDIA 驱动时）/ **内核线程数**（`--top threads`——线程泄漏榜，三平台随整表携带：Linux `/proc stat`、Windows 线程快照、macOS `ps nlwp`）/ **GPU 显存**（`--top gpu-mem`——`nvidia-smi` 已采的 VRAM 数据直接出榜）/ **ESTABLISHED 连接数**（`--top conn`——`--alert-conn` 的排行孪生，谁攥着最多的活动连接）/ **TCP 吞吐速率**（`--top net`——`--alert-net-per-proc` 的排行孪生，发+收字节/秒，两次 `ss(8)` 采样差分，谁在吃网卡一目了然）排名的前 N 个进程（`--top fd` 在 Linux 直读 `/proc/<pid>/fd`、macOS 用 libproc 原生全表扫描（每 pid 一次 `proc_pidinfo` 查询，无子进程）、Windows 用 PowerShell `Get-Process` 句柄数；`--top io` 与 `--top io-rate` 三平台可用——io-rate 按读+写 MB/s 排行，一次性模式隔 1 秒采两帧差分，`--watch` 下用持续采样历史；`--top age` 最老优先——pid 1 永远榜首，末列改显进程状态）。配 `--watch N` 常驻刷新：`--top cpu --watch 5` 每 5 秒重新采样、重排、重绘，Ctrl-C 退出。回答"现在最忙的是谁"不用开界面。榜单本身也吃表格输出：`--top cpu --csv` / `--top cpu --markdown` 把榜单直接交给脚本与文档（`--json` 本就支持；`--top` 与 `--report-html` 组合仍被拒绝）。

**按名聚合（`--by-name`）**：`witr-rs --by-name` 把整张进程表按 (名字, 用户) 折叠——列 NAME / USER / N（实例数）/ ΣCPU% / ΣRSS MB / ΣCPUTIME / AGE(OLDEST)，默认按 ΣRSS 降序。"几百个进程里那 34 个渲染进程加起来到底吃了多少"一屏答完。配 `--csv` / `--markdown` / `--json`（版本化信封：`group_count` + `groups`）交给脚本与文档；`--watch N` 常驻刷新。ΣCPU% 是平台给的生命周期均值之和（与表格列同口径），ΣCPUTIME 是累计 CPU 时间——更诚实的"它总共跑了多少"。

**表格输出（`--csv` / `--markdown`）**：进程表的机器可读形式——`--csv` 按 RFC-4180 转义（命令行里的逗号、引号、换行都安全），`--markdown` 直接贴 issue / 文档；两列都含 NAME 与完整命令行，脚本与报表一等公民。

**CSV 时间序列（`--watch` + `--record`）**：`witr-rs --watch 5 --record load.csv` 每 5 秒把整张进程表按进程追加进 CSV——timestamp / pid / user / name / cpu_pct / rss_mb / io 读写速率 / gpu_sm（平台没有的指标留空列），外加整机四列 `sys_load1` / `sys_mem_pct` / `sys_procs` / `sys_net_bps`（记录在一条 `pid=_system` 的汇总行上——load、内存占用百分比、进程数与全网卡收发合计字节/秒，与进程行同文件同节奏）。收工后用 Excel / pandas / SQLite 回放负载走势，控制台输出不受影响。存成 `.jsonl` 后缀则切换为 **NDJSON 模式**：每个 tick 追加一行版本化 JSON 信封（`{schema_version, generated_at, process_count, processes}`），每进程额外带 ppid / state / age_secs，`jq '.processes[] | select(.rss_mb > 500)'` 直接取数；整机快照在同信封的 `system` 键（`load1` / `cpu_pct` / `mem_used_mb` / `mem_pct` / `proc_count` / `net_bps`，平台测不到时为 null）。**长跑卫生（`--record-max-mb MB`）**：`--record` 与 `--events-log` 的文件超过该大小时滚动为 `<文件>.1`（上一代 .1 丢弃）并重新开始——CSV 模式重转后自动补写表头，`--plot` / `--samples` 无需特殊处理；磁盘占用从此有上界（2×上限），watchdog 跑几个月不再写满盘。该键也可写进配置文件（`record_max_mb = 200`）。

**时序图（`--plot`）**：`witr-rs --plot load.csv` 把 `--record` 产出的样本文件（.csv / .jsonl 都认）画成自包含 HTML 时序图，写入 `load.csv.html` 后退出——内联 SVG 五张图（整机 cpu% / 内存% / 1 分钟负载 / 网络速率 MB/s / 进程数），零 JS 零外部资源，离线双击可看。给**多个文件**则曲线叠加对比——`--plot before.jsonl after.jsonl` 发布前后各录一份，一图看清差异（输出 `witr-plot.html`）。"录制回来看看负载曲线"不用再开 Excel。

**HTML 报告（`--report-html`）**：`witr-rs --report-html status.html` 生成自包含的单文件报告（零 JS 零依赖）：每进程 CPU / 内存占用条、Top CPU / Top 内存榜单、全进程九列明细表，HTML 转义齐全——贴工单、存档、发同事都行。

**树杀（`K`）**：操作栏新增 `K`——沿 ppid 做 BFS 收集选中进程的全部后代（含孙辈，父进程中途被收割也不漏），提示 `kill pid N + M descendant(s)? y 确认`，确认后对整棵树发 SIGTERM。杀 worker 池、清用户会话树不用再逐个查 pid。

**无头击杀（`--kill` / `--kill-tree`）**：`witr-rs runaway --kill` 按常规目标匹配找到进程直接发信号，不进界面——`--signal KILL`（`SIGKILL` 同义，默认 `TERM`）换信号，`--kill-tree` 沿 ppid BFS 先杀全部后代再杀匹配进程（与 TUI 的 `K` 同一套收集逻辑）。与 `-i`/`--watch`/`--follow` 互斥；无匹配退出码 2，有目标击杀失败退出码 1，脚本里可直接判断结果。逐行打印 `killed 名字 (pid N) [SIGKILL]`。**`--dry-run`** 只打印击杀计划（`would kill …`，含 `--kill-tree` 收集的后代，顺序与真实执行一致）不发任何信号、退出码照常——脚本里先看后杀。

**脚本原语（`--pids-only` / `--wait`）**：`witr-rs nginx --pids-only` 只打印空格分隔的匹配 pid（无匹配退出码 2）——`witr-rs nginx --pids-only | xargs kill` 一行完成击杀。`witr-rs --port 8080 --wait` 阻塞等目标出现（`--wait gone` 反过来等消失），每秒轮询一次，条件满足即打印结果并退出 0；**`--timeout N`** 给等待一个上界，超时退出码 124（GNU timeout 惯例），SIGINT 打断为 130——`--pid 1234 --wait gone --timeout 60` 就是"等部署脚本把旧进程退干净"的原语。

**进程备注（`N`）**：Processes 页选中行按 `N` 输入备注（Enter 保存、Esc 放弃、清空即删除），按身份持久化到配置文件 `notes` 键——进程重启换 pid 备注跟着程序走；表格行尾显示 ✎ 标记，详情页有 Note 一节。给"这个 python 到底是干嘛的"留下答案。

**帮助页（`?`）**：任意页面按 `?` 弹出当前标签页的完整键速查（全局键 + 每页专属键分组），`j/k` 滚动；Esc / q / Backspace / 再按 `?` 返回**打开时的页面**（从详情页打开就回详情页，不会落回列表）。全部按键不用背。

**JSON schema**：`--json` 输出升级为带版本信封 `{schema_version, generated_at, process_count, processes}`，下游解析可以校验版本再取数；`--tree --json` 把无目标列表变成**嵌套森林**（子进程挂在父进程的 `children` 下，与 `--tree` 文本同规则：孤儿与 ppid 环升级为根，pid 升序）；`--diff --json` 同款信封外加 `summary` 计数。

**跨重启跟踪（`--follow`）**：`witr-rs --pid 1234 --follow` 在目标死后继续追——进程表里重找同名同程序身份（name+exe+user），切到新 pid 继续溯源（隐含 `--watch`；身份连续 3 个刷新周期找不到才放弃）。多个同名实例并存时取最新启动的那个。

**`--watch [秒]`**：常驻观察模式——带目标时每 N 秒重跑一次溯源管线并重绘（默认 2 秒），不带目标时刷新进程表；配合 `--recent`/`--json` 等原有选项工作。**`--times N`** 给循环一个时长上界（CI/cron 友好）——`--watch 5 --times 12` 采满一分钟自动退出（退出码 0；被 SIGINT 打断则 130）。无目标 watch 的收尾**摘要**：Ctrl-C（unix）或 `--times` 退出时打印本次运行的"发生了什么"（活动计数 + 重启链，和 TUI 的 `S` 同一份数据；`--json` 时以 JSON 信封收尾，带 `ticks` / `interrupted` / `summary`）。无目标 watch 的三种形态：默认重绘整表；**`--quiet`** 跳过重绘只出告警/钩子行（无头 watchdog 跑几天不糊屏）；**`--watch --json`** 每个 tick 往 stdout 吐一行 JSON 信封（告警走 stderr，`| jq` 管道不被污染）。

**事件钩子（`--on-start` / `--on-exit`）**：watch/follow 目标时在出现/消失的边缘各执行一次命令——`--watch 2 --on-start 'say up'` 是 wait-for-deploy 脚本（首次 tick 已在跑也触发），`--follow --on-exit 'say gone'` 是离场哨兵。命令经 `sh -c` 执行，退出码不影响 watch 循环。

**命令审计（`--audit CMD`）**：`witr-rs --audit 'cargo build --release'` 包装运行一条命令，期间每 500ms 采样它的子进程树，命令退出后打印报告——墙钟时长、退出码、派生进程数与峰值存活数、子树峰值 CPU / 峰值 RSS、累计磁盘读写，外加完整进程树（每个成员按最后现身渲染）。两个有意的近似（都写在代码注释里）：中途退出的子进程贡献不丢（累计 I/O 与身份在最后现身时记档）；父进程先退导致 reparent 的子进程按上一帧成员关系追认一代（更深的 reparent 链仍可能溜走——构建树里很少见，因为链条总是根先死）。构建、部署、脚本"这次到底吃了多少资源、拉了多少进程"一条命令；进程退出码原样透传，可直接接 CI。配 **`--json`** 输出同源的版本化信封（`duration_secs` / `exit_code` / `killed_by_signal` / `spawned` / `peak_alive` / `peak_cpu_pct` / `peak_rss_bytes` / `io_read_bytes` / `io_write_bytes` + `tree`），CI 里 jq 直接取数。

**死目标提示**：溯源扑空时给下一步建议——`--pid 999999` 找不到时提示"`--follow` 可跨重启继续追"；名字拼错时按编辑距离给出最接近的三个候选（`witr-rs nginxx` → `closest: nginx, ...`），减少"目标写错白查一轮"。

**对端归因（TUI 详情页）**：进程的每条 ESTABLISHED 连接会反查对端套接字的属主，在详情页显示 `talking to: 进程名 (pid N) — k 条连接`；对端不在本机时显示远端地址。

**控制终端归因（tty）**：每个进程标注它的控制终端（`ttys004` / `pts/3`）；无控制终端的守护进程与 nohup 进程显示 **detached（`-`）**——"这个进程是谁的终端拉起来的，还是没人管的自走进程"一眼可辨。CLI 身份块（detached 时灰显 `detached (no controlling terminal)`）、`--export` 报告与 TUI 详情页都有这一行；`--json` 带可空的 `tty` 字段。同一身份块还有 **进程组与会话**（`pgid` / `sid`，Linux `/proc/<pid>/stat`、macOS `ps`）——判断信号该发给组长还是整组、进程属于哪个会话，不用再 `ps -o pgid -o sid`。

**cgroup 资源面板（Linux 详情页）**：Linux 上打开进程详情时，从 `/proc/<pid>/cgroup` 的 `0::` 行取 cgroup v2 路径，回读 `/sys/fs/cgroup` 下该组的 `memory.current` 与 `cpu.stat` 的 `usage_usec`——CLI 详情块、`--export` 与 TUI 详情页都显示 `cgroup <路径> · mem <用量> · cpu <累计秒>`。这是容器/服务的组级视图：RSS 只回答"这个进程吃了多少"，cgroup 回答"它所在的容器/服务整体吃了多少"。根 cgroup（整台机器）不显示。路径同时做**归属分类**：docker / containerd / podman / kubepods / lxc / colima 识别为容器（标注容器 id，k8s 场景再经 kubectl 反查所属 Pod——`kubernetes pod ns/name · container <id12>`），`*.service` / `*.socket` / `*.timer` 等 `.slice` 下的叶子识别为 systemd 单元（系统级或 `user@` 用户级）——Started by 归因从"进程的父进程是谁"上探到"它是被哪个服务单元/容器运行时拉起来的"。

**Ports 总览页（`o`，Ports 页）**：把逐 socket 的明细表切换成按 (端口, 属主进程) 聚合的总览——列 Port / Proto(s) / Process / PID / User / Addrs（该端口绑定的地址数，tcp+tcp6 合并显示为一行），默认按端口排序，`/` 搜索照常生效，`Enter` 直接跳到属主进程的详情页。表格下方是**监听历史环**（暗色行）：Ports 页打开期间的 LISTEN 边缘——`▲ new` 新监听、`▼ gone` 消失的监听（带时刻与"曾属主"）——"五分钟前谁占过 :8080"答案就在下面；首轮扫描静默建基线（打开页面时就已在监听的不算事件，与 `--alert-port` 金丝雀同一规则），环内最近 30 条，选中光标永不落在历史行上。"这台机器上谁在对外服务"一屏可见。

**退出即取证（crash forensics）**：进程退出事件发生的瞬间自动后台抓取它最后的日志行（macOS 统一日志按进程名 / Linux journald 按 `_PID=`，最多 25 行，缓存最近 50 个），Events 页选中 exited/restarted 事件按 `l` **立即**显示"最后的话"——不用再和日志轮转赛跑，crash 现场定格在退出那一刻。

**桌面通知（`--notify` / `!`）**：TUI 里目标进程重启即弹系统通知；同名进程本会话内重启 ≥2 次后，其普通退出也通知（crash loop 提示）。macOS 走 `osascript`、Linux 走 `notify-send`、Windows 走 PowerShell 原生 WinRT toast（无需额外模块），后台线程发送不卡采样；`--notify` 预开启，TUI 内 `!` 随时开关（页脚有指示）。

**暂停采样（`P`）**：一键冻结 TUI 采样——不刷新、不产生事件、不发通知，页脚显示 `⏸ paused`；再按恢复。看清单、拷贝现场时数据不再从眼前流走。

**会话摘要（`--since` / `S`）**：`witr-rs --replay ev.jsonl --since 1h` 不进界面——直接打印这段录制时间"发生了什么"：出现 / 退出 / 重启计数，加上重启链（哪个程序重启了几次），管道里也能用。TUI 里按 `S` 打开同样的摘要页：活动计数、重启链，外加两张榜——**CPU 尖峰榜**（窗口内瞬时占用峰值最高的进程）与**内存爬升榜**（RSS 增长最快的进程）；`--since` 预设窗口（30、30s、5m、2h、1d，默认整个会话），`r` 重算。回答"刚这半小时机器上忙的是什么"。

**阈值告警（`--alert-cpu` / `--alert-mem` / `--alert-fd` / `--alert-io` / `--alert-conn` / `--alert-threads`）**：`witr-rs --alert-cpu 90 --alert-mem 2048`——进程连续 5 个采样（约 15 秒）超过阈值时：弹桌面通知、Events 页记一条 alert、进程表红色行高亮。每次越界只报一次，占用回落即记一条 **恢复事件**（`✔ recovered: 名字 (pid) — detail`，kind=recovered）——告警的完整生命周期（触发→恢复）在 Events 页、`--events-log` 与无头 watch 的 stdout 里都有留痕，回落后自动重新武装。TUI 里 `M` 一键全局静音：告警判定照常运行但不再触发副作用，被静音的条目以 kind=silenced 进事件环（"这段时间为什么没响"有账可查）。`--alert-fd 4096` 盯打开文件数（Linux 直读 `/proc`，macOS 每周期单次 `lsof` 扫全表——只在告警开启时才扫）；`--alert-io 100` 盯磁盘 I/O 速率（读+写 MB/s，Linux `/proc/<pid>/io` 差分）；`--alert-conn 200` 盯每进程 ESTABLISHED 连接数；`--alert-threads 400` 盯内核线程数（Linux `/proc stat` 与 Windows 线程快照随整表携带——线程只增不减的服务现形）；`--alert-net-per-proc 5` 盯每进程 TCP 吞吐（发+收 MB/s，`ss(8)` 差分——数据偷偷外传、服务打满出口，点名到 pid；Linux 且 PATH 上有 ss 时可用）；`--alert-deviation 10` 盯**自基线偏离**——瞬时 CPU 连续 5 采样超过自身近 2 分钟中位数的 X 倍且不低于 5% 绝对下限即告警："一直安静的任务突然持续繁忙"不需要预先写阈值，基线随进程自适应（约 36s 历史后武装；中位数不会被突发自己拖走，除非半个窗口都翻过去）。机器级阈值十条：**`--alert-load N`**（1 分钟 load average 连续 5 采样超 N）、**`--alert-mem-pct PCT`**（整机内存占用百分比连续 5 采样超 PCT）、**`--alert-count N`**（可见进程数连续 5 采样超 N——fork 炸弹、失控任务生成器把进程表撑爆的哨兵）、**`--alert-disk PCT`**（任一本地磁盘已用百分比连续 5 采样超 PCT——写满之前喊一嗓子，详情点名最满的挂载点；df 扫描只在告警开启时付出）、**`--alert-net MB/S`**（全部非回环网卡收发合计速率连续 5 采样超 MB/S——流量打满出口、进程偷偷外传数据的哨兵；网卡计数器只在告警开启或系统资源页打开时扫描）**`--alert-psi PCT`**（Linux PSI 压力——cpu/memory/io 任一资源的 "full" 全停顿百分比连续 5 采样超 PCT 即告警，详情点名资源与读数；机器卡到连调度都排不上队时sysload/loadavg 还没反应，PSI 已经在喊）、**`--alert-mem-avail-mb MB`**（可回收内存（MemAvailable）连续 5 采样低于该绝对下限（MB）——OOM 前的最后一道哨兵；百分比阈值在大内存机器上失真，"还剩多少 MB" 不会）、**`--alert-swap-pct PCT`**（swap 已用百分比连续 5 采样超 PCT——内存压力外溢到磁盘的哨兵）、**`--alert-retrans SEG/S`**（TCP 重传段速率连续 5 采样超该值——"网络变慢"的头号元凶，load 和 PSI 都看不见它；计数器来自 `/proc/net/snmp` 差分）与 **`--alert-nic-drop PKT/S`**（全部非回环网卡的丢包/错误合计速率连续 5 采样超该值——吞吐量看着正常但包根本没送达的哨兵；`/proc/net/dev` 计数器差分）——同一套"连续 5 采样 + 只报一次"机制，TUI 与 `--watch` 同效，Events 页记 `(system)` 条目，`--alert-repeat` / `--alert-exec` 照常生效。配合 **`--alert-exec`** 可在每次告警触发时执行自定义命令（告警上下文经 `WITR_ALERT_PID` / `WITR_ALERT_NAME` / `WITR_ALERT_DETAIL` 环境变量传入），或用 **`--alert-webhook URL`** 把每次触发 POST 成 JSON（`{schema_version, kind:"alert", at_unix, pid, name, detail}`）到任意 http:// 接收端——后台线程发送、3 秒超时，不卡采样也不阻塞 watch 循环（https 需要前置反代或 gateway；明确给定时才发，零默认流量）。告警不只活在 TUI：**`--alert-*` 配 `--watch` 就是无头 watchdog**——`witr-rs --watch 5 --alert-cpu 90` 每个 tick 检查阈值，触发即打印 `⚠ alert: 进程名 (pid N) — 详情` 行（与 TUI 同一套"连续 5 采样 + 只报一次"机制，`--alert-exec` / `--alert-webhook` 照常生效），没有界面也能盯机；再配 `--events-log` 则告警与 started/exited/restarted 一样逐条 JSONL 落盘（`--replay` 可回放）。这些阈值都可以写进**配置文件**（`alert_cpu = 90` / `alert_webhook = "http://..."`，键名与旗标一一对应）——watchdog 部署成 systemd 服务时阈值集中在 config.toml，命令行只留 `--watch`。

**端口金丝雀（`--alert-port`）+ 重复提醒（`--alert-repeat`）**：`--alert-port 9090` 盯 LISTEN 端口的**边缘**——有人开始监听 :9090 时告警 `listener appeared on :9090 (属主)`（首次观察只武装：启动时已在监听的端口是现状不是事件，与 `--on-start`/`--on-exit` 同一套边缘语义）；前缀 `!` 反转成掉线哨兵，`--alert-port '!8080'` 在监听者消失时报 `listener gone from :8080 (was 属主)`。可重复使用同时盯多个端口。**`--alert-repeat 60`** 让持续越界的告警每 60 秒重发一次（首次触发或回落后重新武装时重置计时；不设则维持每次越界只报一次）——watchdog 场景"不处理就一直响"。TUI 与 `--watch` 同效，告警照常走 `--alert-exec` 与 `--events-log`。

**告警静默窗口（`--alert-silence`）**：`--alert-silence backup=30m db=1h`——名字包含 backup 的进程在会话前 30 分钟内、名字包含 db 的在 1 小时内不再触发告警（**维护窗口**：夜里跑备份/批处理时不被已知负载吵醒）；不带 `=DUR` 则整个会话静默；`!NAME` 反选（只静默名字**不含** NAME 的进程，"只盯着这几个"的反向名单）。可一次给多个，TUI 与 `--watch` 同效；被静默的进程阈值照常判定，只是触发被替换成 kind=silenced 的事件（`--events-log` 照记，审计"静默期间发生了什么"有据可查），`--alert-exec` / `--alert-webhook` / 桌面通知一概不发出。也可写进配置文件（`alert_silence = ["backup=30m", "db"]`）。

**首见进程告警（`--alert-new-proc`）**：`--alert-new-proc xmrig miner`——会话内第一次出现名字包含任一模式的进程就告警（**挖矿/后门哨兵**：正常机器上不该见到的新面孔）。`!NAME` 前缀切换成**白名单模式**——`--alert-new-proc '!nginx' '!cron'` 只对名字不含任何白名单模式的进程告警（"我的机器上只该跑这些"）；两种形态不能混用。每个名字每次会话只报一次（内置 HashSet 记账），TUI 与 `--watch` 同效，照常走 `--alert-exec` / `--alert-webhook` / `--events-log`。也可写进配置文件（`alert_new_proc = ["xmrig", "!nginx"]`）。

**服务安装器（`--install-service`）**：`witr-rs --watch 5 --alert-cpu 90 --install-service` 把**当前这组参数原样固化**成系统服务并注册——Linux 写 systemd 用户单元（`~/.config/systemd/user/witr-rs.service` 并 `enable --now`）、macOS 写 launchd plist（`~/Library/LaunchAgents/` 并 `launchctl load`）、Windows 生成 schtasks XML 并提示注册命令。交互里先用 `--watch` 验证过阈值，验证完一条命令变成开机自启的 watchdog（目标、全部 `--alert-*`、静默/首见名单、`--events-log`、`--record` 都进服务定义）。给自定义路径（`--install-service /tmp/w.service`）则只写文件并提示手动注册——不留系统级副作用；默认路径才自动注册。**systemd 单元自带 `WatchdogSec`**（采样间隔 × 3，60s 起步）：服务进程每个采样 tick 向 sd_notify 发 WATCHDOG=1 心跳——witr-rs 自己挂死（IO 卡死、死锁）时 systemd 杀掉重启，看门狗本身不再是不受监督的单点；`READY=1` 在启动时发出。非 systemd 平台（launchd / schtasks）保持各自的 KeepAlive 机制。

**短命进程捕获（brief）**：阈值告警的采样间隔内"生灭"的进程（端口扫描、fork 炸弹的第一波、crontab 每分钟的任务），按 3 秒采样永远抓不到——TUI 与无目标 `--watch` 会自动起一个 **250ms 高频轮询器**（Linux readdir `/proc`、macOS `proc_listallpids` 原生调用，均无子进程；Windows 无等价廉价扫描则跳过），捕捉存活 ≤5 秒就消失的进程，记 kind=brief 事件（名字在首次发现时解析——死后就问不到了，解析不出则记 `pid N`），`>> brief: sleep (pid 7965) — spawned and exited within ~1292ms` 一行 stdout，`--events-log` 照常落盘，Events 页可见。

**时光回放（`<` / `>`）**：TUI 在后台持续保留最近 30 帧进程表快照——Processes 页按 `<` 逐帧回看历史（进程表回到那一刻：谁当时在、CPU 当时多少；标签栏亮黄色 REPLAY 徽章），`>` 逐帧前进，走到头自动回到实时。回放期间告警机制暂停（回放帧不产生告警/通知），但环形缓冲**照常录制**——看完历史 `>` 走回实时，什么都没漏。"十分钟前机器还是正常的，到底哪一步开始变的"——不用快照不用录像，`<` 按住往回翻。

**远程模式（`--remote URL`，可重复）**：`witr-rs --remote http://10.0.0.7:9100` 不看本机——从远端 `witr-rs --serve` 端点拉 `/api/ps`（`--tree` 时同样拉平表、本地重建森林），用与本地完全相同的渲染器输出表格 / `--json` / `--csv` / `--markdown`；配 `--watch N` 周期重拉（清屏重绘，`--times N` 上界）。**`--remote` 可重复**——一次看一排机器：每台一个分隔段落（`----- [host] -----`），连不上的主机报一行 ⚠ 不拖垮其余（全部不可达才退出码 5）；多机 `--json` 出舰队信封（`host_count` + `hosts[]`，每台 `host` / `process_count` / `processes`，失败主机记 `error`）。跳板机上只装 witr-rs 一个二进制、SSH 只通几条隧道，"看隔壁几台机器的进程表"不用 Prometheus 也不用网页——远端各一台 `--serve`，本机随时 `--remote`。零新增依赖（std::net 手写 HTTP GET，仅 http://，TLS 走前置反代）。

**配置热重载（SIGHUP）**：`kill -HUP $(pidof witr-rs)` 无需重启即重读配置——TUI 立即重折算全部旋钮（采样间隔、排序、告警阈值、静默/首见名单、通知开关；**关注列表与告警状态保留**——调整阈值不丢已触发的告警闩锁），无头 `--watch` 同效（下一个 tick 生效）。语义与启动一致：命令行旗标始终压过配置文件，重载只动文件里改的值。改 config.toml 不用再杀进程。

**端口总览（`--ports`）**：不进界面，直接打印当前全部 LISTEN 端口——列 端口 / 协议 / 属主（同端口多属主逗号并列，共享端口的两个进程一眼可见），按端口排序。TUI Ports 总览页（`o`）的 CLI 孪生：`--json` 出版本化信封（`listener_count` + `listeners`），`--csv` 出 port,proto,owners 三列——"这台机器上现在谁在对外服务"一条命令答完。配 **`--watch N`** 常驻刷新（清屏重绘，Ctrl-C 退出，`--times N` 给时长上界；机器可读格式保持一次性输出——轮询的消费方自己控制节奏）。

**连接总览（`--conns`）**：不进界面，直接打印全机 LISTEN 之外的网络连接——列 PROTO / LOCAL / PEER / STATE / OWNER（ESTABLISHED / TIME_WAIT / … 全状态），属主进程同表解析；对端也在本机（回环互连）时 OWNER 单元追加 `↔ 对端进程`——"这条连接两头各是谁"一眼可见，`--ports` 的镜像面。`--json` 出版本化信封（`connection_count` + `connections`，回环归因独占 `peer_pid` / `peer_owner` 字段），`--csv` / `--markdown` 出机器可读表，配 **`--watch N`** 常驻刷新（机器可读格式保持一次性输出）。加 **`--by-peer`** 切换成**对端聚合**视图：按 (协议, 远端地址, 远端端口) 折叠——列 PEER / CONNS / STATES / OWNERS / LOCAL PORTS，按连接数降序——"这台机器到底在和谁说话、哪条链路最忙"一屏答完（数据库连接池、爬虫目标、被谁连着的端口都藏不住；`--json` / `--csv` / `--markdown` 同样支持）。

**文件锁总览（`--locks`）**：不进界面，直接打印全系统文件锁——列 PID / OWNER / MODE / TYPE / PATH（按 pid 再按路径排序，属主灰显）。TUI Locks 页的 CLI 孪生：`--json` 出版本化信封（`lock_count` + `locks`），`--csv` / `--markdown` 同样支持。数据源与 Locks 页同一套（Linux `/proc/locks`、macOS `lsof` 锁标志）——"谁攥着这个文件不放"脚本里也能问。

**僵尸进程速查（`--zombies`）**：`witr-rs --zombies` 列出全表 `<defunct>` 僵尸——列 PID / NAME / PARENT（父进程名，已退出则 `(gone)`）/ AGE（最老优先）——僵尸本身不耗资源，但成片的僵尸是父进程没 `wait()` 的信号。`--json` 出版本化信封（`zombie_count` + `zombies`），`--csv` / `--markdown` 同样支持；**发现僵尸时退出码 1**，无僵尸 0——`witr-rs --zombies || alert` 直接当巡检探针。

**服务单元总览（`--services`）**：不进界面，直接列出服务管理器当前的单元——列 MANAGER / NAME / STATE / PID / DESCRIPTION（Linux systemd / macOS launchd / Windows SCM），运行中的（有主 pid）排前面。TUI Services 页（6）的 CLI 孪生：`--json` 出版本化信封（`service_count` + `services`），`--csv` / `--markdown` 同样支持——"这台机器上跑着哪些服务、活没活着"一条命令。

**漂移看门狗（`--diff-auto`）**：`witr-rs --watch 30 --diff-auto 30`——常驻观察时每 N 秒在内存里自动拍一帧快照并与上一帧对比，有变化才打印 `== drift · N new / M gone / K restarted / J changed ==` 加着色变化行。`--alert-port` 盯指定端口的边缘，`--diff-auto` 盯全表的漂移——"这半小时机器上多了什么"不用人去跑 `--diff`，watchdog 自己会喊。需要 `--watch`；配 **`--json`** 时每次漂移检查输出一个带版本信封的 drift 帧（`summary: {new, gone, restarted, changed, listen_new, listen_gone, total}` + `entries`，与 `--diff --json` 同构——`| jq '.summary'` 直接盯计数），无变化的检查不产生输出。快照不落盘，纯内存对比，零磁盘写入。

**Prometheus 端点（`--serve`）**：`witr-rs --serve :9100` 起一个 `/metrics` 抓取端点（Prometheus 文本格式，零新增依赖）——没有后台采样线程，**每次抓取现场采样进程表**，抓取频率即采样频率。**`--serve-token TOKEN`** 给全部端点上 Bearer 认证：请求须带 `Authorization: Bearer TOKEN` 否则 401（Prometheus 的 `authorization` 凭据配置直接对接；指标里带进程名，绑非回环地址前先把门）。导出整机 `witr_process_count` / `witr_rss_total_mb`，以及**整机资源 gauge**（`witr_machine_cpu_percent`——刷新间差分的真实瞬时占用、`witr_machine_mem_used_bytes` / `witr_machine_mem_total_bytes`、`witr_machine_mem_available_bytes`、`witr_machine_swap_used/total_bytes`、`witr_machine_load1`）——内置哨兵盯的数 Prometheus 规则也能盯与**每网卡流量 counter**（`witr_machine_net_rx_bytes_total{nic}` / `witr_machine_net_tx_bytes_total{nic}`——PromQL `rate()` 即每网卡吞吐，回环网卡除外），外加 **PSI 压力**（`witr_machine_psi_stall_percent{resource,kind}`——cpu/mem/io 的 some/full 十秒窗停顿占比，Linux）、每网卡丢包 counter（`witr_machine_nic_drop_total{nic,direction}`）与 top-20 CPU 与 top-20 RSS 并集的每进程 gauge（`witr_process_cpu_percent` / `witr_process_rss_bytes` / `witr_process_open_fds`，标签带 pid / name / user，基数有界）；每进程还带 **累计磁盘 I/O counter**（`witr_process_io_read_bytes_total` / `witr_process_io_write_bytes_total`——PromQL 里 `rate()` 即每进程读写吞吐）与 **`witr_process_start_time_seconds`**（启动时刻的 unix 时间戳 gauge——序列值跳回"现在"就是 Prometheus 的标准重启信号，`changes()` 直接告警）；端口侧新增 **`witr_port_listeners{proto,port,owner}`**——每个监听 (协议, 端口) 一条序列，owner 标签带 "name (pid N)" 属主列表，意外监听一目了然。`/metrics` 之外还有七个 JSON 端点：**`/api/ps`**（整张进程表，与 `--json` 相同的版本化信封，含 enrich 后的 user / 启动时间等字段）、**`/api/ports`**（LISTEN 端口表，与 `--ports --json` 同一份信封）、**`/api/conns`**（非 LISTEN 连接表，与 `--conns --json` 同一份信封，含回环对端归因）、**`/api/tree`**（嵌套进程森林，`--tree --json` 的 HTTP 形态）、**`/api/services`**（服务单元表，与 `--services --json` 同一份信封）、**`/api/containers`**（容器表：runtime/id/name/image/state/状态/cpu/mem/限流/OOM/磁盘 I/O——与 `/metrics` 容器序列同一份后台快照）、**`/api/top?metric=cpu|mem|fd|age|io|io-rate|threads|conn|net&n=N`**（进程榜的 HTTP 形态，`--top` 同款排行；`value` 单位随 metric——百分比 / 字节 / 个数 / 秒，io 系与 net 为字节与字节每秒，threads/conn 为个数，非法 metric 返回 400）——`curl -s localhost:9100/api/ports | jq` 直接取数。还有第七个非 JSON 端点 **`/api/events`**（**Server-Sent Events** 实时事件流）：首次访问自动武装一个 5 秒差分采样器，把 started/exited/restarted 边缘以 `data: {...}` 帧持续推给订阅者（与 TUI 事件环 / `--events-log` 同一份 TuiEvent JSON），15 秒无事件发 `: ping` 保活——`curl -N localhost:9100/api/events` 就是这台机器的实时事件直播；纯 `/metrics` 部署不付采样成本（采样器懒启动）。端点自监控三件套：`witr_scrapes_total`（已服务抓取数）、`witr_scrape_duration_seconds`（上次抓取耗时）、`witr_scrape_timestamp_unix`。机器上跑着容器时，`/metrics` 还会导出**每容器指标**（`witr_container_cpu_percent` / `witr_container_mem_used_bytes` / `witr_container_mem_total_bytes`，标签 runtime/id/name/image/state——容器的 cpu/mem 在 Prometheus 里与进程同屏；采样走 30 秒后台缓存，抓取不阻塞在运行时 CLI 上）。裸端口默认绑 `127.0.0.1`（指标里带进程名，别广播出去），`[HOST]:PORT` 可显式指定；配 Prometheus 的 `scrape_interval` 就是采样间隔。机器上跑着容器时 `/metrics` 的容器序列完整到 cgroup 压力：`witr_container_throttled_seconds_total`（CFS 限流累计——`rate()` 即限流速率）、`witr_container_oom_kills_total`（内核 OOM 杀计数）、`witr_container_io_read/write_bytes_total`（容器磁盘读写，与 THR%/OOM 同一轮 cgroup 读取），Prometheus 侧与进程/主机指标同屏。浏览器直接打开 `/` 还有一张**零 JS 仪表盘**（`meta refresh` 每 5 秒自刷新：cpu / 内存 / load / 进程数 gauge 磁贴、温度与 PSI（平台报告时）、top CPU / top 内存两张表、**容器表**（名称/状态/CPU/内存/限额/OOM 计数）、监听端口表——internet 通配监听标红；每次访问现场采样，与 `/metrics` 同源同套，零外部资源零脚本）。

**双语帮助（`--en`）**：帮助文本默认中文——`--help`、`--man` 生成的 man 页、`--completions` 生成的补全脚本全部随语言走，`--en` 切回英文。语言在参数解析前预扫描 `--en` 决定（每条帮助串都在构建 Command 时定稿）；clap 自身的 "Usage:"/"Options:" 脚手架与解析错误保持英文（clap 没有 i18n 钩子可挂）。

**man 页（`--man`）**：`witr-rs --man [FILE]` 生成完整 man 页（roff 格式，clap_mangen 渲染）——无参数打印到 stdout（`witr-rs --man | gzip > /usr/local/share/man/man1/witr-rs.1.gz` 即装），给 FILE 则写入（目录不存在自动创建）。

**配置文件**：`~/.config/witr-rs/config.toml`（macOS 在 `~/Library/Application Support/witr-rs/`，Windows 在 `%APPDATA%\witr-rs\`）——`refresh_secs`（采样间隔）/ `sort`（默认排序）/ `notify` / `paused` / `watch`（关注列表）/ `notes`（进程备注）六个 TUI 键，加上与旗标一一对应的全部 **`alert_*` 键**（`alert_cpu` / `alert_mem` / `alert_fd` / `alert_io` / `alert_conn` / `alert_load` / `alert_mem_pct` / `alert_count` / `alert_disk` / `alert_net` / `alert_psi` / `alert_repeat` 数值型，`alert_exec` / `alert_webhook` 字符串型，`alert_silence` / `alert_new_proc` 字符串数组）与 `serve_token`（`--serve` 的 Bearer 令牌）——watchdog 部署成服务时阈值集中在文件里，命令行只留 `--watch`。相当于 CLI 参数的默认值：文件先行，命令行始终覆盖；运行中 `kill -HUP` 即热重载（见上）。坏行跳过并给出警告，没有文件一切照旧。

**关注列表（`w`）**：Processes 页选中行按 `w` 加 ★ 并置顶（保持所选排序），按 `w` 取消。关注项按 身份（名字 + exe 基名 + 用户）持久化到配置文件的 `watch` 键，不含 pid——进程重启换 pid 后 ★ 跟着程序走。树形视图下不置顶（避免拆散父子），搜索过滤照常生效。

**系统资源页（`y`）**：整机仪表盘——CPU 占用历史图（固定 0–100 刻度，标注当前值与窗口峰值）、内存历史图（绝对刻度 + 峰值标注）、load average（1/5/15 分钟）、swap 用量、每核占用网格（≥90% 红色高亮）、**磁盘挂载点**（设备盘逐个用量条，≥90% 红色；仅本地盘，网络挂载不显示）、**网卡速率**（每网卡 ↓收 ↑发 MB/s 实时速率 + 总计 sparkline 与峰值，按速率降序列前 8；网卡计数器页面打开时开始采样，两次扫描差分出速率——Linux `/proc/net/dev`、macOS `netstat -ib`、Windows `Get-NetAdapterStatistics`）、**温度**（Linux 从 hwmon 读最热的传感器，≥80°C 红、≥65°C 黄）与 **PSI 压力**（Linux `/proc/pressure/*` 每资源的 some/full 停顿百分比，最差 full ≥10% 红——资源全停顿即"机器卡死"前兆）。Linux 直接读 `/proc`（微秒级，每周期采样，打开页面时历史已就绪）；macOS 走 Mach `host_processor_info` + `vm_stat`，Windows 走单次 PowerShell CIM 查询（这两个平台仅页面打开时采样；磁盘区三平台都是页面打开时扫一次 df/CIM）。回答"这台机器整体忙不忙、内存还剩多少、哪个盘快满了、流量跑在哪个网卡上"。CLI 孪生 **`--sys`**：同款整机数字不进 TUI 直接打印（cpu / 内存 / swap / load / 进程数 / 最满磁盘 / 网卡速率 / 温度 / PSI，平台测不到的区自动缺席；`--watch N` 常驻刷新，`--json` / `--csv` / `--markdown` 一次性同源输出）。

## TUI 按键

支持 vim 式浏览（与原版 witr 对齐）：

| 键 | 作用 |
|---|---|
| `j` `k` / `↑` `↓` | 移动选中行 |
| `g` `G` | 跳到第一行 / 最后一行 |
| `f` `b` `空格` / PgUp PgDn | 翻页 |
| `h` `l` / `←` `→` | 切换标签页 |
| `1`–`6` / Tab | 直接跳页 / 切换焦点（表格 ↔ 详情） |
| `/` | 搜索：Processes 页按 PID/用户名/进程名，或**比较表达式**（`cpu>50`、`mem>1g`、`fd>100`、`age<30m`、`io>10m`、`thr>200`——支持 `> < >= <= =`，mem/io/带 k·m·g 后缀的字节数，age 用 s·m·h·d）；Ports 页按端口号/PID/进程名/地址/协议/状态；Events 页按 事件类型/PID/进程名/详情（各页过滤器独立，Enter 应用，Esc 清除；不匹配表达式时退化为普通子串搜索） |
| `Enter` | Processes 页：打开全屏进程详情页；Ports 页：端口详情页（该端口全部连接 + 归属进程）；Containers 页：容器详情页；Locks 页：跳到持锁进程的详情页；Events 页：跳到事件对应进程的详情页 |
| `p` `n` `u` `c` `m` `i` `t` | Processes 页按 PID / 名称 / 用户 / CPU / 内存 / 磁盘 I/O 速率 / 启动时间排序，重复按切换升降序（`i` 按每秒读+写字节排序，需相隔一秒的两次采样） |
| `p` `t` `n` `s` | Ports 页按 端口 / 协议 / 地址 / 状态 排序 |
| `i` `n` `r` `g` `s` `p` | Containers 页按 ID / 名称 / 运行时 / 镜像 / 状态 / compose 项目 排序 |
| `p` `n` `t` `m` `f` | Locks 页按 PID / 进程 / 类型 / 模式 / 路径 排序 |
| `n` `m` `s` `p` | Services 页按 名称 / 管理器 / 状态 / 主 pid 排序 |
| `t` `e` `p` `n` | Events 页按 时间 / 事件 / PID / 进程 排序（时间默认最新在前，重复按切换升降序） |
| `T` | Processes 页：树形视图 ↔ 平铺表格（子进程嵌在父进程下；搜索时显示平铺） |
| `F` | Logs 页：切换实时日志流（容器 `logs -f` / journald `journalctl -f` / macOS `log stream`，按来源自动选择命令） |
| `a` | Ports 页：切换 仅监听 ↔ 全部状态；Locks 页：切换 锁 ↔ 全部打开文件；Processes 页：打开操作栏（`k` kill / `K` 树杀 / `t` term / `p` 暂停 / `r` 恢复 / `n` renice） |
| `w` | Processes 页：关注选中进程（★ 置顶、写入配置文件跨会话保留，按身份匹配、重启换 pid 不丢）；再按取消 |
| `N` | Processes 页：为选中进程写备注（Enter 保存 / Esc 放弃 / 清空删除；按身份持久化，行尾 ✎ 标记，重启换 pid 不丢） |
| `o` | Ports 页：逐 socket 明细 ↔ 按 (端口, 属主) 聚合的总览（`Enter` 跳属主进程详情） |
| `l` | 详情页 / Events 页：拉取该进程最近的日志（容器日志 / journalctl / macOS 统一日志），全屏 Logs 页滚动查看；Events 页已退出的进程优先显示退出瞬间自动捕获的最后日志 |
| `S` | 打开会话摘要页（活动计数 / 重启链 / CPU 尖峰榜 / 内存爬升榜，窗口由 `--since` 预设），`r` 重算，`Esc` 返回 |
| `y` | 打开系统资源页：整机 CPU/内存历史图表、load、swap、每核占用网格；`r` 立即采样，`Esc` 返回 |
| `D` | 打开快照 diff 页：最新自动快照 vs 实时进程表（new/gone/restarted/changed/listen 着色行 + 计数），`j/k` 选中、`Enter` 跳进该进程详情页、`r` 重算、`Esc` 返回 | |
| `P` | 暂停 / 恢复采样（全局冻结，页脚 `⏸ paused` 指示；Events 页 pid 降序改按 `p` 两次） |
| `M` | 全局静音开关：告警判定照常跑、不再触发通知/钩子/告警行，被静音的条目以 silenced 进事件环（页脚有指示） |
| `<` `>` | Processes 页：逐帧回看 / 前进最近 30 帧进程表快照（标签栏 REPLAY 徽章；走到底自动回实时，回放中告警暂停、录制照常） |
| `!` | 桌面通知开关（`--notify` 预开启，页脚有指示） |
| `z` | 缩放：聚焦面板临时占满整行（tmux 风格） |
| `x` | 杀掉选中进程（y/n 确认） |
| `?` | 键速查 overlay：全局键 + 当前标签页专属键分组，`j/k` 滚动，Esc/q/Backspace 返回打开时的页面 |
| `r` | 立即刷新 |
| 详情页内 | `j/k` 滚动、`d/u` 半页、`g/G` 顶部/底部、`b/f` 翻页、`Tab` 切换面板、`a` 操作栏、`l` 最近日志、`/` 搜索环境变量、`z` 缩放、`c` 复制当前面板、`Esc/q` 返回 |
| 鼠标 | 滚轮滚动列表 / 详情面板；点击标签页切换、点击行选中、点击面板聚焦；双击行打开详情 |
| `q` / `Esc` | 退出 |

选中进程的详情在光标停止移动 500ms 后自动刷新（防抖，按住 j 快速滚动不会连发查询），与原版 `selectionDebounce` 一致。

**端口详情页**：在 Ports 页选中某个端口按 `Enter`，可以看到该端口当前的全部 socket——LISTEN 监听项加上**正在发生的请求**（每条 ESTABLISHED 连接的对端地址、状态、归属 PID/进程，端口详情打开瞬间的快照），下方 Owner 面板显示监听进程的完整溯源（归因 + 祖先链 + 告警）。`Tab` 在 Connections / Owner 两个面板间切换焦点，`j/k/d/u/g/G/b-f` 滚动，`Esc` 返回列表。

**进程详情页**：左侧溯源面板（身份信息、Started by 归因、Ancestry Tree、Open Files、风险评分、告警），右侧环境变量面板；`c` 键把当前面板纯文本复制到剪贴板。

**风险评分**：每个进程聚合 0–10 分风险信号——临时目录下的二进制、运行中二进制被删除、`curl | sh` 类管道下载、LD_PRELOAD/DYLD 注入、对公网地址的 ESTABLISHED 连接。CLI 输出 `risk N/10: 信号列表`，TUI 详情页同样显示。

**崩溃重启检测**（TUI）：同一进程身份换新 pid 即记一次重启，`Rst` 列显示总次数，5 分钟内 ≥2 次时详情页黄色告警——crash loop 一眼可见（事件明细见 Events 页）。重启事件还会**对比前后两个生命的命令行与环境变量**：argv 变了在重启详情里标注新命令行（配置改了但服务起错参数这类事故现形），env 变了标注 "env changed"——重启不只是次数，连"为什么这次起得不一样"都有答案。

**瞬时 CPU + Trend sparkline**（TUI）：按累计 CPU 时间的刷新间差值计算真实瞬时占用（非生命周期均值），表格 Trend 列以 8 级 sparkline 展示最近 8 次采样，`c` 排序键按瞬时值排序。

**二进制指纹**（`--export` / TUI 详情页）：对目标二进制计算 sha256 并给出代码签名结论（macOS `codesign`、Windows Authenticode；无效签名计入风险评分 +3）。Linux 无内核级签名体系，以哈希为准。

**GPU 列**（TUI，可选）：装有 NVIDIA 驱动的机器上通过 `nvidia-smi pmon` 显示每进程 SM 占用与显存（`37% 2.3G`），详情页显示完整数值；无 nvidia-smi 时该列自动隐藏，探测失败只发生一次不重复开销。同一份数据也进 **`--top gpu`** 排行榜与 **`--record`** 的 `gpu_sm` 列。

**K8s Pod 归因**（可选）：装有 `kubectl` 且集群可达时，容器会标注所属 Pod（`docker: mongo-demo-2 (id 6838b8ba3c49) · pod data/mongo-0`），TUI Containers 页出现 Pod 列；一次 `kubectl get pods -A -o json` 顺路取出 Pod 的 phase / 重启总数 / 第一个非例行 waiting reason（CrashLoopBackOff、ImagePullBackOff…），供容器/Pod 告警边缘使用。无 kubectl 时零开销跳过。

**容器健康**：Containers 页状态列着色（healthy/running 绿、unhealthy 红、restarting/starting 黄）；容器详情页与 `-c` 目标输出 `inspect` 的 RestartCount（>0 时标注 "restart policy fired"）。Containers 页还会**盯容器的边缘**（打开过 Containers 页的会话自动生效）：机器上有运行时 CLI 时自动起一条 **`docker/podman/nerdctl events` 事件流**——容器的 die / OOM / 健康检查翻红在**毫秒级**直达（`>> container: web — exited (exit code 137)`），不等下一次枚举；事件流不可用（无运行时）时退回**枚举差分**检测：运行中的容器在两次枚举间消失/转死时取 `inspect` 的死因——`exited — OOMKilled (exit 137)` 点名 OOM、`exit N: <错误信息>` 点名 runtime 报错；RestartCount 攀升（旧值 → 新值）即提示 crash loop（差分侧独立生效）；cgroup `memory.events` 的 oom_kill 计数攀升即告警——内核在容器里真的 OOM 杀过进程，restart policy 再快也盖不住这个账；无 kubectl 时到此为止，集群可达时 **Pod 状态也一并盯**：容器 waiting 出现非例行 reason（CrashLoopBackOff / ImagePullBackOff…，部署期的 ContainerCreating / PodInitializing 不算）、Pod 从 Running 退回 Pending、进入 Failed、Pod 级重启数攀升都各触发一条告警。同一套"边缘触发 + 只报一次"机制：桌面通知、`--alert-exec`、`--alert-webhook`、`--events-log` 全部照常生效。TUI 无需旗标；`--watch` 无头跑加 **`--alert-container`** 把同一条边缘接进告警管线（容器与 Pod 枚举走后台线程，每 ≥10 秒一轮，不占采样 tick；`events` 流活着时死亡边缘归流——毫秒级 `>>` 行先到，差分只兜底）——cron/systemd 里容器 OOM 与 Pod CrashLoopBackOff 同样喊得出来。

**崩溃关联日志**：详情页与 Events 页按 `l` 拉取该进程最近的日志（容器走 `docker/podman/nerdctl logs`，Linux 走 `journalctl _PID=<pid>`，macOS 走统一日志 `log show --predicate`）——Events 页看到 crash loop 之后按 `l`，"它为什么一直重启"的答案通常就在最近这几行里。日志在后台线程获取（`log show` 可能要跑好几秒，界面不冻结），全屏 Logs 页滚动查看。Logs 页按 `F` 可切换**实时流**（按来源自动选命令：容器 `logs -f`、Linux `journalctl -f _PID=`、macOS `log stream --predicate`）：停在底部时自动跟随滚动，最多保留最近 500 行，离开页面或退出 TUI 时自动杀掉子进程。CLI 同款：`witr-rs --pid 1234 --logs [N]`（默认 100 行）。

**事件持久化与回放**：`witr-rs --events-log events.jsonl` 让 TUI 把事件采样器产出的每条 started/exited/restarted 以 JSONL 追加落盘——TUI 关了记录还在，回答"我不在的这段时间发生了什么"；**无目标 `--watch` 也认这个旗标**——不开界面常驻跑，事件与阈值告警同样逐条落盘（cron / systemd 里蹲机器）。`witr-rs --replay events.jsonl` 读回文件、直接落在 Events 页（旧事件 + 实时采样继续叠加），时间列按原始时间戳显示。配 **`--follow`** 变成跟随尾巴：`--replay ev.jsonl --follow` 加载完历史后持续盯着文件末尾，录制侧新追加的事件实时流入事件环——一台机器录制、另一台机器（或另一个终端会话）开个窗口直播看， torn 行等待补全、文件轮转自动从头再读。

**样本回放页（`--samples`）**：`witr-rs --samples load.csv` 把 `--record` 产出的样本文件（.csv / .jsonl 都认）导入 TUI 的 **Samples 页**——五条整机曲线（cpu% / 内存% / 1 分钟负载 / 网络 MB/s / 进程数）以 sparkline 呈现，`←/→`（h/l）移动光标逐时刻读数（读数行列出光标处全部五个指标的值），`↑/↓`（j/k）切换图上曲线，`g/G` 跳到首尾，`Esc` 回主表，`c` 复制页面文本。实时采样照常继续——"照着昨晚录制的曲线排查现在这台机器"两个时间面叠在一屏上。

**Containers 页**：通过 PATH 上的运行时 CLI（docker / podman / nerdctl）枚举容器，显示 Runtime / ID / State / Status /（Pod）/（Compose）/ Image / Name，状态按健康度着色；**CPU% / MEM 两列**在首次资源采样落地后出现——后台每约 10 秒跑一次 `stats --no-stream`（每运行时约 2 秒，成本高于列表本身），按容器 id 合并回表格，MEM 列按容器自身限额的占用比例着色（≥70% 黄、≥90% 红——容器撞限额是 OOM 的前奏）；**THR% / OOM 两列**来自容器 cgroup 的限流时间与 oom_kill 计数（Linux cgroup v2，每轮枚举顺路读几个文件，无运行时 CLI 开销）——THR% 是本轮枚举间隔内被 CFS 配额掐住的时间占比（≥50% 红——"容器变慢但 CPU 看着不满"的头号原因），OOM 列非零即容器内发生过内核级 OOM 杀；**I/O 列**读同一 cgroup 的 `io.stat`（各设备 rbytes/wbytes 差分出本轮读写速率，详情页附累计值）——容器的磁盘画像与 THR%/OOM 同一轮扫描顺路拿到；**Compose 列**取容器的 `com.docker.compose.project` 标签（兼容 docker 的 `k=v,k2=v2` 串与 podman/nerdctl 的 JSON object 两种 label 形态，非 compose 容器该列自动隐藏）——开发机上"这排容器是谁家的"一眼分明；`/` 按 名称/镜像/ID/运行时/状态/compose 项目 过滤，`i/n/r/g/s` 排序，`p` 按 compose 项目排序。枚举在后台线程执行（运行时 CLI 挂起不会卡住界面），每 3 秒自动刷新；刷新期间保留旧表格不闪烁，首次加载才显示 loading。**`Enter` 打开容器详情页**：左侧容器属性（Name/Runtime/Compose/ID/Image/State/Status/Ports/Restarts），右侧容器内进程列表（Linux 通过 cgroup 匹配；macOS/Windows 容器进程在 VM 内不可见，显示说明）。

**Locks 页**：文件锁 + 打开文件视图（Linux 读 `/proc/locks`，macOS 从 `lsof` 提取锁标志并辅以锁文件名启发式）；`a` 在 锁视图 ↔ 全部打开文件 之间切换（打开文件视图空搜索时截断显示前 100 行，搜索即放开），选中行按 `Enter` 直接跳到持锁进程的详情页。

**Services 页（6）**：服务管理器的单元视图（Linux systemd / macOS launchd / Windows SCM）——列 Name / Manager / State / PID / Description，运行中的排前面，`n/m/s/p` 排序，`/` 按 名称/管理器/状态/描述 过滤；按 `Enter` 跳到该单元主进程的详情页（launchd 单元经 plist 探测找回程序身份）。CLI 孪生是 `--services`。

**CLI 预置进 TUI（`-i`）**：`witr-rs -i --pid 1234` / `witr-rs -i nginx` / `witr-rs -i --port 8080` / `witr-rs -c web -i` / `witr-rs -i --file /var/log/x.log` — 打开 TUI 并直接落到对应标签页与过滤条件上（name 预填搜索词、pid 选中行、port/file/container 跳到对应页并预填过滤器）。每种类型取第一个目标，多余的会在状态栏提示；无终端时退出码 4。

## 平台支持

| 能力 | Linux | macOS | Windows |
|---|---|---|---|
| 进程表 | `/proc` 直读 | `ps` | ToolHelp32 快照 |
| cmdline / cwd / exe | `/proc/<pid>/*` | `ps` + `lsof` | PowerShell (Get-CimInstance) |
| 端口 → 进程 | `/proc/net/*` + fd inode 匹配 | `lsof -i` | `netstat -ano` |
| 文件 → 进程 | `/proc/*/fd` | `lsof` | ✓（Restart Manager API，无需 Sysinternals） |
| 文件锁（Locks 页 / `--locks`） | `/proc/locks` + fdinfo | `lsof` 锁标志 + 锁文件名启发式 | ✗ |
| 进程组 / 会话（pgid / sid） | ✓ `/proc/<pid>/stat` | ✓ `ps pgid=,sess=` | ✗ |
| cgroup v2 资源面板（详情页） | ✓ `/proc/<pid>/cgroup` + `/sys/fs/cgroup` | ✗ | ✗ |
| 服务归因 | systemd（`systemctl status`） | launchd（`launchctl list` + plist 探测） | SCM（`tasklist /svc`，识别 services.exe 后代） |
| 容器归因 | cgroup（docker/containerd/podman/lxc） | ✗ | ✗ |
| nohup/disown 检测 | ✓（`/proc/<pid>/status` SigIgn SIGHUP 位，计入告警） | ✗ | ✗ |
| 控制终端（tty）归因 | ✓ `/proc/<pid>/stat` tty_nr | ✓ `ps tty=`（`??` 即 detached） | ✗ |
| 环境变量（`--env` / TUI 详情页） | ✓ `/proc/<pid>/environ`（同用户） | ✓ 同用户进程走 `ps -E`（其余受 SIP 限制，面板会提示） | ✗ |
| 每进程磁盘 I/O（TUI IO 列 + 详情累计值） | ✓ `/proc/<pid>/io`（字节差分 → 速率） | ✓ `proc_pid_rusage` | ✓ PowerShell IO_COUNTERS |
| 每进程 fd 数（`--top fd` / `--alert-fd`） | ✓ `/proc/<pid>/fd` 直读 | ✓ libproc `proc_pidinfo` 原生扫描（无子进程） | ✓ PowerShell `Get-Process` HandleCount |
| 每进程内核线程数（`--top threads` / `--alert-threads` / 详情页线程图） | ✓ `/proc/<pid>/stat` nlwp | ✓ `ps nlwp` 随表携带 | ✓ ToolHelp 线程快照 |
| 可回收内存绝对下限（`--alert-mem-avail-mb`） | ✓ MemAvailable | ✗ | ✗ |
| TCP 重传计数（`--alert-retrans`） | ✓ `/proc/net/snmp` | ✗ | ✗ |
| 每网卡丢包/错误计数（`--alert-nic-drop`） | ✓ `/proc/net/dev` | ✗ | ✗ |
| 每进程网络吞吐（`--top net` / `--alert-net-per-proc`） | ✓ `ss(8)` tcp_info 差分 | ✗ | ✗ |
| 启动时间 | btime + starttime | `ps etime` | CIM CreationDate |
| 温度（系统资源页） | ✓ hwmon 最热传感器 | ✗ | ✗ |
| PSI 压力（系统资源页 / `--alert-psi`） | ✓ `/proc/pressure/*` | ✗ | ✗ |

跨平台可选增强（三端一致，缺依赖时静默跳过）：`nvidia-smi`（GPU 列）、`kubectl`（K8s Pod 归因）、`docker`/`podman`/`nerdctl`（Containers 页）。

依赖的外部命令：Linux 无强依赖（systemctl/docker 可选）；macOS 需要 `ps`/`lsof`（系统自带）；Windows 需要 `powershell`/`netstat`/`tasklist`（系统自带）。

## 安装

一行安装（macOS / Linux——自动下载对应平台的发行包、校验 sha256 并装到 `~/.local/bin`，可用 `WITR_INSTALL_DIR` 覆盖）：

```bash
curl -fsSL https://raw.githubusercontent.com/yaowenqiang/witr-rs/main/install.sh | sh
```

或从 [GitHub Releases](https://github.com/yaowenqiang/witr-rs/releases) 下载对应平台的压缩包（sha256 校验见 `sha256sums.txt`），解开即用。打 `v*` 标签时 CI 会自动构建全部平台：

| 文件 | 平台 |
|---|---|
| `witr-rs-x86_64-unknown-linux-musl.tar.gz` | Linux x86_64（静态链接） |
| `witr-rs-aarch64-unknown-linux-musl.tar.gz` | Linux ARM64（静态链接） |
| `witr-rs-x86_64-apple-darwin.tar.gz` | macOS Intel |
| `witr-rs-aarch64-apple-darwin.tar.gz` | macOS Apple Silicon |
| `witr-rs-x86_64-pc-windows-msvc.zip` | Windows x86_64 |

或从源码构建：

```bash
cargo build --release          # 本机平台
cargo check --target x86_64-unknown-linux-gnu   # 三平台代码全平台类型检查
cargo check --target x86_64-pc-windows-msvc
cargo test
```

## 用法

```bash
witr-rs                       # 无参数：进入交互式 TUI（终端）；管道中输出静态进程表
witr-rs --tree                # 无参数 + --tree：全系统进程树（--list 同理走静态输出）
witr-rs --json                # 无参数 + --json：全部进程 JSON
witr-rs nginx                 # 按进程名（子串模糊匹配）
witr-rs python --exact        # 精确匹配（不区分大小写）
witr-rs --pid 1234            # 按 PID
witr-rs --port 8080           # 谁占了这个端口
witr-rs --file /var/log/x.log # 谁打开着这个文件
witr-rs --file '/var/log/*.log' # 通配符：每个匹配文件的持有者一起列出
witr-rs -c web                # 谁在跑这个容器（名称/镜像/ID 前缀匹配）
witr-rs nginx --tree          # 祖先树 + 子进程
witr-rs nginx --short         # 单行输出（脚本友好）
witr-rs --port 8080 --json    # 机器可读 JSON
witr-rs nginx --env           # 只输出命令 + 环境变量（Linux 全量；macOS 同用户进程）
witr-rs --watch               # 常驻刷新进程表（默认 2s，Ctrl-C 退出）
witr-rs --port 8080 --watch 5 # 每 5 秒重跑该目标的溯源并重绘
witr-rs --recent 5m           # 只看最近 5 分钟内启动的进程
witr-rs nginx --warnings      # 只输出告警列表
witr-rs --pid 1234 --export   # 可直接贴 issue 的纯文本排查报告
witr-rs --pid 1234 --logs 50  # 该进程最近 50 行日志（容器/journal/统一日志）
witr-rs --events-log ev.jsonl # TUI 事件采样落盘（JSONL，追加写）
witr-rs --watch 5 --events-log ev.jsonl # 无头也落盘：不开界面常驻记录事件 + 告警（cron/systemd 友好）
witr-rs --replay ev.jsonl     # 回放事件记录，落在 Events 页
witr-rs --replay ev.jsonl --follow # 跟随尾巴：录制侧追加的事件实时流入（远程/跨会话直播窗口）
witr-rs --replay ev.jsonl --since 1h # 录制内容"发生了什么"摘要：计数 + 重启链，直接打印退出
witr-rs --top cpu -n 30       # CPU 前排 30（--top mem|fd|io|io-rate|age 同理；不进 TUI）
witr-rs --top io-rate -n 10   # 磁盘 I/O 速率榜（读+写 MB/s；--watch 下持续采样）
witr-rs --top age -n 10       # 最老进程前 10（存活时长排行，pid 1 永远榜首）
witr-rs --top threads -n 10   # 线程数最多的进程（--top conn 看谁攥着最多 ESTABLISHED 连接，--top net 看谁在吃网卡）
witr-rs --top gpu-mem -n 10    # 显存吃最多的进程（NVIDIA）
witr-rs --pid 1234 --kill --dry-run # 先看后杀：打印击杀计划不发信号
witr-rs --top cpu --watch 5   # 每 5s 重采样重排的常驻 CPU 榜（Ctrl-C 退出）
witr-rs --csv                 # 全表 CSV（RFC-4180 转义；--markdown 贴文档用）
witr-rs --watch 5 --record load.csv # 每 5s 把整张进程表追加进 CSV 时间序列
witr-rs --watch 5 --record load.csv --record-max-mb 200 # 同上，超 200MB 滚动为 load.csv.1（长跑 watchdog 磁盘有上界）
witr-rs --watch 5 --record load.jsonl # 同款时间序列，NDJSON 信封（ppid/state/age 顺路带上）
witr-rs --plot load.csv        # 录制文件画成自包含 HTML 时序图（离线可看的五张 SVG 曲线）
witr-rs --samples load.csv     # 录制文件导入 TUI Samples 页（sparkline + ←→ 光标逐时刻读数）
witr-rs --tree --json         # 全表嵌套 JSON（子进程挂 children，孤儿/ppid 环升级为根）
witr-rs --report-html status.html   # 自包含单文件 HTML 报告（CPU/内存条 + Top 榜 + 全表）
witr-rs --alert-fd 4096 --alert-io 100 # fd 数 / 磁盘 IO 速率阈值告警（同 CPU 告警机制）
witr-rs --alert-conn 200      # 每进程 ESTABLISHED 连接数阈值告警（TUI 与 --watch 同效）
witr-rs --alert-threads 400   # 每进程内核线程数阈值告警（线程泄漏哨兵，TUI 与 --watch 同效）
witr-rs --alert-net-per-proc 5 # 每进程 TCP 吞吐阈值告警（MB/s；悄悄外传数据的进程现形，ss(8) 差分）
witr-rs --watch 5 --alert-deviation 10 # 自基线哨兵：安静任务突然持续繁忙即喊（无需预设阈值）
witr-rs --watch 5 --alert-mem-avail-mb 500 # OOM 前最后一道哨兵：可用内存跌破 500MB 即喊
witr-rs --watch 5 --alert-retrans 100 --alert-nic-drop 50 # 网络质量哨兵：TCP 重传 / 网卡丢包超速即喊（--alert-swap-pct 90 同门）
witr-rs --watch 5 --alert-cpu 90 # 无头 watchdog：--watch 下越阈值打印 ⚠ alert 行（不进 TUI）
witr-rs --watch 5 --quiet --alert-mem 2048 # 更安静的无头 watchdog：跳过每 tick 重绘，只出告警/钩子
witr-rs --watch 5 --times 12  # 采满 1 分钟自动退出并打印摘要（--json 时摘要也是 JSON 信封）
witr-rs --port 8080 --watch 2 --on-start 'say up' # 目标出现的边缘执行一次命令（wait-for-deploy）
witr-rs --alert-cpu 90 --alert-exec 'curl -s $SLACK_HOOK -d "$WITR_ALERT_NAME: $WITR_ALERT_DETAIL"' # 每次告警触发时执行命令（webhook）
witr-rs --watch 2 --alert-port 9090 # 端口金丝雀：有人开始监听 :9090 时告警（TUI 下同效）
witr-rs --watch 2 --alert-port '!8080' --alert-repeat 60 # 8080 监听消失时告警，持续掉线每 60s 重发
witr-rs --audit 'cargo build --release' # 包装命令跑完打印子树资源报告（时长/退出码/峰值 CPU/RSS/磁盘 IO + 进程树）
witr-rs --audit 'cargo build --release' --json # 同上，机器可读信封（CI 里 jq 直接取数）
witr-rs --ports               # 当前 LISTEN 端口总览（--json / --csv 机器可读）
witr-rs --locks               # 全系统文件锁列表（--json / --csv / --markdown）
witr-rs --zombies             # 僵尸进程速查（最老优先；有僵尸退出码 1——巡检探针）
witr-rs --conns               # 全机非 LISTEN 连接表：本地/对端/状态/属主（回环对端自动归因；--watch N 常驻）
witr-rs --services            # 服务管理器单元列表（systemd/launchd/SCM；运行中的排前面）
witr-rs --watch 5 --alert-load 8 --alert-mem-pct 90 # 机器级 watchdog：load / 内存百分比超阈值告警
witr-rs --watch 5 --alert-count 800 # 机器级 watchdog：可见进程数超 800 告警（fork 炸弹哨兵）
witr-rs --watch 5 --alert-disk 90 # 机器级 watchdog：任一磁盘已用 % 超阈值告警（写满哨兵）
witr-rs --watch 5 --alert-psi 10 --alert-webhook http://127.0.0.1:9000/hook # Linux PSI 全停顿告警 + JSON webhook 推送
witr-rs --watch 5 --alert-new-proc xmrig miner # 首见进程告警：新面孔即报（挖矿/后门哨兵；'!nginx' 反选白名单模式）
witr-rs --watch 5 --alert-cpu 90 --alert-silence backup=30m # 维护窗口：backup 名字前 30 分钟静默（!NAME 反选）
witr-rs --watch 5 --alert-cpu 90 --install-service # 一条命令固化成 systemd 用户单元 / launchd plist / schtasks 服务
kill -HUP $(pgrep -f 'witr-rs --watch') # 配置热重载：不重启改阈值/静默名单（告警状态保留）
witr-rs --plot before.jsonl after.jsonl # 两条录制的整机曲线叠加对比（输出 witr-plot.html）
witr-rs --remote http://10.0.0.7:9100    # 渲染远端 --serve 的进程表（--watch N 周期重拉；--tree/--csv/--json 同本地）
witr-rs --remote http://a:9100 --remote http://b:9100 # 一排机器各一段落（--json 出舰队信封；坏主机 ⚠ 不拖垮其余）
witr-rs --remote http://10.0.0.7:9100 --watch 2 # 远端表格常驻刷新
witr-rs --watch 10 --alert-container # 无头容器哨兵：容器退出/OOM、Pod CrashLoopBackOff 即喊（边缘触发只报一次）
witr-rs --sys                 # 整机仪表盘：CPU/内存/load/磁盘/网卡/温度/PSI（--watch 2 常驻；--csv/--markdown/--json 同源）
witr-rs --conns --by-peer      # 连接按对端聚合：谁连得最多、哪条链路最忙（--json/--csv/--markdown 同源）
witr-rs --watch 30 --diff-auto 30 # 漂移看门狗：每 30s 自动对比前后帧，有增减才打印
witr-rs --top cpu --csv       # CPU 榜单直接出 CSV（--markdown 同理）
witr-rs --by-name             # 按 (名字, 用户) 聚合整表：N / ΣCPU / ΣRSS / ΣCPUTIME（--csv/--markdown/--json 同源）
witr-rs --by-name --watch 5   # 聚合视图常驻刷新
witr-rs nginx --pids-only     # 只打印匹配 pid（管道喂 xargs kill；无匹配退出码 2）
witr-rs --port 8080 --wait    # 阻塞等目标出现（--wait gone 等消失；--timeout N 超时退出码 124）
witr-rs --pid 1234 --wait gone --timeout 60 # 等旧进程退干净（部署脚本原语）
witr-rs --ports --watch 2     # LISTEN 端口表常驻刷新（--times N 上界）
witr-rs --watch 30 --diff-auto 30 --json # 漂移看门狗机器可读帧（summary + entries，jq 盯计数）
curl -s 'localhost:9100/api/top?metric=mem&n=5' # 进程榜 HTTP 形态（cpu|mem|fd|age|io|io-rate|threads|conn|net）
witr-rs runaway --kill        # 无头击杀匹配目标（--signal KILL 换信号；--kill-tree 连子进程树先子后父）
witr-rs --pid 1234 --logs 200 --grep ERROR # 日志只看匹配行（需配合 --logs）
witr-rs --snap before.json    # 进程表快照落盘（JSON）后退出
witr-rs --snap                # 自动快照：存配置目录旁 snapshots/，轮转保留 10 份（--keep N 可调）
witr-rs --snap=now.json --sockets # 快照顺路记录 LISTEN 端口（供 --diff 报告监听变化）
witr-rs --diff before.json    # 对比快照：new / gone / restarted / changed / listen-new / listen-gone（身份级判定，pid 复用不误报；有变化退出码 1）
witr-rs --diff last           # 对比最近一份自动快照（--diff 30m 对比半小时前那份）
witr-rs --diff last --json    # 快照对比的机器可读信封（summary 计数 + entries）
witr-rs --serve :9100         # Prometheus /metrics + 零 JS 仪表盘（/）+ /api/ps JSON 进程表端点（每次抓取现场采样，默认绑 127.0.0.1；含端口 gauge、重启信号 start_time 与自监控指标）
witr-rs --serve :9100 --serve-token s3cret # 同上 + Bearer 认证（全部端点；Prometheus authorization 凭据直接对接）
curl -N localhost:9100/api/events # SSE 实时事件流：started/exited/restarted 逐帧推送（15s 无事件保活 ping）
witr-rs --man                 # 生成 man 页（stdout；--man FILE 写入文件，目录自动创建）
witr-rs --en --help           # 英文帮助（--man / --completions 同样随 --en 切语言）
witr-rs --pid 1234 --follow   # 跨重启跟踪目标（同程序换新 pid 继续追；pid 扑空时会提示这条）
witr-rs --pid 1234 --follow --on-exit 'say gone'  # watch/follow 下目标消失时执行一次命令（follow 彻底跟丢后 exit 2）
witr-rs --notify              # TUI 桌面通知：重启必弹，crash loop 的退出也弹
witr-rs --completions zsh     # 输出 shell 补全脚本（bash|zsh|fish|powershell）
witr-rs -i --port 8080        # 进 TUI 并直接落到该端口（-i 预置，见上）
witr-rs nginx --pid 1         # 多目标混用（各目标间以分隔线输出）
NO_COLOR=1 witr-rs nginx      # 禁用着色（--no-color 同理）
```

shell 补全（按所用 shell 选一条）：

```bash
witr-rs --completions bash >> ~/.bashrc      # zsh → ~/.zshrc；fish → ~/.config/fish/completions/witr-rs.fish
```

### 退出码

| 码 | 含义 |
|---|---|
| 0 | 正常且无告警 |
| 1 | 找到了，但有告警（root 运行、监听所有网卡、二进制已删除、LD_PRELOAD、僵尸进程等）；`--zombies` 发现僵尸时同样为 1 |
| 2 | 目标未找到 |
| 3 | 权限不足（如需要 root 的查询） |
| 4 | 参数无效 |
| 5 | 内部错误（如进程表不可读） |
| 6 | 找到了，但无法归因来源（Windows 上不出现——其祖先链常止于已退出进程） |
| 124 | `--wait` 超时（GNU timeout 惯例；被 SIGINT 打断则为 130） |

多目标时取最严重的退出码；严重度排序与原版一致（6 排在 1 之后）。

## 输出示例（macOS）

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

## 架构

```
src/
├── cli.rs          clap 参数定义
├── model.rs        Process / Socket / Source / TargetReport 数据模型
├── ancestry.rs     ppid 链回溯（防环、深度限制、父进程已退出的告警）
├── pipeline.rs     目标解析（name/pid/port/file/container → pid）、归因优先级、风险告警
├── tui.rs          交互界面（ratatui/crossterm）：五标签页 + 详情面板 + 鼠标 + 3s 自动刷新
├── render.rs       standard / tree / short / json / env / warnings / export / csv / markdown / top / html 渲染
├── history.rs      采样历史：瞬时 CPU、sparkline、内存趋势 + 泄漏嫌疑、重启检测、Events 事件流、会话摘要、告警静默/首见名单、短命进程捕获、容器事件流解析
├── config.rs       用户配置文件（flat toml 子集：refresh_secs/sort/notify/paused/watch/notes，CLI 覆盖）
├── snapshot.rs     --snap / --diff：全表快照（含自动轮转）与 new/gone/restarted/changed 对比
├── serve.rs        --serve：Prometheus 文本格式端点（std::net 手写 HTTP，抓取即采样，基数有界；/api/events SSE 懒启动差分采样器）
├── logs.rs         崩溃关联日志：容器日志 / journalctl / macOS 统一日志
├── risk.rs         0–10 风险评分（临时目录二进制、curl|sh、注入、公网对端、无效签名等）
├── binary_id.rs    二进制 sha256 + 代码签名结论（codesign / Authenticode）
├── gpu.rs          nvidia-smi pmon 采样 → 每进程 GPU 列
├── k8s.rs          kubectl get pods → 容器所属 Pod 归因
├── util.rs         带超时的命令执行、时间格式化、用户名解析（带负缓存）、host:port 解析
└── platform/
    ├── mod.rs      Platform trait（唯一的平台接缝）+ 容器枚举 / inspect
    ├── linux.rs    /proc 全家桶
    ├── macos.rs    ps / lsof / launchctl
    └── windows.rs  ToolHelp32 / PowerShell / netstat / tasklist / Restart Manager
```

归因优先级：容器 > ssh 会话 > 交互 shell > 服务管理器（systemd/launchd/SCM）> 保活 supervisor（supervisord/runc 等，含 cmdline 令牌匹配）> cron > init 兜底（pid 1 直启且链上无 shell，如系统 daemon）。Linux 的 service_source 返回 "init" 兜底时会被 pipeline 放弃，转而走通用归因。

## 已知限制

- TUI 的 Ports/Containers/详情页均为打开瞬间快照，`r` 手动刷新
- Windows 进程详情依赖 PowerShell 批量查询（每个目标一次调用，20s 超时保护）；CPU% 列来自 `Get-Process` 采样的刷新间差值（PowerShell 不可用时该列回退为空）
- 日志关联（`l` / `--logs`）覆盖 容器日志 / Linux journald / macOS 统一日志；Windows 暂无对应的单一日志源（退出即取证在 Windows 同样缺席）。实时流 `F` 覆盖 容器 / journald / macOS 统一日志，Windows 事件日志无流式等价
- 桌面通知三平台齐备（macOS osascript / Linux notify-send / Windows WinRT toast）；Windows 无每进程 I/O，IO 列与详情页 I/O 历史图同样缺席
- 事件持久化（`--events-log`）：TUI 与无目标 `--watch` 均可录制，`--replay` 均可回放；watch 的采样粒度等于 `--watch` 间隔（默认 2 秒），粒度内生灭的进程由短命进程捕获兜底（存活 ≤5 秒的经 250ms 轮询器可见，更长的走常规 started/exited）
- `--watch` 的 Ctrl-C 摘要依赖 SIGINT 钩子（unix）；Windows 用 `--times N` 收尾（摘要在 `--times` 退出与 `--json` 信封里都有）
- 会话摘要（`--since`/`S`）的 CPU 尖峰榜与内存爬升榜只覆盖最后一次刷新时仍存活的进程（死进程采样被剪枝）——尖峰后即退出的进程体现在活动计数里，不在榜单上；`--replay` 的文件摘要只有活动计数与重启链（录制里没有采样数据）
- `--follow` 按程序身份（name+exe+user）匹配：同一程序并行跑多份时，重启可能落在"最新的兄弟实例"而非严格意义上的继任者
- FD 趋势图仅详情页打开期间采样（Linux/macOS 均为原生查询，微秒级；Windows 有全表句柄扫描但无每进程 fd 查询，该节缺席）
- 容器归因目前仅 Linux（macOS 上 colima/Docker Desktop 的容器进程未归因，但 `-c` 目标有运行时侧兜底视图）
- Windows 有 `--file`（Restart Manager）但无 Locks 页数据
- macOS `launchctl list` 只覆盖当前用户域，系统域 daemon 需要 sudo 才能标注；文件锁来自 `lsof` 标志近似，内核未导出锁表
- nohup/disown 检测仅 Linux（macOS/Windows 无 `/proc`，TUI/CLI 不显示该告警）
- GPU 列只支持 NVIDIA（`nvidia-smi`）；Apple Silicon / AMD 显卡无每进程占用数据源
- `--top fd` / `--alert-fd` 在 Windows 统计的是内核句柄数（PowerShell `Get-Process` HandleCount，与 Sysinternals 的 Handles 同源）
- cgroup 资源面板与 `--locks` 仅 Linux/macOS 有数据（Windows 两项均缺席）；cgroup 数字读不到时（如容器命名空间里路径对不上宿主挂载）只显示路径
- `--replay --follow` 的尾随粒度是录制侧的写入节奏——文件没有新行时 nothing 流入，录制进程退出后 TUI 继续等（Ctrl-C 离开）

## 许可

Apache-2.0。设计参照 pranshuparmar/witr（同为 Apache-2.0）。

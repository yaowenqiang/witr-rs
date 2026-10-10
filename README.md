# witr-rs

[English](README.en.md) | **简体中文**

**Why is this running?** — 给出进程名、PID、端口或文件，一路追溯它是被谁、以何种方式拉起来的。

Rust 实现的 [pranshuparmar/witr](https://github.com/pranshuparmar/witr)（Go，Apache-2.0）同类工具，平台采集策略与其对齐。

**直接运行 `witr-rs`（无参数）进入交互式 TUI**，布局与原版一致：顶部五个标签页（1. Processes / 2. Ports / 3. Containers / 4. Locks / 5. Events），左侧进程表（PID / User / Name / CPU% / Trend / Mem / GPU / Age），右侧实时显示选中进程的溯源摘要，按 `Enter` 进入全屏**进程详情页**（左 70% 详情 + 右 30% 环境变量，双面板独立滚动），底部快捷键提示，每 3 秒自动刷新。支持鼠标（滚轮滚动、点击标签/行/面板、双击打开详情）。带目标时用 `-i` 也能进 TUI 并直接定位到目标（`witr-rs -i --port 8080` 打开即落在 Ports 页的该端口上）。管道输出时自动退化为静态进程表（`--list` 可强制）。

**Events 事件页（TUI）**：以 3 秒采样记录进程的 出现 / 退出 / 重启 事件流（保留最近 500 条），`/` 可按 事件类型/PID/进程名/详情 过滤，选中事件按 `Enter` 直接跳到对应进程的详情页（已退出则提示）。配合采样历史实现 **崩溃重启检测**：同一进程身份换新 pid 即记一次重启，`Rst` 列显示总次数，5 分钟内 ≥2 次时详情页黄色告警。

**`--watch [秒]`**：常驻观察模式——带目标时每 N 秒重跑一次溯源管线并重绘（默认 2 秒），不带目标时刷新进程表；配合 `--recent`/`--json` 等原有选项工作，Ctrl-C 退出。

**对端归因（TUI 详情页）**：进程的每条 ESTABLISHED 连接会反查对端套接字的属主，在详情页显示 `talking to: 进程名 (pid N) — k 条连接`；对端不在本机时显示远端地址。

## TUI 按键

支持 vim 式浏览（与原版 witr 对齐）：

| 键 | 作用 |
|---|---|
| `j` `k` / `↑` `↓` | 移动选中行 |
| `g` `G` | 跳到第一行 / 最后一行 |
| `f` `b` `空格` / PgUp PgDn | 翻页 |
| `h` `l` / `←` `→` | 切换标签页 |
| `1`–`5` / Tab | 直接跳页 / 切换焦点（表格 ↔ 详情） |
| `/` | 搜索：Processes 页按 PID/用户名/进程名；Ports 页按端口号/PID/进程名/地址/协议/状态；Events 页按 事件类型/PID/进程名/详情（各页过滤器独立，Enter 应用，Esc 清除） |
| `Enter` | Processes 页：打开全屏进程详情页；Ports 页：端口详情页（该端口全部连接 + 归属进程）；Containers 页：容器详情页；Locks 页：跳到持锁进程的详情页；Events 页：跳到事件对应进程的详情页 |
| `p` `n` `u` `c` `m` `t` | Processes 页按 PID / 名称 / 用户 / CPU / 内存 / 启动时间排序，重复按切换升降序 |
| `p` `t` `n` `s` | Ports 页按 端口 / 协议 / 地址 / 状态 排序 |
| `i` `n` `r` `g` `s` | Containers 页按 ID / 名称 / 运行时 / 镜像 / 状态 排序 |
| `p` `n` `t` `m` `f` | Locks 页按 PID / 进程 / 类型 / 模式 / 路径 排序 |
| `t` `e` `p` `n` | Events 页按 时间 / 事件 / PID / 进程 排序（时间默认最新在前，重复按切换升降序） |
| `a` | Ports 页：切换 仅监听 ↔ 全部状态；Locks 页：切换 锁 ↔ 全部打开文件；Processes 页：打开操作栏（`k` kill / `t` term / `p` 暂停 / `r` 恢复 / `n` renice） |
| `z` | 缩放：聚焦面板临时占满整行（tmux 风格） |
| `x` | 杀掉选中进程（y/n 确认） |
| `r` | 立即刷新 |
| 详情页内 | `j/k` 滚动、`d/u` 半页、`g/G` 顶部/底部、`b/f` 翻页、`Tab` 切换面板、`a` 操作栏、`/` 搜索环境变量、`z` 缩放、`c` 复制当前面板、`Esc/q` 返回 |
| 鼠标 | 滚轮滚动列表 / 详情面板；点击标签页切换、点击行选中、点击面板聚焦；双击行打开详情 |
| `q` / `Esc` | 退出 |

选中进程的详情在光标停止移动 500ms 后自动刷新（防抖，按住 j 快速滚动不会连发查询），与原版 `selectionDebounce` 一致。

**端口详情页**：在 Ports 页选中某个端口按 `Enter`，可以看到该端口当前的全部 socket——LISTEN 监听项加上**正在发生的请求**（每条 ESTABLISHED 连接的对端地址、状态、归属 PID/进程，端口详情打开瞬间的快照），下方 Owner 面板显示监听进程的完整溯源（归因 + 祖先链 + 告警）。`Tab` 在 Connections / Owner 两个面板间切换焦点，`j/k/d/u/g/G/b-f` 滚动，`Esc` 返回列表。

**进程详情页**：左侧溯源面板（身份信息、Started by 归因、Ancestry Tree、Open Files、风险评分、告警），右侧环境变量面板；`c` 键把当前面板纯文本复制到剪贴板。

**风险评分**：每个进程聚合 0–10 分风险信号——临时目录下的二进制、运行中二进制被删除、`curl | sh` 类管道下载、LD_PRELOAD/DYLD 注入、对公网地址的 ESTABLISHED 连接。CLI 输出 `risk N/10: 信号列表`，TUI 详情页同样显示。

**崩溃重启检测**（TUI）：同一进程身份换新 pid 即记一次重启，`Rst` 列显示总次数，5 分钟内 ≥2 次时详情页黄色告警——crash loop 一眼可见（事件明细见 Events 页）。

**瞬时 CPU + Trend sparkline**（TUI）：按累计 CPU 时间的刷新间差值计算真实瞬时占用（非生命周期均值），表格 Trend 列以 8 级 sparkline 展示最近 8 次采样，`c` 排序键按瞬时值排序。

**二进制指纹**（`--export` / TUI 详情页）：对目标二进制计算 sha256 并给出代码签名结论（macOS `codesign`、Windows Authenticode；无效签名计入风险评分 +3）。Linux 无内核级签名体系，以哈希为准。

**GPU 列**（TUI，可选）：装有 NVIDIA 驱动的机器上通过 `nvidia-smi pmon` 显示每进程 SM 占用与显存（`37% 2.3G`），详情页显示完整数值；无 nvidia-smi 时该列自动隐藏，探测失败只发生一次不重复开销。

**K8s Pod 归因**（可选）：装有 `kubectl` 且集群可达时，容器会标注所属 Pod（`docker: mongo-demo-2 (id 6838b8ba3c49) · pod data/mongo-0`），TUI Containers 页出现 Pod 列。无 kubectl 时零开销跳过。

**容器健康**：Containers 页状态列着色（healthy/running 绿、unhealthy 红、restarting/starting 黄）；容器详情页与 `-c` 目标输出 `inspect` 的 RestartCount（>0 时标注 "restart policy fired"）。

**`--export`**：`witr-rs --pid <N> --export` 输出可直接贴进 issue 的纯文本排查报告（含环境变量值、打开文件列表、二进制 sha256 与签名结论）。

**Containers 页**：通过 PATH 上的运行时 CLI（docker / podman / nerdctl）枚举容器，显示 Runtime / ID / State / Status /（Pod）/ Image / Name，状态按健康度着色；`/` 按 名称/镜像/ID/运行时/状态 过滤，`i/n/r/g/s` 排序。枚举在后台线程执行（运行时 CLI 挂起不会卡住界面），每 3 秒自动刷新；刷新期间保留旧表格不闪烁，首次加载才显示 loading。**`Enter` 打开容器详情页**：左侧容器属性（Name/Runtime/ID/Image/State/Status/Ports/Restarts），右侧容器内进程列表（Linux 通过 cgroup 匹配；macOS/Windows 容器进程在 VM 内不可见，显示说明）。

**Locks 页**：文件锁 + 打开文件视图（Linux 读 `/proc/locks`，macOS 从 `lsof` 提取锁标志并辅以锁文件名启发式）；`a` 在 锁视图 ↔ 全部打开文件 之间切换（打开文件视图空搜索时截断显示前 100 行，搜索即放开），选中行按 `Enter` 直接跳到持锁进程的详情页。

**CLI 预置进 TUI（`-i`）**：`witr-rs -i --pid 1234` / `witr-rs -i nginx` / `witr-rs -i --port 8080` / `witr-rs -c web -i` / `witr-rs -i --file /var/log/x.log` — 打开 TUI 并直接落到对应标签页与过滤条件上（name 预填搜索词、pid 选中行、port/file/container 跳到对应页并预填过滤器）。每种类型取第一个目标，多余的会在状态栏提示；无终端时退出码 4。

## 平台支持

| 能力 | Linux | macOS | Windows |
|---|---|---|---|
| 进程表 | `/proc` 直读 | `ps` | ToolHelp32 快照 |
| cmdline / cwd / exe | `/proc/<pid>/*` | `ps` + `lsof` | PowerShell (Get-CimInstance) |
| 端口 → 进程 | `/proc/net/*` + fd inode 匹配 | `lsof -i` | `netstat -ano` |
| 文件 → 进程 | `/proc/*/fd` | `lsof` | ✓（Restart Manager API，无需 Sysinternals） |
| 文件锁（Locks 页） | `/proc/locks` + fdinfo | `lsof` 锁标志 + 锁文件名启发式 | ✗ |
| 服务归因 | systemd（`systemctl status`） | launchd（`launchctl list` + plist 探测） | SCM（`tasklist /svc`，识别 services.exe 后代） |
| 容器归因 | cgroup（docker/containerd/podman/lxc） | ✗ | ✗ |
| nohup/disown 检测 | ✓（`/proc/<pid>/status` SigIgn SIGHUP 位，计入告警） | ✗ | ✗ |
| 环境变量（`--env` / TUI 详情页） | ✓ `/proc/<pid>/environ`（同用户） | ✓ 同用户进程走 `ps -E`（其余受 SIP 限制，面板会提示） | ✗ |
| 启动时间 | btime + starttime | `ps etime` | CIM CreationDate |

跨平台可选增强（三端一致，缺依赖时静默跳过）：`nvidia-smi`（GPU 列）、`kubectl`（K8s Pod 归因）、`docker`/`podman`/`nerdctl`（Containers 页）。

依赖的外部命令：Linux 无强依赖（systemctl/docker 可选）；macOS 需要 `ps`/`lsof`（系统自带）；Windows 需要 `powershell`/`netstat`/`tasklist`（系统自带）。

## 安装

从 [GitHub Releases](https://github.com/yaowenqiang/witr-rs/releases) 下载对应平台的压缩包（含 sha256 校验文件），解开即用。打 `v*` 标签时 CI 会自动构建全部平台：

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
witr-rs -i --port 8080        # 进 TUI 并直接落到该端口（-i 预置，见上）
witr-rs nginx --pid 1         # 多目标混用（各目标间以分隔线输出）
NO_COLOR=1 witr-rs nginx      # 禁用着色（--no-color 同理）
```

### 退出码

| 码 | 含义 |
|---|---|
| 0 | 正常且无告警 |
| 1 | 找到了，但有告警（root 运行、监听所有网卡、二进制已删除、LD_PRELOAD 等） |
| 2 | 目标未找到 |
| 3 | 权限不足（如需要 root 的查询） |
| 4 | 参数无效 |
| 5 | 内部错误（如进程表不可读） |
| 6 | 找到了，但无法归因来源（Windows 上不出现——其祖先链常止于已退出进程） |

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
├── render.rs       standard / tree / short / json / env / warnings / export 渲染
├── history.rs      采样历史：瞬时 CPU、sparkline、重启检测、Events 事件流
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

## v0.4 已知限制

- TUI 的 Ports/Containers/详情页均为打开瞬间快照，`r` 手动刷新
- Windows 进程详情依赖 PowerShell 批量查询（每个目标一次调用，20s 超时保护）
- TUI 中 Windows 的 CPU% 列为空（tasklist 不提供）
- 容器归因目前仅 Linux（macOS 上 colima/Docker Desktop 的容器进程未归因，但 `-c` 目标有运行时侧兜底视图）
- Windows 有 `--file`（Restart Manager）但无 Locks 页数据
- macOS `launchctl list` 只覆盖当前用户域，系统域 daemon 需要 sudo 才能标注；文件锁来自 `lsof` 标志近似，内核未导出锁表
- nohup/disown 检测仅 Linux（macOS/Windows 无 `/proc`，TUI/CLI 不显示该告警）
- GPU 列只支持 NVIDIA（`nvidia-smi`）；Apple Silicon / AMD 显卡无每进程占用数据源

## 许可

Apache-2.0。设计参照 pranshuparmar/witr（同为 Apache-2.0）。

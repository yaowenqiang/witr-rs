# witr-rs

**Why is this running?** — 给出进程名、PID、端口或文件，一路追溯它是被谁、以何种方式拉起来的。

Rust 实现的 [pranshuparmar/witr](https://github.com/pranshuparmar/witr)（Go，Apache-2.0）同类工具，平台采集策略与其对齐。

**直接运行 `witr-rs`（无参数）进入交互式 TUI**，布局与原版一致：顶部四个标签页（1. Processes / 2. Ports / 3. Containers / 4. Locks），左侧进程表（PID / User / Name / CPU% / Mem / Started），右侧实时显示选中进程的溯源摘要，按 `Enter` 进入全屏**进程详情页**（左 70% 详情 + 右 30% 环境变量，双面板独立滚动），底部快捷键提示，每 3 秒自动刷新。管道输出时自动退化为静态进程表（`--list` 可强制）。

## TUI 按键

支持 vim 式浏览（与原版 witr 对齐）：

| 键 | 作用 |
|---|---|
| `j` `k` / `↑` `↓` | 移动选中行 |
| `g` `G` | 跳到第一行 / 最后一行 |
| `f` `b` `空格` / PgUp PgDn | 翻页 |
| `h` `l` / `←` `→` | 切换标签页 |
| `1`–`4` / Tab | 直接跳页 / 切换焦点（表格 ↔ 详情） |
| `/` | 搜索：Processes 页按 PID/用户名/进程名；Ports 页按端口号/PID/进程名/地址/协议/状态（两页过滤器独立，Enter 应用，Esc 清除） |
| `Enter` | Processes 页：打开全屏进程详情页（左侧详情 + 右侧环境变量）；Ports 页：打开端口详情页（该端口全部连接 + 归属进程） |
| `p` `n` `u` `c` `m` `t` | 按 PID / 名称 / 用户 / CPU / 内存 / 启动时间排序，重复按切换升降序 |
| `x` | 杀掉选中进程（y/n 确认） |
| `r` | 立即刷新 |
| 详情页内 | `j/k` 滚动、`d/u` 半页、`g/G` 顶部/底部、`b/f` 翻页、`Tab` 切换面板、`c` 复制当前面板、`Esc/q` 返回 |
| `q` / `Esc` | 退出 |

选中进程的详情在光标停止移动 500ms 后自动刷新（防抖，按住 j 快速滚动不会连发查询），与原版 `selectionDebounce` 一致。

**端口详情页**：在 Ports 页选中某个端口按 `Enter`，可以看到该端口当前的全部 socket——LISTEN 监听项加上**正在发生的请求**（每条 ESTABLISHED 连接的对端地址、状态、归属 PID/进程，端口详情打开瞬间的快照），下方 Owner 面板显示监听进程的完整溯源（归因 + 祖先链 + 告警）。`Tab` 在 Connections / Owner 两个面板间切换焦点，`j/k/d/u/g/G/b-f` 滚动，`Esc` 返回列表。

**进程详情页**：左侧溯源面板（身份信息、Started by 归因、Ancestry Tree、Open Files、风险评分、告警），右侧环境变量面板；`c` 键把当前面板纯文本复制到剪贴板。

**风险评分**：每个进程聚合 0–10 分风险信号——临时目录下的二进制、运行中二进制被删除、`curl | sh` 类管道下载、LD_PRELOAD/DYLD 注入、对公网地址的 ESTABLISHED 连接。CLI 输出 `risk N/10: 信号列表`，TUI 详情页同样显示。

**崩溃重启检测**（TUI）：同一进程身份换新 pid 即记一次重启，`Rst` 列显示总次数，5 分钟内 ≥2 次时详情页黄色告警——crash loop 一眼可见。

**瞬时 CPU + Trend sparkline**（TUI）：按累计 CPU 时间的刷新间差值计算真实瞬时占用（非生命周期均值），表格 Trend 列以 8 级 sparkline 展示最近 8 次采样，`c` 排序键按瞬时值排序。

**`--export`**：`witr-rs --pid <N> --export` 输出可直接贴进 issue 的纯文本排查报告（含环境变量值与打开文件列表）。

**Containers 页**：通过 PATH 上的运行时 CLI（docker / podman / nerdctl）枚举容器，显示 Runtime / ID / State / Status / Image / Name；`/` 按 名称/镜像/ID/运行时/状态 过滤。枚举在后台线程执行（运行时 CLI 挂起不会卡住界面），每 3 秒自动刷新；刷新期间保留旧表格不闪烁，首次加载才显示 loading。**`Enter` 打开容器详情页**：左侧容器属性（Name/Runtime/ID/Image/State/Status/Ports），右侧容器内进程列表（Linux 通过 cgroup 匹配；macOS/Windows 容器进程在 VM 内不可见，显示说明）。

## 平台支持

| 能力 | Linux | macOS | Windows |
|---|---|---|---|
| 进程表 | `/proc` 直读 | `ps` | ToolHelp32 快照 |
| cmdline / cwd / exe | `/proc/<pid>/*` | `ps` + `lsof` | PowerShell (Get-CimInstance) |
| 端口 → 进程 | `/proc/net/*` + fd inode 匹配 | `lsof -i` | `netstat -ano` |
| 文件 → 进程 | `/proc/*/fd` | `lsof` | ✗（需 Sysinternals handle.exe） |
| 服务归因 | systemd（`systemctl status`） | launchd（`launchctl list` + plist 探测） | SCM（`tasklist /svc`，识别 services.exe 后代） |
| 容器归因 | cgroup（docker/containerd/podman/lxc） | ✗ | ✗ |
| 环境变量（`--env` / TUI 详情页） | ✓ `/proc/<pid>/environ`（同用户） | ✓ 同用户进程走 `ps -E`（其余受 SIP 限制，面板会提示） | ✗ |
| 启动时间 | btime + starttime | `ps etime` | CIM CreationDate |

依赖的外部命令：Linux 无强依赖（systemctl/docker 可选）；macOS 需要 `ps`/`lsof`（系统自带）；Windows 需要 `powershell`/`netstat`/`tasklist`（系统自带）。

## 构建

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
witr-rs nginx --tree          # 祖先树 + 子进程
witr-rs nginx --short         # 单行输出（脚本友好）
witr-rs --port 8080 --json    # 机器可读 JSON
witr-rs nginx --env           # 顺带收集环境变量（仅 Linux）
witr-rs nginx --pid 1         # 多目标混用
```

### 退出码

| 码 | 含义 |
|---|---|
| 0 | 正常且无告警 |
| 1 | 找到了，但有告警（root 运行、监听所有网卡、二进制已删除、LD_PRELOAD 等） |
| 2 | 目标未找到 |
| 4 | 参数无效 |
| 5 | 内部错误（如进程表不可读） |

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
├── pipeline.rs     目标解析（name/pid/port/file → pid）、归因优先级、风险告警
├── tui.rs          交互界面（ratatui/crossterm）：四标签页 + 详情面板 + 3s 自动刷新
├── render.rs       standard / tree / short / json 四种渲染
├── util.rs         带超时的命令执行、时间格式化、用户名解析（带负缓存）、host:port 解析
└── platform/
    ├── mod.rs      Platform trait（唯一的平台接缝）
    ├── linux.rs    /proc 全家桶
    ├── macos.rs    ps / lsof / launchctl
    └── windows.rs  ToolHelp32 / PowerShell / netstat / tasklist
```

归因优先级：容器 > 服务管理器（systemd/launchd/SCM）> cron/tmux/screen/ssh > 交互 shell。Linux 的 service_source 返回 "init" 兜底时会被 pipeline 放弃，转而走通用归因。

## v0.2 已知限制

- Locks 页仅 Linux；TUI 的 Ports/Containers/详情页均为打开瞬间快照，`r` 手动刷新
- Windows 进程详情依赖 PowerShell 批量查询（每个目标一次调用，20s 超时保护）
- TUI 中 Windows 的 CPU% 列为空（tasklist 不提供）
- 容器归因目前仅 Linux（macOS 上 colima/Docker Desktop 的容器进程未归因）
- Windows 上 `--file` 返回 "不支持" 并计入告警
- macOS `launchctl list` 只覆盖当前用户域，系统域 daemon 需要 sudo 才能标注

## 许可

Apache-2.0。设计参照 pranshuparmar/witr（同为 Apache-2.0）。

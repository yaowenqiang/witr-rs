# Events 事件页实现原理

> 对应代码：`src/history.rs`（采样与事件生成）、`src/tui.rs`（`rebuild_event_view`、Events 按键、`push_history_lines`）。
> 引入于 commit `109bb08` — feat: v0.4.0。

## 1. 要解决的问题

进程表每 3 秒重画一次，但它是**无状态快照**：某一轮里少了一行，你不知道它是正常退出还是崩了；某个进程换了个 pid 重新出现，静态表格毫无感知。Events 页把相邻两轮快照的**差分**沉淀成事件流，回答三个问题：

- 谁刚出现（`started`）
- 谁刚消失（`exited`）
- 谁换了 pid 卷土重来（`restarted` —— 崩溃重启的直接证据）

## 2. 采样管线

```
TUI 主循环（每 3s，tui.rs REFRESH）
  └─ refresh()
       ├─ list_processes()          平台进程表
       ├─ gpu::enrich()             （可选）GPU 列
       └─ hist.update(&procs)       差分 → 事件 + 瞬时 CPU（见 §5）
            └─ Events 页停留时：rebuild_event_view() 重放过滤+排序
```

`hist.update` 在**每次**刷新都跑（不止 Events 页），因为崩溃重启告警、`Rst` 列、Trend sparkline 都依赖它持续累积。Events 页停留时只是多一步把新事件重放进当前视图。

## 3. 三种事件的判定

`History` 维护 `prev_seen: HashMap<Pid, 进程名>`（上一轮的非内核进程）。对每轮快照：

| 本轮状态 | prev_seen 查询 | 事件 |
|---|---|---|
| pid 在场 | 命中（上轮也在） | 无 |
| pid 在场 | 未命中，且该**身份**此前记过别的 pid | `restarted`，detail = `came back after exiting (N restarts total)` |
| pid 在场 | 未命中，首次见该身份 | `started` |
| pid 消失 | —— | `exited`（用 prev_seen 里留的名字） |

内核线程（`kernel_thread`）全程排除——它们成千上万且从不"退出"，只会制造噪声。

### pid 复用的盲区

如果 pid A 退出后 3 秒内被 pid A 复用（旧进程退、新进程生，同一轮差分里抵消），`prev_seen` 查询命中，**两条事件都不产生**——旧进程的退出被静默吞掉。这是 3 秒采样粒度的固有盲区，不是 bug；对崩溃重启检测无影响（身份变了，重启计数器不会误触发）。

## 4. 进程身份：重启检测的核心

判定"换了 pid 的同一个程序"不能看 pid（pid 正是变化的量），也不能直接存结构体做相等比较。实现用三元组哈希：

```rust
pub fn identity(p: &Process) -> u64 {      // util.rs（history/snapshot/--follow 共用）
    (p.name, basename(p.exe), p.user) hash  // DefaultHasher
}
```

选这三个字段的理由：

- **exe**：最能代表"同一个程序"——nginx 崩溃重启后路径不变；取 basename 是因为列表视图（ps comm 给 `sleep`）与详情视图（lsof 给 `/bin/sleep`）报的粒度不同，全路径哈希会让重启被误判成新程序
- **name**：exe 拿不到时（权限/已删除）的兜底
- **user**：区分"同一路径被不同用户各跑一份"——那不是重启，是两个实例

不进哈希的字段：cmdline（参数变化会打碎身份）、启动时间（每次重启都变）。`identity_of: HashMap<Pid, u64>` 记录"每个 pid 当前归属哪个身份"，是 `Rst` 列和详情页告警从 pid 反查重启状态的桥。`--diff` 的 restarted 判定与 `--follow` 的跨重启跟踪复用同一个函数。

`RestartState`（按身份存储）：

```rust
struct RestartState {
    last_pid: Pid,            // 该身份上一个 pid；0 = 首见，不算重启
    total: u32,               // TUI 启动以来总重启数 → Rst 列
    events: Vec<Instant>,     // 最近 5 分钟内的重启时刻 → 告警判定
    last_seen: Option<Instant>,
}
```

## 5. 与 CPU 采样器的耦合

同一次 `update` 顺带完成瞬时 CPU：相邻两轮 `cpu_time_ms` 的差 ÷ 墙钟时间差 × 100。工程细节：

- **首样本无输出**——只有一个累计值没有 delta，不能瞎猜
- **间隔 < 50ms 保留旧值**——两次采样贴太近时 delta 噪声放大
- **上限 400%**——多线程进程合法地超过 100%，但要封顶防止采样抖动产出荒谬值
- 每个 pid 保留最近 8 个样本 → 8 级 sparkline（`▁▂▃▄▅▆▇█`，按百分比映射）
- 同一套差分机制还喂三处：详情页 **CPU history 大图**（独立 120 样本窗口，按窗口峰值归一化并裁到面板宽度）、Linux 的**磁盘 I/O 速率**（`/proc/<pid>/io` 字节差分 ÷ 采样间隔，进程表 IO 列）、`--follow` 的身份重捕获

Events 页的 `Time` 列排序键 `at_unix` 与此无关——那是事件产生时的墙钟秒数，表格里显示为相对年龄（`23s`）。

## 6. 内存治理

采样器是常驻的，所有结构都有界：

| 结构 | 界 | 策略 |
|---|---|---|
| `events` | 500 条 | 新事件 `insert(0)` 置顶 + `truncate(500)`，旧事件自然淘汰 |
| `restarts[].events` | 5 分钟 | 每轮 `retain`，窗口外的时间戳剔除（告警窗口的滑动实现） |
| `restarts` 整体 | 10 分钟未现身即删 | `PRUNE_AFTER`——一个身份消失 10 分钟后，它的重启历史不再保留 |
| `cpu_now` / `sparks` / `samples` / `cpu_prev` / `identity_of` | 进程在场 | 每轮 `retain(seen)`，消失即清 |

## 7. TUI 集成

**视图是索引不是拷贝**：`event_view: Vec<usize>` 存的是 `hist.events` 的下标，过滤（`/` 按 事件类型/PID/进程名/详情 子串，Enter 应用、Esc 清除）和排序（`t/e/p/n`，同列再按翻转升降）都只重排这个下标数组。事件环本身永远保持最新在前。

排序默认值：`Time` 降序（与事件环原生顺序一致，切到页即所见即所得）；切到其它列时升序起步。

选中事件按 `Enter` → 取该行 pid → 打开对应进程详情页；进程已退出时状态栏提示而不是静默失败。

**崩溃重启告警**（`push_history_lines`，详情页两块面板共用）：

- 5 分钟内 ≥2 次重启 → 黄色 `⚠ restarted N× in the last 5 min`
- 累计 ≥2 次 → 灰色 `total N restarts since TUI start`
- 进程表 `Rst` 列显示 `total`，无需进详情页就能看到崩溃循环

**崩溃的下一步是看日志**：详情页与 Events 页按 `l` 拉取该进程最近的日志（`src/logs.rs`），全屏 Logs 页滚动查看。来源选择：容器归因（cgroup source 的 runtime+label，或 `-c` 目标的身份行里的真实 id）→ `docker/podman/nerdctl logs`；否则 Linux `journalctl _PID=<pid>`、macOS `log show --predicate 'process == "name"'`（过滤掉 "Filtering…" 前导行后取尾部 N 行）。工程细节：日志获取在后台线程（`log show` 要 2–10 秒），结果经 mpsc 回主循环（与容器枚举同款模式）；journalctl 无匹配时以退出码 1 退出，按"无日志"处理而非报错；macOS 的进程名会过滤掉引号/反斜杠再拼进 predicate。

## 8. 持久化与回放

采样器随 TUI 生灭是 §8 说的边界之一，`--events-log` / `--replay` 把它打破：

- **记录**：`witr-rs --events-log events.jsonl` 时，`History::update` 返回本轮新生成的事件（方法签名从 `()` 改为 `Vec<TuiEvent>`，调用方不关心可忽略），TUI 把每条 `serde_json` 序列化后追加写入文件（单写者——事件循环线程，无需加锁）。
- **回放**：`--replay events.jsonl` 读文件（每行一条，坏行跳过），`load_events_log` 把追加序（旧→新）反转为环的原生顺序（新→旧）注入 `hist.events`，TUI 直接落在 Events 页；实时采样继续叠加，旧事件保留原始 `at_unix`（时间列显示为大年龄）。需要终端，无 tty 退出码 4。
- **粒度代价**：记录覆盖 TUI 打开期间；TUI 没跑的时候的事件无法补录——长周期观测需要外部保活（如 tmux 常驻）。

## 9. 设计边界

- **只覆盖 TUI 打开期间**——采样器随 TUI 生灭，CLI/`--watch` 模式不产生事件；TUI 启动瞬间已在跑的进程只产生一条 `started`（没有"之前"可差分）
- **3 秒粒度**——快于 3 秒的生灭不可见（§3 盲区）；需要更细粒度得改 `REFRESH`，代价是差分误报率上升
- **重启 ≠ 崩溃**——supervisor 拉活（systemd/docker/pm2 的 respawn）和真实崩溃后手动重跑长得一样；工具只报告事实（换 pid 回来了），归因留给使用者
- 哈希碰撞理论上会合并两个身份（64 位空间，实际可忽略）

## 10. 测试锚点

`src/history.rs`：`restart_detection`（换 pid 计数、不同身份隔离）、`events_feed_start_exit_restart`（三种事件的顺序与 detail、500 上限）、`cpu_delta_sampling`（首样本无值、delta 计算）、`cpu_chart_builds_and_thins`（大图需两个 delta、按宽度裁剪）、`io_rate_sampling`（首样本无值、速率计算、消失即清）、`vanished_processes_are_pruned`、`events_update_returns_fresh_and_round_trips`（update 返回新事件、JSONL 往返）。
`src/tui.rs`：`events_tab_filter_and_selection`（过滤与光标隔离）、`events_tab_sort_keys`（四列排序 + 降序翻转）。
`src/logs.rs`：`container_identity_parses`、`tail_keeps_last_n_and_skips_blank`、`predicate_is_sanitized` 等纯函数测试。

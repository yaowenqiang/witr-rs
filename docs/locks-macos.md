# macOS Locks 实现原理

> 对应代码：`src/platform/macos.rs`（`list_locks` 及其解析函数）、`src/platform/linux.rs`（对照实现）。
> 引入于 commit `32dd56b` — feat(tui): working Locks panel on macOS, resolved paths on Linux。

## 1. 根本问题：macOS 没有锁表

Linux 内核把所有文件锁导出在 `/proc/locks`，读一个文件就能拿到全系统锁的持有者、类型、模式。**macOS 没有任何等价接口**——内核不向用户态导出锁清单。

实测验证（用 Python 分别持有 `flock(2)` 锁和 POSIX `fcntl` 锁后观察 lsof）：

```
Python  87803  501  3w  REG  1,14  0  154117320 /tmp/witr_lock_test.lock
```

即使进程真的持有排它锁，lsof 的 FD 列也只显示 `3w`（**访问模式**），没有任何锁标志。所以 macOS 上"真实锁检测"这条路在 lsof 层面基本走不通。

## 2. Go witr 的做法（作为对照）

- **详情页**：纯粹启发式——跑 `lsof -p <pid>`，把路径长得像锁文件的（`.lock` / `.pid` 结尾、含 `/lock`）当作锁展示。
- **TUI Locks 面板**：看 FD 列**最后一个字符**——`W`→WRITE、`R`→READ、`u`→RW。

Go 的做法有个明显误报：普通未加锁的 fd 在 lsof 里是 `5u`（5 号 fd，读写模式），最后一个字符恰好是 `u`——按它的逻辑每个进程打开的每个普通文件都会被报成 "RW 锁"（一台普通机器上有几千行这样的 fd）。

## 3. witr-rs 的实现

一次 `lsof -l -n -P -w` 扫描（详情页用 `-p PID`，快得多），解析每行 9 列：

```
COMMAND   PID  USER  FD   TYPE  DEVICE  SIZE/OFF  NODE  NAME
openclaw  5314  501  15w  REG   1,14    0         123   /Users/.../gateway.eabed588.lock
```

### 原理 A：FD 列的语法是 `[数字][访问模式][锁标志?]`

lsof(8) 规定锁标志是**追加在访问模式之后**的：`3uW` = 3 号 fd、读写模式、整文件写锁；`5u` = 只是读写模式、没锁。所以按**位置**判断——只有含 2 个以上尾部字母的 FD 才带锁：

| FD | 尾部字母数 | 判定 |
|----|-----------|------|
| `5u` | 1 | 未加锁（Go 会误判为 RW）|
| `3uW` | 2 | WRITE 整文件锁 |
| `10uw` | 2 | WRITE 区域锁 |
| `5ur` / `5uR` | 2 | READ 锁 |
| `txt` / `cwd` / `KQUEUE` | 特殊名 | 排除 |

### 原理 B：锁文件名启发式

补上 macOS 检测不到真实锁的缺口：守护进程的通用模式是「打开锁文件 → flock → 长期持有 fd」，所以 `REG` 类型且路径以 `.lock` / `.pid` 结尾或含 `/lock` 的文件，几乎必然是锁工件。例如 openclaw 网关的 `gateway.eabed588.lock`（实测 pid 5314 的 node 正确命中）。

### 工程细节

- lsof 扫到没权限的进程会**非零退出但 stdout 仍有有效数据**，所以不走 `util::run`（它把非零退出当失败），直接 `Command::output()` 抢救 stdout。
- 同一锁文件被多个 fd 持有会重复出现，按 `(pid, path)` 去重。
- 全量扫描 1-2 秒，只在**切到 Locks tab 时**执行一次；周期刷新只在 Linux 做（`/proc/locks` 读取几乎零成本），避免 UI 卡顿。

## 4. Linux 侧（对照）

`/proc/locks` 每行：`1: FLOCK ADVISORY WRITE 4242 00:1f:12345 0 EOF`。

- kind/mode/pid 直接取列；`设备:inode` 通过扫持有者的 `/proc/<pid>/fd/*`（readlink + stat 取 inode）反查出真实路径——内核在该文件里用的设备号格式与用户态 stat 不一致，所以只按 inode 匹配（跨文件系统撞 inode 概率可忽略）。
- owner 显示 `/proc/<pid>/comm`（持有者进程名）。
- fd 表按 pid 缓存，一次扫描内多个锁共享。

## 5. 对照总结

| | Go witr | witr-rs |
|---|---------|---------|
| 真实锁标志 | 尾字符判断（大量误报）| 位置判断（无误报）|
| 锁文件启发式 | `.lock`/`.pid`/`/lock` | 相同 |
| Linux | /proc/locks + inode 反查路径 | 相同（fd 表扫描 + comm 进程名）|

效果：Locks 面板在 macOS 显示真实有意义的锁文件（Spotlight、iTerm2、skhd、openclaw……实测约 19 条），而不是 Go 那样几千条噪声，也不是早期的"仅 Linux 支持"占位符。

# HeapQuickScan

**English** | [中文](#中文)

---

## English

Fast JVM heap dump (.hprof) triage CLI — class histograms and the identity of the biggest objects in **seconds**, on dumps of any size, with a tiny memory footprint and zero dependencies.

### Why

[Eclipse MAT](https://eclipse.dev/mat/) is the reference tool for heap analysis, but every question — even a plain histogram — requires a full index build first: minutes of CPU, tens of GB of RAM, and gigabytes of index files on disk. HeapQuickScan answers the first-line triage questions ("what is eating the heap? which objects exactly?") in a single streaming pass, and hands you object IDs you can feed straight into MAT for the deep questions.

### What it does

| Command | Output |
|---------|--------|
| `top-classes` | Classes (incl. array types) ranked by shallow size or instance count |
| `top-arrays` | The largest individual arrays: size, length, type, **object ID** |
| `threads` | Every thread with its name and Java stack, from the dump itself |
| `paths <objectId>` | Shortest reference path from an object to its GC root, with owning thread + stack |
| `summary` | Heap totals + top classes + top arrays |

### Feature comparison with MAT

What both tools do, and what only MAT does:

| Capability | HeapQuickScan | MAT |
|------------|:---:|:---:|
| Class histogram (instance counts + shallow size) | ✅ in one streaming pass | ✅ after full index build |
| Largest individual arrays with object IDs | ✅ | ✅ (via OQL / sorted views) |
| Count *all* objects in the dump, incl. unreachable (like `jmap -histo`) | ✅ default | opt-in flag (discards garbage by default) |
| Compressed / uncompressed oops handling | ✅ auto-detected | ✅ |
| Works on any dump size with bounded memory | ✅ ~256 MB regardless of dump size | needs RAM ≈ dump size for smooth indexing |
| No disk writes (read-only, no indexes) | ✅ | ❌ writes ~dump-size index files |
| Zero dependencies, single source file, Java 8+ | ✅ | ❌ full Eclipse RCP application |
| Retained sizes / dominator tree | ❌ | ✅ |
| Automatic leak suspects (attribution to threads/classloaders) | ❌ | ✅ |
| Path to GC roots / referrer chains | ❌ (prints object IDs to look up in MAT) | ✅ |
| OQL queries | ❌ | ✅ |
| Inspect object fields, string contents, collections | ❌ | ✅ |
| Thread stacks from the dump | ❌ | ✅ |
| Duplicate classes / classloader analysis | ❌ | ✅ |
| GUI with drill-down | ❌ CLI only | ✅ |
| Fast repeated queries (indexed snapshot) | ❌ rescan each run | ✅ |
| Other formats (IBM dumps, ...) | ❌ hprof only | ✅ via extensions |

### Our advantages

Measured on the same machine, same 12.7 GB production dump (176M objects):

| | HeapQuickScan | MAT 1.16 |
|---|---|---|
| Time to first histogram | **~31 s** (428 MB/s) | ~7 min (index + overview report) |
| Full analysis suite | 31 s (it only has one mode) | ~18.5 min (leak suspects, top components) |
| Peak memory | **~256 MB** (`-Xmx256m`) | ~26 GB |
| Disk written | **0 bytes** | ~13 GB indexes |

In short:

- **Speed** — one linear pass; time is bounded by disk read, not by object count or analysis depth
- **Memory** — bounded state (per-class counters + a capped top-4096 array pool), independent of dump size
- **Footprint** — one ~700-line file, `javac` and go; runs anywhere Java 8+ runs, including small containers and jump boxes
- **Exact where it counts** — instance counts match `jmap -histo` and MAT byte-for-byte; shallow sizes match MAT within fractions of a percent
- **Bridges into MAT** — the object IDs from `top-arrays` can be resolved in MAT headless via `path2gc 0x...`, so the slow tool starts exactly at the interesting object

Recommended workflow: run HeapQuickScan first for triage, then open the dump in MAT only if you need retained sizes or root paths.

### Usage

```bash
javac src/HeapQuickScan.java -d target/

java -cp target HeapQuickScan top-classes /path/to/dump.hprof          # top 20 by shallow size
java -cp target HeapQuickScan top-classes /path/to/dump.hprof -n 50 --sort count
java -cp target HeapQuickScan top-arrays  /path/to/dump.hprof -n 30    # biggest arrays + object IDs
java -cp target HeapQuickScan summary    /path/to/dump.hprof
java -cp target HeapQuickScan --uncompressed-oops summary /path/to/dump.hprof  # override oops detection

# Thread attribution (Java tool only)
java -cp target HeapQuickScan threads /path/to/dump.hprof
java -cp target HeapQuickScan paths /path/to/dump.hprof 0x7d1800000

# Fastest: build the first-referrer index during one pass (--parents), then
# attribute ANY number of objects instantly. Needs heap ~ 40 bytes per heap
# object (e.g. -Xmx20g for a 229M-object dump); on smaller heaps drop the flag
# and paths falls back to per-object BFS (no extra memory, 1-6 min each).
java -Xmx20g -cp target HeapQuickScan paths --parents /path/to/dump.hprof 0x631719d20 0x7d1800000
```

`paths` walks inbound references level by level (one file pass per level, whole
query typically 1-6 min on a 15 GB dump under `-Xmx1g`) and reproduces MAT's
"path to GC roots + owning thread + stack" for a specific object without any
index. Example from a 15.5 GB production dump (leaked xlsx export):

```
ROOT: object @631719d20  [GC root: Java stack frame, thread "Jetty-Worker-69", frame 11]
  └─ "table" → object @63171c350
    └─ TARGET: object @7d1800000
Owning thread: "Jetty-Worker-9170-Thread-69" (frame 11)
  at org.apache.poi.xssf.model.SharedStringsTable.addEntry (SharedStringsTable.java:202)
  at org.apache.poi.xssf.usermodel.XSSFCell.setCellValueImpl (XSSFCell.java:427)
  at com.example.utils.ExportExcelWrapper.exportExcel2007 (ExportExcelWrapper.java:160)
```

### Verified accuracy

Cross-checked against `jmap -histo` and Eclipse MAT 1.16:

- Instance counts match `jmap -histo` exactly (byte[] 408,114; String 407,507; HashMap$Node 200,996; ...)
- With MAT in keep-unreachable-objects mode (same semantics), counts **and** shallow bytes match per class exactly (e.g. String 9,780,168 bytes in all three tools)
- Object IDs verified in MAT via `path2gc`: `byte[67108864] @ 0x415000000` → shallow heap 67,108,880 in both tools
- 12.7 GB production dump / 176M objects: MAT (live set) total 8,414,241,392 bytes vs HeapQuickScan (all objects) within 0.2%
- Oops auto-detection verified on JDK 8 and JDK 17 compressed dumps and a `-XX:-UseCompressedOops` dump

### How it works

1. Streams the hprof binary format sequentially (8 MB read buffer); parses only CLASS DUMP, INSTANCE DUMP, OBJECT ARRAY DUMP and PRIMITIVE ARRAY DUMP records; skips GC-root records by their fixed sizes
2. Resolves class names from STRING + LOAD_CLASS records
3. Reconstructs real shallow sizes: the hprof `instanceSize` field is the field sum with references at `idSize` bytes and no header/alignment; references are re-counted at 4 bytes (compressed oops) and 8-byte aligned
4. Auto-detects the reference width from java.lang.String address spacing: two same-class objects can never overlap, and the minimal String is 24 bytes compressed / 32 uncompressed, so a gap of exactly 24 can only occur under compressed oops and exactly 32 only under uncompressed — an unambiguous physical tell
5. Keeps only bounded state: per-class counters, per-array-type aggregates and a capped pool of the 4096 largest individual arrays

Note: the dump file is always larger than the sum of shallow sizes — each instance record carries ~25 bytes of header and references are stored at 8 bytes even when the heap used 4.

### Limitations

- Shallow size only — no retained sizes, no reachability analysis (that is exactly what MAT's index buys)
- Classes with 8-byte-aligned fields (long/double mixed with references) can be under-estimated by up to 8 bytes/instance (~3% observed for such classes)
- `top-arrays` tracks at most 4096 individual arrays; `-n` above that is capped
- hprof only; gzipped dumps must be gunzipped first
- 32-bit dumps (idSize 4) are parsed but were not tested against a real 32-bit JVM

### Testing

`test/BigObjectDemo.java` allocates large objects with known sizes, prints its PID and sleeps:

```bash
javac test/BigObjectDemo.java -d /tmp/t && java -cp /tmp/t BigObjectDemo &
jmap -dump:all,format=b,file=/tmp/demo.hprof <pid>
java -cp target HeapQuickScan summary /tmp/demo.hprof   # every fixture object should appear with expected size
```

## License

MIT

---

## 中文

快速 JVM 堆转储（.hprof）分诊命令行工具——在**数秒内**给出类直方图和最大对象的身份，支持任意大小的 dump，内存占用极小，零依赖。

### 为什么需要它

[Eclipse MAT](https://eclipse.dev/mat/) 是堆分析的标准工具，但任何问题——哪怕只是看一眼直方图——都必须先完成完整索引：多 GB 的 dump 需要数分钟 CPU、几十 GB 内存和大量索引文件。HeapQuickScan 用单遍流式扫描直接回答第一层分诊问题（"堆被什么吃掉了？具体是哪些对象？"），并输出对象 ID，可以无缝交给 MAT 做深度分析。

### 功能

| 命令 | 输出 |
|------|------|
| `top-classes` | 类（含数组类型）按浅层大小或实例数排序 |
| `top-arrays` | 最大的单个数组：大小、长度、类型、**对象 ID** |
| `summary` | 堆总量概览 + 以上两者 |

### 与 MAT 的功能对比

两者都能做的、以及只有 MAT 能做的：

| 能力 | HeapQuickScan | MAT |
|------|:---:|:---:|
| 类直方图（实例数 + 浅层大小） | ✅ 单遍流式扫描 | ✅ 需先建完整索引 |
| 最大单个数组及对象 ID | ✅ | ✅（通过 OQL / 排序视图） |
| 统计 dump 内全部对象（含不可达，同 `jmap -histo`） | ✅ 默认 | 需加参数（默认剔除垃圾对象） |
| 压缩 / 非压缩指针处理 | ✅ 自动检测 | ✅ |
| 任意大小 dump、内存占用有界 | ✅ 恒定 ~256 MB，与 dump 大小无关 | 索引建议内存 ≈ dump 大小 |
| 不写磁盘（只读、无索引文件） | ✅ | ❌ 写入约等于 dump 大小的索引 |
| 零依赖、单源文件、Java 8+ | ✅ | ❌ 完整 Eclipse RCP 应用 |
| 保留大小 / 支配树 | ❌ | ✅ |
| 自动泄漏嫌疑分析（归因到线程/类加载器） | ❌ | ✅ |
| GC 根路径 / 引用链 | ❌（输出对象 ID 供 MAT 查询） | ✅ |
| OQL 查询 | ❌ | ✅ |
| 查看对象字段、字符串内容、集合详情 | ❌ | ✅ |
| dump 中的线程栈 | ❌ | ✅ |
| 重复类 / 类加载器分析 | ❌ | ✅ |
| 图形界面下钻 | ❌ 仅命令行 | ✅ |
| 索引后快速重复查询 | ❌ 每次重新扫描 | ✅ |
| 其他格式（IBM dump 等） | ❌ 仅 hprof | ✅ 通过扩展支持 |

### 我们的优势

同一台机器、同一个 12.7 GB 生产 dump（1.76 亿对象）实测：

| | HeapQuickScan | MAT 1.16 |
|---|---|---|
| 出第一份直方图耗时 | **约 31 秒**（428 MB/s） | 约 7 分钟（索引 + overview 报告） |
| 完整分析套件 | 31 秒（它只有这一种模式） | 约 18.5 分钟（泄漏嫌疑、Top Components） |
| 峰值内存 | **约 256 MB**（`-Xmx256m`） | 约 26 GB |
| 磁盘写入 | **0 字节** | 约 13 GB 索引 |

总结：

- **快** — 单次线性扫描，耗时只受磁盘读取限制，与对象数量和分析深度无关
- **省内存** — 状态有界（每类计数器 + 上限 4096 的大数组池），与 dump 大小无关
- **轻** — 一个约 700 行的源文件，`javac` 即用；Java 8+ 的任何环境都能跑，包括小容器和跳板机
- **该准的地方分毫不差** — 实例数与 `jmap -histo`、MAT 完全一致；浅层大小与 MAT 偏差在千分之几以内
- **与 MAT 无缝衔接** — `top-arrays` 输出的对象 ID 可在 MAT 无界面模式下用 `path2gc 0x...` 直接解析，让重型工具从最关键的对象开始

推荐工作流：先用 HeapQuickScan 分诊；只在需要保留大小或 GC 根路径时再打开 MAT。

### 用法

```bash
javac src/HeapQuickScan.java -d target/

java -cp target HeapQuickScan top-classes /path/to/dump.hprof          # 浅层大小 Top 20
java -cp target HeapQuickScan top-classes /path/to/dump.hprof -n 50 --sort count
java -cp target HeapQuickScan top-arrays  /path/to/dump.hprof -n 30    # 最大数组 + 对象 ID
java -cp target HeapQuickScan summary    /path/to/dump.hprof
java -cp target HeapQuickScan --uncompressed-oops summary /path/to/dump.hprof  # 手动覆盖指针模式检测
```

### 准确性验证

与 `jmap -histo` 和 Eclipse MAT 1.16 交叉验证：

- 实例数与 `jmap -histo` 完全一致（byte[] 408,114；String 407,507；HashMap$Node 200,996……）
- MAT 以保留不可达对象模式运行（与本工具口径一致）时，各类的实例数**和**浅层字节数完全一致（如 String 三个工具均为 9,780,168 字节）
- 对象 ID 经 MAT `path2gc` 验证：`byte[67108864] @ 0x415000000`，两工具浅层大小均为 67,108,880
- 12.7 GB 生产 dump / 1.76 亿对象：MAT（存活集）总量 8,414,241,392 字节，HeapQuickScan（全量）偏差 0.2% 以内
- 指针模式自动检测在 JDK 8、JDK 17 压缩指针 dump 及 `-XX:-UseCompressedOops` dump 上验证通过

### 工作原理

1. 顺序流式读取 hprof 二进制格式（8 MB 读缓冲）；只解析 CLASS DUMP、INSTANCE DUMP、OBJECT ARRAY DUMP、PRIMITIVE ARRAY DUMP 四种记录；GC 根记录按固定长度跳过
2. 从 STRING + LOAD_CLASS 记录解析类名
3. 重建真实浅层大小：hprof 的 `instanceSize` 字段是字段总和（引用按 `idSize` 字节计、无对象头、无对齐）；本工具将引用重按 4 字节（压缩指针）计算并做 8 字节对齐
4. 通过 java.lang.String 实例地址间距自动检测引用宽度：同类对象在地址上不可能重叠，而 String 最小为 24 字节（压缩）/ 32 字节（非压缩），因此相邻 String 间距恰好为 24 只可能是压缩指针、恰好为 32 只可能是非压缩——物理上无歧义
5. 只保存有界状态：每类计数器、每种数组类型的聚合值、以及上限 4096 的最大单个数组池

说明：dump 文件总是大于浅层大小之和——每条实例记录自带约 25 字节记录头，且引用即使堆内只占 4 字节，文件里也按 8 字节存储。

### 局限

- 只有浅层大小——没有保留大小和可达性分析（这正是 MAT 索引所买来的能力）
- 含 8 字节对齐字段（long/double 与引用混排）的类每实例最多低估 8 字节（此类类观测偏差约 3%）
- `top-arrays` 最多追踪 4096 个单个数组，`-n` 超过该值会被截断
- 仅支持 hprof；gzip 压缩的 dump 需先解压
- 32 位 dump（idSize 4）可解析，但未在真实 32 位 JVM 上验证

### 测试

`test/BigObjectDemo.java` 分配已知大小的大对象、打印 PID 后休眠：

```bash
javac test/BigObjectDemo.java -d /tmp/t && java -cp /tmp/t BigObjectDemo &
jmap -dump:all,format=b,file=/tmp/demo.hprof <pid>
java -cp target HeapQuickScan summary /tmp/demo.hprof   # 每个测试对象都应以预期大小出现
```

## 许可证

MIT

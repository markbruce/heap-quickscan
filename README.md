# HeapQuickScan

Fast JVM heap dump (.hprof) analyzer CLI.

MAT (Memory Analyzer Tool) takes minutes to index a multi-GB heap dump before you can see any results. HeapQuickScan gets you answers in **seconds** by scanning only the records that matter.

## Features

| Command | What it does | Speed |
|---------|-------------|-------|
| `top-classes` | Classes ranked by instance count + shallow size | Seconds |
| `top-arrays` | Arrays ranked by total byte size | Seconds |
| `summary` | Combined overview | Seconds |

## How it works

Instead of loading the entire heap into memory, HeapQuickScan:

1. Reads the hprof binary format **sequentially**
2. Only processes 4 record types: CLASS DUMP (0x2C), INSTANCE DUMP (0x33), PRIMITIVE ARRAY (0x36), OBJECT ARRAY (0x37)
3. Skips everything else in a single `skip()` call
4. Maintains only lightweight HashMaps in memory

This means a 13GB dump file takes ~1-3 minutes (disk I/O bound), vs 10-30 minutes for MAT indexing.

## Requirements

- Java 8+
- Zero external dependencies

## Usage

```bash
# Compile
javac src/HeapQuickScan.java -d target/

# Top 20 classes by instance count
java -cp target HeapQuickScan top-classes /path/to/dump.hprof

# Top 50 arrays by size
java -cp target HeapQuickScan top-arrays /path/to/dump.hprof -n 50

# Full summary
java -cp target HeapQuickScan summary /path/to/dump.hprof
```

### Example Output

```
=== Top 20 Classes by Instance Count ===

Count        Shallow Size      Avg Size Class Name
---------- ------------ -------------- ----------
      1258432       82.4 MB           65 byte[]
       893421      234.7 MB          263 java.lang.String
       423191       12.1 MB           28 java.util.concurrent.ConcurrentHashMap$Node
       ...
---------- ------------ -------------- ----------
     3842193        1.2 GB               TOTAL (15431 unique classes)
```

## Limitations

- **Shallow size only** — Does not compute retained size (that requires building the full object reference graph, which is what makes MAT slow)
- **No leak analysis** — For that, use MAT after HeapQuickScan narrows down the suspect classes
- **No GUI** — CLI only

## Build

```bash
mkdir -p target
javac src/HeapQuickScan.java -d target/
```

## License

MIT

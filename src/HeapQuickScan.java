import java.io.*;
import java.util.*;

/**
 * HeapQuickScan - Fast JVM heap dump (.hprof) analyzer
 *
 * Reads the hprof binary format sequentially and reports:
 *   - Classes (and array types) ranked by instance count / shallow size
 *   - The largest individual arrays with their object IDs
 *
 * hprof layout reference (top-level records):
 *   0x01 STRING, 0x02 LOAD_CLASS, 0x0C/0x1C HEAP_DUMP(_SEGMENT), 0x2B HEAP_DUMP_END
 * Heap-dump sub-records (inside 0x0C / 0x1C):
 *   0x01..0x08, 0xFF  GC roots
 *   0x20 CLASS_DUMP, 0x21 INSTANCE_DUMP,
 *   0x22 OBJECT_ARRAY_DUMP, 0x23 PRIMITIVE_ARRAY_DUMP
 *
 * Usage: java HeapQuickScan <command> <file.hprof> [options]
 *   Commands:
 *     top-classes  - List classes by shallow size (or instance count)
 *     top-arrays   - List the largest individual arrays
 *     summary      - Overview (totals + top classes + top arrays)
 *   Options:
 *     -n <num>        - Number of entries to show (default: 20)
 *     --sort <mode>   - top-classes sort key: bytes (default) or count
 *     -h              - Show help
 *
 * Java 8+ compatible, zero dependencies.
 */
public class HeapQuickScan {

    // ---- top-level record tags ----
    static final int TAG_STRING            = 0x01;
    static final int TAG_LOAD_CLASS        = 0x02;
    static final int TAG_UNLOAD_CLASS      = 0x03;
    static final int TAG_FRAME             = 0x04;
    static final int TAG_TRACE             = 0x05;
    static final int TAG_ALLOC_SITES       = 0x06;
    static final int TAG_HEAP_SUMMARY      = 0x07;
    static final int TAG_START_THREAD      = 0x0A;
    static final int TAG_END_THREAD        = 0x0B;
    static final int TAG_HEAP_DUMP         = 0x0C;
    static final int TAG_HEAP_DUMP_SEGMENT = 0x1C;
    static final int TAG_HEAP_DUMP_END     = 0x2B;

    // ---- heap-dump sub-record tags ----
    static final int TAG_GC_ROOT_UNKNOWN      = 0xFF;
    static final int TAG_GC_ROOT_JNI_GLOBAL   = 0x01;
    static final int TAG_GC_ROOT_JNI_LOCAL    = 0x02;
    static final int TAG_GC_ROOT_JAVA_FRAME   = 0x03;
    static final int TAG_GC_ROOT_NATIVE_STACK = 0x04;
    static final int TAG_GC_ROOT_STICKY_CLASS = 0x05;
    static final int TAG_GC_ROOT_THREAD_BLOCK = 0x06;
    static final int TAG_GC_ROOT_MONITOR_USED = 0x07;
    static final int TAG_GC_ROOT_THREAD_OBJ   = 0x08;
    static final int TAG_CLASS_DUMP           = 0x20;
    static final int TAG_INSTANCE_DUMP        = 0x21;
    static final int TAG_OBJECT_ARRAY_DUMP    = 0x22;
    static final int TAG_PRIMITIVE_ARRAY_DUMP = 0x23;

    // hprof primitive type codes -> element size in bytes
    // 4=boolean, 5=char, 6=float, 7=double, 8=byte, 9=short, 10=int, 11=long
    static final int[] PRIM_SIZE = new int[256];
    static final String[] PRIM_NAME = new String[256];
    static {
        PRIM_SIZE[4] = 1;  PRIM_NAME[4] = "boolean";
        PRIM_SIZE[5] = 2;  PRIM_NAME[5] = "char";
        PRIM_SIZE[6] = 4;  PRIM_NAME[6] = "float";
        PRIM_SIZE[7] = 8;  PRIM_NAME[7] = "double";
        PRIM_SIZE[8] = 1;  PRIM_NAME[8] = "byte";
        PRIM_SIZE[9] = 2;  PRIM_NAME[9] = "short";
        PRIM_SIZE[10] = 4; PRIM_NAME[10] = "int";
        PRIM_SIZE[11] = 8; PRIM_NAME[11] = "long";
    }

    // Cap on individual arrays tracked for `top-arrays` (bounded memory; the
    // exact -n value is not known until after the scan, so keep a fixed pool).
    static final int MAX_TRACKED_ARRAYS = 4096;

    int idSize;               // 4 or 8
    CountingInputStream counting;
    DataInputStream in;
    long fileSize;
    String fileName;
    String version;

    /** Single source of truth for the absolute file offset of the read cursor. */
    long pos() { return counting == null ? 0 : counting.count; }

    /** Filter stream that tracks how many bytes have been consumed. */
    static class CountingInputStream extends FilterInputStream {
        long count;
        CountingInputStream(InputStream in) { super(in); }
        public int read() throws IOException {
            int r = super.read();
            if (r >= 0) count++;
            return r;
        }
        public int read(byte[] b, int off, int len) throws IOException {
            int r = super.read(b, off, len);
            if (r > 0) count += r;
            return r;
        }
        public long skip(long n) throws IOException {
            long s = super.skip(n);
            count += s;
            return s;
        }
    }

    // ---- scan results ----
    final Map<Long, String> stringTable = new HashMap<Long, String>();
    final Map<Long, Long> classNameStrId = new HashMap<Long, Long>();   // classId -> string id of class name

    /**
     * Per-class metadata from CLASS_DUMP records.
     *
     * The hprof instanceSize field is the sum of ALL instance fields (declared
     * plus inherited), with references counted at idSize bytes, WITHOUT the
     * object header and WITHOUT alignment. E.g. java.lang.String dumps as 14
     * (ref 8 + int 4 + byte 1 + boolean 1) but occupies 24 bytes on heap.
     * Real shallow size is reconstructed at report time by walking the class
     * hierarchy to re-count references at 4 bytes (compressed oops).
     */
    static class ClassInfo {
        long superId;
        int instanceSize;
        int ownRefFields;          // instance fields of type 'object' declared here
        long[] fieldNames;         // own instance field name string ids (declaration order)
        byte[] fieldTypes;         // own instance field hprof type codes
    }
    final Map<Long, ClassInfo> classInfos = new HashMap<Long, ClassInfo>();
    final Map<Long, Integer> shallowPerInstance = new HashMap<Long, Integer>(); // resolved lazily
    final Map<Long, Long> classCounts = new HashMap<Long, Long>();      // classId -> instance count

    // ---- GC root / thread attribution (bounded) ----
    static final int MAX_ROOTS = 2_000_000;
    static final int MAX_FRAMES = 200_000;
    static final int MAX_TRACES = 200_000;

    /** A GC root: sub-record tag plus its auxiliary u4s. */
    static class Root {
        final int tag;
        final long a, b;           // THREAD_OBJ: threadSeq, stackSeq; JNI_LOCAL/JAVA_FRAME: threadSeq, frameNum
        Root(int tag, long a, long b) { this.tag = tag; this.a = a; this.b = b; }
    }
    final Map<Long, Root> roots = new HashMap<Long, Root>();       // objectId -> root info
    final Map<Integer, Long> serialToClass = new HashMap<Integer, Long>(); // LOAD_CLASS serial -> classId
    final Map<Long, long[]> frames = new HashMap<Long, long[]>();  // frameId -> {nameId, sigId, fileId, classSerial, lineNo}
    final Map<Integer, long[]> traces = new HashMap<Integer, long[]>(); // traceSerial -> frame ids
    final Map<Integer, Integer> traceToThreadSerial = new HashMap<Integer, Integer>();
    final Map<Integer, Integer> threadSerialToTrace = new HashMap<Integer, Integer>();
    final List<Long> threadObjIds = new ArrayList<Long>();         // THREAD_OBJ-rooted object ids
    long threadClassId = -1;
    int oopsStringVotesCompressed, oopsStringVotesUncompressed;

    // ---- first-referrer index ("who points at me"), optional ----
    // Open-addressing long->long map: object id -> first referrer seen in file
    // order. Thread-sourced edges take priority so paths lead to threads.
    // Enabled with --parents; needs heap ~= 22 bytes per heap object.
    ParentIndex parents;
    boolean parentsDegraded;

    // ---- reference extraction during the main scan (parent capture) ----
    private final Map<Long, List<long[]>> mainRefOffsetCache = new HashMap<Long, List<long[]>>();
    private byte[] payloadBuf = new byte[65536];

    static class ParentIndex {
        // 16 B/slot: key (8) + value (8, bit63 = thread-sourced edge flag).
        // Object addresses use <= 47 significant bits, so bit63 is free.
        static final long THREAD_FLAG = Long.MIN_VALUE;
        long[] keys;               // 0 = empty slot (null refs never stored)
        long[] vals;
        int cap;
        long size;
        long maxSlots;
        boolean degraded;

        ParentIndex(long maxSlots) {
            this.maxSlots = maxSlots;
            cap = 1 << 16;
            keys = new long[cap];
            vals = new long[cap];
        }

        /** First referrer wins; a thread-sourced referrer replaces a plain one. */
        void put(long k, long v, boolean threadSrcEdge) {
            if (k == 0) return;
            if (size >= cap * 3L / 4L) {
                if (!grow()) { degraded = true; return; }
            }
            int i = index(k);
            while (keys[i] != 0) {
                if (keys[i] == k) {
                    if (threadSrcEdge) vals[i] |= THREAD_FLAG;
                    return;                        // keep first referrer
                }
                i = (i + 1) % cap;
            }
            if (degraded) return;                  // table full: stop inserting
            keys[i] = k;
            vals[i] = threadSrcEdge ? (v | THREAD_FLAG) : v;
            size++;
        }

        long get(long k) {
            int i = index(k);
            while (keys[i] != 0) {
                if (keys[i] == k) return vals[i] & Long.MAX_VALUE;
                i = (i + 1) % cap;
            }
            return -1;
        }

        boolean isThreadEdge(long k) {
            int i = index(k);
            while (keys[i] != 0) {
                if (keys[i] == k) return (vals[i] & THREAD_FLAG) != 0;
                i = (i + 1) % cap;
            }
            return false;
        }

        private int index(long k) {
            long h = k * 0x9E3779B97F4A7C15L;
            return (int) Long.remainderUnsigned(h, cap);
        }

        /** x1.5 growth (non-power-of-two capacity works with modulo) halves the rehash memory peak. */
        private boolean grow() {
            long newCap = cap + Math.max(cap / 2, 65536);
            if (newCap > maxSlots) return false;
            long[] ok = keys;
            long[] ov = vals;
            try {
                keys = new long[(int) newCap];
                vals = new long[(int) newCap];
                cap = (int) newCap;
                for (int i = 0; i < ok.length; i++) {
                    if (ok[i] == 0) continue;
                    int j = index(ok[i]);
                    while (keys[j] != 0) j = (j + 1) % cap;
                    keys[j] = ok[i];
                    vals[j] = ov[i];
                }
                return true;
            } catch (OutOfMemoryError e) {
                keys = ok;                 // keep serving existing entries;
                vals = ov;                 // paths falls back to BFS for misses
                cap = ok.length;
                degraded = true;
                return false;
            }
        }
    }

    // array type display name -> {count, totalBytes}
    final Map<String, long[]> arrayStats = new HashMap<String, long[]>();

    static class ArrayEntry {
        final long size;
        final long length;
        final long objectId;
        final String type;
        ArrayEntry(long size, long length, long objectId, String type) {
            this.size = size; this.length = length; this.objectId = objectId; this.type = type;
        }
    }
    // min-heap of the largest individual arrays, capped at MAX_TRACKED_ARRAYS
    final PriorityQueue<ArrayEntry> topArrays =
            new PriorityQueue<ArrayEntry>(64, new Comparator<ArrayEntry>() {
                public int compare(ArrayEntry a, ArrayEntry b) { return Long.compare(a.size, b.size); }
            });

    /**
     * Reference width assumption for 64-bit dumps. The hprof format does not
     * record whether the JVM used compressed oops, but it changes shallow
     * sizes: compressed = 12-byte header + 4-byte refs (JVM default below
     * 32 GB heaps); full = 16-byte header + 8-byte refs. Auto-detected after
     * the scan from String instance address spacing (see detectOopsMode);
     * --uncompressed-oops overrides the detection.
     */
    boolean uncompressedOops = false;
    boolean oopsAutoDetected;

    // String-address samples for reference-width detection (bounded).
    static final int OOPS_SAMPLE_CAP = 200_000;
    long stringClassId = -1;
    long[] stringSample = new long[4096];
    int stringSampleCount;

    public static void main(String[] args) {
        String command = null;
        String filePath = null;
        String objectIdArg = null;
        int topN = 20;
        String sort = "bytes";
        boolean forceUncompressed = false;

        for (int i = 0; i < args.length; i++) {
            String a = args[i];
            if ("-h".equals(a) || "--help".equals(a)) {
                printUsage();
                return;
            } else if ("-n".equals(a)) {
                if (i + 1 >= args.length) { fail("Missing value for -n"); return; }
                topN = Integer.parseInt(args[++i]);
                if (topN <= 0) { fail("-n must be positive"); return; }
            } else if ("--sort".equals(a)) {
                if (i + 1 >= args.length) { fail("Missing value for --sort"); return; }
                sort = args[++i];
                if (!sort.equals("bytes") && !sort.equals("count")) {
                    fail("--sort must be 'bytes' or 'count'"); return;
                }
            } else if ("--uncompressed-oops".equals(a)) {
                // parsed into the scanner below
            } else if ("--parents".equals(a)) {
                // parsed into the scanner below
            } else if (a.startsWith("-")) {
                fail("Unknown option: " + a);
                return;
            } else if (command == null) {
                command = a;
            } else if (filePath == null) {
                filePath = a;
            } else if (objectIdArg == null) {
                objectIdArg = a;
            } else {
                fail("Unexpected argument: " + a);
                return;
            }
        }

        if (command == null || filePath == null) {
            printUsage();
            return;
        }
        boolean needsObject = command.equals("paths");
        boolean wantsParents = false;
        for (String a : args) if ("--parents".equals(a)) wantsParents = true;
        if (!command.equals("top-classes") && !command.equals("top-arrays") && !command.equals("summary")
                && !command.equals("threads") && !needsObject) {
            fail("Unknown command: " + command);
            return;
        }
        if (needsObject && objectIdArg == null) {
            fail("paths requires an object id, e.g. paths dump.hprof 0x415000000");
            return;
        }

        HeapQuickScan scanner = new HeapQuickScan();
        boolean forceUncompressedF = false;
        for (String a : args) {
            if ("--uncompressed-oops".equals(a)) { scanner.uncompressedOops = true; forceUncompressedF = true; }
        }
        if (wantsParents || (needsObject && Runtime.getRuntime().maxMemory() >= 3L * 1024 * 1024 * 1024)) {
            long maxSlots = Math.min(1L << 30, Runtime.getRuntime().maxMemory() / 30L);
            scanner.parents = new ParentIndex(maxSlots);
        }
        try {
            scanner.scan(filePath);
        } catch (IOException e) {
            fail("Failed to parse " + filePath + " at offset " + scanner.pos() + ": " + e.getMessage());
            return;
        }
        if (!forceUncompressedF) scanner.detectOopsMode();

        File dumpFile = new File(filePath);
        if (command.equals("threads") || needsObject) {
            try {
                System.err.println("Resolving thread names...");
                scanner.resolveThreadNames(dumpFile, scanner.threadNames);
            } catch (IOException e) {
                System.err.println("Thread name resolution failed: " + e.getMessage());
                e.printStackTrace();
            }
        }
        if (command.equals("threads")) {
            scanner.reportThreads(topN);
        } else if (needsObject) {
            List<Long> targets = new ArrayList<Long>();
            for (String tok : objectIdArg.split("[,\\s]+")) {
                String t = tok.toLowerCase();
                if (t.isEmpty()) continue;
                targets.add(t.startsWith("0x") ? Long.parseLong(t.substring(2), 16) : Long.parseLong(t));
            }
            try {
                scanner.reportPaths(dumpFile, targets, 30);
            } catch (IOException e) {
                fail("Path search failed: " + e.getMessage());
            }
        } else {
            scanner.report(command, topN, sort);
        }
    }

    static void fail(String msg) {
        System.err.println("Error: " + msg);
        System.err.println("Run with -h for usage.");
        System.exit(1);
    }

    static void printUsage() {
        System.out.println("HeapQuickScan - Fast JVM heap dump analyzer");
        System.out.println();
        System.out.println("Usage: java HeapQuickScan <command> <file.hprof> [options]");
        System.out.println();
        System.out.println("Commands:");
        System.out.println("  summary            Overview: totals + top classes + top arrays");
        System.out.println("  top-classes        Classes by shallow size (or instance count)");
        System.out.println("  top-arrays         Largest individual arrays (with object IDs)");
        System.out.println("  threads            Thread list with names and Java stacks");
        System.out.println("  paths <objectId>   Shortest reference path from an object to its GC root,");
        System.out.println("                     with thread attribution (e.g. paths dump.hprof 0x415000000)");
        System.out.println();
        System.out.println("Options:");
        System.out.println("  -n <num>      Number of entries to show (default: 20)");
        System.out.println("  --sort <mode> top-classes sort key: bytes (default) or count");
        System.out.println("  --uncompressed-oops  Assume -XX:-UseCompressedOops (8-byte refs,");
        System.out.println("                16-byte headers) when estimating 64-bit dump sizes");
        System.out.println("  -h            Show this help");
    }

    // ======================================================================
    // Parsing
    // ======================================================================

    void scan(String path) throws IOException {
        File file = new File(path);
        if (!file.isFile()) {
            throw new IOException("No such file: " + path);
        }
        this.fileName = file.getName();
        this.fileSize = file.length();

        System.err.println("Scanning " + path + " (" + formatSize(fileSize) + ")...");

        long startTime = System.currentTimeMillis();
        counting = new CountingInputStream(new BufferedInputStream(new FileInputStream(file), 8 * 1024 * 1024));
        in = new DataInputStream(counting);
        try {
            readHeader();

            long lastProgress = 0;
            while (pos() < fileSize) {
                int tag = in.readUnsignedByte();
                in.readInt();       // micro-seconds since dump start (unused)
                long length = in.readInt() & 0xFFFFFFFFL;

                if (length > fileSize - pos()) {
                    throw new IOException(String.format(
                            "Record tag 0x%02X declares %d bytes but only %d remain - truncated dump?",
                            tag, length, fileSize - pos()));
                }

                switch (tag) {
                    case TAG_STRING:
                        readStringRecord((int) length);
                        break;
                    case TAG_LOAD_CLASS:
                        readLoadClassRecord();
                        break;
                    case TAG_FRAME:
                        readFrameRecord();
                        break;
                    case TAG_TRACE:
                        readTraceRecord();
                        break;
                    case TAG_HEAP_DUMP:
                    case TAG_HEAP_DUMP_SEGMENT:
                        parseHeapSegment(length);
                        break;
                    default:
                        skipFully(length);
                        break;
                }

                if (pos() - lastProgress >= 512L * 1024 * 1024) {
                    lastProgress = pos();
                    System.err.printf("  %s / %s scanned...%n", formatSize(pos()), formatSize(fileSize));
                }
            }
        } finally {
            in.close();
        }

        long elapsed = System.currentTimeMillis() - startTime;
        System.err.printf("Scan complete in %.1fs (%.0f MB/s)%n",
                elapsed / 1000.0, fileSize / 1024.0 / 1024.0 / Math.max(elapsed / 1000.0, 0.001));
    }

    void readHeader() throws IOException {
        // Header: NUL-terminated version string (e.g. "JAVA PROFILE 1.0.2\0"), u4 idSize, u8 timestamp.
        ByteArrayOutputStream buf = new ByteArrayOutputStream(24);
        int b;
        while ((b = in.read()) != 0) {
            if (b < 0) throw new IOException("Unexpected EOF in header");
            buf.write(b);
        }
        version = new String(buf.toByteArray(), "ASCII");
        if (!version.startsWith("JAVA PROFILE")) {
            String shown = version.length() > 48 ? version.substring(0, 48) + "..." : version;
            throw new IOException("Not a valid hprof file (version string: \"" + shown + "\")");
        }

        idSize = in.readInt();
        long timestamp = in.readLong();
        if (idSize != 4 && idSize != 8) {
            throw new IOException("Unsupported identifier size: " + idSize);
        }
        System.err.println("Format: " + version + ", ID size: " + idSize
                + " bytes, dumped at " + new Date(timestamp));
    }

    void readStringRecord(int length) throws IOException {
        long id = readId();
        byte[] data = new byte[length - idSize];
        in.readFully(data);
        stringTable.put(id, new String(data, "UTF-8"));
    }

    void readLoadClassRecord() throws IOException {
        int classSerial = in.readInt();        // class serial number (frame references use it)
        long classId = readId();
        in.readInt();                          // stack trace serial number (unused)
        long strId = readId();
        classNameStrId.put(classId, strId);
        serialToClass.put(classSerial, classId);
        if (threadClassId == -1 && "java/lang/Thread".equals(stringTable.get(strId))) {
            threadClassId = classId;
        }
        // Names are resolved lazily at report time: STRING records may appear
        // after LOAD_CLASS records in some dumps. The String class id is needed
        // during the scan itself (for oops detection), so resolve it eagerly
        // when the name is already known.
        if (stringClassId == -1 && "java/lang/String".equals(stringTable.get(strId))) {
            stringClassId = classId;
        }
    }

    void parseHeapSegment(long length) throws IOException {
        long segStart = pos();
        long segEnd = segStart + length;

        final boolean dbg = System.getenv("HQS_DEBUG") != null;
        while (pos() < segEnd) {
            int tag = in.readUnsignedByte();
            if (dbg) System.err.println("MAIN @"+pos()+" 0x"+Integer.toHexString(tag));

            switch (tag) {
                case TAG_GC_ROOT_UNKNOWN:
                case TAG_GC_ROOT_STICKY_CLASS:
                case TAG_GC_ROOT_MONITOR_USED:
                    recordRoot(readId(), tag, 0, 0);
                    break;
                case TAG_GC_ROOT_JNI_GLOBAL:
                    recordRoot(readId(), tag, 0, readId());
                    break;
                case TAG_GC_ROOT_JNI_LOCAL:
                case TAG_GC_ROOT_JAVA_FRAME:
                case TAG_GC_ROOT_THREAD_OBJ: {
                    long objId = readId();
                    long a = in.readInt() & 0xFFFFFFFFL;
                    long b = in.readInt() & 0xFFFFFFFFL;
                    recordRoot(objId, tag, a, b);
                    if (tag == TAG_GC_ROOT_THREAD_OBJ) {
                        threadObjIds.add(objId);
                        if (threadSeqToObj.size() < MAX_ROOTS) {
                            threadSeqToObj.put(a, objId);
                        }
                    }
                    break;
                }
                case TAG_GC_ROOT_NATIVE_STACK:
                case TAG_GC_ROOT_THREAD_BLOCK:
                    recordRoot(readId(), tag, in.readInt() & 0xFFFFFFFFL, 0);
                    break;
                case TAG_CLASS_DUMP:
                    parseClassDump();
                    break;
                case TAG_INSTANCE_DUMP:
                    parseInstanceDump();
                    break;
                case TAG_OBJECT_ARRAY_DUMP:
                    parseObjectArrayDump();
                    break;
                case TAG_PRIMITIVE_ARRAY_DUMP:
                    parsePrimitiveArrayDump();
                    break;
                default:
                    throw new IOException(String.format(
                            "Unknown heap-dump sub-record tag 0x%02X at offset %d (segment started at %d)",
                            tag, pos() - 1, segStart));
            }
        }
        if (pos() != segEnd) {
            throw new IOException(String.format(
                    "Heap segment over-run: sub-records ended at %d but segment ends at %d", pos(), segEnd));
        }
    }

    void parseClassDump() throws IOException {
        long classId = readId();
        in.readInt();              // stack trace serial number
        long superId = readId();
        readId();                  // class loader object ID
        readId();                  // signers object ID
        readId();                  // protection domain object ID
        readId();                  // reserved
        readId();                  // reserved
        int instanceSize = in.readInt();

        // Constant pool: u2 count, then per entry: u2 index, u1 type, value.
        int cpCount = in.readUnsignedShort();
        for (int i = 0; i < cpCount; i++) {
            in.readUnsignedShort(); // constant pool index
            skipValue(in.readUnsignedByte());
        }

        // Static fields: u2 count, then per entry: id name, u1 type, value.
        int staticCount = in.readUnsignedShort();
        for (int i = 0; i < staticCount; i++) {
            readId();               // field name string ID
            int vt = in.readUnsignedByte();
            if (parents != null && vt == 2) {
                long dst = readId();
                if (dst != 0 && dst != classId) putParent(dst, classId, 0);
            } else {
                skipValue(vt);
            }
        }

        // Instance fields: u2 count, then per entry: id name, u1 type.
        // (Values live in each INSTANCE_DUMP record.)
        int fieldCount = in.readUnsignedShort();
        long[] fieldNames = new long[fieldCount];
        byte[] fieldTypes = new byte[fieldCount];
        int ownRefs = 0;
        for (int i = 0; i < fieldCount; i++) {
            fieldNames[i] = readId();
            byte t = in.readByte();
            fieldTypes[i] = t;
            if (t == 2) ownRefs++;
        }

        ClassInfo info = new ClassInfo();
        info.superId = superId;
        info.instanceSize = instanceSize;
        info.ownRefFields = ownRefs;
        info.fieldNames = fieldNames;
        info.fieldTypes = fieldTypes;
        classInfos.put(classId, info);
    }

    /** Memoized ref-field byte offsets (and labels) for instances of a class. */
    private void mainRefOffsets(long classId, int base, List<long[]> offs, List<String> labels) {
        if (classId == 0 || offs.size() > 4096) return;
        ClassInfo ci = classInfos.get(classId);
        if (ci == null) return;
        int off = 0;
        for (int i = 0; i < ci.fieldTypes.length; i++) {
            if (ci.fieldTypes[i] == 2) {
                offs.add(new long[]{off});
                String n = stringTable.get(ci.fieldNames[i]);
                labels.add(n == null ? "?" : n);
            }
            off += ci.fieldTypes[i] == 2 ? idSize : PRIM_SIZE[ci.fieldTypes[i]];
        }
        mainRefOffsets(ci.superId, off, offs, labels);
    }

    private List<long[]> mainRefOffsets(long classId) {
        List<long[]> offs = mainRefOffsetCache.get(classId);
        if (offs == null) {
            offs = new ArrayList<long[]>();
            List<String> labels = new ArrayList<String>();
            mainRefOffsets(classId, 0, offs, labels);
            mainRefOffsetCache.put(classId, offs);
        }
        return offs;
    }

    private final Map<Long, Boolean> threadClassCache = new HashMap<Long, Boolean>();

    private boolean isThreadClass(long classId) {
        if (classId == 0 || threadClassId == -1) return false;
        Boolean b = threadClassCache.get(classId);
        if (b != null) return b;
        boolean r = classId == threadClassId || isThreadClass(classInfos.get(classId) == null ? 0 : classInfos.get(classId).superId);
        threadClassCache.put(classId, r);
        return r;
    }

    private void in2ReadFully(int n) throws IOException {
        in.readFully(payloadBuf, 0, n);
    }

    private void skipFullyOnMain(long bytes) throws IOException {
        skipFully(bytes);
    }

    private void putParent(long dst, long src, long srcClassId) {
        parents.put(dst, src, isThreadClass(srcClassId));
    }

    void recordRoot(long objId, int tag, long a, long b) {
        if (roots.size() < MAX_ROOTS) {
            roots.put(objId, new Root(tag, a, b));
        }
    }

    void parseInstanceDump() throws IOException {
        long objId = readId();
        in.readInt();              // stack trace serial number
        long classId = readId();
        int valueBytes = in.readInt(); // number of instance-field bytes that follow
        if (parents != null) {
            if (valueBytes > payloadBuf.length) {
                payloadBuf = new byte[Math.max(valueBytes, payloadBuf.length * 2)];
            }
            in.readFully(payloadBuf, 0, valueBytes);
            List<long[]> offs = mainRefOffsets(classId);
            for (int i = 0; i < offs.size(); i++) {
                long dst = idFromBytes(payloadBuf, (int) offs.get(i)[0]);
                if (dst != 0 && dst != objId) putParent(dst, objId, classId);
            }
        } else {
            skipFully(valueBytes);
        }

        if (classId == stringClassId && stringSampleCount < OOPS_SAMPLE_CAP) {
            if (stringSampleCount == stringSample.length) {
                stringSample = Arrays.copyOf(stringSample, Math.min(stringSample.length * 2, OOPS_SAMPLE_CAP));
            }
            stringSample[stringSampleCount++] = objId;
        }

        Long count = classCounts.get(classId);
        classCounts.put(classId, count == null ? 1L : count + 1);
    }

    void parseObjectArrayDump() throws IOException {
        long arrayId = readId();
        in.readInt();              // stack trace serial number
        long n = in.readInt() & 0xFFFFFFFFL; // number of elements
        long arrayClassId = readId();
        if (parents != null && n > 0) {
            long bytes = n * idSize;
            if (bytes > payloadBuf.length) {
                payloadBuf = new byte[(int) Math.min(bytes, Math.max(payloadBuf.length * 2, 1 << 26))];
            }
            int take = (int) Math.min(bytes, payloadBuf.length);
            in2ReadFully(take);
            long takeN = take / idSize;
            for (long i = 0; i < takeN; i++) {
                long dst = idFromBytes(payloadBuf, (int) (i * idSize));
                if (dst != 0 && dst != arrayId) parents.put(dst, arrayId, false);
            }
            skipFullyOnMain(bytes - take);
        } else {
            skipFully(n * idSize);     // element IDs
        }

        recordArray(prettyClassName(className(arrayClassId, "object[]")),
                n, shallowArraySize(n, objectRefWidth()), arrayId);
    }

    void parsePrimitiveArrayDump() throws IOException {
        long arrayId = readId();
        in.readInt();              // stack trace serial number
        long n = in.readInt() & 0xFFFFFFFFL; // number of elements
        int elemType = in.readUnsignedByte();
        int elemSize = PRIM_SIZE[elemType];
        if (elemSize == 0) {
            throw new IOException(String.format(
                    "Invalid primitive array element type 0x%02X at offset %d", elemType, pos() - 1));
        }
        skipFully(n * elemSize);

        recordArray(PRIM_NAME[elemType] + "[]", n, shallowArraySize(n, elemSize), arrayId);
    }

    void recordArray(String typeName, long length, long size, long arrayId) {        long[] stats = arrayStats.get(typeName);
        if (stats == null) {
            stats = new long[2];
            arrayStats.put(typeName, stats);
        }
        stats[0]++;
        stats[1] += size;

        if (topArrays.size() < MAX_TRACKED_ARRAYS) {
            topArrays.offer(new ArrayEntry(size, length, arrayId, typeName));
        } else if (topArrays.peek().size < size) {
            topArrays.poll();
            topArrays.offer(new ArrayEntry(size, length, arrayId, typeName));
        }
    }

    /** In-heap width of an object reference under the current assumptions. */
    int objectRefWidth() {
        return (idSize == 8 && !uncompressedOops) ? 4 : idSize;
    }

    /** Shallow size estimate for an array: header + payload, 8-byte aligned. */
    long shallowArraySize(long n, int elemSize) {
        long header = idSize == 4 ? 8 : 16; // 32-bit: mark+klass; 64-bit: mark+klass(+length)
        long size = header + n * elemSize;
        return (size + 7) & ~7L;
    }

    /**
     * Skips a value of the given hprof type code (2=object ref, 4..11 primitives).
     * Used for constant-pool and static field values, whose types vary.
     */
    void skipValue(int type) throws IOException {
        switch (type) {
            case 2:  skipFully(idSize); break; // object reference
            case 4: case 8:  skipFully(1); break; // boolean, byte
            case 5: case 9:  skipFully(2); break; // char, short
            case 6: case 10: skipFully(4); break; // float, int
            case 7: case 11: skipFully(8); break; // double, long
            default:
                throw new IOException("Unknown field type code: " + type);
        }
    }

    // ---- low-level readers ----

    long readId() throws IOException {
        if (idSize == 8) {
            return in.readLong();
        }
        return in.readInt() & 0xFFFFFFFFL;
    }

    void skipFully(long bytes) throws IOException {
        if (bytes <= 0) return;
        while (bytes > 0) {
            long skipped = in.skip(bytes);
            if (skipped > 0) {
                bytes -= skipped;
            } else if (in.read() != -1) {
                bytes--; // skip() refused but a byte was consumed via read()
            } else {
                throw new EOFException("Unexpected EOF at offset " + pos());
            }
        }
    }

    // ======================================================================
    // Thread / stack / reference-path attribution
    // ======================================================================

    /** HPROF_FRAME: id frameId, id methodName, id methodSig, id srcFile, u4 classSerial, u4 lineNo. */
    void readFrameRecord() throws IOException {
        long frameId = readId();
        long nameId = readId();
        long sigId = readId();
        long fileId = readId();
        long classSerial = in.readInt() & 0xFFFFFFFFL;
        long lineNo = in.readInt() & 0xFFFFFFFFL;
        if (frames.size() < MAX_FRAMES) {
            frames.put(frameId, new long[]{nameId, sigId, fileId, classSerial, lineNo});
        }
    }

    /** HPROF_TRACE: u4 serial, u4 threadSerial, u4 frameCount, id frameId * frameCount. */
    void readTraceRecord() throws IOException {
        int serial = in.readInt();
        int threadSerial = in.readInt();
        int n = in.readInt();
        if (n < 0 || n > 65536) {
            skipFully(n * (long) idSize);
            return;
        }
        long[] fr = new long[n];
        for (int i = 0; i < n; i++) {
            fr[i] = readId();
        }
        if (traces.size() < MAX_TRACES) {
            traces.put(serial, fr);
            traceToThreadSerial.put(serial, threadSerial);
            if (threadSerialToTrace.size() < MAX_TRACES) {
                threadSerialToTrace.put(threadSerial, serial);
            }
        }
    }

    /** Renders a stack trace serial to lines (class.method(file:line)). */
    List<String> renderStack(int traceSerial, int maxFrames) {
        List<String> out = new ArrayList<String>();
        long[] fr = traces.get(traceSerial);
        if (fr == null) return out;
        for (int i = 0; i < fr.length && out.size() < maxFrames; i++) {
            long[] f = frames.get(fr[i]);
            if (f == null) continue;
            String cls = signatureToDisplayName(className(
                    serialToClass.get((int) f[3]) == null ? -1 : serialToClass.get((int) f[3]),
                    "?"));
            String method = stringTable.get(f[0]);
            String file = stringTable.get(f[2]);
            long line = f[4];
            String lineStr = line == 0 ? "" : (line > 0x80000000L ? " (native)" : " ("
                    + (file == null ? "?" : file) + ":" + (line & 0x7FFFFFFFL) + ")");
            out.add("at " + cls + "." + method + lineStr);
        }
        return out;
    }

    /** Locates the string id for a literal name by scanning the string table once. */
    Long nameStringId(String literal) {
        for (Map.Entry<Long, String> e : stringTable.entrySet()) {
            if (literal.equals(e.getValue())) return e.getKey();
        }
        return null;
    }

    /** Offset of a named own instance field within instance value bytes (Thread/Object have no superclass fields). */
    int ownFieldOffset(long classId, long fieldNameId) {
        ClassInfo ci = classInfos.get(classId);
        if (ci == null) return -1;
        int off = 0;
        for (int i = 0; i < ci.fieldTypes.length; i++) {
            if (ci.fieldNames[i] == fieldNameId) return off;
            off += ci.fieldTypes[i] == 2 ? idSize : PRIM_SIZE[ci.fieldTypes[i]];
        }
        return -1;
    }

    /** One targeted pass: capture raw instance value bytes for the wanted object ids. */
    void captureInstances(File file, Set<Long> wanted, Map<Long, byte[]> out) throws IOException {
        if (wanted.isEmpty()) return;
        long remaining = wanted.size();
        CountingInputStream counting = new CountingInputStream(
                new BufferedInputStream(new FileInputStream(file), 8 * 1024 * 1024));
        DataInputStream in2 = new DataInputStream(counting);
        try {
            readHeaderOn(in2);
            while (counting.count < fileSize && remaining > 0) {
                int tag = in2.readUnsignedByte();
                in2.readInt();
                long length = in2.readInt() & 0xFFFFFFFFL;
                if (tag == TAG_HEAP_DUMP || tag == TAG_HEAP_DUMP_SEGMENT) {
                    long segEnd = counting.count + length;
                    while (counting.count < segEnd && remaining > 0) {
                        int st = in2.readUnsignedByte();
                        if (st == TAG_INSTANCE_DUMP) {
                            long objId = readIdOn(in2);
                            in2.readInt();
                            long classId = readIdOn(in2);
                            int n = in2.readInt();
                            if (wanted.contains(objId) && !out.containsKey(objId)) {
                                byte[] buf = new byte[n];
                                in2.readFully(buf);
                                out.put(objId, buf);
                                remaining--;
                            } else {
                                skipFullyOn(in2, n);
                            }
                        } else {
                            skipSubRecordOn(in2, counting, st);
                        }
                    }
                } else {
                    skipFullyOn(in2, length);
                }
            }
        } finally {
            in2.close();
        }
    }

    /** One targeted pass: capture the first elements of wanted primitive arrays as strings. */
    void capturePrimArrays(File file, Set<Long> wanted, Map<Long, String> out, int maxElems) throws IOException {
        if (wanted.isEmpty()) return;
        long remaining = wanted.size();
        CountingInputStream counting = new CountingInputStream(
                new BufferedInputStream(new FileInputStream(file), 8 * 1024 * 1024));
        DataInputStream in2 = new DataInputStream(counting);
        try {
            readHeaderOn(in2);
            while (counting.count < fileSize && remaining > 0) {
                int tag = in2.readUnsignedByte();
                in2.readInt();
                long length = in2.readInt() & 0xFFFFFFFFL;
                if (tag == TAG_HEAP_DUMP || tag == TAG_HEAP_DUMP_SEGMENT) {
                    long segEnd = counting.count + length;
                    while (counting.count < segEnd && remaining > 0) {
                        int st = in2.readUnsignedByte();
                        if (st == TAG_PRIMITIVE_ARRAY_DUMP) {
                            long objId = readIdOn(in2);
                            in2.readInt();
                            long n = in2.readInt() & 0xFFFFFFFFL;
                            int etype = in2.readUnsignedByte();
                            int es = PRIM_SIZE[etype];
                            if (wanted.contains(objId) && !out.containsKey(objId)) {
                                int take = (int) Math.min(n, maxElems);
                                byte[] buf = new byte[take * es];
                                in2.readFully(buf);
                                out.put(objId, (etype == 5 ? "C:" : "B:") + new String(buf,
                                        etype == 5 ? "UTF-16BE" : "UTF-8"));
                                remaining--;
                            } else {
                                skipFullyOn(in2, n * es);
                            }
                        } else {
                            skipSubRecordOn(in2, counting, st);
                        }
                    }
                } else {
                    skipFullyOn(in2, length);
                }
            }
        } finally {
            in2.close();
        }
    }

    /** Resolves thread object ids to display names via Thread.name -> String -> backing array. */
    void resolveThreadNames(File file, Map<Long, String> outNames) throws IOException {
        Long nameId = nameStringId("name");
        Long valueId = nameStringId("value");
        if (nameId == null || valueId == null || threadClassId == -1) return;

        Set<Long> threadIds = new HashSet<Long>(threadObjIds);
        Map<Long, byte[]> rawThreads = new HashMap<Long, byte[]>();
        captureInstances(file, threadIds, rawThreads);

        // Thread.name is an own field of java.lang.Thread (Object adds no fields).
        int nameOff = ownFieldOffset(threadClassId, nameId);
        if (nameOff < 0) return;
        Set<Long> nameStringIds = new HashSet<Long>();
        Map<Long, Long> threadToStr = new HashMap<Long, Long>();
        for (Map.Entry<Long, byte[]> e : rawThreads.entrySet()) {
            if (e.getValue().length >= nameOff + idSize) {
                long strId = idFromBytes(e.getValue(), nameOff);
                nameStringIds.add(strId);
                threadToStr.put(e.getKey(), strId);
            }
        }
        Map<Long, byte[]> rawStrings = new HashMap<Long, byte[]>();
        captureInstances(file, nameStringIds, rawStrings);

        ClassInfo strInfo = classInfos.get(stringClassId);
        int valueOff = strInfo == null ? 0 : ownFieldOffset(stringClassId, valueId);
        Set<Long> arrayIds = new HashSet<Long>();
        Map<Long, Long> strToArray = new HashMap<Long, Long>();
        for (Map.Entry<Long, byte[]> e : rawStrings.entrySet()) {
            if (valueOff >= 0 && e.getValue().length >= valueOff + idSize) {
                long arrId = idFromBytes(e.getValue(), valueOff);
                arrayIds.add(arrId);
                strToArray.put(e.getKey(), arrId);
            }
        }
        Map<Long, String> arrayVals = new HashMap<Long, String>();
        capturePrimArrays(file, arrayIds, arrayVals, 256);

        for (Long threadId : threadObjIds) {
            Long strId = threadToStr.get(threadId);
            Long arrId = strId == null ? null : strToArray.get(strId);
            String name = arrId == null ? null : arrayVals.get(arrId);
            if (name != null) {
                int c = name.indexOf("B:");
                outNames.put(threadId, c == 0 ? name.substring(2) : name);
            }
        }
    }

    long idFromBytes(byte[] b, int off) {
        if (idSize == 8) {
            long v = 0;
            for (int i = 0; i < 8; i++) v = (v << 8) | (b[off + i] & 0xFFL);
            return v;
        }
        long v = 0;
        for (int i = 0; i < 4; i++) v = (v << 8) | (b[off + i] & 0xFFL);
        return v;
    }

    // ---- stream helpers for targeted passes (operate on a secondary stream) ----

    void readHeaderOn(DataInputStream in2) throws IOException {
        ByteArrayOutputStream buf = new ByteArrayOutputStream(24);
        int b;
        while ((b = in2.read()) != 0) {
            if (b < 0) throw new IOException("Unexpected EOF in header");
            buf.write(b);
        }
        int ids = in2.readInt();
        in2.readLong();
        if (ids != idSize) throw new IOException("Identifier size changed between passes?");
    }

    long readIdOn(DataInputStream in2) throws IOException {
        if (idSize == 8) return in2.readLong();
        return in2.readInt() & 0xFFFFFFFFL;
    }

    void skipFullyOn(DataInputStream in2, long bytes) throws IOException {
        if (bytes <= 0) return;
        while (bytes > 0) {
            long skipped = in2.skip(bytes);
            if (skipped > 0) bytes -= skipped;
            else if (in2.read() != -1) bytes--;
            else throw new EOFException();
        }
    }

    /** Skips one heap sub-record on a secondary stream (roots by size, payloads by length). */
    void skipSubRecordOn(DataInputStream in2, CountingInputStream counting, int st) throws IOException {
        switch (st) {
            case TAG_GC_ROOT_UNKNOWN:
            case TAG_GC_ROOT_STICKY_CLASS:
            case TAG_GC_ROOT_MONITOR_USED:
                skipFullyOn(in2, idSize);
                break;
            case TAG_GC_ROOT_JNI_GLOBAL:
                skipFullyOn(in2, 2L * idSize);
                break;
            case TAG_GC_ROOT_JNI_LOCAL:
            case TAG_GC_ROOT_JAVA_FRAME:
            case TAG_GC_ROOT_THREAD_OBJ:
                skipFullyOn(in2, idSize + 8L);
                break;
            case TAG_GC_ROOT_NATIVE_STACK:
            case TAG_GC_ROOT_THREAD_BLOCK:
                skipFullyOn(in2, idSize + 4L);
                break;
            case TAG_CLASS_DUMP:
                skipClassDumpOn(in2);
                break;
            case TAG_INSTANCE_DUMP:
                readIdOn(in2);          // objId
                in2.readInt();          // stack trace serial
                readIdOn(in2);          // class id
                skipFullyOn(in2, in2.readInt()); // n value bytes
                break;
            case TAG_OBJECT_ARRAY_DUMP: {
                readIdOn(in2);
                in2.readInt();
                long n = in2.readInt() & 0xFFFFFFFFL;
                readIdOn(in2);
                skipFullyOn(in2, n * idSize);
                break;
            }
            case TAG_PRIMITIVE_ARRAY_DUMP: {
                readIdOn(in2);
                in2.readInt();
                long n = in2.readInt() & 0xFFFFFFFFL;
                int es = PRIM_SIZE[in2.readUnsignedByte()];
                skipFullyOn(in2, n * es);
                break;
            }
            default:
                long pp = -1;
                pp = counting == null ? -1 : counting.count;
                throw new IOException("Unknown sub-record 0x" + Integer.toHexString(st) + " at offset " + pp);
        }
    }

    void skipClassDumpOn(DataInputStream in2) throws IOException {
        readIdOn(in2);
        in2.readInt();
        for (int i = 0; i < 6; i++) readIdOn(in2);
        in2.readInt();
        int cp = in2.readUnsignedShort();
        for (int i = 0; i < cp; i++) {
            in2.readUnsignedShort();
            skipValueOn(in2, in2.readUnsignedByte());
        }
        int sf = in2.readUnsignedShort();
        for (int i = 0; i < sf; i++) {
            readIdOn(in2);
            skipValueOn(in2, in2.readUnsignedByte());
        }
        int inf = in2.readUnsignedShort();
        for (int i = 0; i < inf; i++) {
            readIdOn(in2);
            in2.readUnsignedByte();
        }
    }

    /** Skips a field value of the given hprof type code on a secondary stream. */
    void skipValueOn(DataInputStream in2, int type) throws IOException {
        switch (type) {
            case 2:  skipFullyOn(in2, idSize); break;
            case 4: case 8:  skipFullyOn(in2, 1); break;
            case 5: case 9:  skipFullyOn(in2, 2); break;
            case 6: case 10: skipFullyOn(in2, 4); break;
            case 7: case 11: skipFullyOn(in2, 8); break;
            default: throw new IOException("Unknown field type code: " + type);
        }
    }

    // ---- reference walking + inbound BFS ----

    /** Reference with a human label for path rendering. */
    static class Ref {
        final long src;
        final String label;
        Ref(long src, String label) { this.src = src; this.label = label; }
    }

    /** Memoized per-class list of (offset, label) for every reference-typed field. */
    private final Map<Long, List<long[]>> refOffsetCache = new HashMap<Long, List<long[]>>();
    private final Map<Long, List<String>> refLabelCache = new HashMap<Long, List<String>>();

    void refOffsets(long classId, int base, List<long[]> offs, List<String> labels) {
        if (classId == 0 || base > 4096) return;
        ClassInfo ci = classInfos.get(classId);
        if (ci == null) return;
        int off = base;
        for (int i = 0; i < ci.fieldTypes.length; i++) {
            if (ci.fieldTypes[i] == 2) {
                offs.add(new long[]{off});
                String n = stringTable.get(ci.fieldNames[i]);
                labels.add(n == null ? "?" : n);
            }
            off += ci.fieldTypes[i] == 2 ? idSize : PRIM_SIZE[ci.fieldTypes[i]];
        }
        refOffsets(ci.superId, off, offs, labels);
    }

    /**
     * One reference-yielding pass over the heap. Calls back for every
     * instance field ref, object-array element and class static ref.
     * Returns early when the visitor returns true.
     */
    interface RefVisitor { boolean seeRef(long srcId, long dstId, String label) throws IOException; }

    boolean walkRefs(File file, RefVisitor visitor) throws IOException {
        CountingInputStream counting = new CountingInputStream(
                new BufferedInputStream(new FileInputStream(file), 8 * 1024 * 1024));
        DataInputStream in2 = new DataInputStream(counting);
        boolean stop = false;
        try {
            readHeaderOn(in2);
            refOffsetCache.clear();
            refLabelCache.clear();
            while (counting.count < fileSize && !stop) {
                int tag = in2.readUnsignedByte();
                in2.readInt();
                long length = in2.readInt() & 0xFFFFFFFFL;
                if (tag == TAG_HEAP_DUMP || tag == TAG_HEAP_DUMP_SEGMENT) {
                    long segEnd = counting.count + length;
                    while (counting.count < segEnd && !stop) {
                        int st = in2.readUnsignedByte();
                        if (st == TAG_INSTANCE_DUMP) {
                            long srcId = readIdOn(in2);
                            in2.readInt();
                            long classId = readIdOn(in2);
                            int n = in2.readInt();
                            List<long[]> offs = refOffsetCache.get(classId);
                            if (offs == null) {
                                offs = new ArrayList<long[]>();
                                List<String> labels = new ArrayList<String>();
                                refOffsets(classId, 0, offs, labels);
                                refOffsetCache.put(classId, offs);
                                refLabelCache.put(classId, labels);
                            }
                            byte[] buf = new byte[n];
                            in2.readFully(buf);
                            List<String> labels = refLabelCache.get(classId);
                            for (int i = 0; i < offs.size(); i++) {
                                long dst = idFromBytes(buf, (int) offs.get(i)[0]);
                                if (dst != 0) {
                                    stop = visitor.seeRef(srcId, dst, labels.get(i));
                                    if (stop) break;
                                }
                            }
                        } else if (st == TAG_OBJECT_ARRAY_DUMP) {
                            long srcId = readIdOn(in2);
                            in2.readInt();
                            long n = in2.readInt() & 0xFFFFFFFFL;
                            readIdOn(in2);
                            for (long i = 0; i < n && !stop; i++) {
                                long dst = readIdOn(in2);
                                if (dst != 0) {
                                    stop = visitor.seeRef(srcId, dst, "[" + i + "]");
                                }
                            }
                        } else if (st == TAG_CLASS_DUMP) {
                            long srcId = readIdOn(in2);
                            in2.readInt();
                            for (int i = 0; i < 6; i++) readIdOn(in2);
                            in2.readInt();
                            int cp = in2.readUnsignedShort();
                            for (int i = 0; i < cp; i++) {
                                in2.readUnsignedShort();
                                skipValueOn(in2, in2.readUnsignedByte());
                            }
                            int sf = in2.readUnsignedShort();
                            for (int i = 0; i < sf && !stop; i++) {
                                long nameId = readIdOn(in2);
                                int t = in2.readUnsignedByte();
                                if (t == 2) {
                                    long dst = readIdOn(in2);
                                    String nm = stringTable.get(nameId);
                                    stop = visitor.seeRef(srcId, dst, "static " + (nm == null ? "?" : nm));
                                } else {
                                    skipValueOn(in2, t);
                                }
                            }
                            int inf = in2.readUnsignedShort();
                            skipFullyOn(in2, inf * (idSize + 1L));
                        } else {
                            skipSubRecordOn(in2, counting, st);
                        }
                    }
                } else {
                    skipFullyOn(in2, length);
                }
            }
        } finally {
            in2.close();
        }
        return stop;
    }

    /** Renders a root->target chain. Entry label "TARGET" marks the queried object. */
    void printChain(List<Object[]> chain) {
        if (System.getenv("HQS_DEBUG") != null) {
            for (int i = 0; i < chain.size(); i++) {
                long id = (Long) chain.get(i)[0];
                System.err.println("dbg chain[" + i + "] = 0x" + Long.toHexString(id)
                        + " inRoots=" + roots.containsKey(id) + " label=" + chain.get(i)[1]);
            }
        }
        for (int i = 0; i < chain.size(); i++) {
            long id = (Long) chain.get(i)[0];
            String label = (String) chain.get(i)[1];
            String name = prettyClassName(className(id, "object @" + Long.toHexString(id)));
            String indent = i == 0 ? "" : "  ";
            for (int s = 1; s < i; s++) indent += "  ";
            if (i == 0) {
                Root r = roots.get(id);
                System.out.println(indent + "ROOT: " + name + " @0x" + Long.toHexString(id)
                        + (r != null ? "  [GC root: " + rootType(r) + describeThreadRoot(r) + "]" : ""));
            } else if (label.equals("TARGET")) {
                System.out.println(indent + "\u2514\u2500 TARGET: " + name + " @0x" + Long.toHexString(id));
            } else if (label.equals("(reference)")) {
                System.out.println(indent + "\u2514\u2500 references \u2192 " + name + " @0x" + Long.toHexString(id));
            } else {
                System.out.println(indent + "\u2514\u2500 \"" + label + "\" \u2192 " + name
                        + " @0x" + Long.toHexString(id));
            }
        }
    }

    /** One target of the paths command. */
    static class PathSearch {
        final long targetId;
        String targetName = "";
        Set<Long> frontier = new HashSet<Long>();
        final Map<Long, Object[]> parent = new HashMap<Long, Object[]>(); // srcId -> {viaId, label}
        Set<Long> next = new HashSet<Long>();
        long foundRoot = -1;
        boolean done;

        PathSearch(long targetId) {
            this.targetId = targetId;
            this.frontier.add(targetId);
        }
    }

    /** paths command: parent-index chain first (instant), then a shared BFS sweep for the rest. */
    void reportPaths(File file, List<Long> targets, int maxDepth) throws IOException {
        List<PathSearch> pending = new ArrayList<PathSearch>();
        for (int i = 0; i < targets.size(); i++) {
            if (i > 0) System.out.println();
            long t = targets.get(i).longValue();
            String tName = prettyClassName(className(t, "object @" + Long.toHexString(t)));
            Root targetRoot = roots.get(t);
            if (targetRoot != null) {
                System.out.println("Object " + tName + " @0x" + Long.toHexString(t)
                        + " is itself a GC root (" + rootType(targetRoot) + describeThreadRoot(targetRoot) + ").");
                printRootStack(targetRoot);
                continue;
            }
            // Fast path: walk the first-referrer index (built with --parents / paths).
            if (parents != null && !parents.degraded) {
                List<Object[]> chain = new ArrayList<Object[]>(); // root->...->target, {id, label:""}
                Set<Long> seen = new HashSet<Long>();
                seen.add(t);
                long cur = t;
                boolean rooted = roots.containsKey(cur);
                int steps = 0;
                while (!rooted && steps++ < 100000) {
                    long p = parents.get(cur);
                    if (p == -1 || seen.contains(p)) break;   // unknown referrer or cycle
                    chain.add(new Object[]{p, "(reference)"});
                    seen.add(p);
                    cur = p;
                    rooted = roots.containsKey(cur);
                }
                if (rooted) {
                    Collections.reverse(chain);
                    chain.add(new Object[]{t, "TARGET"});
                    System.out.println("=== Path to GC root via first-referrer index (" + (chain.size() - 1) + " hops) ===");
                    System.out.println();
                    printChain(chain);
                    Root rr = roots.get(cur);
                    if (rr != null) {
                        System.out.println();
                        printRootStack(rr);
                    }
                    continue;
                }
                System.out.println("(first-referrer index has no rooted chain for 0x"
                        + Long.toHexString(t) + "; falling back to BFS)");
            }
            PathSearch ps = new PathSearch(t);
            ps.targetName = tName;
            pending.add(ps);
        }

        if (!pending.isEmpty()) {
            bfsSweep(file, pending, maxDepth);
        }
    }

    /** Shared multi-target inbound BFS: one file pass per level for ALL targets. */
    void bfsSweep(File file, List<PathSearch> active, int maxDepth) throws IOException {
        Set<Long> globalVisited = new HashSet<Long>();
        for (PathSearch s : active) globalVisited.add(s.targetId);

        for (int depth = 1; depth <= maxDepth && !active.isEmpty(); depth++) {
            final Set<Long> frontierUnion = new HashSet<Long>();
            for (PathSearch s : active) frontierUnion.addAll(s.frontier);
            final List<PathSearch> activeF = active;
            final Set<Long> newVisited = new HashSet<Long>();
            boolean hit = walkRefs(file, new RefVisitor() {
                public boolean seeRef(long src, long dst, String label) {
                    if (!frontierUnion.contains(dst)) return false;
                    for (PathSearch s : activeF) {
                        if (s.done || !s.frontier.contains(dst) || s.parent.containsKey(src)) continue;
                        s.parent.put(src, new Object[]{dst, label});
                        if (roots.containsKey(src)) s.foundRoot = src;
                        if (!globalVisited.contains(src) && s.next.size() < 20000) {
                            s.next.add(src);
                        }
                    }
                    return false;
                }
            });
            List<PathSearch> stillActive = new ArrayList<PathSearch>();
            for (PathSearch s : active) {
                globalVisited.addAll(s.next);
                if (s.foundRoot != -1) {
                    s.done = true;
                    System.out.println("=== Shortest path to GC root via inbound BFS (" + depth + " hops) ===");
                    System.out.println();
                    List<Object[]> chain = new ArrayList<Object[]>();
                    long cur2 = s.foundRoot;
                    while (cur2 != s.targetId) {
                        Object[] p = s.parent.get(cur2);
                        if (p == null) break;
                        chain.add(new Object[]{cur2, p[1]});
                        cur2 = (Long) p[0];
                    }
                    chain.add(new Object[]{s.targetId, "TARGET"});
                    printChain(chain);
                    System.out.println();
                    Root r = roots.get(s.foundRoot);
                    if (r != null) printRootStack(r);
                } else if (!s.next.isEmpty()) {
                    s.frontier = s.next;
                    s.next = new HashSet<Long>();
                    stillActive.add(s);
                }
            }
            System.err.printf("  depth %d: active %d, global visited %d%s%n",
                    depth, stillActive.size(), globalVisited.size(), hit ? ", root reached" : "");
            active = stillActive;
        }
        for (PathSearch s : active) {
            if (!s.done) {
                System.out.println("No GC root reachable within " + maxDepth
                        + " reference hops from " + s.targetName + " @0x"
                        + Long.toHexString(s.targetId) + ".");
            }
        }
    }

    private final Map<Long, String> threadNames = new HashMap<Long, String>();
    private final Map<Long, Long> threadSeqToObj = new HashMap<Long, Long>();

    Long threadSeqToObj(long seq) {
        return threadSeqToObj.get(seq);
    }

    /** Prints the Java stack of a thread-attributed root, when resolvable. */
    void printRootStack(Root r) {
        Integer stackSeq = null;
        if (r.tag == TAG_GC_ROOT_THREAD_OBJ) stackSeq = (int) r.b;
        else if (r.tag == TAG_GC_ROOT_JNI_LOCAL || r.tag == TAG_GC_ROOT_JAVA_FRAME) {
            Integer ts = threadSerialToTrace.get((int) r.a);
            stackSeq = ts;
        }
        if (stackSeq == null) return;
        List<String> stack = renderStack(stackSeq, 15);
        if (stack.isEmpty()) return;
        Long threadObj = threadSeqToObj.get(r.a);
        String name = threadObj == null ? null : threadNames.get(threadObj);
        System.out.println("Owning thread: " + (name != null ? "\"" + name + "\"" : "seq " + r.a)
                + (r.tag == TAG_GC_ROOT_JAVA_FRAME || r.tag == TAG_GC_ROOT_JNI_LOCAL
                    ? "  (frame " + r.b + ")" : ""));
        for (String line : stack) System.out.println("  " + line);
    }

    String rootType(Root r) {
        switch (r.tag) {
            case TAG_GC_ROOT_THREAD_OBJ: return "thread object";
            case TAG_GC_ROOT_JNI_LOCAL: return "JNI local";
            case TAG_GC_ROOT_JAVA_FRAME: return "Java stack frame";
            case TAG_GC_ROOT_JNI_GLOBAL: return "JNI global";
            case TAG_GC_ROOT_STICKY_CLASS: return "sticky class";
            case TAG_GC_ROOT_THREAD_BLOCK: return "thread block";
            case TAG_GC_ROOT_NATIVE_STACK: return "native stack";
            case TAG_GC_ROOT_MONITOR_USED: return "monitor";
            default: return "unknown";
        }
    }

    String describeThreadRoot(Root r) {
        if (r.tag == TAG_GC_ROOT_THREAD_OBJ) {
            Long objId = threadSeqToObj.get(r.a);
            String n = objId == null ? null : threadNames.get(objId);
            return n != null ? ", thread \"" + n + "\"" : "";
        }
        if (r.tag == TAG_GC_ROOT_JNI_LOCAL || r.tag == TAG_GC_ROOT_JAVA_FRAME) {
            Long objId = threadSeqToObj.get(r.a);
            String n = objId == null ? null : threadNames.get(objId);
            return (n != null ? ", thread \"" + n + "\"" : "") + ", frame " + r.b;
        }
        return "";
    }

    // ======================================================================
    // Reporting
    // ======================================================================

    /** Resolves a class id to its name; arrays classes use JVM signatures. */
    String className(long classId, String fallback) {
        Long strId = classNameStrId.get(classId);
        if (strId == null) return fallback;
        String name = stringTable.get(strId);
        if (name == null) return fallback;
        return name;
    }

    /** Converts JVM type signatures like "[B" or "[Ljava.lang.String;" to "byte[]" etc. */
    static String signatureToDisplayName(String sig) {
        if (sig == null || !sig.startsWith("[")) return sig;
        int dims = 0;
        int i = 0;
        while (i < sig.length() && sig.charAt(i) == '[') { dims++; i++; }
        String base;
        char c = sig.charAt(i);
        switch (c) {
            case 'Z': base = "boolean"; break;
            case 'B': base = "byte"; break;
            case 'C': base = "char"; break;
            case 'S': base = "short"; break;
            case 'I': base = "int"; break;
            case 'J': base = "long"; break;
            case 'F': base = "float"; break;
            case 'D': base = "double"; break;
            case 'L':
                int semi = sig.indexOf(';', i);
                base = sig.substring(i + 1, semi < 0 ? sig.length() : semi);
                break;
            default: return sig;
        }
        StringBuilder sb = new StringBuilder(base);
        for (int d = 0; d < dims; d++) sb.append("[]");
        return sb.toString();
    }

    static class Row {
        String name;
        long count;
        long bytes;
    }

    /** Total reference-typed instance fields across the whole hierarchy (memoized). */
    int totalRefFields(long classId, int depth) {
        if (depth > 200) return 0; // defensive: broken hierarchy/cycle in a corrupt dump
        ClassInfo info = classInfos.get(classId);
        if (info == null) return 0;
        return info.ownRefFields + totalRefFields(info.superId, depth + 1);
    }

    /**
     * Reconstructs the real per-instance shallow size from the hprof
     * instanceSize field (= all fields summed, refs at idSize bytes, no header,
     * no alignment): align8(header + fields with refs re-counted).
     * Compressed oops (default): 12-byte header, 4-byte refs.
     * Uncompressed: 16-byte header, refs already 8 bytes as recorded.
     */
    int shallowPerInstance(long classId) {
        Integer cached = shallowPerInstance.get(classId);
        if (cached != null) return cached;

        int size;
        ClassInfo info = classInfos.get(classId);
        if (info == null) {
            size = 16; // unknown class: minimal object
        } else {
            long body = info.instanceSize;
            long header;
            if (idSize == 4) {
                header = 8;            // 32-bit JVM: refs are 4 bytes already
            } else if (uncompressedOops) {
                header = 16;           // 64-bit, -XX:-UseCompressedOops
            } else {
                header = 12;           // 64-bit, compressed oops (default)
                body -= (long) totalRefFields(classId, 0) * 4; // refs: 8 -> 4 bytes
            }
            size = (int) ((header + body + 7) & ~7L);
        }
        if (size < 16) size = 16; // even empty objects take two 8-byte words
        shallowPerInstance.put(classId, size);
        return size;
    }

    /** Merges instance classes and array types into one ranked list. */
    List<Row> buildClassRows() {
        List<Row> rows = new ArrayList<Row>(classCounts.size() + arrayStats.size());
        for (Map.Entry<Long, Long> e : classCounts.entrySet()) {
            Row r = new Row();
            r.name = prettyClassName(className(e.getKey(), "0x" + Long.toHexString(e.getKey())));
            r.count = e.getValue();
            r.bytes = r.count * shallowPerInstance(e.getKey());
            rows.add(r);
        }
        for (Map.Entry<String, long[]> e : arrayStats.entrySet()) {
            Row r = new Row();
            r.name = e.getKey();
            r.count = e.getValue()[0];
            r.bytes = e.getValue()[1];
            rows.add(r);
        }
        return rows;
    }

    /** hprof stores names as "java/lang/String"; display as "java.lang.String". */
    static String prettyClassName(String name) {
        return signatureToDisplayName(name.replace('/', '.'));
    }

    /**
     * Determines the reference width of a 64-bit dump empirically: two String
     * instances can never overlap, so the gap between consecutive String
     * addresses (in sorted order) is at least the String size and always a
     * sum of object sizes. java.lang.String is 24 bytes with compressed oops
     * and 32 without, and the next-smallest possible gap after one String is
     * 24+16=40 resp. 32+16=48 — so a gap of exactly 24 can ONLY occur with
     * compressed oops, and exactly 32 ONLY without. Whichever vote wins is
     * the mode the JVM actually ran in.
     */
    void detectOopsMode() {
        if (idSize != 8 || stringSampleCount < 100) {
            if (idSize == 8) {
                System.err.println("Reference width: not enough String samples to auto-detect; assuming compressed oops");
            }
            return;
        }
        long[] a = Arrays.copyOf(stringSample, stringSampleCount);
        Arrays.sort(a);
        int compressedVotes = 0, uncompressedVotes = 0;
        for (int i = 1; i < a.length; i++) {
            long d = a[i] - a[i - 1];
            if (d == 24) compressedVotes++;
            else if (d == 32) uncompressedVotes++;
        }
        if (compressedVotes == 0 && uncompressedVotes == 0) {
            System.err.println("Reference width: inconclusive spacing votes; assuming compressed oops");
            return;
        }
        uncompressedOops = uncompressedVotes > compressedVotes;
        oopsAutoDetected = true;
        System.err.printf("Reference width: auto-detected %s oops (%d vs %d spacing votes)%n",
                uncompressedOops ? "UNCOMPRESSED" : "compressed",
                uncompressedOops ? uncompressedVotes : compressedVotes,
                uncompressedOops ? compressedVotes : uncompressedVotes);
    }

    /** threads command: per-thread name, directly rooted locals, and Java stack. */
    void reportThreads(int topN) {
        final Map<Long, Integer> localsBySeq = new HashMap<Long, Integer>();
        for (Root x : roots.values()) {
            if (x.tag == TAG_GC_ROOT_JNI_LOCAL || x.tag == TAG_GC_ROOT_JAVA_FRAME) {
                Integer c = localsBySeq.get(x.a);
                localsBySeq.put(x.a, c == null ? 1 : c + 1);
            }
        }
        System.out.println("=== Threads (" + threadObjIds.size() + " thread objects) ===");
        System.out.println();
        int shown = 0;
        for (long threadId : threadObjIds) {
            if (shown >= topN) break;
            Root r = roots.get(threadId);
            String name = threadNames.get(threadId);
            long seq = r == null ? -1 : r.a;
            long stackSeq = r == null ? -1 : r.b;
            Integer locals = localsBySeq.get(seq);

            System.out.println("Thread \"" + (name != null ? name : ("seq " + seq)) + "\" @0x"
                    + Long.toHexString(threadId) + "  (locals rooted: "
                    + (locals == null ? 0 : locals.intValue()) + ")");
            List<String> stack = renderStack((int) stackSeq, 10);
            if (stack.isEmpty()) {
                System.out.println("  (no stack frames in dump)");
            } else {
                for (String line : stack) System.out.println("  " + line);
            }
            System.out.println();
            shown++;
        }
        if (threadObjIds.size() > shown) {
            System.out.println("(" + (threadObjIds.size() - shown) + " more threads, use -n)");
        }
    }

    void report(String command, int topN, String sort) {        if (command.equals("top-arrays")) {
            reportTopArrays(topN);
            return;
        }

        if (command.equals("summary")) {
            List<Row> rows = buildClassRows();
            long totalInstances = 0;
            long totalBytes = 0;
            for (Row r : rows) { totalInstances += r.count; totalBytes += r.bytes; }

            System.out.println("========================================");
            System.out.println("  HeapQuickScan Summary");
            System.out.println("  File: " + fileName + " (" + formatSize(fileSize) + "), " + version);
            System.out.println("========================================");
            System.out.println();
            System.out.printf("Classes with instances: %,d%n", classCounts.size());
            System.out.printf("Array types:            %,d%n", arrayStats.size());
            System.out.printf("Total objects:          %,d (instances + arrays)%n", totalInstances);
            System.out.printf("Total shallow size:     %s (estimate)%n", formatSize(totalBytes));
            System.out.println();
        }

        reportTopClasses(topN, sort);
        if (command.equals("summary")) {
            System.out.println();
            reportTopArrays(Math.min(topN, MAX_TRACKED_ARRAYS));
        }
    }

    void reportTopClasses(int topN, String sort) {
        List<Row> rows = buildClassRows();
        if (sort.equals("count")) {
            Collections.sort(rows, new Comparator<Row>() {
                public int compare(Row a, Row b) { return Long.compare(b.count, a.count); }
            });
        } else {
            Collections.sort(rows, new Comparator<Row>() {
                public int compare(Row a, Row b) {
                    int byBytes = Long.compare(b.bytes, a.bytes);
                    return byBytes != 0 ? byBytes : Long.compare(b.count, a.count);
                }
            });
        }

        String title = sort.equals("count") ? "Instance Count" : "Shallow Size";
        System.out.println("=== Top " + Math.min(topN, rows.size()) + " Classes by " + title + " ===");
        System.out.println();
        System.out.printf("%12s %13s %10s  %s%n", "Count", "Shallow Size", "Avg Size", "Type");
        System.out.println("------------ ------------- ----------  ----------");

        long shownCount = 0, shownBytes = 0;
        int shown = 0;
        long totalCount = 0, totalBytes = 0;
        for (Row r : rows) { totalCount += r.count; totalBytes += r.bytes; }
        for (Row r : rows) {
            if (shown >= topN) break;
            long avg = r.count > 0 ? r.bytes / r.count : 0;
            System.out.printf("%,12d %13s %10s  %s%n", r.count, formatSize(r.bytes), formatSize(avg), r.name);
            shownCount += r.count;
            shownBytes += r.bytes;
            shown++;
        }

        System.out.println("------------ ------------- ----------  ----------");
        System.out.printf("%,12d %13s %10s  TOTAL shown / %,d types / all: %,d objects, %s%n",
                shownCount, formatSize(shownBytes), "",
                rows.size(), totalCount, formatSize(totalBytes));
    }

    void reportTopArrays(int topN) {
        List<ArrayEntry> sorted = new ArrayList<ArrayEntry>(topArrays);
        Collections.sort(sorted, new Comparator<ArrayEntry>() {
            public int compare(ArrayEntry a, ArrayEntry b) { return Long.compare(b.size, a.size); }
        });

        long totalArrays = 0, totalBytes = 0;
        for (long[] s : arrayStats.values()) { totalArrays += s[0]; totalBytes += s[1]; }

        System.out.println("=== Top " + Math.min(topN, sorted.size()) + " Individual Arrays by Size ===");
        System.out.println();
        System.out.printf("%13s %13s  %-24s %s%n", "Size", "Length", "Type", "Object ID");
        System.out.println("------------- -------------  ------------------------ ----------");

        int shown = 0;
        for (ArrayEntry a : sorted) {
            if (shown >= topN) break;
            System.out.printf("%13s %13d  %-24s 0x%X%n",
                    formatSize(a.size), a.length, a.type, a.objectId);
            shown++;
        }

        System.out.println("------------- -------------  ------------------------ ----------");
        System.out.printf("All arrays: %,d totaling %s (estimate; object refs at %d bytes)%n",
                totalArrays, formatSize(totalBytes), objectRefWidth());
    }

    static String formatSize(long bytes) {
        if (bytes < 1024) return bytes + " B";
        if (bytes < 1024 * 1024) return String.format("%.1f KB", bytes / 1024.0);
        if (bytes < 1024L * 1024 * 1024) return String.format("%.1f MB", bytes / (1024.0 * 1024.0));
        return String.format("%.2f GB", bytes / (1024.0 * 1024.0 * 1024.0));
    }
}

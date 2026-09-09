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
    }
    final Map<Long, ClassInfo> classInfos = new HashMap<Long, ClassInfo>();
    final Map<Long, Integer> shallowPerInstance = new HashMap<Long, Integer>(); // resolved lazily
    final Map<Long, Long> classCounts = new HashMap<Long, Long>();      // classId -> instance count
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
        int topN = 20;
        String sort = "bytes";

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
            } else if (a.startsWith("-")) {
                fail("Unknown option: " + a);
                return;
            } else if (command == null) {
                command = a;
            } else if (filePath == null) {
                filePath = a;
            } else {
                fail("Unexpected argument: " + a);
                return;
            }
        }

        if (command == null || filePath == null) {
            printUsage();
            return;
        }
        if (!command.equals("top-classes") && !command.equals("top-arrays") && !command.equals("summary")) {
            fail("Unknown command: " + command);
            return;
        }

        HeapQuickScan scanner = new HeapQuickScan();
        boolean forceUncompressed = false;
        for (String a : args) {
            if ("--uncompressed-oops".equals(a)) { scanner.uncompressedOops = true; forceUncompressed = true; }
        }
        try {
            scanner.scan(filePath);
        } catch (IOException e) {
            fail("Failed to parse " + filePath + " at offset " + scanner.pos() + ": " + e.getMessage());
            return;
        }
        if (!forceUncompressed) scanner.detectOopsMode();
        scanner.report(command, topN, sort);
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
        System.out.println("  top-classes   List classes by shallow size (or instance count)");
        System.out.println("  top-arrays    List the largest individual arrays (with object IDs)");
        System.out.println("  summary       Overview: totals + top classes + top arrays");
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
        in.readInt();              // class serial number (unused)
        long classId = readId();
        in.readInt();              // stack trace serial number (unused)
        long strId = readId();
        classNameStrId.put(classId, strId);
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

        while (pos() < segEnd) {
            int tag = in.readUnsignedByte();

            switch (tag) {
                case TAG_GC_ROOT_UNKNOWN:
                case TAG_GC_ROOT_STICKY_CLASS:
                case TAG_GC_ROOT_MONITOR_USED:
                    skipFully(idSize);
                    break;
                case TAG_GC_ROOT_JNI_GLOBAL:
                    skipFully(2L * idSize);
                    break;
                case TAG_GC_ROOT_JNI_LOCAL:
                case TAG_GC_ROOT_JAVA_FRAME:
                case TAG_GC_ROOT_THREAD_OBJ:
                    skipFully(idSize + 8L);
                    break;
                case TAG_GC_ROOT_NATIVE_STACK:
                case TAG_GC_ROOT_THREAD_BLOCK:
                    skipFully(idSize + 4L);
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
            skipValue(in.readUnsignedByte());
        }

        // Instance fields: u2 count, then per entry: id name, u1 type.
        // (Values live in each INSTANCE_DUMP record.)
        int fieldCount = in.readUnsignedShort();
        int ownRefs = 0;
        for (int i = 0; i < fieldCount; i++) {
            readId();               // field name string ID
            if (in.readUnsignedByte() == 2) ownRefs++;
        }

        ClassInfo info = new ClassInfo();
        info.superId = superId;
        info.instanceSize = instanceSize;
        info.ownRefFields = ownRefs;
        classInfos.put(classId, info);
    }

    void parseInstanceDump() throws IOException {
        long objId = readId();
        in.readInt();              // stack trace serial number
        long classId = readId();
        int valueBytes = in.readInt(); // number of instance-field bytes that follow
        skipFully(valueBytes);

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
        skipFully(n * idSize);     // element IDs

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

    void recordArray(String typeName, long length, long size, long arrayId) {
        long[] stats = arrayStats.get(typeName);
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

    void report(String command, int topN, String sort) {
        if (command.equals("top-arrays")) {
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

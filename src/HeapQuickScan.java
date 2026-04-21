import java.io.*;
import java.util.*;

/**
 * HeapQuickScan - Fast JVM heap dump (.hprof) analyzer
 * 
 * Scans hprof binary format sequentially, extracts:
 *   - Class instance counts (tag 0x33)
 *   - Primitive/Object array sizes (tag 0x36, 0x37)
 *   - Class names from CLASS DUMP records (tag 0x2C)
 *
 * Usage: java HeapQuickScan <command> <file.hprof> [options]
 *   Commands:
 *     top-classes  - List classes by instance count
 *     top-arrays   - List arrays by size
 *     summary      - Overview (top 20 classes + top 20 arrays)
 *   Options:
 *     -n <num>     - Number of entries to show (default: 20)
 *     -h           - Show help
 *
 * Java 8+ compatible, zero dependencies.
 */
public class HeapQuickScan {

    // HPROF tag constants
    static final int TAG_STRING         = 0x01;
    static final int TAG_LOAD_CLASS     = 0x02;
    static final int TAG_UNLOAD_CLASS   = 0x03;
    static final int TAG_FRAME          = 0x04;
    static final int TAG_TRACE          = 0x05;
    static final int TAG_ALLOC_SITES    = 0x06;
    static final int TAG_HEAP_SUMMARY   = 0x07;
    static final int TAG_START_THREAD   = 0x0A;
    static final int TAG_END_THREAD     = 0x0B;
    static final int TAG_HEAP_DUMP      = 0x0C;
    static final int TAG_HEAP_DUMP_SEGMENT = 0x1C;
    static final int TAG_HEAP_DUMP_END  = 0x2B;
    static final int TAG_GC_ROOT_UNKNOWN  = 0xFF;
    static final int TAG_GC_ROOT_JNI_GLOBAL = 0x01;
    static final int TAG_GC_ROOT_JNI_LOCAL = 0x02;
    static final int TAG_GC_ROOT_JAVA_FRAME = 0x03;
    static final int TAG_GC_ROOT_NATIVE_STACK = 0x04;
    static final int TAG_GC_ROOT_STICKY_CLASS = 0x05;
    static final int TAG_GC_ROOT_THREAD_BLOCK = 0x06;
    static final int TAG_GC_ROOT_MONITOR_USED = 0x07;
    static final int TAG_GC_ROOT_THREAD_OBJ  = 0x08;
    static final int TAG_CLASS_DUMP     = 0x2C;
    static final int TAG_INSTANCE_DUMP  = 0x33;
    static final int TAG_OBJECT_ARRAY_DUMP = 0x36;
    static final int TAG_PRIMITIVE_ARRAY_DUMP = 0x37;

    // Primitive type sizes
    static final int[] PRIM_SIZE = new int[256];
    static {
        PRIM_SIZE[2] = 2; // boolean (jboolean = unsigned byte, but we store as 1 in hprof)
        PRIM_SIZE[4] = 1; // byte / jbyte
        PRIM_SIZE[5] = 2; // char / jchar
        PRIM_SIZE[6] = 4; // short / jshort
        PRIM_SIZE[7] = 4; // int / jint
        PRIM_SIZE[8] = 8; // long / jlong
        PRIM_SIZE[9] = 4; // float / jfloat
        PRIM_SIZE[10] = 8; // double / jdouble
        // Fix: boolean type code in hprof is actually stored differently
        // Type 2 = OBJ (reference), Type 4 = boolean in some versions
        // Let's use the standard hprof type codes:
        // 2=object ref(4 or 8 bytes), 4=boolean(1), 5=char(2), 6=float(4), 
        // 7=double(8), 8=byte(1), 9=short(2), 10=int(4), 11=long(8)
        PRIM_SIZE[2] = -1; // object reference, handled separately based on idSize
        PRIM_SIZE[4] = 1;  // boolean
        PRIM_SIZE[5] = 2;  // char
        PRIM_SIZE[6] = 4;  // float
        PRIM_SIZE[7] = 8;  // double
        PRIM_SIZE[8] = 1;  // byte
        PRIM_SIZE[9] = 2;  // short
        PRIM_SIZE[10] = 4; // int
        PRIM_SIZE[11] = 8; // long
    }

    int idSize; // 4 or 8
    long bytesRead;
    DataInputStream in;
    long fileSize;
    String fileName;

    // Data structures
    Map<Long, String> classNames = new HashMap<>();
    Map<Long, int[]> classFieldInfo = new HashMap<>(); // classId -> [totalInstanceBytes (excluding refs)]
    Map<Long, long[]> classStats = new HashMap<>(); // classId -> [count, totalShallowBytes]
    List<long[]> arrayEntries = new ArrayList<>(); // [arrayId, length, elementSize, tag]

    // For human-readable class names (from LOAD_CLASS records)
    Map<Long, Long> classSerialToClassId = new HashMap<>();
    Map<Long, String> stringTable = new HashMap<>();

    public static void main(String[] args) throws Exception {
        if (args.length < 2) {
            printUsage();
            return;
        }

        String command = args[0];
        String filePath = args[1];
        int topN = 20;

        for (int i = 2; i < args.length; i++) {
            if ("-n".equals(args[i]) && i + 1 < args.length) {
                topN = Integer.parseInt(args[++i]);
            } else if ("-h".equals(args[i])) {
                printUsage();
                return;
            }
        }

        if (command.equals("top-classes") || command.equals("top-arrays") || command.equals("summary")) {
            HeapQuickScan scanner = new HeapQuickScan();
            scanner.scan(filePath);
            scanner.report(command, topN);
        } else {
            System.err.println("Unknown command: " + command);
            printUsage();
        }
    }

    static void printUsage() {
        System.out.println("HeapQuickScan - Fast JVM heap dump analyzer");
        System.out.println();
        System.out.println("Usage: java HeapQuickScan <command> <file.hprof> [options]");
        System.out.println();
        System.out.println("Commands:");
        System.out.println("  top-classes  List classes by instance count");
        System.out.println("  top-arrays   List arrays by size");
        System.out.println("  summary      Overview (top 20 classes + top 20 arrays)");
        System.out.println();
        System.out.println("Options:");
        System.out.println("  -n <num>     Number of entries to show (default: 20)");
        System.out.println("  -h           Show this help");
    }

    void scan(String path) throws Exception {
        this.fileName = new File(path).getName();
        File file = new File(path);
        this.fileSize = file.length();

        System.err.println("Scanning " + this.fileName + " (" + formatSize(fileSize) + ")...");

        long startTime = System.currentTimeMillis();
        in = new DataInputStream(new BufferedInputStream(new FileInputStream(file), 8 * 1024 * 1024));

        // Read header
        byte[] magic = new byte[17];
        in.readFully(magic);
        String magicStr = new String(magic, "ASCII");
        if (!magicStr.startsWith("JAVA PROFILE")) {
            throw new IOException("Not a valid hprof file (magic: " + magicStr + ")");
        }

        int idSizeIn = in.readInt();
        long timestamp = in.readLong();
        this.idSize = idSizeIn;
        bytesRead = 17 + 4 + 8; // magic + idSize + timestamp

        System.err.println("ID size: " + idSize + " bytes, timestamp: " + new Date(timestamp));

        // Read records
        while (bytesRead < fileSize) {
            int tag = in.readUnsignedByte();
            int time = in.readInt();
            int length = in.readInt();
            bytesRead += 1 + 4 + 4;

            if (length < 0 || length > fileSize - bytesRead) {
                // Corrupted or EOF
                break;
            }

            switch (tag) {
                case TAG_STRING:
                    readString(length);
                    break;
                case TAG_LOAD_CLASS:
                    readLoadClass();
                    break;
                case TAG_CLASS_DUMP:
                    readClassDump(length);
                    break;
                case TAG_INSTANCE_DUMP:
                    readInstanceDump(length);
                    break;
                case TAG_OBJECT_ARRAY_DUMP:
                    readObjectArrayDump(length);
                    break;
                case TAG_PRIMITIVE_ARRAY_DUMP:
                    readPrimitiveArrayDump(length);
                    break;
                default:
                    // Skip unknown records
                    skip(length);
                    break;
            }
        }

        long elapsed = System.currentTimeMillis() - startTime;
        System.err.printf("Scan complete in %.1fs%n", elapsed / 1000.0);
    }

    void readString(int length) throws IOException {
        long id = readId();
        byte[] data = new byte[length - idSize];
        in.readFully(data);
        String s = new String(data, "UTF-8");
        stringTable.put(id, s);
    }

    void readLoadClass() throws IOException {
        int classSerial = in.readInt();       // 4 bytes
        long classObjId = readId();            // idSize
        int stackTraceSerial = in.readInt();   // 4 bytes
        long classNameStrId = readId();        // idSize
        classSerialToClassId.put((long) classSerial, classObjId);
        // Try to resolve class name from string table
        String name = stringTable.get(classNameStrId);
        if (name != null) {
            classNames.put(classObjId, name);
        }
    }

    void readClassDump(int length) throws IOException {
        long classObjId = readId();
        int stackTraceSerial = in.readInt();
        long superClassId = readId();
        long classLoaderId = readId();
        long signersId = readId();
        long protDomainId = readId();
        long reserved1 = readId();
        long reserved2 = readId();
        int instanceSize = in.readInt();

        // Read constant pool (skip)
        short cpCount = in.readShort();
        for (int i = 0; i < cpCount; i++) {
            short cpType = in.readShort();
            skipValue(cpType);
        }

        // Read static fields (skip)
        short staticCount = in.readShort();
        for (int i = 0; i < staticCount; i++) {
            long nameId = readId();
            byte type = in.readByte();
            skipValue(type);
        }

        // Read instance field descriptions
        short fieldCount = in.readShort();
        int totalFieldBytes = 0;
        for (int i = 0; i < fieldCount; i++) {
            long nameId = readId();
            byte type = in.readByte();
            if (type == 2) {
                totalFieldBytes += idSize; // object reference
            } else if (type >= 4 && type <= 11) {
                totalFieldBytes += PRIM_SIZE[type];
            }
        }

        // Calculate shallow size per instance: object header + field bytes
        int shallowPerInstance = 8 + 4 + idSize + totalFieldBytes; // approx: 8 (mark word) + 4 (class ptr) + idSize (fields start)
        // Actually JVM object header is typically 12-16 bytes (mark word 8 + class pointer 4/8)
        // Let's use a simpler estimate: header (16 on 64-bit, 12 on 32-bit) + instanceSize from hprof
        // The instanceSize field in CLASS DUMP already includes the header
        // But instanceSize is sometimes 0 or inaccurate. Let's use our calculation as fallback.
        if (instanceSize > 0 && instanceSize < 10000) {
            shallowPerInstance = instanceSize;
        } else {
            // Estimate: mark word + class pointer + alignment
            shallowPerInstance = 8 + idSize + totalFieldBytes;
            // Align to 8 bytes
            shallowPerInstance = (shallowPerInstance + 7) & ~7;
        }

        classFieldInfo.put(classObjId, new int[]{shallowPerInstance, fieldCount});
    }

    void readInstanceDump(int length) throws IOException {
        long objId = readId();
        int stackTraceSerial = in.readInt();
        long classObjId = readId();

        // Skip instance field values
        int[] info = classFieldInfo.get(classObjId);
        if (info != null) {
            // We don't know the exact types without re-reading CLASS DUMP,
            // so use instanceSize to skip
            skip(length - idSize * 2 - 4);
        } else {
            // Unknown class, skip remaining bytes
            skip(length - idSize * 2 - 4);
        }

        // Update stats
        long[] stats = classStats.get(classObjId);
        if (stats == null) {
            stats = new long[2];
            classStats.put(classObjId, stats);
        }
        stats[0]++; // count

        if (info != null) {
            stats[1] += info[0]; // total shallow bytes
        }
    }

    void readObjectArrayDump(int length) throws IOException {
        long arrayId = readId();
        int stackTraceSerial = in.readInt();
        long classObjId = readId();
        int numElements = in.readInt();

        long arrayBytes = (long) numElements * idSize; // each element is an object ref
        arrayEntries.add(new long[]{arrayId, numElements, arrayBytes, TAG_OBJECT_ARRAY_DUMP});

        // Skip the reference values
        skip(numElements * idSize);
    }

    void readPrimitiveArrayDump(int length) throws IOException {
        long arrayId = readId();
        int stackTraceSerial = in.readInt();
        long classObjId = readId();
        int numElements = in.readInt();
        byte elemType = in.readByte();

        int elemSize = PRIM_SIZE[elemType];
        if (elemSize <= 0) elemSize = 1; // fallback

        long arrayBytes = (long) numElements * elemSize;
        arrayEntries.add(new long[]{arrayId, numElements, arrayBytes, TAG_PRIMITIVE_ARRAY_DUMP});

        // Skip the values
        skip(numElements * elemSize);
    }

    long readId() throws IOException {
        bytesRead += idSize;
        if (idSize == 8) {
            return in.readLong();
        } else {
            return in.readInt() & 0xFFFFFFFFL;
        }
    }

    void skipValue(short type) throws IOException {
        switch (type) {
            case 2: readId(); break; // object ref
            case 4: case 8: in.readByte(); bytesRead += 1; break; // boolean, byte
            case 5: case 9: in.readShort(); bytesRead += 2; break; // char, short
            case 6: case 10: in.readInt(); bytesRead += 4; break; // float, int
            case 7: case 11: in.readLong(); bytesRead += 8; break; // double, long
            default: throw new IOException("Unknown constant pool type: " + type);
        }
    }

    void skip(int bytes) throws IOException {
        if (bytes > 0) {
            in.skipBytes(bytes);
        }
        bytesRead += bytes;
    }

    void report(String command, int topN) {
        switch (command) {
            case "top-classes":
                reportTopClasses(topN);
                break;
            case "top-arrays":
                reportTopArrays(topN);
                break;
            case "summary":
                reportSummary(topN);
                break;
        }
    }

    void reportTopClasses(int topN) {
        System.out.println("=== Top " + topN + " Classes by Instance Count ===");
        System.out.println();
        System.out.printf("%-12s %12s %14s %s%n", "Count", "Shallow Size", "Avg Size", "Class Name");
        System.out.println("---------- ------------ -------------- ----------");

        List<Map.Entry<Long, long[]>> sorted = new ArrayList<>(classStats.entrySet());
        sorted.sort((a, b) -> Long.compare(b.getValue()[0], a.getValue()[0]));

        int shown = 0;
        long totalCount = 0;
        long totalBytes = 0;
        for (Map.Entry<Long, long[]> entry : sorted) {
            if (shown >= topN) break;
            long classId = entry.getKey();
            long count = entry.getValue()[0];
            long bytes = entry.getValue()[1];
            String name = classNames.getOrDefault(classId, "0x" + Long.toHexString(classId));

            totalCount += count;
            totalBytes += bytes;
            long avgSize = count > 0 ? bytes / count : 0;

            System.out.printf("%-12d %14s %14d %s%n", count, formatSize(bytes), avgSize, name);
            shown++;
        }

        System.out.println("---------- ------------ -------------- ----------");
        System.out.printf("%-12d %14s %14s %s%n", totalCount, formatSize(totalBytes), "", "TOTAL (" + classStats.size() + " unique classes)");
    }

    void reportTopArrays(int topN) {
        System.out.println("=== Top " + topN + " Arrays by Size ===");
        System.out.println();
        System.out.printf("%14s %12s %12s %s%n", "Array Size", "Elements", "Elem Size", "Type (Class)");
        System.out.println("-------------- ------------ ------------ ----------");

        List<long[]> sorted = new ArrayList<>(arrayEntries);
        sorted.sort((a, b) -> Long.compare(b[2], a[2]));

        int shown = 0;
        long totalArrayBytes = 0;
        for (long[] entry : sorted) {
            if (shown >= topN) break;
            long arrayId = entry[0];
            long numElements = entry[1];
            long arrayBytes = entry[2];
            int tag = (int) entry[3];
            String type = (tag == TAG_OBJECT_ARRAY_DUMP) ? "object[]" : "primitive[]";
            String className = classNames.getOrDefault(arrayId, "");
            if (!className.isEmpty()) className = " (" + className + ")";

            totalArrayBytes += arrayBytes;
            int elemSize = numElements > 0 ? (int)(arrayBytes / numElements) : 0;

            System.out.printf("%14s %12d %12d %s%s%n", formatSize(arrayBytes), numElements, elemSize, type, className);
            shown++;
        }

        System.out.println("-------------- ------------ ------------ ----------");
        System.out.printf("%14s %12s %12s %s%n", formatSize(totalArrayBytes), "", "", "TOTAL (" + arrayEntries.size() + " arrays)");
    }

    void reportSummary(int topN) {
        System.out.println("========================================");
        System.out.println("  HeapQuickScan Summary");
        System.out.println("  File: " + fileName + " (" + formatSize(fileSize) + ")");
        System.out.println("========================================");
        System.out.println();

        // Classes summary
        System.out.printf("Unique classes: %,d%n", classStats.size());
        long totalInstances = 0;
        for (long[] stats : classStats.values()) totalInstances += stats[0];
        System.out.printf("Total instances: %,d%n", totalInstances);

        long totalInstanceBytes = 0;
        for (long[] stats : classStats.values()) totalInstanceBytes += stats[1];
        System.out.printf("Total instance shallow size: %s%n", formatSize(totalInstanceBytes));

        System.out.printf("Total arrays: %,d%n", arrayEntries.size());
        long totalArrayBytes = 0;
        for (long[] arr : arrayEntries) totalArrayBytes += arr[2];
        System.out.printf("Total array size: %s%n", formatSize(totalArrayBytes));

        System.out.println();

        reportTopClasses(topN);
        System.out.println();
        reportTopArrays(topN);
    }

    static String formatSize(long bytes) {
        if (bytes < 1024) return bytes + " B";
        if (bytes < 1024 * 1024) return String.format("%.1f KB", bytes / 1024.0);
        if (bytes < 1024 * 1024 * 1024) return String.format("%.1f MB", bytes / (1024.0 * 1024));
        return String.format("%.2f GB", bytes / (1024.0 * 1024 * 1024));
    }
}

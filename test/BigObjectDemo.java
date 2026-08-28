import java.util.*;

/**
 * Test fixture for HeapQuickScan: allocates large objects with known,
 * easily-verifiable sizes, then blocks so a heap dump can be taken with jmap.
 *
 * Expected allocations (shallow sizes):
 *   bigBytes   byte[67108864]    ~64.0 MB
 *   bigInts    int[8388608]      ~32.0 MB
 *   bigLongs   long[4194304]     ~32.0 MB
 *   bigChars   char[8388608]     ~16.0 MB  (2 bytes/elem)
 *   bigString  "x" * 16777216    ~16.0 MB  (compact strings -> byte[])
 *   blobList   200 x byte[262144] ~50.0 MB
 *   refs       Object[1000000]    ~4.0 MB  (+ 1M small java.lang.Object)
 *   map        HashMap 200k entries -> ~200k Node + String churn
 */
public class BigObjectDemo {
    static byte[] bigBytes;
    static int[] bigInts;
    static long[] bigLongs;
    static char[] bigChars;
    static String bigString;
    static List<byte[]> blobList;
    static Object[] refs;
    static HashMap<String, String> map;

    public static void main(String[] args) throws Exception {
        bigBytes = new byte[64 * 1024 * 1024];
        Arrays.fill(bigBytes, (byte) 7);

        bigInts = new int[8 * 1024 * 1024];
        Arrays.fill(bigInts, 42);

        bigLongs = new long[4 * 1024 * 1024];
        Arrays.fill(bigLongs, 42L);

        bigChars = new char[8 * 1024 * 1024];
        Arrays.fill(bigChars, 'c');

        bigString = "x".repeat(16 * 1024 * 1024);

        blobList = new ArrayList<>();
        for (int i = 0; i < 200; i++) {
            byte[] b = new byte[256 * 1024];
            b[0] = 1;
            blobList.add(b);
        }

        refs = new Object[1_000_000];
        for (int i = 0; i < refs.length; i++) {
            refs[i] = new Object();
        }

        map = new HashMap<>();
        for (int i = 0; i < 200_000; i++) {
            map.put("key-" + i, "value-" + i);
        }

        System.out.println("READY pid=" + ProcessHandle.current().pid());
        System.out.flush();
        Thread.sleep(Long.MAX_VALUE);
    }
}

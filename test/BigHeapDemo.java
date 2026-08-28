import java.util.*;

/**
 * Performance fixture: tens of millions of objects, a few GB of arrays,
 * then blocks for a heap dump.
 */
public class BigHeapDemo {
    static class Person {
        String name;
        int age;
        long id;
        double score;
        List<String> tags;
    }

    static List<Person> people = new ArrayList<>();
    static List<byte[]> blobs = new ArrayList<>();
    static Map<String, Person> index = new HashMap<>();
    static byte[] giant;
    static int[][] matrix;

    public static void main(String[] args) throws Exception {
        giant = new byte[512 * 1024 * 1024]; // 512 MB
        Arrays.fill(giant, (byte) 3);

        matrix = new int[2048][];
        for (int i = 0; i < matrix.length; i++) matrix[i] = new int[65536]; // 512 MB total

        for (int i = 0; i < 3_000_000; i++) {
            Person p = new Person();
            p.name = "person-" + i;
            p.age = i % 100;
            p.id = i;
            p.score = i / 100.0;
            p.tags = i % 10 == 0 ? new ArrayList<>(Arrays.asList("a", "b", "c")) : null;
            people.add(p);
        }
        for (int i = 0; i < 4000; i++) {
            byte[] b = new byte[128 * 1024];
            b[0] = 1;
            blobs.add(b);
        }
        for (int i = 0; i < 1_000_000; i++) {
            index.put("idx-" + i, people.get(i % people.size()));
        }

        System.out.println("READY pid=" + ProcessHandle.current().pid());
        System.out.flush();
        Thread.sleep(Long.MAX_VALUE);
    }
}

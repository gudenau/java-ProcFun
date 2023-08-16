package procfun;

import java.lang.invoke.MethodHandles;
import java.lang.reflect.AccessibleObject;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.channels.FileChannel;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.List;

public class ProcFun {
    static final class Magic {
        private final long magica;
        private final long magicb;
        private final AccessibleObject object;

        Magic(
            long magica,
            long magicb,
            AccessibleObject object
        ) {
            this.magica = magica;
            this.magicb = magicb;
            this.object = object;
        }
    }

    record Mapping(
        long start,
        long end,
        long size,
        String perms
    ) {
        Mapping(long start, long end, String perms) {
            this(start, end, end - start, perms);
        }
    }

    public static void main(String[] args) throws Throwable {
        if(!ProcFun.class.getModule().isNamed()) {
            System.out.println("This works when using jigsaw you know!");
        }

        var constructor = MethodHandles.Lookup.class.getDeclaredConstructor(Class.class, Class.class, int.class);

        // Magic stuff to let us find an object in heap.
        var magic = new Magic(
            // We need to avoid polluting the heap with our magic
            Long.parseUnsignedLong("DEADBEEFCAFEBABE", 16),
            ~Long.parseUnsignedLong("DEADBEEFCAFEBABE", 16),
            constructor
        );

        // Java doesn't let us directly find addresses or holes in sparse files, so parse memory mappings instead.
        List<Mapping> mappings;
        try(var reader = Files.newBufferedReader(Path.of("/proc/self/maps"))) {
            mappings = reader.lines()
                .map((line) -> {
                    var split = line.split("\\s+", 6);
                    var address = split[0];
                    var perms = split[1];

                    var addressSplit = address.split("-");

                    return new Mapping(
                        Long.parseUnsignedLong(addressSplit[0], 16),
                        Long.parseUnsignedLong(addressSplit[1], 16),
                        perms
                    );
                })
                // We only care about R/W mappings
                .filter((mapping) -> {
                    var perms = mapping.perms;
                    return perms.contains("r") && perms.contains("w");
                })
                .toList();
        }

        try(var mem = (FileChannel) Files.newByteChannel(Path.of("/proc/self/mem"), StandardOpenOption.WRITE, StandardOpenOption.READ)) {
            // 1GiB at a time because we are ballers
            var buffer = ByteBuffer.allocate(1024 * 1024 * 1024).order(ByteOrder.nativeOrder());
            outer:
            for (var mapping : mappings) {
                mem.position(mapping.start);
                long mappingRemaining = mapping.size();
                // Technically this can cause issues, but objects should generally be aligned enough and this is a hack
                while(mappingRemaining > 0) {
                    buffer.limit((int) Math.min(buffer.capacity(), mappingRemaining));
                    mappingRemaining -= mem.read(buffer);
                    buffer.flip();
                    while(buffer.remaining() > 8) {
                        if(buffer.getLong() != magic.magica) {
                            continue;
                        }
                        if(buffer.getLong() != magic.magicb) {
                            continue;
                        }

                        // The object is before the longs because padding
                        buffer.position(buffer.position() - 20);
                        var oop = buffer.getInt();
                        System.out.printf("Candidate oops: %08X\n", oop);

                        // By default oops are compressed with a base of 0 and a shift of 3 YMMV.
                        var address = (((long) oop) & 0xFFFFFFFFL) << 3;
                        System.out.printf("Address: %016X\n", address);
                        var position = mem.position();
                        try {
                            // AccessibleObject.override is 12 bytes in (on Java 19 AMD64 Linux with default settings)
                            mem.position(address + 12);
                            buffer.position(0).put(0, (byte) 1);
                            buffer.limit(1);
                            mem.write(buffer);
                        } finally {
                            mem.position(position);
                        }

                        if(magic.object.isAccessible()) {
                            break outer;
                        } else {
                            System.out.println("Oops, hit the wrong thing!");
                        }
                    }
                }
            }
        }

        var trustUsBro = constructor.newInstance(Object.class, null, -1);
        System.out.println("Our lookup as proof: " + trustUsBro);

        // You are now free to roam about the cabin
    }
}

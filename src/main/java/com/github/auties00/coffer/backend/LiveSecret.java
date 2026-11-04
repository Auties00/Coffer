package com.github.auties00.coffer.backend;

import com.github.auties00.coffer.Secret;

import javax.crypto.SecretKey;
import java.io.IOException;
import java.io.NotSerializableException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serial;
import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.lang.ref.Cleaner;
import java.nio.CharBuffer;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Objects;

/// A [Secret] in native memory of its own: a shared arena, so any thread may read it and any thread may destroy it.
///
/// The arena is closed by a [Cleaner] action, which [#destroy()] runs at once and the garbage collector runs for a
/// secret that became unreachable alive; the action holds the memory, never the secret, or the secret would never
/// become unreachable.
public final class LiveSecret implements Secret {
    private final MemorySegment memory;
    private final Cleaner.Cleanable erasure;

    private LiveSecret(long length) {
        var arena = Arena.ofShared();
        // Native memory from an arena starts zeroed
        this.memory = arena.allocate(length);
        this.erasure = Erasures.CLEANER.register(this, new Erasure(arena, memory));
    }

    /// {@return a zeroed secret of `length` bytes, which the caller fills through [#memory()]}
    public static LiveSecret allocate(int length) {
        if (length < 0) {
            throw new IllegalArgumentException("A secret cannot have a negative length: " + length);
        }
        return new LiveSecret(length);
    }

    /// {@return a secret holding a copy of `bytes`}
    public static LiveSecret copyOf(byte[] bytes) {
        Objects.requireNonNull(bytes, "bytes");
        var secret = new LiveSecret(bytes.length);
        MemorySegment.copy(bytes, 0, secret.memory, ValueLayout.JAVA_BYTE, 0, bytes.length);
        return secret;
    }

    /// {@return a secret holding a copy of the bytes of `bytes`}
    public static LiveSecret copyOf(MemorySegment bytes) {
        Objects.requireNonNull(bytes, "bytes");
        if (bytes.byteSize() > Integer.MAX_VALUE) {
            throw new IllegalArgumentException("A secret holds at most " + Integer.MAX_VALUE + " bytes: " + bytes.byteSize());
        }
        var secret = new LiveSecret(bytes.byteSize());
        MemorySegment.copy(bytes, 0, secret.memory, 0, bytes.byteSize());
        return secret;
    }

    /// {@return a secret holding `characters` encoded as UTF-8}
    public static LiveSecret copyOf(char[] characters) {
        Objects.requireNonNull(characters, "characters");
        var encoder = StandardCharsets.UTF_8.newEncoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT);
        try (var arena = Arena.ofConfined()) {
            var scratch = arena.allocate((long) Math.ceil(encoder.maxBytesPerChar() * characters.length));
            try {
                var output = scratch.asByteBuffer();
                var result = encoder.encode(CharBuffer.wrap(characters), output, true);
                if (!result.isError()) {
                    result = encoder.flush(output);
                }
                if (result.isError()) {
                    throw new IllegalArgumentException("The characters hold a lone surrogate, which UTF-8 cannot encode");
                }
                return copyOf(scratch.asSlice(0, output.position()));
            } finally {
                scratch.fill((byte) 0);
            }
        }
    }

    /// {@return a secret of `length` bytes from `random`}
    public static LiveSecret random(int length, SecureRandom random) {
        // SecureRandom fills arrays only: the heap copy is erased at once
        var bytes = new byte[length];
        try {
            random.nextBytes(bytes);
            return copyOf(bytes);
        } finally {
            Arrays.fill(bytes, (byte) 0);
        }
    }

    /// {@return the writable memory of the secret, for the backends to fill or read without a copy}
    ///
    /// @throws IllegalStateException if the secret is destroyed
    public MemorySegment memory() {
        ensureAlive();
        return memory;
    }

    @Override
    public int length() {
        return (int) memory.byteSize();
    }

    @Override
    public byte[] toByteArray() {
        ensureAlive();
        return memory.toArray(ValueLayout.JAVA_BYTE);
    }

    @Override
    public char[] toCharArray() {
        ensureAlive();
        var decoder = StandardCharsets.UTF_8.newDecoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT);
        // UTF-8 never decodes to more characters than it has bytes
        var output = CharBuffer.allocate(length());
        try {
            var result = decoder.decode(memory.asReadOnly().asByteBuffer(), output, true);
            if (!result.isError()) {
                result = decoder.flush(output);
            }
            if (result.isError()) {
                throw new IllegalStateException("The secret is not UTF-8 text");
            }
            return Arrays.copyOf(output.array(), output.position());
        } finally {
            Arrays.fill(output.array(), '\0');
        }
    }

    @Override
    public MemorySegment asSegment() {
        ensureAlive();
        return memory.asReadOnly();
    }

    @Override
    public SecretKey asKey(String algorithm) {
        Objects.requireNonNull(algorithm, "algorithm");
        ensureAlive();
        if (memory.byteSize() == 0) {
            throw new IllegalStateException("An empty secret is not a key");
        }
        return new KeyView(this, algorithm);
    }

    @Override
    public void destroy() {
        erasure.clean();
    }

    @Override
    public boolean isDestroyed() {
        return !memory.scope().isAlive();
    }

    @Override
    public void close() {
        destroy();
    }

    @Override
    public String toString() {
        return "Secret[" + length() + " bytes" + (isDestroyed() ? ", destroyed" : "") + "]";
    }

    private void ensureAlive() {
        if (isDestroyed()) {
            throw new IllegalStateException("The secret is destroyed");
        }
    }

    /// The Cleaner of every secret, started with the first one.
    private static final class Erasures {
        static final Cleaner CLEANER = Cleaner.create();
    }

    /// Overwrites a secret's memory and frees it.
    private record Erasure(Arena arena, MemorySegment memory) implements Runnable {
        @Override
        public void run() {
            memory.fill((byte) 0);
            arena.close();
        }
    }

    /// A secret seen as a key of one algorithm.
    ///
    /// [SecretKey] is [java.io.Serializable], and a serialized key would carry its bytes out of the process, so the
    /// view refuses serialization both ways; its fields are transient so that nothing reaches the stream before the
    /// refusal.
    private static final class KeyView implements SecretKey {
        @Serial
        private static final long serialVersionUID = 1L;

        private final transient LiveSecret secret;
        private final transient String algorithm;

        private KeyView(LiveSecret secret, String algorithm) {
            this.secret = secret;
            this.algorithm = algorithm;
        }

        @Override
        public String getAlgorithm() {
            return algorithm;
        }

        @Override
        public String getFormat() {
            return "RAW";
        }

        @Override
        public byte[] getEncoded() {
            return secret.toByteArray();
        }

        @Override
        public void destroy() {
            secret.destroy();
        }

        @Override
        public boolean isDestroyed() {
            return secret.isDestroyed();
        }

        @Override
        public String toString() {
            return "SecretKey[" + algorithm + ", " + secret.length() + " bytes" + (secret.isDestroyed() ? ", destroyed" : "") + "]";
        }

        @Serial
        private void writeObject(ObjectOutputStream stream) throws IOException {
            throw new NotSerializableException("A key of a Coffer secret is not serializable");
        }

        @Serial
        private void readObject(ObjectInputStream stream) throws IOException {
            throw new NotSerializableException("A key of a Coffer secret is not serializable");
        }
    }
}

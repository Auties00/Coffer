package com.github.auties00.coffer;

import com.github.auties00.coffer.backend.LiveSecret;

import javax.crypto.SecretKey;
import javax.security.auth.Destroyable;
import java.lang.foreign.MemorySegment;

/// A secret in memory: a key, a token or a password, as a coffer reads it or as an application hands it to one.
///
/// {@snippet lang = java :
/// try (var coffer = Coffer.open("myapp");
///      var key = coffer.readOrCreate("database-key", 32)) {
///     var mac = Mac.getInstance("HmacSHA256");
///     mac.init(key.asKey("HmacSHA256"));
/// }
/// }
///
/// # Memory
/// The bytes are kept outside the Java heap, where the garbage collector never moves or copies them, and
/// [#destroy()] overwrites them with zeros and frees them: once a secret is destroyed, no copy of it is left in the
/// memory the secret owned. A secret that becomes unreachable without being destroyed is erased the same way, at a
/// time the garbage collector chooses.
///
/// [#toByteArray()], [#toCharArray()] and the encoding of [#asKey(String)] are copies on the heap, which the caller
/// owns and should overwrite once done with them; the garbage collector may have copied them in the meantime.
/// [#asSegment()] is a view, which needs no copy.
///
/// # Lifecycle
/// A secret is [AutoCloseable]: [#close()] is [#destroy()], so `try`-with-resources erases it. Destroying a destroyed
/// secret does nothing; every other method of a destroyed secret throws [IllegalStateException], except
/// [#length()], [#isDestroyed()] and [#toString()].
///
/// # Threading
/// A secret may be read from any thread. Destroying one while another thread reads it may give that thread zeros or
/// an [IllegalStateException].
public sealed interface Secret extends AutoCloseable, Destroyable permits LiveSecret {
    /// {@return a secret holding a copy of `bytes`}
    ///
    /// The caller may overwrite `bytes` once the method returns.
    ///
    /// @param bytes the bytes
    static Secret copyOf(byte[] bytes) {
        return LiveSecret.copyOf(bytes);
    }

    /// {@return a secret holding a copy of the bytes of `bytes`}
    ///
    /// @param bytes the bytes, on or off the heap, at most [Integer#MAX_VALUE] of them
    /// @throws IllegalArgumentException if `bytes` is longer than [Integer#MAX_VALUE]
    static Secret copyOf(MemorySegment bytes) {
        return LiveSecret.copyOf(bytes);
    }

    /// {@return a secret holding `characters` encoded as UTF-8}
    ///
    /// This is the form [#toCharArray()] reads back, for passwords: Java keeps those in `char[]` arrays, which unlike
    /// strings can be overwritten. The caller may overwrite `characters` once the method returns.
    ///
    /// @param characters the characters
    /// @throws IllegalArgumentException if `characters` holds a lone surrogate, which UTF-8 cannot encode
    static Secret copyOf(char[] characters) {
        return LiveSecret.copyOf(characters);
    }

    /// {@return how many bytes the secret holds}
    int length();

    /// {@return a copy of the bytes, which the caller owns}
    ///
    /// @throws IllegalStateException if the secret is destroyed
    byte[] toByteArray();

    /// {@return the bytes decoded as UTF-8, in an array the caller owns}
    ///
    /// @throws IllegalStateException if the secret is destroyed, or its bytes are not UTF-8
    /// @see #copyOf(char[])
    char[] toCharArray();

    /// {@return a read-only view of the bytes, valid until the secret is destroyed}
    ///
    /// Reading the view after that throws [IllegalStateException].
    ///
    /// @apiNote The view hands the bytes to native code, or to an API that takes a [MemorySegment] or a
    /// [java.nio.ByteBuffer] (`asSegment().asByteBuffer()`), without a copy on the heap.
    /// @throws IllegalStateException if the secret is destroyed
    MemorySegment asSegment();

    /// {@return a view of the secret as a key of `algorithm`, in the `RAW` format, for [javax.crypto.Cipher],
    /// [javax.crypto.Mac] and the other cryptographic APIs}
    ///
    /// The view is the secret: destroying the view destroys the secret, and the view of a destroyed secret is
    /// destroyed. It is not [java.io.Serializable], although [SecretKey] is: serializing it throws
    /// [java.io.NotSerializableException], so a key never leaves the process that way.
    ///
    /// @apiNote A provider copies the key into memory of its own when it is initialized with it, which destroying
    /// the secret does not reach.
    /// @param algorithm the standard name of the key's algorithm, such as `AES` or `HmacSHA256`
    /// @throws IllegalStateException if the secret is destroyed, or empty
    SecretKey asKey(String algorithm);

    /// Overwrites the bytes with zeros and frees them; destroying a destroyed secret does nothing.
    @Override
    void destroy();

    /// {@return whether the secret is destroyed}
    @Override
    boolean isDestroyed();

    /// Destroys the secret.
    ///
    /// @see #destroy()
    @Override
    void close();

    /// {@return a description with the secret's length, never its bytes}
    @Override
    String toString();
}

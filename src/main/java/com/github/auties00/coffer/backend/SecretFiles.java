package com.github.auties00.coffer.backend;

import com.github.auties00.coffer.CofferException;

import java.io.IOException;
import java.lang.foreign.MemorySegment;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/// The files that hold secrets, one per name, for the backends that keep them in the namespace's directory.
///
/// A plain secret is in `<name>.secret`, a sealed one in `<name>.sealed`: both backends may share a directory, which
/// a move between them fills with the copies before it deletes the originals.
///
/// ```text
/// 0  magic "COFFER"
/// 6  format version, 1
/// 7  kind: 0 the secret itself, 1 the secret sealed by the Windows Data Protection API
/// 8  payload
/// ```
///
/// A file is replaced atomically ([PrivateFiles#write(Path, ByteBuffer...)]), so a crash leaves the old secret or the new
/// one.
public final class SecretFiles {
    public static final byte PLAIN = 0;
    public static final byte DATA_PROTECTION = 1;
    private static final byte[] MAGIC = "COFFER".getBytes(StandardCharsets.US_ASCII);
    private static final byte VERSION = 1;
    private static final int HEADER_LENGTH = MAGIC.length + 2;
    // A sealed secret is longer than the secret: the Windows Data Protection API adds a few hundred bytes
    private static final int MAX_PAYLOAD = 1 << 20;

    private SecretFiles() {
    }

    private static String suffix(byte kind) {
        return kind == PLAIN ? ".secret" : ".sealed";
    }

    /// {@return the payload stored under `name` in `directory`, which the caller destroys, or `null` if there is none}
    ///
    /// The payload goes from the file to the secret's native memory through a direct buffer, with no copy on the heap.
    ///
    /// @throws CofferException if the file is damaged, or of another kind than `kind`
    public static LiveSecret read(Path directory, String name, byte kind) {
        try (var channel = FileChannel.open(directory.resolve(name + suffix(kind)), StandardOpenOption.READ)) {
            var size = channel.size();
            if (size < HEADER_LENGTH || size > HEADER_LENGTH + MAX_PAYLOAD) {
                throw damaged(name);
            }
            var header = ByteBuffer.allocate(HEADER_LENGTH);
            readFully(channel, header, name);
            if (!Arrays.equals(header.array(), 0, MAGIC.length, MAGIC, 0, MAGIC.length) || header.get(MAGIC.length) != VERSION) {
                throw damaged(name);
            }
            if (header.get(MAGIC.length + 1) != kind) {
                throw new CofferException(CofferException.Reason.CORRUPTED, "The file of the secret " + name + " was written by another backend", null);
            }
            var payload = LiveSecret.allocate((int) (size - HEADER_LENGTH));
            try {
                readFully(channel, payload.memory().asByteBuffer(), name);
                return payload;
            } catch (RuntimeException exception) {
                payload.destroy();
                throw exception;
            }
        } catch (NoSuchFileException _) {
            return null;
        } catch (IOException exception) {
            throw new CofferException(CofferException.Reason.IO, "The secret " + name + " could not be read", exception);
        }
    }

    private static void readFully(FileChannel channel, ByteBuffer target, String name) throws IOException {
        while (target.hasRemaining()) {
            if (channel.read(target) < 0) {
                // Shorter than its size said: replaced while it was read, which the atomic writes rule out, or damaged
                throw damaged(name);
            }
        }
    }

    private static CofferException damaged(String name) {
        return new CofferException(CofferException.Reason.CORRUPTED, "The file of the secret " + name + " is damaged", null);
    }

    /// Stores `payload` under `name` in `directory`, straight from its memory when it is native.
    public static void write(Path directory, String name, byte kind, MemorySegment payload) {
        var header = ByteBuffer.allocate(HEADER_LENGTH).put(MAGIC).put(VERSION).put(kind).flip();
        try {
            PrivateFiles.write(directory.resolve(name + suffix(kind)), header, payload.asByteBuffer());
        } catch (IOException exception) {
            throw new CofferException(CofferException.Reason.IO, "The secret " + name + " could not be written", exception);
        }
    }

    /// Deletes the secret of `kind` stored under `name` in `directory`.
    ///
    /// @return whether there was one
    public static boolean delete(Path directory, String name, byte kind) {
        try {
            var deleted = Files.deleteIfExists(directory.resolve(name + suffix(kind)));
            if (deleted) {
                PrivateFiles.forceDirectory(directory);
            }
            return deleted;
        } catch (IOException exception) {
            throw new CofferException(CofferException.Reason.IO, "The secret " + name + " could not be deleted", exception);
        }
    }

    /// {@return the names of the secrets of `kind` stored in `directory`}
    public static List<String> names(Path directory, byte kind) {
        var suffix = suffix(kind);
        var names = new ArrayList<String>();
        try (var files = Files.list(directory)) {
            for (var file : (Iterable<Path>) files::iterator) {
                var fileName = file.getFileName().toString();
                if (fileName.endsWith(suffix)) {
                    var name = fileName.substring(0, fileName.length() - suffix.length());
                    if (Names.isName(name)) {
                        names.add(name);
                    }
                }
            }
        } catch (NoSuchFileException _) {
            return names;
        } catch (IOException exception) {
            throw new CofferException(CofferException.Reason.IO, "The secrets in " + directory + " could not be listed", exception);
        }
        return names;
    }
}

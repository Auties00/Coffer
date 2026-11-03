package com.github.auties00.coffer.backend;

import com.github.auties00.coffer.CofferException;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
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
/// A file is replaced atomically ([PrivateFiles#write(Path, byte\[\])]), so a crash leaves the old secret or the new
/// one.
public final class SecretFiles {
    public static final byte PLAIN = 0;
    public static final byte DATA_PROTECTION = 1;
    private static final byte[] MAGIC = "COFFER".getBytes(StandardCharsets.US_ASCII);
    private static final byte VERSION = 1;

    private SecretFiles() {
    }

    private static String suffix(byte kind) {
        return kind == PLAIN ? ".secret" : ".sealed";
    }

    /// {@return the payload stored under `name` in `directory`, or `null` if there is none}
    ///
    /// @throws CofferException if the file is damaged, or of another kind than `kind`
    public static byte[] read(Path directory, String name, byte kind) {
        byte[] content;
        try {
            content = Files.readAllBytes(directory.resolve(name + suffix(kind)));
        } catch (NoSuchFileException _) {
            return null;
        } catch (IOException exception) {
            throw new CofferException(CofferException.Reason.IO, "The secret " + name + " could not be read", exception);
        }
        try {
            if (content.length < MAGIC.length + 2 || !Arrays.equals(content, 0, MAGIC.length, MAGIC, 0, MAGIC.length)
                    || content[MAGIC.length] != VERSION) {
                throw new CofferException(CofferException.Reason.CORRUPTED, "The file of the secret " + name + " is damaged", null);
            }
            if (content[MAGIC.length + 1] != kind) {
                throw new CofferException(CofferException.Reason.CORRUPTED, "The file of the secret " + name + " was written by another backend", null);
            }
            return Arrays.copyOfRange(content, MAGIC.length + 2, content.length);
        } finally {
            Arrays.fill(content, (byte) 0);
        }
    }

    /// Stores `payload` under `name` in `directory`.
    public static void write(Path directory, String name, byte kind, byte[] payload) {
        var content = new byte[MAGIC.length + 2 + payload.length];
        System.arraycopy(MAGIC, 0, content, 0, MAGIC.length);
        content[MAGIC.length] = VERSION;
        content[MAGIC.length + 1] = kind;
        System.arraycopy(payload, 0, content, MAGIC.length + 2, payload.length);
        try {
            PrivateFiles.write(directory.resolve(name + suffix(kind)), content);
        } catch (IOException exception) {
            throw new CofferException(CofferException.Reason.IO, "The secret " + name + " could not be written", exception);
        } finally {
            Arrays.fill(content, (byte) 0);
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

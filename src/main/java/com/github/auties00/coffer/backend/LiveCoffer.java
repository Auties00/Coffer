package com.github.auties00.coffer.backend;

import com.github.auties00.coffer.Backend;
import com.github.auties00.coffer.Coffer;
import com.github.auties00.coffer.CofferException;

import java.io.IOException;
import java.nio.channels.FileChannel;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.SecureRandom;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.locks.ReentrantLock;

/// A [Coffer] over the [Vault] of its backend.
///
/// The namespace's directory holds a record of the backend, written with the first secret, and a lock file: creating
/// a secret holds a lock of this process for the directory, then an operating system lock on the file, since the JDK
/// refuses two locks on one file in one process.
public final class LiveCoffer implements Coffer {
    static final String BACKEND_FILE = "backend";
    private static final String LOCK_FILE = ".lock";
    private static final SecureRandom RANDOM = new SecureRandom();
    // One lock per namespace directory, for the threads of this process
    private static final ConcurrentHashMap<Path, ReentrantLock> DIRECTORY_LOCKS = new ConcurrentHashMap<>();

    private final String namespace;
    private final Backend backend;
    private final Vault vault;
    private final Path directory;
    private volatile boolean closed;
    private volatile boolean recordWritten;

    /// Creates the coffer of `namespace` over `vault`.
    ///
    /// @param recorded whether `directory` records the backend already
    LiveCoffer(String namespace, Backend backend, Vault vault, Path directory, boolean recorded) {
        this.namespace = namespace;
        this.backend = backend;
        this.vault = vault;
        this.directory = directory;
        this.recordWritten = recorded;
    }

    /// {@return the backend recorded in `directory`, or `null` if the namespace has never stored a secret}
    static Backend recordedBackend(Path directory) {
        try {
            var name = Files.readString(directory.resolve(BACKEND_FILE)).strip();
            try {
                return Backend.valueOf(name);
            } catch (IllegalArgumentException exception) {
                throw new CofferException(CofferException.Reason.CORRUPTED, "The backend recorded in " + directory + " is unknown: " + name, exception);
            }
        } catch (NoSuchFileException _) {
            return null;
        } catch (IOException exception) {
            throw new CofferException(CofferException.Reason.IO, "The backend recorded in " + directory + " could not be read", exception);
        }
    }

    @Override
    public String namespace() {
        return namespace;
    }

    @Override
    public Backend backend() {
        return backend;
    }

    @Override
    public Optional<byte[]> read(String name) {
        Names.checkName(name);
        ensureOpen();
        return Optional.ofNullable(vault.read(name));
    }

    @Override
    public void write(String name, byte[] secret) {
        Names.checkName(name);
        Objects.requireNonNull(secret, "secret");
        if (secret.length > MAX_LENGTH) {
            throw new IllegalArgumentException("A secret holds at most " + MAX_LENGTH + " bytes: " + secret.length);
        }
        ensureOpen();
        withDirectoryLock(() -> {
            record();
            vault.write(name, secret.clone());
            return null;
        });
    }

    @Override
    public byte[] readOrCreate(String name, int length) {
        Names.checkName(name);
        if (length < 1 || length > MAX_LENGTH) {
            throw new IllegalArgumentException("A new secret holds 1 to " + MAX_LENGTH + " bytes: " + length);
        }
        ensureOpen();
        var existing = vault.read(name);
        if (existing != null) {
            return existing;
        }
        return withDirectoryLock(() -> {
            // Another thread or process may have created it while this one waited
            var raced = vault.read(name);
            if (raced != null) {
                return raced;
            }
            record();
            var created = new byte[length];
            RANDOM.nextBytes(created);
            vault.write(name, created);
            return created.clone();
        });
    }

    @Override
    public boolean delete(String name) {
        Names.checkName(name);
        ensureOpen();
        return vault.delete(name);
    }

    @Override
    public List<String> names() {
        ensureOpen();
        return vault.names().stream().sorted().toList();
    }

    @Override
    public void close() {
        if (!closed) {
            closed = true;
            vault.close();
        }
    }

    private void ensureOpen() {
        if (closed) {
            throw new IllegalStateException("The coffer is closed");
        }
    }

    /// Records the backend, so later coffers of the namespace use it; called holding the directory lock.
    private void record() {
        if (recordWritten) {
            return;
        }
        var current = recordedBackend(directory);
        if (current != null && current != backend) {
            throw new CofferException(CofferException.Reason.UNAVAILABLE,
                    "Another process stored the secrets of " + namespace + " in " + current + " while this coffer uses " + backend, null);
        }
        if (current == null) {
            try {
                PrivateFiles.write(directory.resolve(BACKEND_FILE), (backend.name() + "\n").getBytes(java.nio.charset.StandardCharsets.US_ASCII));
            } catch (IOException exception) {
                throw new CofferException(CofferException.Reason.IO, "The backend of " + namespace + " could not be recorded", exception);
            }
        }
        recordWritten = true;
    }

    private <T> T withDirectoryLock(Action<T> action) {
        var lock = DIRECTORY_LOCKS.computeIfAbsent(directory.toAbsolutePath().normalize(), _ -> new ReentrantLock());
        lock.lock();
        try (var channel = FileChannel.open(directory.resolve(LOCK_FILE), StandardOpenOption.CREATE, StandardOpenOption.WRITE);
             var _ = channel.lock()) {
            return action.run();
        } catch (IOException exception) {
            throw new CofferException(CofferException.Reason.IO, "The lock of " + directory + " could not be taken", exception);
        } finally {
            lock.unlock();
        }
    }

    /// Work done holding the directory lock.
    @FunctionalInterface
    private interface Action<T> {
        T run();
    }
}

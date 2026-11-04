package com.github.auties00.coffer.backend;

import com.github.auties00.coffer.Backend;
import com.github.auties00.coffer.Coffer;
import com.github.auties00.coffer.CofferException;
import com.github.auties00.coffer.Secret;

import java.io.IOException;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.locks.ReentrantLock;

/// A [Coffer] over the [Vault] of its backend.
///
/// The namespace's directory holds the record of its backend and a lock file. Every write checks the record, holding
/// the directory lock: the first one writes it, and a write made after another process moved the secrets fails rather
/// than store a secret where no later coffer looks. The lock is a lock of this process for the directory, then an
/// operating system lock on the file, since the JDK refuses two locks on one file in one process.
///
/// ```text
/// SECRET_SERVICE           the backend
/// from FILE                while a move away from FILE has not deleted its secrets there yet
/// ```
public final class LiveCoffer implements Coffer {
    static final String RECORD_FILE = "backend";
    private static final String LOCK_FILE = ".lock";
    private static final String LEAVING = "from ";
    private static final SecureRandom RANDOM = new SecureRandom();
    // One lock per namespace directory, for the threads of this process
    private static final ConcurrentHashMap<Path, ReentrantLock> DIRECTORY_LOCKS = new ConcurrentHashMap<>();

    private final String namespace;
    private final Backend backend;
    private final Vault vault;
    private final Path directory;
    private final Opener opener;
    private volatile boolean closed;

    /// Creates the coffer of `namespace` over `vault`.
    ///
    /// @param opener opens the vault of another backend, for [#moveTo(Backend)]
    LiveCoffer(String namespace, Backend backend, Vault vault, Path directory, Opener opener) {
        this.namespace = namespace;
        this.backend = backend;
        this.vault = vault;
        this.directory = directory;
        this.opener = opener;
    }

    /// Opens the vault of a backend, as the builder of a coffer would.
    @FunctionalInterface
    interface Opener {
        /// @throws CofferException with [CofferException.Reason#UNAVAILABLE] if the backend cannot be reached
        Vault open(Backend backend);
    }

    /// The backend of a namespace, as its directory records it.
    ///
    /// @param backend where the secrets are
    /// @param leaving the backend a move took them from, which may still hold copies, or `null`
    record Record(Backend backend, Backend leaving) {
        String encode() {
            return backend.name() + "\n" + (leaving == null ? "" : LEAVING + leaving.name() + "\n");
        }
    }

    /// {@return the record in `directory`, or `null` if the namespace has never stored a secret}
    static Record readRecord(Path directory) {
        String text;
        try {
            text = Files.readString(directory.resolve(RECORD_FILE), StandardCharsets.US_ASCII);
        } catch (NoSuchFileException _) {
            return null;
        } catch (IOException exception) {
            throw new CofferException(CofferException.Reason.IO, "The backend recorded in " + directory + " could not be read", exception);
        }
        try {
            var lines = text.strip().lines().toList();
            var backend = Backend.valueOf(lines.getFirst().strip());
            var leaving = lines.size() > 1 && lines.get(1).startsWith(LEAVING) ? Backend.valueOf(lines.get(1).substring(LEAVING.length()).strip()) : null;
            return new Record(backend, leaving);
        } catch (RuntimeException exception) {
            throw new CofferException(CofferException.Reason.CORRUPTED, "The backend recorded in " + directory + " is not one Coffer knows", exception);
        }
    }

    private void writeRecord(Record record) {
        try {
            PrivateFiles.write(directory.resolve(RECORD_FILE), record.encode().getBytes(StandardCharsets.US_ASCII));
        } catch (IOException exception) {
            throw new CofferException(CofferException.Reason.IO, "The backend of " + namespace + " could not be recorded", exception);
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
    public Optional<Secret> read(String name) {
        Names.checkName(name);
        ensureOpen();
        return Optional.ofNullable(vault.read(name));
    }

    @Override
    public void write(String name, Secret secret) {
        Names.checkName(name);
        Objects.requireNonNull(secret, "secret");
        if (secret.isDestroyed()) {
            throw new IllegalArgumentException("The secret is destroyed");
        }
        if (secret.length() > MAX_LENGTH) {
            throw new IllegalArgumentException("A secret holds at most " + MAX_LENGTH + " bytes: " + secret.length());
        }
        ensureOpen();
        var memory = ((LiveSecret) secret).memory();
        withDirectoryLock(() -> {
            claim();
            vault.write(name, memory);
            return null;
        });
    }

    @Override
    public void write(String name, byte[] secret) {
        Names.checkName(name);
        Objects.requireNonNull(secret, "secret");
        if (secret.length > MAX_LENGTH) {
            throw new IllegalArgumentException("A secret holds at most " + MAX_LENGTH + " bytes: " + secret.length);
        }
        try (var copy = LiveSecret.copyOf(secret)) {
            write(name, copy);
        }
    }

    @Override
    public Secret readOrCreate(String name, int length) {
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
            claim();
            var created = LiveSecret.random(length, RANDOM);
            try {
                vault.write(name, created.memory());
                return created;
            } catch (RuntimeException exception) {
                created.destroy();
                throw exception;
            }
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
    public Coffer moveTo(Backend target) {
        Objects.requireNonNull(target, "target");
        ensureOpen();
        if (target == backend) {
            return this;
        }
        var destination = opener.open(target);
        try {
            withDirectoryLock(() -> {
                var record = readRecord(directory);
                if (record != null && record.backend() != backend) {
                    throw moved(record.backend());
                }
                // The record does not name the destination, so what it holds is stale: copies of an earlier move that
                // was cut short before the record changed
                for (var name : destination.names()) {
                    destination.delete(name);
                }
                var copied = new ArrayList<String>();
                try {
                    for (var name : vault.names()) {
                        try (var secret = vault.read(name)) {
                            if (secret != null) {
                                destination.write(name, secret.memory());
                                copied.add(name);
                            }
                        }
                    }
                } catch (RuntimeException exception) {
                    // The record still names this backend: take back what was copied
                    for (var name : copied) {
                        try {
                            destination.delete(name);
                        } catch (RuntimeException cleanup) {
                            exception.addSuppressed(cleanup);
                        }
                    }
                    throw exception;
                }
                writeRecord(new Record(target, backend));
                deleteLeft(vault, target);
                return null;
            });
        } catch (RuntimeException exception) {
            destination.close();
            throw exception;
        }
        close();
        return new LiveCoffer(namespace, target, destination, directory, opener);
    }

    /// Deletes the secrets a move left in the backend it took them from, then records that it is done.
    ///
    /// A backend that cannot be reached keeps them until the namespace next opens with it reachable.
    void finishMove(Backend leaving) {
        withDirectoryLock(() -> {
            var record = readRecord(directory);
            if (record == null || record.backend() != backend || record.leaving() != leaving) {
                return null;
            }
            Vault old;
            try {
                old = opener.open(leaving);
            } catch (CofferException exception) {
                if (exception.reason() == CofferException.Reason.UNAVAILABLE) {
                    return null;
                }
                throw exception;
            }
            try {
                deleteLeft(old, backend);
            } finally {
                old.close();
            }
            return null;
        });
    }

    /// Deletes every secret of `left`, which a move to `target` copied, then records the move as done; called holding
    /// the directory lock.
    private void deleteLeft(Vault left, Backend target) {
        for (var name : left.names()) {
            left.delete(name);
        }
        writeRecord(new Record(target, null));
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

    /// Records this coffer's backend as the namespace's, or checks that it still is; called holding the directory lock.
    private void claim() {
        var record = readRecord(directory);
        if (record == null) {
            writeRecord(new Record(backend, null));
        } else if (record.backend() != backend) {
            throw moved(record.backend());
        }
    }

    private CofferException moved(Backend current) {
        return new CofferException(CofferException.Reason.UNAVAILABLE,
                "The secrets of " + namespace + " are in " + current + " now, not in " + backend + ": open the coffer again", null);
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

package com.github.auties00.coffer.backend;

import com.github.auties00.coffer.Backend;
import com.github.auties00.coffer.Coffer;
import com.github.auties00.coffer.CofferException;
import com.github.auties00.coffer.backend.macos.KeychainVault;
import com.github.auties00.coffer.backend.secretservice.SecretServiceVault;
import com.github.auties00.coffer.backend.windows.DataProtectionVault;

import java.io.IOException;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/// The builder of a [LiveCoffer].
public final class CofferBuilder implements Coffer.Builder {
    private final String namespace;
    private List<Backend> backends;
    private Path directory;
    private Duration interactive;

    /// Creates a builder of the coffer of `namespace`.
    ///
    /// @throws IllegalArgumentException if `namespace` is not valid
    public CofferBuilder(String namespace) {
        this.namespace = Names.checkNamespace(namespace);
        this.backends = defaultBackends();
    }

    private static List<Backend> defaultBackends() {
        return switch (Platform.current()) {
            case WINDOWS -> List.of(Backend.WINDOWS_DATA_PROTECTION, Backend.FILE);
            case MACOS -> List.of(Backend.MACOS_KEYCHAIN, Backend.FILE);
            case UNIX -> List.of(Backend.SECRET_SERVICE, Backend.FILE);
        };
    }

    @Override
    public Coffer.Builder backends(Backend... backends) {
        Objects.requireNonNull(backends, "backends");
        if (backends.length == 0) {
            throw new IllegalArgumentException("A coffer needs at least one backend");
        }
        var list = new ArrayList<Backend>(backends.length);
        for (var backend : backends) {
            list.add(Objects.requireNonNull(backend, "backend"));
        }
        this.backends = List.copyOf(list);
        return this;
    }

    @Override
    public Coffer.Builder directory(Path directory) {
        this.directory = Objects.requireNonNull(directory, "directory");
        return this;
    }

    @Override
    public Coffer.Builder interactive(Duration timeout) {
        Objects.requireNonNull(timeout, "timeout");
        if (timeout.isNegative() || timeout.isZero()) {
            throw new IllegalArgumentException("The wait for the user must be positive: " + timeout);
        }
        this.interactive = timeout;
        return this;
    }

    @Override
    public Coffer build() {
        var root = directory != null ? directory : Platform.current().dataDirectory().resolve("coffer").resolve(namespace);
        try {
            PrivateFiles.createDirectories(root);
        } catch (IOException exception) {
            throw new CofferException(CofferException.Reason.IO, "The directory of " + namespace + " could not be created: " + root, exception);
        }
        var recorded = LiveCoffer.recordedBackend(root);
        if (recorded != null) {
            if (!backends.contains(recorded)) {
                throw new CofferException(CofferException.Reason.UNAVAILABLE,
                        "The secrets of " + namespace + " are in " + recorded + ", which the coffer may not use", null);
            }
            // The secrets are there: no other backend may stand in for it
            return new LiveCoffer(namespace, recorded, open(recorded, root), root, true);
        }
        var failures = new ArrayList<CofferException>();
        for (var backend : backends) {
            try {
                return new LiveCoffer(namespace, backend, open(backend, root), root, false);
            } catch (CofferException exception) {
                if (exception.reason() != CofferException.Reason.UNAVAILABLE) {
                    throw exception;
                }
                failures.add(exception);
            }
        }
        var failure = new CofferException(CofferException.Reason.UNAVAILABLE, "No backend of " + backends + " is available", null);
        failures.forEach(failure::addSuppressed);
        throw failure;
    }

    /// {@return the vault of `backend`}
    ///
    /// @throws CofferException with [CofferException.Reason#UNAVAILABLE] if the backend cannot be reached here
    private Vault open(Backend backend, Path root) {
        var platform = Platform.current();
        return switch (backend) {
            case FILE -> new FileVault(root);
            case WINDOWS_DATA_PROTECTION -> {
                if (platform != Platform.WINDOWS) {
                    throw unavailable(backend);
                }
                yield new DataProtectionVault(root, namespace);
            }
            case MACOS_KEYCHAIN -> {
                if (platform != Platform.MACOS) {
                    throw unavailable(backend);
                }
                yield new KeychainVault(namespace);
            }
            case SECRET_SERVICE -> {
                if (platform != Platform.UNIX) {
                    throw unavailable(backend);
                }
                yield SecretServiceVault.open(namespace, interactive);
            }
        };
    }

    private static CofferException unavailable(Backend backend) {
        return new CofferException(CofferException.Reason.UNAVAILABLE, backend + " does not exist on " + Platform.current(), null);
    }
}

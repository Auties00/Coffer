package com.github.auties00.coffer.backend;

import java.nio.file.Path;
import java.util.List;

/// The [com.github.auties00.coffer.Backend#FILE] backend: each secret in an owner-only file of the namespace's
/// directory, unencrypted.
final class FileVault implements Vault {
    private final Path directory;

    FileVault(Path directory) {
        this.directory = directory;
    }

    @Override
    public byte[] read(String name) {
        return SecretFiles.read(directory, name, SecretFiles.PLAIN);
    }

    @Override
    public void write(String name, byte[] secret) {
        SecretFiles.write(directory, name, SecretFiles.PLAIN, secret);
    }

    @Override
    public boolean delete(String name) {
        return SecretFiles.delete(directory, name, SecretFiles.PLAIN);
    }

    @Override
    public List<String> names() {
        return SecretFiles.names(directory, SecretFiles.PLAIN);
    }
}

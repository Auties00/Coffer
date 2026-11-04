package com.github.auties00.coffer.backend;

import com.github.auties00.coffer.CofferException;
import com.github.auties00.coffer.backend.macos.KeychainVault;
import com.github.auties00.coffer.backend.secretservice.SecretServiceVault;
import com.github.auties00.coffer.backend.windows.DataProtectionVault;

import java.lang.foreign.MemorySegment;
import java.util.List;

/// The secrets of one namespace in one backend.
///
/// Names reach a vault validated. Every method may throw [CofferException]. A vault erases every copy of a secret it
/// makes in memory it controls; the copies the operating system's keyring makes are its own.
public sealed interface Vault extends AutoCloseable permits FileVault, DataProtectionVault, KeychainVault, SecretServiceVault {
    /// {@return the secret stored under `name`, which the caller destroys, or `null` if there is none}
    LiveSecret read(String name);

    /// Stores the bytes of `secret` under `name`, replacing what was stored under it.
    ///
    /// @param secret the bytes, which the vault reads and never keeps
    void write(String name, MemorySegment secret);

    /// Deletes the secret stored under `name`.
    ///
    /// @return whether there was one
    boolean delete(String name);

    /// {@return the names of the stored secrets, in any order}
    List<String> names();

    /// Releases what the vault holds; the default does nothing.
    @Override
    default void close() {
    }
}

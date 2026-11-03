package com.github.auties00.coffer.backend;

import com.github.auties00.coffer.CofferException;
import com.github.auties00.coffer.backend.macos.KeychainVault;
import com.github.auties00.coffer.backend.secretservice.SecretServiceVault;
import com.github.auties00.coffer.backend.windows.DataProtectionVault;

import java.util.List;

/// The secrets of one namespace in one backend.
///
/// Names reach a vault validated. Every method may throw [CofferException].
public sealed interface Vault extends AutoCloseable permits FileVault, DataProtectionVault, KeychainVault, SecretServiceVault {
    /// {@return a copy of the secret stored under `name`, or `null` if there is none}
    byte[] read(String name);

    /// Stores `secret` under `name`, replacing what was stored under it.
    void write(String name, byte[] secret);

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

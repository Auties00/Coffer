package com.github.auties00.coffer.backend.windows;

import com.github.auties00.coffer.CofferException;
import com.github.auties00.coffer.backend.SecretFiles;
import com.github.auties00.coffer.backend.Vault;
import com.github.auties00.coffer.backend.windows.ffm.Win32;
import com.github.auties00.coffer.backend.windows.ffm._CRYPTOAPI_BLOB;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.List;

/// The [com.github.auties00.coffer.Backend#WINDOWS_DATA_PROTECTION] backend: each secret in a file of the namespace's
/// directory, sealed by `CryptProtectData` in user scope.
///
/// The seal binds each secret to its namespace and name through the optional entropy, so a sealed file copied under
/// another name, or into another namespace, does not open. The calls never show a dialog
/// (`CRYPTPROTECT_UI_FORBIDDEN`).
///
/// @spec https://learn.microsoft.com/en-us/windows/win32/api/dpapi/nf-dpapi-cryptprotectdata CryptProtectData function
public final class DataProtectionVault implements Vault {
    private final Path directory;
    private final String namespace;

    /// Creates the vault of `namespace`, whose sealed files are in `directory`.
    public DataProtectionVault(Path directory, String namespace) {
        this.directory = directory;
        this.namespace = namespace;
    }

    @Override
    public byte[] read(String name) {
        var sealed = SecretFiles.read(directory, name, SecretFiles.DATA_PROTECTION);
        return sealed == null ? null : unprotect(name, sealed);
    }

    @Override
    public void write(String name, byte[] secret) {
        SecretFiles.write(directory, name, SecretFiles.DATA_PROTECTION, protect(name, secret));
    }

    @Override
    public boolean delete(String name) {
        return SecretFiles.delete(directory, name);
    }

    @Override
    public List<String> names() {
        return SecretFiles.names(directory);
    }

    private byte[] entropy(String name) {
        return ("coffer/" + namespace + "/" + name).getBytes(StandardCharsets.US_ASCII);
    }

    private byte[] protect(String name, byte[] secret) {
        try (var arena = Arena.ofConfined()) {
            var data = arena.allocateFrom(ValueLayout.JAVA_BYTE, secret);
            try {
                var output = _CRYPTOAPI_BLOB.allocate(arena);
                var succeeded = Win32.CryptProtectData(blob(arena, data), MemorySegment.NULL, blob(arena, arena.allocateFrom(ValueLayout.JAVA_BYTE, entropy(name))),
                        MemorySegment.NULL, MemorySegment.NULL, Win32.CRYPTPROTECT_UI_FORBIDDEN(), output);
                if (succeeded == 0) {
                    throw new CofferException(CofferException.Reason.IO, "CryptProtectData could not seal the secret " + name, null);
                }
                return take(output);
            } finally {
                data.fill((byte) 0);
            }
        }
    }

    private byte[] unprotect(String name, byte[] sealed) {
        try (var arena = Arena.ofConfined()) {
            var output = _CRYPTOAPI_BLOB.allocate(arena);
            var succeeded = Win32.CryptUnprotectData(blob(arena, arena.allocateFrom(ValueLayout.JAVA_BYTE, sealed)), MemorySegment.NULL,
                    blob(arena, arena.allocateFrom(ValueLayout.JAVA_BYTE, entropy(name))), MemorySegment.NULL, MemorySegment.NULL,
                    Win32.CRYPTPROTECT_UI_FORBIDDEN(), output);
            if (succeeded == 0) {
                throw new CofferException(CofferException.Reason.CORRUPTED,
                        "The secret " + name + " does not open: it is damaged, or was sealed by another user, on another computer or under another name", null);
            }
            return take(output);
        }
    }

    private static MemorySegment blob(Arena arena, MemorySegment data) {
        var blob = _CRYPTOAPI_BLOB.allocate(arena);
        _CRYPTOAPI_BLOB.cbData(blob, (int) data.byteSize());
        _CRYPTOAPI_BLOB.pbData(blob, data);
        return blob;
    }

    /// {@return the bytes of `blob`, which Windows allocated, after freeing them}
    private static byte[] take(MemorySegment blob) {
        var length = _CRYPTOAPI_BLOB.cbData(blob);
        var data = _CRYPTOAPI_BLOB.pbData(blob).reinterpret(Integer.toUnsignedLong(length));
        try {
            return data.toArray(ValueLayout.JAVA_BYTE);
        } finally {
            data.fill((byte) 0);
            Win32.LocalFree(data);
        }
    }
}

package com.github.auties00.coffer.backend.windows;

import com.github.auties00.coffer.CofferException;
import com.github.auties00.coffer.backend.CapturedCall;
import com.github.auties00.coffer.backend.LiveSecret;
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
    private static final CapturedCall PROTECT = CapturedCall.of(Win32.CryptProtectData$address(), Win32.CryptProtectData$descriptor(), "GetLastError");
    private static final CapturedCall UNPROTECT = CapturedCall.of(Win32.CryptUnprotectData$address(), Win32.CryptUnprotectData$descriptor(), "GetLastError");

    private final Path directory;
    private final String namespace;

    /// Creates the vault of `namespace`, whose sealed files are in `directory`.
    public DataProtectionVault(Path directory, String namespace) {
        this.directory = directory;
        this.namespace = namespace;
    }

    @Override
    public LiveSecret read(String name) {
        try (var sealed = SecretFiles.read(directory, name, SecretFiles.DATA_PROTECTION)) {
            return sealed == null ? null : unprotect(name, sealed.memory());
        }
    }

    @Override
    public void write(String name, MemorySegment secret) {
        try (var arena = Arena.ofConfined()) {
            var output = _CRYPTOAPI_BLOB.allocate(arena);
            var state = CapturedCall.state(arena);
            var succeeded = (int) PROTECT.invoke(state, blob(arena, secret), MemorySegment.NULL,
                    blob(arena, arena.allocateFrom(ValueLayout.JAVA_BYTE, entropy(name))), MemorySegment.NULL, MemorySegment.NULL,
                    Win32.CRYPTPROTECT_UI_FORBIDDEN(), output);
            if (succeeded == 0) {
                throw new CofferException(CofferException.Reason.IO,
                        "CryptProtectData could not seal the secret " + name + " (" + code(PROTECT.error(state)) + ")", null);
            }
            var sealed = data(output);
            try {
                SecretFiles.write(directory, name, SecretFiles.DATA_PROTECTION, sealed);
            } finally {
                release(sealed);
            }
        }
    }

    @Override
    public boolean delete(String name) {
        return SecretFiles.delete(directory, name, SecretFiles.DATA_PROTECTION);
    }

    @Override
    public List<String> names() {
        return SecretFiles.names(directory, SecretFiles.DATA_PROTECTION);
    }

    private byte[] entropy(String name) {
        return ("coffer/" + namespace + "/" + name).getBytes(StandardCharsets.US_ASCII);
    }

    private LiveSecret unprotect(String name, MemorySegment sealed) {
        try (var arena = Arena.ofConfined()) {
            var output = _CRYPTOAPI_BLOB.allocate(arena);
            var state = CapturedCall.state(arena);
            var succeeded = (int) UNPROTECT.invoke(state, blob(arena, sealed), MemorySegment.NULL,
                    blob(arena, arena.allocateFrom(ValueLayout.JAVA_BYTE, entropy(name))), MemorySegment.NULL, MemorySegment.NULL,
                    Win32.CRYPTPROTECT_UI_FORBIDDEN(), output);
            if (succeeded == 0) {
                var error = UNPROTECT.error(state);
                if (error == Win32.NTE_BAD_KEY_STATE()) {
                    throw new CofferException(CofferException.Reason.CORRUPTED, "The secret " + name
                            + " does not open: it was sealed by another user or on another computer, or the user's password was reset ("
                            + code(error) + ")", null);
                }
                if (error == Win32.ERROR_INVALID_DATA() || error == Win32.NTE_BAD_DATA()) {
                    throw new CofferException(CofferException.Reason.CORRUPTED,
                            "The secret " + name + " does not open: it is damaged, or was sealed under another name (" + code(error) + ")", null);
                }
                throw new CofferException(CofferException.Reason.IO, "CryptUnprotectData could not open the secret " + name + " (" + code(error) + ")", null);
            }
            var opened = data(output);
            try {
                return LiveSecret.copyOf(opened);
            } finally {
                release(opened);
            }
        }
    }

    private static String code(int error) {
        return "Windows error 0x" + Integer.toHexString(error).toUpperCase(java.util.Locale.ROOT);
    }

    private static MemorySegment blob(Arena arena, MemorySegment data) {
        var blob = _CRYPTOAPI_BLOB.allocate(arena);
        _CRYPTOAPI_BLOB.cbData(blob, (int) data.byteSize());
        _CRYPTOAPI_BLOB.pbData(blob, data);
        return blob;
    }

    /// {@return the memory `blob` points to, which Windows allocated}
    private static MemorySegment data(MemorySegment blob) {
        return _CRYPTOAPI_BLOB.pbData(blob).reinterpret(Integer.toUnsignedLong(_CRYPTOAPI_BLOB.cbData(blob)));
    }

    /// Overwrites `data`, which Windows allocated, and frees it.
    private static void release(MemorySegment data) {
        data.fill((byte) 0);
        Win32.LocalFree(data);
    }
}

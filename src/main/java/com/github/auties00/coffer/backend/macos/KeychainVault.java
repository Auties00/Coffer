package com.github.auties00.coffer.backend.macos;

import com.github.auties00.coffer.CofferException;
import com.github.auties00.coffer.backend.Vault;
import com.github.auties00.coffer.backend.macos.ffm.Darwin;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/// The [com.github.auties00.coffer.Backend#MACOS_KEYCHAIN] backend: each secret a generic password of the user's
/// default keychain, its service `coffer/` and the namespace, its account the name.
///
/// The keychain grants the application that created an item access to it without asking; any other application, or
/// the same one after an update that changed its code signature, makes the keychain ask the user. A locked keychain
/// asks for its password on its own.
///
/// @spec https://developer.apple.com/documentation/security/keychain-services Keychain services
public final class KeychainVault implements Vault {
    private final String service;

    /// Creates the vault of `namespace`.
    public KeychainVault(String namespace) {
        this.service = "coffer/" + namespace;
    }

    @Override
    public byte[] read(String name) {
        try (var objects = new CoreFoundation()) {
            var query = objects.dictionary(
                    Darwin.kSecClass(), Darwin.kSecClassGenericPassword(),
                    Darwin.kSecAttrService(), objects.string(service),
                    Darwin.kSecAttrAccount(), objects.string(name),
                    Darwin.kSecReturnData(), Darwin.kCFBooleanTrue(),
                    Darwin.kSecMatchLimit(), Darwin.kSecMatchLimitOne());
            var result = objects.arena().allocate(ValueLayout.ADDRESS);
            var status = Darwin.SecItemCopyMatching(query, result);
            if (status == Darwin.errSecItemNotFound()) {
                return null;
            }
            check(status, "read the secret " + name);
            var data = objects.own(result.get(ValueLayout.ADDRESS, 0));
            return CoreFoundation.bytes(data);
        }
    }

    @Override
    public void write(String name, byte[] secret) {
        try (var objects = new CoreFoundation()) {
            var query = objects.dictionary(
                    Darwin.kSecClass(), Darwin.kSecClassGenericPassword(),
                    Darwin.kSecAttrService(), objects.string(service),
                    Darwin.kSecAttrAccount(), objects.string(name));
            var value = objects.data(secret);
            var update = objects.dictionary(Darwin.kSecValueData(), value);
            var status = Darwin.SecItemUpdate(query, update);
            if (status == Darwin.errSecItemNotFound()) {
                var item = objects.dictionary(
                        Darwin.kSecClass(), Darwin.kSecClassGenericPassword(),
                        Darwin.kSecAttrService(), objects.string(service),
                        Darwin.kSecAttrAccount(), objects.string(name),
                        Darwin.kSecAttrLabel(), objects.string(service + "/" + name),
                        Darwin.kSecValueData(), value);
                status = Darwin.SecItemAdd(item, MemorySegment.NULL);
                if (status == Darwin.errSecDuplicateItem()) {
                    // Added by another process since the update found nothing
                    status = Darwin.SecItemUpdate(query, update);
                }
            }
            check(status, "write the secret " + name);
        }
    }

    @Override
    public boolean delete(String name) {
        try (var objects = new CoreFoundation()) {
            var query = objects.dictionary(
                    Darwin.kSecClass(), Darwin.kSecClassGenericPassword(),
                    Darwin.kSecAttrService(), objects.string(service),
                    Darwin.kSecAttrAccount(), objects.string(name));
            var status = Darwin.SecItemDelete(query);
            if (status == Darwin.errSecItemNotFound()) {
                return false;
            }
            check(status, "delete the secret " + name);
            return true;
        }
    }

    @Override
    public List<String> names() {
        try (var objects = new CoreFoundation()) {
            var query = objects.dictionary(
                    Darwin.kSecClass(), Darwin.kSecClassGenericPassword(),
                    Darwin.kSecAttrService(), objects.string(service),
                    Darwin.kSecReturnAttributes(), Darwin.kCFBooleanTrue(),
                    Darwin.kSecMatchLimit(), Darwin.kSecMatchLimitAll());
            var result = objects.arena().allocate(ValueLayout.ADDRESS);
            var status = Darwin.SecItemCopyMatching(query, result);
            if (status == Darwin.errSecItemNotFound()) {
                return List.of();
            }
            check(status, "list the secrets");
            var items = objects.own(result.get(ValueLayout.ADDRESS, 0));
            var names = new ArrayList<String>();
            for (var i = 0L; i < Darwin.CFArrayGetCount(items); i++) {
                var account = Darwin.CFDictionaryGetValue(Darwin.CFArrayGetValueAtIndex(items, i), Darwin.kSecAttrAccount());
                if (!account.equals(MemorySegment.NULL)) {
                    names.add(CoreFoundation.string(account));
                }
            }
            return names;
        }
    }

    private static void check(int status, String operation) {
        if (status == Darwin.errSecSuccess()) {
            return;
        }
        var reason = status == Darwin.errSecInteractionNotAllowed() || status == Darwin.errSecUserCanceled() ? CofferException.Reason.LOCKED
                : status == Darwin.errSecAuthFailed() ? CofferException.Reason.DENIED
                : status == Darwin.errSecNoSuchKeychain() || status == Darwin.errSecNotAvailable() ? CofferException.Reason.UNAVAILABLE
                : CofferException.Reason.IO;
        throw new CofferException(reason, "The keychain could not " + operation + ": " + message(status) + " (" + status + ")", null);
    }

    private static String message(int status) {
        var message = Darwin.SecCopyErrorMessageString(status, MemorySegment.NULL);
        if (message.equals(MemorySegment.NULL)) {
            return "unknown error";
        }
        try {
            return CoreFoundation.string(message);
        } finally {
            Darwin.CFRelease(message);
        }
    }

    /// The Core Foundation objects one operation creates, released together.
    private static final class CoreFoundation implements AutoCloseable {
        private final Arena arena;
        private final List<MemorySegment> owned;

        CoreFoundation() {
            this.arena = Arena.ofConfined();
            this.owned = new ArrayList<>();
        }

        Arena arena() {
            return arena;
        }

        /// {@return `object`, which this operation now releases}
        MemorySegment own(MemorySegment object) {
            if (!object.equals(MemorySegment.NULL)) {
                owned.add(object);
            }
            return object;
        }

        MemorySegment string(String value) {
            var bytes = value.getBytes(StandardCharsets.UTF_8);
            var created = Darwin.CFStringCreateWithBytes(MemorySegment.NULL, arena.allocateFrom(ValueLayout.JAVA_BYTE, bytes),
                    bytes.length, Darwin.kCFStringEncodingUTF8(), (byte) 0);
            return checked(own(created), "a string");
        }

        MemorySegment data(byte[] value) {
            var copy = arena.allocateFrom(ValueLayout.JAVA_BYTE, value);
            try {
                return checked(own(Darwin.CFDataCreate(MemorySegment.NULL, copy, value.length)), "a data object");
            } finally {
                copy.fill((byte) 0);
            }
        }

        /// {@return a dictionary of the alternating keys and values in `entries`}
        MemorySegment dictionary(MemorySegment... entries) {
            var count = entries.length / 2;
            var keys = arena.allocate(ValueLayout.ADDRESS, count);
            var values = arena.allocate(ValueLayout.ADDRESS, count);
            for (var i = 0; i < count; i++) {
                keys.setAtIndex(ValueLayout.ADDRESS, i, entries[2 * i]);
                values.setAtIndex(ValueLayout.ADDRESS, i, entries[2 * i + 1]);
            }
            var created = Darwin.CFDictionaryCreate(MemorySegment.NULL, keys, values, count,
                    Darwin.kCFTypeDictionaryKeyCallBacks(), Darwin.kCFTypeDictionaryValueCallBacks());
            return checked(own(created), "a dictionary");
        }

        private static MemorySegment checked(MemorySegment object, String what) {
            if (object.equals(MemorySegment.NULL)) {
                throw new CofferException(CofferException.Reason.IO, "Core Foundation could not create " + what, null);
            }
            return object;
        }

        /// {@return the bytes of the data object `data`}
        static byte[] bytes(MemorySegment data) {
            var length = Darwin.CFDataGetLength(data);
            return Darwin.CFDataGetBytePtr(data).reinterpret(length).toArray(ValueLayout.JAVA_BYTE);
        }

        /// {@return the string object `string` as a Java string}
        static String string(MemorySegment string) {
            var length = Darwin.CFStringGetLength(string);
            var size = Darwin.CFStringGetMaximumSizeForEncoding(length, Darwin.kCFStringEncodingUTF8()) + 1;
            try (var arena = Arena.ofConfined()) {
                var buffer = arena.allocate(size);
                if (Darwin.CFStringGetCString(string, buffer, size, Darwin.kCFStringEncodingUTF8()) == 0) {
                    throw new CofferException(CofferException.Reason.IO, "Core Foundation could not convert a string", null);
                }
                return buffer.getString(0, StandardCharsets.UTF_8);
            }
        }

        @Override
        public void close() {
            try {
                for (var object : owned) {
                    Darwin.CFRelease(object);
                }
            } finally {
                arena.close();
            }
        }
    }
}

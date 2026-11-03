package com.github.auties00.coffer;

import com.github.auties00.coffer.backend.Platform;
import com.github.auties00.coffer.backend.dbus.DBusConnection;
import com.github.auties00.coffer.backend.dbus.ObjectPath;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.DisabledOnOs;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.junit.jupiter.api.condition.OS;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTimeoutPreemptively;

/// A coffer that may not ask the user, on a keyring that locks while it runs: it fails with
/// [CofferException.Reason#LOCKED] rather than wait on a dialog.
///
/// It locks the user's real keyring and leaves it locked, so it runs only where `COFFER_TEST_LOCK=true`, which CI sets
/// in a step of its own after every other test.
@EnabledIfEnvironmentVariable(named = "COFFER_TEST_LOCK", matches = "true")
@DisabledOnOs(value = OS.WINDOWS, disabledReason = "The Windows Data Protection API has no lock")
class LockedKeyringTest {
    @Test
    @DisplayName("a coffer that may not ask the user fails with LOCKED once the keyring locks")
    void locked(@TempDir Path directory) throws Exception {
        var namespace = "coffer-lock-" + UUID.randomUUID().toString().substring(0, 8);
        try (var coffer = Coffer.builder(namespace).directory(directory).build()) {
            coffer.write("key", new byte[]{1});
            lock();
            assertTimeoutPreemptively(Duration.ofSeconds(60), () -> {
                var read = assertThrows(CofferException.class, () -> coffer.read("key"));
                assertEquals(CofferException.Reason.LOCKED, read.reason(), read::getMessage);
                var written = assertThrows(CofferException.class, () -> coffer.write("other", new byte[]{2}));
                assertEquals(CofferException.Reason.LOCKED, written.reason(), written::getMessage);
            });
        }
    }

    private static void lock() throws Exception {
        if (Platform.current() == Platform.MACOS) {
            // The default keychain, which CI points at its own
            var process = new ProcessBuilder("security", "lock-keychain").inheritIO().start();
            assertEquals(0, process.waitFor());
            return;
        }
        try (var bus = DBusConnection.openSessionBus()) {
            var service = new ObjectPath("/org/freedesktop/secrets");
            var collection = (ObjectPath) bus.call("org.freedesktop.secrets", service, "org.freedesktop.Secret.Service", "ReadAlias", "s", "default").arguments()[0];
            bus.call("org.freedesktop.secrets", service, "org.freedesktop.Secret.Service", "Lock", "ao", List.of(collection));
        }
    }
}

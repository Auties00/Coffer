package com.github.auties00.coffer;

import com.github.auties00.coffer.backend.Platform;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledOnOs;
import org.junit.jupiter.api.condition.OS;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.Callable;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/// Coffers on this machine's own keyring and on files: what they store, what they refuse, and how they agree on a
/// secret created by many at once.
///
/// Each test uses a namespace of its own and deletes what it stored, since the keyring backends write to the user's
/// real keyring. `COFFER_REQUIRE_KEYRING=true`, which CI sets, fails instead of skipping when the operating system's
/// keyring cannot be reached.
class CofferTest {
    private final List<Coffer> opened = new ArrayList<>();

    private static String namespace() {
        return "coffer-test-" + UUID.randomUUID().toString().substring(0, 8);
    }

    private static Backend platformBackend() {
        return switch (Platform.current()) {
            case WINDOWS -> Backend.WINDOWS_DATA_PROTECTION;
            case MACOS -> Backend.MACOS_KEYCHAIN;
            case UNIX -> Backend.SECRET_SERVICE;
        };
    }

    private Coffer open(Path directory, Backend backend) {
        var coffer = Coffer.builder(namespace()).directory(directory).backends(backend).build();
        opened.add(coffer);
        return coffer;
    }

    private Coffer openPlatform(Path directory) {
        return openPlatform(directory, namespace());
    }

    private Coffer openPlatform(Path directory, String namespace) {
        try {
            var coffer = Coffer.builder(namespace).directory(directory).backends(platformBackend()).build();
            opened.add(coffer);
            return coffer;
        } catch (CofferException exception) {
            if (exception.reason() == CofferException.Reason.UNAVAILABLE && !"true".equals(System.getenv("COFFER_REQUIRE_KEYRING"))) {
                org.junit.jupiter.api.Assumptions.abort(platformBackend() + " is not available here: " + exception.getMessage());
            }
            throw exception;
        }
    }

    @AfterEach
    void cleanUp() {
        for (var coffer : opened) {
            try {
                for (var name : coffer.names()) {
                    coffer.delete(name);
                }
            } catch (IllegalStateException _) {
                // Closed by the test
            } finally {
                coffer.close();
            }
        }
    }

    @Nested
    @DisplayName("on each backend")
    class OnEachBackend {
        private Coffer coffer(Path directory, boolean platform) {
            return platform ? openPlatform(directory) : open(directory, Backend.FILE);
        }

        @ParameterizedTest(name = "keyring of the system: {0}")
        @org.junit.jupiter.params.provider.ValueSource(booleans = {true, false})
        @DisplayName("secrets are written, read, replaced, listed and deleted")
        void lifecycle(boolean platform, @TempDir Path directory) {
            var coffer = coffer(directory, platform);
            assertEquals(Optional.empty(), coffer.read("token"));
            coffer.write("token", "first".getBytes(StandardCharsets.UTF_8));
            coffer.write("other", new byte[0]);
            assertArrayEquals("first".getBytes(StandardCharsets.UTF_8), coffer.read("token").orElseThrow());
            coffer.write("token", "second".getBytes(StandardCharsets.UTF_8));
            assertArrayEquals("second".getBytes(StandardCharsets.UTF_8), coffer.read("token").orElseThrow());
            assertArrayEquals(new byte[0], coffer.read("other").orElseThrow());
            assertEquals(List.of("other", "token"), coffer.names());
            assertTrue(coffer.delete("token"));
            assertFalse(coffer.delete("token"));
            assertEquals(Optional.empty(), coffer.read("token"));
            assertEquals(List.of("other"), coffer.names());
        }

        @ParameterizedTest(name = "keyring of the system: {0}")
        @org.junit.jupiter.params.provider.ValueSource(booleans = {true, false})
        @DisplayName("a large binary secret survives")
        void large(boolean platform, @TempDir Path directory) {
            var coffer = coffer(directory, platform);
            var secret = new byte[Coffer.MAX_LENGTH];
            new java.util.Random(1).nextBytes(secret);
            coffer.write("large", secret);
            assertArrayEquals(secret, coffer.read("large").orElseThrow());
        }

        @ParameterizedTest(name = "keyring of the system: {0}")
        @org.junit.jupiter.params.provider.ValueSource(booleans = {true, false})
        @DisplayName("threads that race to create a secret all get the first one")
        void racingThreads(boolean platform, @TempDir Path directory) throws Exception {
            var coffer = coffer(directory, platform);
            var results = new ArrayList<java.util.concurrent.Future<String>>();
            try (var executor = Executors.newVirtualThreadPerTaskExecutor()) {
                for (var i = 0; i < 16; i++) {
                    results.add(executor.submit((Callable<String>) () -> HexFormat.of().formatHex(coffer.readOrCreate("key", 32))));
                }
            }
            var values = new HashSet<String>();
            for (var result : results) {
                values.add(result.get());
            }
            assertEquals(1, values.size(), () -> values.size() + " different secrets");
            assertEquals(64, values.iterator().next().length());
        }

        @Test
        @DisplayName("processes that race to create a secret all get the first one")
        void racingProcesses(@TempDir Path directory) throws Exception {
            var backend = Backend.FILE;
            var namespace = namespace();
            var classPath = location(Coffer.class) + java.io.File.pathSeparator + location(CofferChild.class);
            var java = ProcessHandle.current().info().command().orElse("java");
            var children = new ArrayList<Process>();
            for (var i = 0; i < 4; i++) {
                children.add(new ProcessBuilder(java, "--enable-native-access=ALL-UNNAMED", "-cp", classPath, CofferChild.class.getName(),
                        namespace, directory.toString(), backend.name()).redirectErrorStream(true).start());
            }
            var values = new HashSet<String>();
            for (var child : children) {
                assertTrue(child.waitFor(60, TimeUnit.SECONDS), "a child did not finish");
                var output = new String(child.getInputStream().readAllBytes(), StandardCharsets.UTF_8).strip();
                assertEquals(0, child.exitValue(), output);
                values.add(output);
            }
            assertEquals(1, values.size(), () -> "different secrets: " + values);
        }

        private static String location(Class<?> type) throws Exception {
            return Path.of(type.getProtectionDomain().getCodeSource().getLocation().toURI()).toString();
        }
    }

    @Nested
    @DisplayName("the backend of a namespace")
    class Pinning {
        @Test
        @DisplayName("is recorded with the first secret and kept, even when another backend would be preferred")
        void kept(@TempDir Path directory) {
            var namespace = namespace();
            try (var first = Coffer.builder(namespace).directory(directory).backends(Backend.FILE).build()) {
                first.write("key", new byte[]{1});
            }
            try (var reopened = Coffer.builder(namespace).directory(directory).backends(platformBackend(), Backend.FILE).build()) {
                assertEquals(Backend.FILE, reopened.backend());
                assertArrayEquals(new byte[]{1}, reopened.read("key").orElseThrow());
                reopened.delete("key");
            }
        }

        @Test
        @DisplayName("must be among the backends a builder allows")
        void refused(@TempDir Path directory) {
            var namespace = namespace();
            try (var first = Coffer.builder(namespace).directory(directory).backends(Backend.FILE).build()) {
                first.write("key", new byte[]{1});
            }
            var refused = assertThrows(CofferException.class, () -> Coffer.builder(namespace).directory(directory).backends(platformBackend()).build());
            assertEquals(CofferException.Reason.UNAVAILABLE, refused.reason());
        }

        @Test
        @DisplayName("of a new namespace is the first available, the system's keyring before files")
        void preferred(@TempDir Path directory) {
            try (var coffer = Coffer.builder(namespace()).directory(directory).build()) {
                if ("true".equals(System.getenv("COFFER_REQUIRE_KEYRING"))) {
                    assertEquals(platformBackend(), coffer.backend());
                }
                assertEquals(coffer.backend().protection(), coffer.protection());
            }
        }
    }

    @Nested
    @DisplayName("moving a namespace")
    class Moving {
        private Coffer track(Coffer coffer) {
            opened.add(coffer);
            return coffer;
        }

        private Coffer fileCoffer(String namespace, Path directory) {
            return track(Coffer.builder(namespace).directory(directory).backends(Backend.FILE, platformBackend()).build());
        }

        private Coffer moveToPlatform(Coffer coffer) {
            try {
                return track(coffer.moveTo(platformBackend()));
            } catch (CofferException exception) {
                if (exception.reason() == CofferException.Reason.UNAVAILABLE && !"true".equals(System.getenv("COFFER_REQUIRE_KEYRING"))) {
                    org.junit.jupiter.api.Assumptions.abort(platformBackend() + " is not available here: " + exception.getMessage());
                }
                throw exception;
            }
        }

        @Test
        @DisplayName("takes every secret to the system's keyring and back, leaving no copy behind")
        void roundTrip(@TempDir Path directory, @TempDir Path elsewhere) throws IOException {
            var namespace = namespace();
            var file = fileCoffer(namespace, directory);
            file.write("first", new byte[]{1});
            file.write("second", new byte[]{2, 2});
            var platform = moveToPlatform(file);
            assertEquals(platformBackend(), platform.backend());
            assertThrows(IllegalStateException.class, () -> file.read("first"));
            assertEquals(List.of("first", "second"), platform.names());
            assertArrayEquals(new byte[]{2, 2}, platform.read("second").orElseThrow());
            assertFalse(Files.exists(directory.resolve("first.secret")));
            assertEquals(platformBackend().name() + "\n", Files.readString(directory.resolve("backend")));
            try (var reopened = Coffer.builder(namespace).directory(directory).build()) {
                assertEquals(platformBackend(), reopened.backend());
            }

            var back = track(platform.moveTo(Backend.FILE));
            assertEquals(Backend.FILE, back.backend());
            assertEquals(List.of("first", "second"), back.names());
            assertArrayEquals(new byte[]{1}, back.read("first").orElseThrow());
            assertFalse(Files.exists(directory.resolve("first.sealed")));
            try (var empty = Coffer.builder(namespace).directory(elsewhere).backends(platformBackend()).build()) {
                assertEquals(List.of(), empty.names());
            }
        }

        @Test
        @DisplayName("a move cut short after its record changed is finished by the next coffer")
        void resumed(@TempDir Path directory) throws IOException {
            var namespace = namespace();
            var file = fileCoffer(namespace, directory);
            file.write("key", new byte[]{7});
            moveToPlatform(file).close();
            // What a move cut short leaves: a record that names both backends, and the copy in the old one
            var content = new byte[]{'C', 'O', 'F', 'F', 'E', 'R', 1, 0, 7};
            Files.write(directory.resolve("key.secret"), content);
            Files.writeString(directory.resolve("backend"), platformBackend().name() + "\nfrom FILE\n");

            var resumed = track(Coffer.builder(namespace).directory(directory).build());
            assertEquals(platformBackend(), resumed.backend());
            assertFalse(Files.exists(directory.resolve("key.secret")));
            assertEquals(platformBackend().name() + "\n", Files.readString(directory.resolve("backend")));
            assertArrayEquals(new byte[]{7}, resumed.read("key").orElseThrow());
        }

        @Test
        @DisplayName("copies a move cut short before its record changed are not brought back")
        void staleCopies(@TempDir Path directory, @TempDir Path elsewhere) throws IOException {
            var namespace = namespace();
            var file = fileCoffer(namespace, directory);
            file.write("key", new byte[]{1});
            // A copy in the keyring that no record names, as an earlier move would leave it
            var stale = openPlatform(elsewhere, namespace);
            stale.write("ghost", new byte[]{9});
            if (Platform.current() == Platform.WINDOWS) {
                Files.copy(elsewhere.resolve("ghost.sealed"), directory.resolve("ghost.sealed"));
            }

            var platform = moveToPlatform(file);
            assertEquals(List.of("key"), platform.names());
        }

        @Test
        @DisplayName("a coffer opened before the move refuses to write after it")
        void staleCoffer(@TempDir Path directory) {
            var namespace = namespace();
            var first = fileCoffer(namespace, directory);
            first.write("key", new byte[]{1});
            var before = fileCoffer(namespace, directory);
            var platform = moveToPlatform(first);
            var refused = assertThrows(CofferException.class, () -> before.write("key", new byte[]{2}));
            assertEquals(CofferException.Reason.UNAVAILABLE, refused.reason());
            assertArrayEquals(new byte[]{1}, platform.read("key").orElseThrow());
        }
    }

    @Nested
    @DisplayName("refusals")
    class Refusals {
        @ParameterizedTest
        @EnumSource(value = Backend.class, names = {"FILE"})
        @DisplayName("names and lengths outside the rules are refused")
        void invalid(Backend backend, @TempDir Path directory) {
            var coffer = open(directory, backend);
            assertThrows(IllegalArgumentException.class, () -> coffer.read("Upper"));
            assertThrows(IllegalArgumentException.class, () -> coffer.read("../escape"));
            assertThrows(IllegalArgumentException.class, () -> coffer.read(".hidden"));
            assertThrows(IllegalArgumentException.class, () -> coffer.write("big", new byte[Coffer.MAX_LENGTH + 1]));
            assertThrows(IllegalArgumentException.class, () -> coffer.readOrCreate("zero", 0));
            assertThrows(IllegalArgumentException.class, () -> Coffer.builder("Bad Namespace"));
        }

        @Test
        @DisplayName("a closed coffer refuses every call")
        void closed(@TempDir Path directory) {
            var coffer = open(directory, Backend.FILE);
            coffer.close();
            assertThrows(IllegalStateException.class, () -> coffer.read("key"));
            coffer.close();
        }

        @Test
        @EnabledOnOs(OS.WINDOWS)
        @DisplayName("a sealed secret copied under another name does not open")
        void boundToName(@TempDir Path directory) throws IOException {
            var coffer = open(directory, Backend.WINDOWS_DATA_PROTECTION);
            coffer.write("original", new byte[]{1, 2, 3});
            Files.copy(directory.resolve("original.sealed"), directory.resolve("copy.sealed"));
            var failure = assertThrows(CofferException.class, () -> coffer.read("copy"));
            assertEquals(CofferException.Reason.CORRUPTED, failure.reason());
        }

        @Test
        @DisplayName("a file of another backend is refused as damaged")
        void wrongKind(@TempDir Path directory) throws IOException {
            var coffer = open(directory, Backend.FILE);
            coffer.write("key", new byte[]{1});
            var bytes = Files.readAllBytes(directory.resolve("key.secret"));
            bytes[7] = 1;
            Files.write(directory.resolve("key.secret"), bytes);
            var failure = assertThrows(CofferException.class, () -> coffer.read("key"));
            assertEquals(CofferException.Reason.CORRUPTED, failure.reason());
        }
    }
}

package com.github.auties00.coffer;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.io.NotSerializableException;
import java.io.ObjectOutputStream;
import java.lang.foreign.Arena;
import java.lang.foreign.ValueLayout;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/// The secret type on its own: what it copies, what it erases, and how it serves as a key.
class SecretTest {
    @Nested
    @DisplayName("copies")
    class Copies {
        @Test
        @DisplayName("bytes come back as they went in, and the source may be overwritten")
        void bytes() {
            var source = new byte[]{1, 2, 3};
            try (var secret = Secret.copyOf(source)) {
                source[0] = 9;
                assertEquals(3, secret.length());
                assertArrayEquals(new byte[]{1, 2, 3}, secret.toByteArray());
            }
        }

        @Test
        @DisplayName("a segment is copied, on or off the heap")
        void segments() {
            try (var arena = Arena.ofConfined(); var secret = Secret.copyOf(arena.allocateFrom(ValueLayout.JAVA_BYTE, (byte) 4, (byte) 5))) {
                assertArrayEquals(new byte[]{4, 5}, secret.toByteArray());
            }
        }

        @Test
        @DisplayName("characters are kept as UTF-8 and decode back")
        void characters() {
            var password = "pässwörd 🔑".toCharArray();
            try (var secret = Secret.copyOf(password)) {
                assertArrayEquals("pässwörd 🔑".getBytes(StandardCharsets.UTF_8), secret.toByteArray());
                assertArrayEquals(password, secret.toCharArray());
            }
        }

        @Test
        @DisplayName("a lone surrogate, which UTF-8 cannot encode, is refused")
        void loneSurrogate() {
            assertThrows(IllegalArgumentException.class, () -> Secret.copyOf(new char[]{'a', '\uD83D'}));
        }

        @Test
        @DisplayName("bytes that are not UTF-8 do not decode")
        void notText() {
            try (var secret = Secret.copyOf(new byte[]{(byte) 0xFF, (byte) 0xFE})) {
                assertThrows(IllegalStateException.class, secret::toCharArray);
            }
        }

        @Test
        @DisplayName("the segment view is read-only")
        void readOnlyView() {
            try (var secret = Secret.copyOf(new byte[]{1})) {
                var view = secret.asSegment();
                assertTrue(view.isReadOnly());
                assertEquals(1, view.get(ValueLayout.JAVA_BYTE, 0));
                assertThrows(IllegalArgumentException.class, () -> view.set(ValueLayout.JAVA_BYTE, 0, (byte) 2));
            }
        }
    }

    @Nested
    @DisplayName("destroying")
    class Destroying {
        @Test
        @DisplayName("closing destroys, once, and every read afterwards fails")
        void close() {
            var secret = Secret.copyOf(new byte[]{1, 2});
            var view = secret.asSegment();
            assertFalse(secret.isDestroyed());
            secret.close();
            assertTrue(secret.isDestroyed());
            secret.destroy();
            assertEquals(2, secret.length());
            assertThrows(IllegalStateException.class, secret::toByteArray);
            assertThrows(IllegalStateException.class, secret::toCharArray);
            assertThrows(IllegalStateException.class, secret::asSegment);
            assertThrows(IllegalStateException.class, () -> secret.asKey("AES"));
            assertThrows(IllegalStateException.class, () -> view.get(ValueLayout.JAVA_BYTE, 0));
        }

        @Test
        @DisplayName("the description never shows the bytes")
        void description() {
            var secret = Secret.copyOf("hunter2".getBytes(StandardCharsets.UTF_8));
            assertEquals("Secret[7 bytes]", secret.toString());
            secret.close();
            assertEquals("Secret[7 bytes, destroyed]", secret.toString());
        }
    }

    @Nested
    @DisplayName("as a key")
    class AsKey {
        @Test
        @DisplayName("a MAC computed with the view matches one computed with the raw bytes")
        void mac() throws Exception {
            var bytes = new byte[32];
            bytes[0] = 42;
            try (var secret = Secret.copyOf(bytes)) {
                var viewed = Mac.getInstance("HmacSHA256");
                viewed.init(secret.asKey("HmacSHA256"));
                var raw = Mac.getInstance("HmacSHA256");
                raw.init(new SecretKeySpec(bytes, "HmacSHA256"));
                var message = "message".getBytes(StandardCharsets.UTF_8);
                assertArrayEquals(raw.doFinal(message), viewed.doFinal(message));
            }
        }

        @Test
        @DisplayName("the view encrypts with AES")
        void aes() throws Exception {
            try (var secret = Secret.copyOf(new byte[16])) {
                var key = secret.asKey("AES");
                var cipher = Cipher.getInstance("AES/GCM/NoPadding");
                var parameters = new GCMParameterSpec(128, new byte[12]);
                cipher.init(Cipher.ENCRYPT_MODE, key, parameters);
                var sealed = cipher.doFinal(new byte[]{1, 2, 3});
                cipher.init(Cipher.DECRYPT_MODE, key, parameters);
                assertArrayEquals(new byte[]{1, 2, 3}, cipher.doFinal(sealed));
            }
        }

        @Test
        @DisplayName("the view is the secret: destroying one destroys the other")
        void sameLifecycle() throws Exception {
            var secret = Secret.copyOf(new byte[16]);
            var key = secret.asKey("AES");
            assertEquals("AES", key.getAlgorithm());
            assertEquals("RAW", key.getFormat());
            key.destroy();
            assertTrue(secret.isDestroyed());
            assertTrue(key.isDestroyed());
            assertThrows(IllegalStateException.class, key::getEncoded);
        }

        @Test
        @DisplayName("the view refuses serialization")
        void notSerializable() {
            try (var secret = Secret.copyOf(new byte[16])) {
                var key = secret.asKey("AES");
                assertThrows(NotSerializableException.class, () -> {
                    try (var stream = new ObjectOutputStream(new ByteArrayOutputStream())) {
                        stream.writeObject(key);
                    }
                });
            }
        }

        @Test
        @DisplayName("an empty secret is not a key")
        void empty() {
            try (var secret = Secret.copyOf(new byte[0])) {
                assertThrows(IllegalStateException.class, () -> secret.asKey("AES"));
            }
        }
    }
}

package com.github.auties00.coffer.backend.secretservice;

import com.github.auties00.coffer.backend.dbus.ObjectPath;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.security.SecureRandom;
import java.util.Arrays;
import java.util.HexFormat;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/// The encrypted transport of the Secret Service, with the other end played by a second session.
class SecretSessionTest {
    private static final ObjectPath PATH = new ObjectPath("/org/freedesktop/secrets/session/1");

    @Test
    @DisplayName("both ends derive the same key, so a secret sealed by one opens at the other")
    void agreement() {
        var random = new SecureRandom();
        var client = SecretSession.encrypted(random);
        var service = SecretSession.encrypted(random);
        client.agree(PATH, service.publicKey());
        service.agree(PATH, client.publicKey());
        var secret = "correct horse battery staple".getBytes();
        var sealed = client.seal(secret);
        assertEquals(PATH, sealed[0]);
        assertEquals(16, ((byte[]) sealed[1]).length);
        assertArrayEquals(secret, service.open((byte[]) sealed[1], (byte[]) sealed[2]));
    }

    @Test
    @DisplayName("HKDF without salt or info matches RFC 5869, test case 3")
    void hkdf() {
        var ikm = new byte[22];
        Arrays.fill(ikm, (byte) 0x0b);
        assertEquals("8da4e775a563c18f715f802a063c5a31", HexFormat.of().formatHex(SecretSession.hkdf(ikm)));
    }

    @Test
    @DisplayName("a public key outside the group is refused")
    void invalidPeer() {
        var session = SecretSession.encrypted(new SecureRandom());
        assertThrows(IllegalArgumentException.class, () -> session.agree(PATH, new byte[]{1}));
    }

    @Test
    @DisplayName("a plain session carries secrets as they are")
    void plain() {
        var session = SecretSession.plain(PATH);
        var sealed = session.seal(new byte[]{1, 2, 3});
        assertArrayEquals(new byte[0], (byte[]) sealed[1]);
        assertArrayEquals(new byte[]{1, 2, 3}, session.open((byte[]) sealed[1], (byte[]) sealed[2]));
    }
}

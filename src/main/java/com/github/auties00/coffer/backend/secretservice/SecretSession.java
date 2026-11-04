package com.github.auties00.coffer.backend.secretservice;

import com.github.auties00.coffer.backend.dbus.ObjectPath;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Arrays;

/// How secrets travel between a coffer and the Secret Service: encrypted, or in the clear for a service that only
/// offers `plain`.
///
/// `dh-ietf1024-sha256-aes128-cbc-pkcs7` agrees on a key with Diffie-Hellman in the 1024-bit MODP group of RFC 2409,
/// derives a 128-bit AES key from the shared secret, padded to 128 bytes, with HKDF-SHA256 without salt or info, and
/// encrypts each secret with AES-128-CBC, PKCS #7 padding and a random IV sent as the secret's parameters.
///
/// @spec https://specifications.freedesktop.org/secret-service-spec/latest/ Secret Service API
/// @spec https://www.rfc-editor.org/rfc/rfc2409 The Internet Key Exchange (IKE)
/// @spec https://www.rfc-editor.org/rfc/rfc5869 HMAC-based Extract-and-Expand Key Derivation Function (HKDF)
final class SecretSession {
    static final String ENCRYPTED = "dh-ietf1024-sha256-aes128-cbc-pkcs7";
    static final String PLAIN = "plain";
    private static final String CONTENT_TYPE = "application/octet-stream";
    // The second Oakley group, the 1024-bit MODP group of RFC 2409, section 6.2
    private static final BigInteger PRIME = new BigInteger(
            "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DD"
                    + "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
                    + "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF", 16);
    private static final int PRIME_BYTES = 128;
    private static final int KEY_BYTES = 16;
    private static final int IV_BYTES = 16;

    private final SecureRandom random;
    private final BigInteger privateKey;
    private SecretKeySpec key;
    private ObjectPath path;

    private SecretSession(SecureRandom random, BigInteger privateKey) {
        this.random = random;
        this.privateKey = privateKey;
    }

    /// {@return a session that will encrypt, once [#agree(ObjectPath, byte\[\])] has the service's public key}
    static SecretSession encrypted(SecureRandom random) {
        BigInteger privateKey;
        do {
            privateKey = new BigInteger(PRIME_BYTES * 8, random);
        } while (privateKey.compareTo(BigInteger.TWO) < 0 || privateKey.compareTo(PRIME.subtract(BigInteger.TWO)) > 0);
        return new SecretSession(random, privateKey);
    }

    /// {@return a session that sends secrets in the clear}
    static SecretSession plain(ObjectPath path) {
        var session = new SecretSession(null, null);
        session.path = path;
        return session;
    }

    /// {@return the public key to send the service, big-endian}
    byte[] publicKey() {
        return unsigned(BigInteger.TWO.modPow(privateKey, PRIME));
    }

    /// Derives the key from the service's public key, and records the session's object path.
    ///
    /// @throws IllegalArgumentException if `servicePublicKey` is not a valid public key of the group
    void agree(ObjectPath path, byte[] servicePublicKey) {
        var peer = new BigInteger(1, servicePublicKey);
        if (peer.compareTo(BigInteger.TWO) < 0 || peer.compareTo(PRIME.subtract(BigInteger.TWO)) > 0) {
            throw new IllegalArgumentException("The Secret Service sent an invalid public key");
        }
        var shared = padded(peer.modPow(privateKey, PRIME));
        try {
            this.key = new SecretKeySpec(hkdf(shared), "AES");
        } finally {
            Arrays.fill(shared, (byte) 0);
        }
        this.path = path;
    }

    /// {@return the HKDF-SHA256 of `secret` without salt or info, [#KEY_BYTES] long}
    static byte[] hkdf(byte[] secret) {
        try {
            var extract = Mac.getInstance("HmacSHA256");
            // A missing salt is a string of zeros as long as the hash
            extract.init(new SecretKeySpec(new byte[32], "HmacSHA256"));
            var pseudorandomKey = extract.doFinal(secret);
            var expand = Mac.getInstance("HmacSHA256");
            expand.init(new SecretKeySpec(pseudorandomKey, "HmacSHA256"));
            Arrays.fill(pseudorandomKey, (byte) 0);
            var block = expand.doFinal(new byte[]{1});
            try {
                return Arrays.copyOf(block, KEY_BYTES);
            } finally {
                Arrays.fill(block, (byte) 0);
            }
        } catch (GeneralSecurityException exception) {
            throw new IllegalStateException("HMAC-SHA256 is unavailable", exception);
        }
    }

    /// {@return `value` as an unsigned big-endian array of [#PRIME_BYTES] bytes}
    private static byte[] padded(BigInteger value) {
        var bytes = unsigned(value);
        var padded = new byte[PRIME_BYTES];
        System.arraycopy(bytes, 0, padded, PRIME_BYTES - bytes.length, bytes.length);
        Arrays.fill(bytes, (byte) 0);
        return padded;
    }

    private static byte[] unsigned(BigInteger value) {
        var bytes = value.toByteArray();
        return bytes[0] == 0 && bytes.length > 1 ? Arrays.copyOfRange(bytes, 1, bytes.length) : bytes;
    }

    /// {@return the session's object path}
    ObjectPath path() {
        return path;
    }

    /// {@return the `(oayays)` secret struct that carries `secret`, its value a new array the caller erases}
    Object[] seal(byte[] secret) {
        if (key == null) {
            return new Object[]{path, new byte[0], secret.clone(), CONTENT_TYPE};
        }
        var iv = new byte[IV_BYTES];
        random.nextBytes(iv);
        try {
            var cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));
            return new Object[]{path, iv, cipher.doFinal(secret), CONTENT_TYPE};
        } catch (GeneralSecurityException exception) {
            throw new IllegalStateException("AES-128-CBC is unavailable", exception);
        }
    }

    /// {@return the secret carried by the `parameters` and `value` of a secret struct, in a new array the caller erases}
    ///
    /// @throws IllegalArgumentException if they do not decrypt
    byte[] open(byte[] parameters, byte[] value) {
        if (key == null) {
            return value.clone();
        }
        try {
            var cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(parameters));
            return cipher.doFinal(value);
        } catch (GeneralSecurityException exception) {
            throw new IllegalArgumentException("The Secret Service sent a secret that does not decrypt", exception);
        }
    }
}

# Coffer

A keyring for the secrets of Java applications: keys, tokens and passwords that the operating system keeps for the
user, in pure Java, with no native library to ship.

```java
try (var coffer = Coffer.open("myapp")) {
    if (coffer.protection() != Protection.OPERATING_SYSTEM) {
        // Only file permissions keep other users out
    }
    byte[] key = coffer.readOrCreate("database-key", 32);
}
```

## Backends

| Backend | System | How the secrets are kept |
|---|---|---|
| `WINDOWS_DATA_PROTECTION` | Windows | Files sealed by `CryptProtectData` in user scope, bound to their name |
| `MACOS_KEYCHAIN` | macOS | Generic passwords of the default keychain |
| `SECRET_SERVICE` | Linux, the BSDs | Items of the freedesktop Secret Service (GNOME Keyring, KeePassXC, KWallet), over D-Bus |
| `FILE` | everywhere | Owner-only files, unencrypted |

A new namespace uses the system's keyring, or files where it cannot be reached; `protection()` says which kind it got,
so an application can refuse the weaker one. The first secret records the namespace's backend in its directory, and
every later coffer of the namespace uses it: a keyring that cannot be reached fails `build()` instead of starting an
empty keyring elsewhere.

A coffer only touches the secrets its namespace created. `readOrCreate` creates a secret once, even when threads and
processes race for it.

## Native access

The Windows and macOS backends call the operating system through the Foreign Function and Memory API, with bindings
[jextract](https://github.com/openjdk/jextract) generates. Run applications that use them with
`--enable-native-access=com.github.auties00.coffer` (or `ALL-UNNAMED` on the class path) to avoid the JDK's warning.
The Secret Service backend speaks D-Bus in Java, with no native access; it reaches buses that listen on a socket path,
as every systemd session's does, but not those that listen only on an abstract socket.

## Building

Java 26 and Maven: `mvn verify`. The bindings under `backend/windows/ffm` and `backend/macos/ffm` are generated from
`bindings/` by the `Bindings` workflow, on Windows and macOS runners, and committed; run it after changing a header or
an argument file.

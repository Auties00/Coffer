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
| `SECRET_SERVICE` | Linux, FreeBSD | Items of the freedesktop Secret Service (GNOME Keyring, KeePassXC, KWallet 5.97 and later), over D-Bus |
| `FILE` | everywhere | Owner-only files, unencrypted |

A new namespace uses the system's keyring, or files where it cannot be reached; `protection()` says which kind it got,
so an application can refuse the weaker one. The first secret records the namespace's backend in its directory, and
every later coffer of the namespace uses it: a keyring that cannot be reached fails `build()` instead of starting an
empty keyring elsewhere.

A coffer only touches the secrets its namespace created. `readOrCreate` creates a secret once, even when threads and
processes race for it.

`moveTo(backend)` moves a namespace's secrets, for instance from files to the system's keyring once one is available.
It copies them, records the new backend, then deletes the old copies; a move cut short is finished by the next coffer
of the namespace, and coffers that other processes opened before the move refuse to write after it.

## Asking the user

By default a coffer never waits on the user: an operation that needs a locked keyring unlocked, or the user's consent,
fails with `LOCKED`. `Coffer.builder(namespace).interactive(timeout)` lets it ask. The Secret Service's prompt is
bounded by `timeout`; the macOS Keychain's dialog stays open as long as the user takes. On macOS a coffer that may not
ask turns the keychain's user interaction off around each of its calls, the only switch the file-based keychain obeys,
and that switch is process-wide.

## Native access

The Windows and macOS backends call the operating system through the Foreign Function and Memory API, with bindings
[jextract](https://github.com/openjdk/jextract) generates. Run applications that use them with
`--enable-native-access=com.github.auties00.coffer` (or `ALL-UNNAMED` on the class path) to avoid the JDK's warning.
The Secret Service backend speaks D-Bus in Java, and needs no native access for a bus that listens on a socket path,
as every systemd session's does; a bus that listens only on a Linux abstract socket, as `dbus-daemon` does on
distributions without systemd's user bus, is reached through libc, which needs it.

## Tested on

CI runs every test against the real keyring of Windows, macOS, Linux (with the session bus on a socket path, and on an
abstract socket only) and FreeBSD, then locks the keyring and checks that a coffer that may not ask the user fails
with `LOCKED` rather than wait.

## Building

Java 26 and Maven: `mvn verify`. The bindings under `backend/windows/ffm`, `backend/macos/ffm` and `backend/dbus/ffm`
are generated from `bindings/` by the `Bindings` workflow, on Windows, macOS and Linux runners, and committed; run it
after changing a header or an argument file.

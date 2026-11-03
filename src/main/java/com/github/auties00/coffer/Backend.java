package com.github.auties00.coffer;

/// Where a [Coffer] keeps its secrets.
public enum Backend {
    /// Files encrypted by the Windows Data Protection API in user scope, under a key Windows derives from the user's
    /// logon credentials: another user, or anyone who copies the files to another computer, cannot decrypt them.
    WINDOWS_DATA_PROTECTION(Protection.OPERATING_SYSTEM),
    /// Generic passwords in the user's default macOS Keychain, encrypted under the keychain's password.
    MACOS_KEYCHAIN(Protection.OPERATING_SYSTEM),
    /// Items of the freedesktop Secret Service (GNOME Keyring, KeePassXC, KWallet), reached over the D-Bus session
    /// bus and stored in its default collection, encrypted under the collection's password.
    SECRET_SERVICE(Protection.OPERATING_SYSTEM),
    /// Files that only the user may read, unencrypted.
    FILE(Protection.FILE_PERMISSIONS);

    private final Protection protection;

    Backend(Protection protection) {
        this.protection = protection;
    }

    /// {@return how the backend protects its secrets}
    public Protection protection() {
        return protection;
    }
}

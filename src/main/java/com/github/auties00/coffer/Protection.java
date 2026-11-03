package com.github.auties00.coffer;

/// How a [Backend] protects the secrets it keeps.
public enum Protection {
    /// The operating system encrypts the secrets under a key of the user's: another user cannot read them, and neither
    /// can anyone who reads the disk without the user's credentials. Any process the user runs may still ask for them.
    OPERATING_SYSTEM,
    /// Only file permissions keep other users out: an administrator, a backup or anyone who reads the disk reads the
    /// secrets.
    FILE_PERMISSIONS
}

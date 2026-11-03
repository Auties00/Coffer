package com.github.auties00.coffer.backend.dbus;

import java.util.Objects;

/// A D-Bus object path: the `o` type.
///
/// @param value the path, such as `/org/freedesktop/secrets`
public record ObjectPath(String value) {
    /// The path `/`, which the Secret Service returns for "no object".
    public static final ObjectPath ROOT = new ObjectPath("/");

    /// Checks the path.
    ///
    /// @throws IllegalArgumentException if `value` does not start with `/`
    public ObjectPath {
        Objects.requireNonNull(value, "value");
        if (!value.startsWith("/")) {
            throw new IllegalArgumentException("An object path starts with /: " + value);
        }
    }

    /// {@return whether this is the path `/`}
    public boolean isRoot() {
        return value.equals("/");
    }

    @Override
    public String toString() {
        return value;
    }
}

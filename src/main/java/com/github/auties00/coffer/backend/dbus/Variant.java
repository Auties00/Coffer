package com.github.auties00.coffer.backend.dbus;

import java.util.Objects;

/// A D-Bus variant: a value with its own signature, the `v` type.
///
/// @param signature the single complete type of the value
/// @param value the value, as [DBusWriter] takes it and [DBusReader] returns it
public record Variant(String signature, Object value) {
    /// Checks the components.
    public Variant {
        Objects.requireNonNull(signature, "signature");
        Objects.requireNonNull(value, "value");
    }
}

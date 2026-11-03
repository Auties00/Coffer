package com.github.auties00.coffer.backend.dbus;

import java.io.IOException;

/// The error a D-Bus peer answered a method call with.
public final class DBusErrorException extends IOException {
    private final String name;

    DBusErrorException(String name, String message) {
        super(name + (message == null ? "" : ": " + message));
        this.name = name;
    }

    /// {@return the error's name, such as `org.freedesktop.Secret.Error.IsLocked`}
    public String name() {
        return name;
    }
}

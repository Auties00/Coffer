package com.github.auties00.coffer.backend.dbus;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HexFormat;
import java.util.List;

/// The address of a D-Bus server that a client can connect to: a Unix socket, named by a path or, on Linux, by an
/// abstract name.
///
/// @spec https://dbus.freedesktop.org/doc/dbus-specification.html D-Bus Specification
sealed interface DBusAddress permits DBusAddress.UnixPath, DBusAddress.UnixAbstract {
    /// A socket named by a path in the file system.
    ///
    /// @param path the socket
    record UnixPath(Path path) implements DBusAddress {
    }

    /// A Linux abstract socket, named outside the file system.
    ///
    /// @param name the name, without the leading NUL that marks it abstract
    record UnixAbstract(String name) implements DBusAddress {
    }

    /// {@return the addresses in `addresses`, a `;`-separated list, that name a socket to connect to}
    ///
    /// Path addresses come first, and otherwise the list keeps its order: they reach the same bus as the abstract
    /// ones, without the native access an abstract socket needs. Addresses of other transports, and the listening-only
    /// `unix` forms (`dir`, `tmpdir`, `runtime`), are left out.
    static List<DBusAddress> parse(String addresses) {
        var parsed = new ArrayList<DBusAddress>();
        for (var address : addresses.split(";")) {
            if (!address.startsWith("unix:")) {
                continue;
            }
            for (var parameter : address.substring(5).split(",")) {
                var separator = parameter.indexOf('=');
                if (separator <= 0) {
                    continue;
                }
                var value = unescape(parameter.substring(separator + 1));
                switch (parameter.substring(0, separator)) {
                    case "path" -> parsed.add(new UnixPath(Path.of(value)));
                    case "abstract" -> parsed.add(new UnixAbstract(value));
                    default -> {
                    }
                }
            }
        }
        parsed.sort(Comparator.comparingInt(candidate -> candidate instanceof UnixPath ? 0 : 1));
        return parsed;
    }

    /// {@return `value` with the `%xx` escapes of a D-Bus address undone}
    static String unescape(String value) {
        var bytes = new ByteArrayOutputStream();
        for (var i = 0; i < value.length(); i++) {
            var c = value.charAt(i);
            if (c == '%' && i + 2 < value.length()) {
                bytes.write(HexFormat.fromHexDigits(value, i + 1, i + 3));
                i += 2;
            } else {
                bytes.write(c);
            }
        }
        return bytes.toString(StandardCharsets.UTF_8);
    }
}

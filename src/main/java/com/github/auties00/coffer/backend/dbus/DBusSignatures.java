package com.github.auties00.coffer.backend.dbus;

import java.util.ArrayList;
import java.util.List;

/// D-Bus type signatures: splitting them into single complete types and the alignment of each type.
///
/// @spec https://dbus.freedesktop.org/doc/dbus-specification.html D-Bus Specification
final class DBusSignatures {
    private DBusSignatures() {
    }

    /// {@return the single complete types of `signature`, in order}
    ///
    /// @throws IllegalArgumentException if `signature` is malformed
    static List<String> split(String signature) {
        var types = new ArrayList<String>();
        var index = 0;
        while (index < signature.length()) {
            var end = end(signature, index);
            types.add(signature.substring(index, end));
            index = end;
        }
        return types;
    }

    /// {@return the index past the single complete type that starts at `start` of `signature`}
    ///
    /// @throws IllegalArgumentException if no complete type starts there
    static int end(String signature, int start) {
        if (start >= signature.length()) {
            throw new IllegalArgumentException("The signature " + signature + " ends inside a type");
        }
        return switch (signature.charAt(start)) {
            case 'y', 'b', 'n', 'q', 'i', 'u', 'x', 't', 'd', 's', 'o', 'g', 'v', 'h' -> start + 1;
            case 'a' -> {
                if (start + 1 < signature.length() && signature.charAt(start + 1) == '{') {
                    var key = start + 2;
                    var value = end(signature, key);
                    var close = end(signature, value);
                    if (close >= signature.length() || signature.charAt(close) != '}') {
                        throw new IllegalArgumentException("The signature " + signature + " has an unclosed dict entry");
                    }
                    yield close + 1;
                }
                yield end(signature, start + 1);
            }
            case '(' -> {
                var index = start + 1;
                while (index < signature.length() && signature.charAt(index) != ')') {
                    index = end(signature, index);
                }
                if (index >= signature.length()) {
                    throw new IllegalArgumentException("The signature " + signature + " has an unclosed struct");
                }
                yield index + 1;
            }
            default -> throw new IllegalArgumentException("The signature " + signature + " has an unknown type " + signature.charAt(start));
        };
    }

    /// {@return the alignment, in bytes, of a value whose type starts with `type`}
    static int alignment(char type) {
        return switch (type) {
            case 'y', 'g', 'v' -> 1;
            case 'n', 'q' -> 2;
            case 'b', 'i', 'u', 's', 'o', 'a', 'h' -> 4;
            case 'x', 't', 'd', '(', '{' -> 8;
            default -> throw new IllegalArgumentException("Unknown type " + type);
        };
    }
}

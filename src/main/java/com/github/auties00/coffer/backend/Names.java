package com.github.auties00.coffer.backend;

import java.util.regex.Pattern;

/// The rules for namespaces and the names of secrets.
///
/// Both are lowercase so that every backend tells the same names apart: a file system that ignores case would merge
/// names a keyring keeps apart.
public final class Names {
    private static final Pattern NAMESPACE = Pattern.compile("[a-z0-9][a-z0-9._-]{0,63}");
    private static final Pattern NAME = Pattern.compile("[a-z0-9][a-z0-9._-]{0,127}");

    private Names() {
    }

    /// {@return `namespace` if it is valid}
    ///
    /// @throws IllegalArgumentException if it is not
    public static String checkNamespace(String namespace) {
        if (namespace == null || !NAMESPACE.matcher(namespace).matches()) {
            throw new IllegalArgumentException("A namespace is 1 to 64 of [a-z0-9._-], starting with a letter or digit: " + namespace);
        }
        return namespace;
    }

    /// {@return `name` if it is valid}
    ///
    /// @throws IllegalArgumentException if it is not
    public static String checkName(String name) {
        if (!isName(name)) {
            throw new IllegalArgumentException("A secret's name is 1 to 128 of [a-z0-9._-], starting with a letter or digit: " + name);
        }
        return name;
    }

    /// {@return whether `name` is a valid name}
    public static boolean isName(String name) {
        return name != null && NAME.matcher(name).matches();
    }
}

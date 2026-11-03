package com.github.auties00.coffer;

import java.nio.file.Path;
import java.util.HexFormat;

/// A child process for the tests: creates or reads the secret `shared` of a namespace and prints it in hex.
///
/// Arguments: the namespace, its directory and the backend.
public final class CofferChild {
    private CofferChild() {
    }

    public static void main(String[] arguments) {
        try (var coffer = Coffer.builder(arguments[0]).directory(Path.of(arguments[1])).backends(Backend.valueOf(arguments[2])).build()) {
            System.out.println(HexFormat.of().formatHex(coffer.readOrCreate("shared", 32)));
        }
    }
}

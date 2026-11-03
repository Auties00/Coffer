package com.github.auties00.coffer.backend;

import java.nio.file.Path;
import java.util.Locale;

/// The operating system the process runs on, and where it keeps per-user data.
public enum Platform {
    WINDOWS,
    MACOS,
    /// Linux, the BSDs and every other system with a freedesktop session.
    UNIX;

    private static final Platform CURRENT = detect();

    private static Platform detect() {
        var name = System.getProperty("os.name", "").toLowerCase(Locale.ROOT);
        if (name.startsWith("windows")) {
            return WINDOWS;
        }
        if (name.contains("mac") || name.contains("darwin")) {
            return MACOS;
        }
        return UNIX;
    }

    /// {@return the platform of this process}
    public static Platform current() {
        return CURRENT;
    }

    /// {@return the directory the user's applications keep their data in}
    public Path dataDirectory() {
        var home = System.getProperty("user.home");
        return switch (this) {
            case WINDOWS -> {
                var local = System.getenv("LOCALAPPDATA");
                yield local != null && !local.isBlank() ? Path.of(local) : Path.of(home, "AppData", "Local");
            }
            case MACOS -> Path.of(home, "Library", "Application Support");
            case UNIX -> {
                var data = System.getenv("XDG_DATA_HOME");
                // The specification ignores a relative value
                yield data != null && !data.isBlank() && Path.of(data).isAbsolute() ? Path.of(data) : Path.of(home, ".local", "share");
            }
        };
    }
}

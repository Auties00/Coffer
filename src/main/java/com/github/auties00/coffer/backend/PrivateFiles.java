package com.github.auties00.coffer.backend;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.AclEntry;
import java.nio.file.attribute.AclEntryFlag;
import java.nio.file.attribute.AclEntryPermission;
import java.nio.file.attribute.AclEntryType;
import java.nio.file.attribute.AclFileAttributeView;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.nio.file.attribute.UserPrincipal;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/// Creates the files and directories of a coffer so that only the user running the process can read them.
///
/// On a POSIX file system a directory is `rwx------` and a file `rw-------`, set atomically as they are created. On a
/// file system with access control lists (NTFS), the list holds only allow entries for the owner, the user running the
/// process and the `SYSTEM` account, and a directory's entries are inherited by what is created in it.
public final class PrivateFiles {
    private static final System.Logger LOGGER = System.getLogger(PrivateFiles.class.getName());
    private static final Set<PosixFilePermission> PRIVATE_DIRECTORY = PosixFilePermissions.fromString("rwx------");
    private static final Set<PosixFilePermission> PRIVATE_FILE = PosixFilePermissions.fromString("rw-------");
    // The account Windows backup and indexing services run as
    private static final String SYSTEM_ACCOUNT = "SYSTEM";

    private PrivateFiles() {
    }

    /// Creates `directory` and its missing parents, restricting each directory this call creates to the user.
    ///
    /// Directories that already exist keep their permissions.
    public static void createDirectories(Path directory) throws IOException {
        var absolute = directory.toAbsolutePath();
        if (Files.isDirectory(absolute)) {
            return;
        }
        var missing = new ArrayList<Path>();
        for (var current = absolute; current != null && Files.notExists(current, LinkOption.NOFOLLOW_LINKS); current = current.getParent()) {
            missing.add(current);
        }
        for (var index = missing.size() - 1; index >= 0; index--) {
            var created = missing.get(index);
            try {
                if (posix(created)) {
                    Files.createDirectory(created, PosixFilePermissions.asFileAttribute(PRIVATE_DIRECTORY));
                } else {
                    Files.createDirectory(created);
                    restrict(created, true);
                }
            } catch (FileAlreadyExistsException exception) {
                if (!Files.isDirectory(created)) {
                    throw exception;
                }
            }
        }
    }

    /// Replaces `file` with `content` atomically: a reader sees the old content or the new one, never a part.
    ///
    /// The content is forced to the device before it takes the file's name, and the directory after.
    public static void write(Path file, byte[] content) throws IOException {
        var directory = file.toAbsolutePath().getParent();
        var temporary = posix(directory)
                ? Files.createTempFile(directory, ".coffer", ".tmp", PosixFilePermissions.asFileAttribute(PRIVATE_FILE))
                : Files.createTempFile(directory, ".coffer", ".tmp");
        try {
            if (!posix(directory)) {
                restrict(temporary, false);
            }
            try (var channel = FileChannel.open(temporary, StandardOpenOption.WRITE)) {
                var buffer = ByteBuffer.wrap(content);
                while (buffer.hasRemaining()) {
                    channel.write(buffer);
                }
                channel.force(true);
            }
            try {
                Files.move(temporary, file, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
            } catch (AtomicMoveNotSupportedException _) {
                Files.move(temporary, file, StandardCopyOption.REPLACE_EXISTING);
            }
        } finally {
            Files.deleteIfExists(temporary);
        }
        forceDirectory(directory);
    }

    /// Forces the entries of `directory` to the device, where the system allows it: Windows opens no directory as a
    /// file, and makes renames durable with its own journal.
    public static void forceDirectory(Path directory) throws IOException {
        if (Platform.current() == Platform.WINDOWS) {
            return;
        }
        try (var channel = FileChannel.open(directory, StandardOpenOption.READ)) {
            channel.force(true);
        }
    }

    private static boolean posix(Path path) {
        return path.getFileSystem().supportedFileAttributeViews().contains("posix");
    }

    private static void restrict(Path path, boolean directory) {
        try {
            var view = Files.getFileAttributeView(path, AclFileAttributeView.class, LinkOption.NOFOLLOW_LINKS);
            if (view == null) {
                return;
            }
            var flags = directory
                    ? EnumSet.of(AclEntryFlag.FILE_INHERIT, AclEntryFlag.DIRECTORY_INHERIT)
                    : EnumSet.noneOf(AclEntryFlag.class);
            var entries = new ArrayList<AclEntry>();
            for (var principal : trusted(path, view.getOwner())) {
                entries.add(AclEntry.newBuilder()
                        .setType(AclEntryType.ALLOW)
                        .setPrincipal(principal)
                        .setPermissions(EnumSet.allOf(AclEntryPermission.class))
                        .setFlags(flags)
                        .build());
            }
            view.setAcl(entries);
        } catch (IOException | UnsupportedOperationException | SecurityException exception) {
            // A file that cannot be restricted is still better written than lost
            LOGGER.log(System.Logger.Level.WARNING, "Could not restrict " + path + " to the current user", exception);
        }
    }

    private static Set<UserPrincipal> trusted(Path path, UserPrincipal owner) {
        var principals = new LinkedHashSet<UserPrincipal>();
        principals.add(owner);
        var lookup = path.getFileSystem().getUserPrincipalLookupService();
        for (var name : List.of(System.getProperty("user.name", ""), SYSTEM_ACCOUNT)) {
            if (name.isBlank()) {
                continue;
            }
            try {
                principals.add(lookup.lookupPrincipalByName(name));
            } catch (IOException | UnsupportedOperationException _) {
                // A principal that does not resolve is left out
            }
        }
        return principals;
    }
}

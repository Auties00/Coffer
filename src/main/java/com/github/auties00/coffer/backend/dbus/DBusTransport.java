package com.github.auties00.coffer.backend.dbus;

import java.io.IOException;

/// The byte stream of a connection to a D-Bus server.
///
/// Deadlines are [System#nanoTime()] values. A transport is not safe for concurrent use: [DBusConnection] serializes
/// its calls.
sealed interface DBusTransport extends AutoCloseable permits PathTransport, AbstractSocketTransport {
    /// {@return a transport connected to `address`}
    ///
    /// @throws IOException if the server cannot be reached, or `address` is an abstract socket and the system is not
    ///                     Linux
    static DBusTransport connect(DBusAddress address) throws IOException {
        return switch (address) {
            case DBusAddress.UnixPath(var path) -> PathTransport.connect(path);
            case DBusAddress.UnixAbstract(var name) -> {
                // Checked before the transport's class loads, since its static handles bind the Linux C library
                if (!System.getProperty("os.name", "").equals("Linux")) {
                    throw new IOException("Abstract sockets exist on Linux only: unix:abstract=" + name);
                }
                yield AbstractSocketTransport.connect(name);
            }
        };
    }

    /// Reads `length` bytes into `target` from `offset`.
    ///
    /// @throws java.net.SocketTimeoutException if they have not all come by `deadline`
    /// @throws IOException if the server closes the connection, or the socket fails
    void readFully(byte[] target, int offset, int length, long deadline) throws IOException;

    /// Writes every byte of `source`.
    ///
    /// @throws java.net.SocketTimeoutException if they cannot all be written by `deadline`
    /// @throws IOException if the server closes the connection, or the socket fails
    void writeFully(byte[] source, long deadline) throws IOException;

    /// Closes the connection.
    @Override
    void close() throws IOException;
}

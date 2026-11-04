package com.github.auties00.coffer.backend.dbus;

import java.io.IOException;
import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.net.SocketTimeoutException;
import java.net.StandardProtocolFamily;
import java.net.UnixDomainSocketAddress;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.nio.channels.SocketChannel;
import java.nio.file.Path;

/// A [DBusTransport] over a Unix socket named by a path, through a non-blocking [SocketChannel].
///
/// Bytes go through a native staging buffer of the transport's own, erased after each use: given a heap buffer, the
/// channel would copy it into a temporary direct buffer of the JDK's, which keeps what a message carried, secrets
/// included, until the buffer is reused.
final class PathTransport implements DBusTransport {
    // The staging buffer; D-Bus messages are mostly far smaller
    private static final int BUFFER_LENGTH = 64 * 1024;

    private final SocketChannel channel;
    private final Selector selector;
    private final Arena arena;
    private final MemorySegment staging;

    private PathTransport(SocketChannel channel, Selector selector) {
        this.channel = channel;
        this.selector = selector;
        // Shared, since the connection is used by whichever thread holds its lock
        this.arena = Arena.ofShared();
        this.staging = arena.allocate(BUFFER_LENGTH);
    }

    /// {@return a transport connected to the socket at `path`}
    static PathTransport connect(Path path) throws IOException {
        var channel = SocketChannel.open(StandardProtocolFamily.UNIX);
        try {
            channel.connect(UnixDomainSocketAddress.of(path));
            channel.configureBlocking(false);
            var selector = Selector.open();
            try {
                channel.register(selector, SelectionKey.OP_READ);
                return new PathTransport(channel, selector);
            } catch (IOException | RuntimeException exception) {
                selector.close();
                throw exception;
            }
        } catch (IOException | RuntimeException exception) {
            channel.close();
            throw exception;
        }
    }

    @Override
    public void readFully(byte[] target, int offset, int length, long deadline) throws IOException {
        while (length > 0) {
            var buffer = staging.asSlice(0, Math.min(length, BUFFER_LENGTH)).asByteBuffer();
            var read = channel.read(buffer);
            if (read < 0) {
                throw new IOException("The D-Bus session bus closed the connection");
            }
            if (read == 0) {
                await(SelectionKey.OP_READ, deadline);
                continue;
            }
            MemorySegment.copy(staging, ValueLayout.JAVA_BYTE, 0, target, offset, read);
            staging.asSlice(0, read).fill((byte) 0);
            offset += read;
            length -= read;
        }
    }

    @Override
    public void writeFully(byte[] source, long deadline) throws IOException {
        var offset = 0;
        while (offset < source.length) {
            var chunk = Math.min(source.length - offset, BUFFER_LENGTH);
            MemorySegment.copy(source, offset, staging, ValueLayout.JAVA_BYTE, 0, chunk);
            try {
                var buffer = staging.asSlice(0, chunk).asByteBuffer();
                while (buffer.hasRemaining()) {
                    if (channel.write(buffer) == 0) {
                        await(SelectionKey.OP_WRITE, deadline);
                    }
                }
            } finally {
                staging.asSlice(0, chunk).fill((byte) 0);
            }
            offset += chunk;
        }
    }

    private void await(int operation, long deadline) throws IOException {
        var key = channel.keyFor(selector);
        key.interestOps(operation);
        var remaining = deadline - System.nanoTime();
        if (remaining <= 0 || selector.select(Math.max(1, remaining / 1_000_000)) == 0 && System.nanoTime() >= deadline) {
            throw new SocketTimeoutException("The D-Bus session bus did not answer in time");
        }
        selector.selectedKeys().clear();
    }

    @Override
    public void close() throws IOException {
        try {
            selector.close();
        } finally {
            try {
                channel.close();
            } finally {
                arena.close();
            }
        }
    }
}

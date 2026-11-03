package com.github.auties00.coffer.backend.dbus;

import java.io.IOException;
import java.net.SocketTimeoutException;
import java.net.StandardProtocolFamily;
import java.net.UnixDomainSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.nio.channels.SocketChannel;
import java.nio.file.Path;

/// A [DBusTransport] over a Unix socket named by a path, through a non-blocking [SocketChannel].
final class PathTransport implements DBusTransport {
    private final SocketChannel channel;
    private final Selector selector;

    private PathTransport(SocketChannel channel, Selector selector) {
        this.channel = channel;
        this.selector = selector;
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
        var buffer = ByteBuffer.wrap(target, offset, length);
        while (buffer.hasRemaining()) {
            var read = channel.read(buffer);
            if (read < 0) {
                throw new IOException("The D-Bus session bus closed the connection");
            }
            if (read == 0) {
                await(SelectionKey.OP_READ, deadline);
            }
        }
    }

    @Override
    public void writeFully(byte[] source, long deadline) throws IOException {
        var buffer = ByteBuffer.wrap(source);
        while (buffer.hasRemaining()) {
            if (channel.write(buffer) == 0) {
                await(SelectionKey.OP_WRITE, deadline);
            }
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
            channel.close();
        }
    }
}

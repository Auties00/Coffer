package com.github.auties00.coffer.backend.dbus;

import com.github.auties00.coffer.backend.CapturedCall;
import com.github.auties00.coffer.backend.dbus.ffm.Libc;
import com.github.auties00.coffer.backend.dbus.ffm.pollfd;
import com.github.auties00.coffer.backend.dbus.ffm.sockaddr_un;

import java.io.IOException;
import java.io.InterruptedIOException;
import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.net.SocketTimeoutException;
import java.nio.charset.StandardCharsets;

/// A [DBusTransport] over a Linux abstract socket, through the C library.
///
/// An abstract socket has a name outside the file system, and the JDK names Unix sockets by path only. A session bus
/// that listens on one alone, as `dbus-daemon` does on distributions without systemd's user bus, is reached through
/// libc instead, which needs native access for Coffer's module.
///
/// The socket blocks in `connect`, then is read and written with `MSG_DONTWAIT`, waiting in `poll` until it is ready.
/// A native wait would hold the carrier of a virtual thread, so a virtual thread polls without waiting and sleeps
/// between polls instead.
///
/// @spec https://man7.org/linux/man-pages/man7/unix.7.html unix(7)
final class AbstractSocketTransport implements DBusTransport {
    // The staging buffer between Java arrays and the socket; D-Bus messages are mostly far smaller
    private static final int BUFFER_LENGTH = 64 * 1024;
    // The longest sleep between two polls of a virtual thread, in milliseconds
    private static final long LONGEST_PAUSE = 50;
    private static final CapturedCall SOCKET = CapturedCall.of(Libc.socket$address(), Libc.socket$descriptor(), "errno");
    private static final CapturedCall CONNECT = CapturedCall.of(Libc.connect$address(), Libc.connect$descriptor(), "errno");
    private static final CapturedCall SEND = CapturedCall.of(Libc.send$address(), Libc.send$descriptor(), "errno");
    private static final CapturedCall RECV = CapturedCall.of(Libc.recv$address(), Libc.recv$descriptor(), "errno");
    private static final CapturedCall POLL = CapturedCall.of(Libc.poll$address(), Libc.poll$descriptor(), "errno");

    private final Arena arena;
    private final MemorySegment state;
    private final MemorySegment buffer;
    private final MemorySegment poll;
    private final int descriptor;
    private boolean closed;

    private AbstractSocketTransport(Arena arena, MemorySegment state, int descriptor) {
        this.arena = arena;
        this.state = state;
        this.descriptor = descriptor;
        this.buffer = arena.allocate(BUFFER_LENGTH);
        this.poll = pollfd.allocate(arena);
    }

    /// {@return a transport connected to the abstract socket `name`}
    static AbstractSocketTransport connect(String name) throws IOException {
        var bytes = name.getBytes(StandardCharsets.UTF_8);
        var path = sockaddr_un.sun_path$offset();
        // One byte of the path is the NUL that marks the name abstract
        if (1 + bytes.length > sockaddr_un.sun_path$layout().byteSize()) {
            throw new IOException("The abstract socket name is longer than Linux allows: " + name);
        }
        // Shared, since the connection is used by whichever thread holds its lock
        var arena = Arena.ofShared();
        try {
            var state = CapturedCall.state(arena);
            var descriptor = (int) SOCKET.invoke(state, Libc.AF_UNIX(), Libc.SOCK_STREAM() | Libc.SOCK_CLOEXEC(), 0);
            if (descriptor < 0) {
                throw failure("open a socket", SOCKET.error(state));
            }
            try {
                var address = sockaddr_un.allocate(arena);
                sockaddr_un.sun_family(address, (short) Libc.AF_UNIX());
                // The memory starts zeroed, so the path's first byte is already the NUL; the length, not a terminator,
                // ends the name
                MemorySegment.copy(bytes, 0, address, ValueLayout.JAVA_BYTE, path + 1, bytes.length);
                var connected = (int) CONNECT.invoke(state, descriptor, address, (int) (path + 1 + bytes.length));
                if (connected < 0) {
                    throw failure("connect to unix:abstract=" + name, CONNECT.error(state));
                }
                return new AbstractSocketTransport(arena, state, descriptor);
            } catch (IOException | RuntimeException exception) {
                Libc.close(descriptor);
                throw exception;
            }
        } catch (IOException | RuntimeException exception) {
            arena.close();
            throw exception;
        }
    }

    @Override
    public void readFully(byte[] target, int offset, int length, long deadline) throws IOException {
        ensureOpen();
        while (length > 0) {
            var wanted = Math.min(length, BUFFER_LENGTH);
            var read = (long) RECV.invoke(state, descriptor, buffer, (long) wanted, Libc.MSG_DONTWAIT());
            if (read > 0) {
                MemorySegment.copy(buffer, ValueLayout.JAVA_BYTE, 0, target, offset, (int) read);
                // Replies may carry secrets
                buffer.asSlice(0, read).fill((byte) 0);
                offset += (int) read;
                length -= (int) read;
            } else if (read == 0) {
                throw new IOException("The D-Bus session bus closed the connection");
            } else {
                retry("read from the D-Bus session bus", RECV.error(state), Libc.POLLIN(), deadline);
            }
        }
    }

    @Override
    public void writeFully(byte[] source, long deadline) throws IOException {
        ensureOpen();
        var offset = 0;
        while (offset < source.length) {
            var chunk = Math.min(source.length - offset, BUFFER_LENGTH);
            MemorySegment.copy(source, offset, buffer, ValueLayout.JAVA_BYTE, 0, chunk);
            try {
                // MSG_NOSIGNAL: a closed peer fails the call with EPIPE instead of killing the JVM with SIGPIPE
                var written = (long) SEND.invoke(state, descriptor, buffer, (long) chunk, Libc.MSG_NOSIGNAL() | Libc.MSG_DONTWAIT());
                if (written >= 0) {
                    offset += (int) written;
                } else {
                    retry("write to the D-Bus session bus", SEND.error(state), Libc.POLLOUT(), deadline);
                }
            } finally {
                buffer.asSlice(0, chunk).fill((byte) 0);
            }
        }
    }

    /// Waits, after a call failed with `error`, until the socket is ready for `events`.
    ///
    /// @throws IOException if `error` is not one a retry overcomes
    private void retry(String operation, int error, int events, long deadline) throws IOException {
        if (error == Libc.EINTR()) {
            return;
        }
        if (error != Libc.EAGAIN()) {
            throw failure(operation, error);
        }
        var virtual = Thread.currentThread().isVirtual();
        var pause = 1L;
        while (true) {
            var remaining = deadline - System.nanoTime();
            if (remaining <= 0) {
                throw new SocketTimeoutException("The D-Bus session bus did not answer in time");
            }
            var millis = Math.max(1, remaining / 1_000_000);
            pollfd.fd(poll, descriptor);
            pollfd.events(poll, (short) events);
            pollfd.revents(poll, (short) 0);
            var ready = (int) POLL.invoke(state, poll, 1L, virtual ? 0 : (int) Math.min(Integer.MAX_VALUE, millis));
            if (ready > 0) {
                return;
            }
            if (ready < 0 && POLL.error(state) != Libc.EINTR()) {
                throw failure("wait for the D-Bus session bus", POLL.error(state));
            }
            if (virtual && ready == 0) {
                try {
                    Thread.sleep(Math.min(pause, millis));
                } catch (InterruptedException exception) {
                    Thread.currentThread().interrupt();
                    throw new InterruptedIOException("Interrupted while waiting for the D-Bus session bus");
                }
                pause = Math.min(2 * pause, LONGEST_PAUSE);
            }
        }
    }

    private static IOException failure(String operation, int error) {
        return new IOException("Could not " + operation + ": errno " + error);
    }

    private void ensureOpen() throws IOException {
        if (closed) {
            throw new IOException("The connection to the D-Bus session bus is closed");
        }
    }

    @Override
    public void close() {
        if (!closed) {
            closed = true;
            try {
                Libc.close(descriptor);
            } finally {
                arena.close();
            }
        }
    }
}

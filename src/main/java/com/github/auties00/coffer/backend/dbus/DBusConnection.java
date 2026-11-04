package com.github.auties00.coffer.backend.dbus;

import java.io.IOException;
import java.net.SocketTimeoutException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayDeque;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;
import java.util.function.Predicate;

/// A connection to the D-Bus session bus, over its Unix domain socket, in Java.
///
/// It authenticates with the `EXTERNAL` mechanism, as the user that owns the process, and sends one call at a time:
/// [#call] waits for the reply, keeping the signals that arrive meanwhile for [#awaitSignal]. A bus named by a path is
/// reached through the JDK's socket channels; one listening on a Linux abstract socket only, through the C library.
///
/// It is safe for concurrent use; calls are serialized.
///
/// @spec https://dbus.freedesktop.org/doc/dbus-specification.html D-Bus Specification
public final class DBusConnection implements AutoCloseable {
    private static final String BUS = "org.freedesktop.DBus";
    private static final ObjectPath BUS_PATH = new ObjectPath("/org/freedesktop/DBus");
    // The default timeout of the reference implementation
    private static final Duration CALL_TIMEOUT = Duration.ofSeconds(25);
    private static final int MAX_SIGNALS = 256;

    private final DBusTransport transport;
    private final Object lock;
    private final ArrayDeque<DBusMessage> signals;
    private int serial;

    private DBusConnection(DBusTransport transport) {
        this.transport = transport;
        this.lock = new Object();
        this.signals = new ArrayDeque<>();
    }

    /// {@return a connection to the session bus `DBUS_SESSION_BUS_ADDRESS` names, or `$XDG_RUNTIME_DIR/bus`}
    ///
    /// @throws IOException if no address names a reachable bus
    public static DBusConnection openSessionBus() throws IOException {
        var variable = System.getenv("DBUS_SESSION_BUS_ADDRESS");
        if (variable != null && !variable.isBlank()) {
            return open(variable);
        }
        var runtime = System.getenv("XDG_RUNTIME_DIR");
        if (runtime == null || runtime.isBlank()) {
            throw new IOException("No D-Bus session bus address: DBUS_SESSION_BUS_ADDRESS and XDG_RUNTIME_DIR are unset");
        }
        return open(List.of(new DBusAddress.UnixPath(Path.of(runtime, "bus"))));
    }

    /// {@return a connection to the first bus of `addresses`, a D-Bus address list, that can be reached}
    ///
    /// @throws IOException if no address names a reachable bus
    static DBusConnection open(String addresses) throws IOException {
        var parsed = DBusAddress.parse(addresses);
        if (parsed.isEmpty()) {
            throw new IOException("The D-Bus address names no Unix socket to connect to: " + addresses);
        }
        return open(parsed);
    }

    private static DBusConnection open(List<DBusAddress> addresses) throws IOException {
        IOException failure = null;
        for (var address : addresses) {
            try {
                return open(address);
            } catch (IOException exception) {
                if (failure == null) {
                    failure = exception;
                } else {
                    failure.addSuppressed(exception);
                }
            }
        }
        throw failure;
    }

    private static DBusConnection open(DBusAddress address) throws IOException {
        var connection = new DBusConnection(DBusTransport.connect(address));
        try {
            connection.authenticate();
            connection.call(BUS, BUS_PATH, BUS, "Hello", "");
            return connection;
        } catch (IOException | RuntimeException exception) {
            connection.close();
            throw exception;
        }
    }

    /// Authenticates as the user that owns the process, with the `EXTERNAL` mechanism.
    private void authenticate() throws IOException {
        var deadline = System.nanoTime() + CALL_TIMEOUT.toNanos();
        var uid = HexFormat.of().formatHex(Long.toString(uid()).getBytes(StandardCharsets.US_ASCII));
        send(("\0AUTH EXTERNAL " + uid + "\r\n").getBytes(StandardCharsets.US_ASCII), deadline);
        var line = readLine(deadline);
        if (!line.startsWith("OK ")) {
            throw new IOException("The D-Bus session bus refused the authentication: " + line);
        }
        send("BEGIN\r\n".getBytes(StandardCharsets.US_ASCII), deadline);
    }

    /// {@return the user id that owns the process, which owns the files it creates}
    private static long uid() throws IOException {
        var probe = Files.createTempFile("coffer", ".uid");
        try {
            return ((Number) Files.getAttribute(probe, "unix:uid")).longValue();
        } catch (UnsupportedOperationException | IllegalArgumentException exception) {
            throw new IOException("The user id of the process cannot be read on this system", exception);
        } finally {
            Files.deleteIfExists(probe);
        }
    }

    private String readLine(long deadline) throws IOException {
        var line = new StringBuilder();
        var one = new byte[1];
        while (true) {
            receiveFully(one, 0, 1, deadline);
            if (one[0] == '\n' && !line.isEmpty() && line.charAt(line.length() - 1) == '\r') {
                line.setLength(line.length() - 1);
                return line.toString();
            }
            if (line.length() > 16_384) {
                throw new IOException("The D-Bus session bus sent an authentication line that does not end");
            }
            line.append((char) (one[0] & 0xFF));
        }
    }

    /// Calls `member` of `interfaceName` on the object `path` of `destination` and waits for the reply.
    ///
    /// @return the reply
    /// @throws DBusErrorException if the reply is an error
    /// @throws IOException if the bus cannot be reached, or no reply comes within 25 seconds
    public DBusMessage call(String destination, ObjectPath path, String interfaceName, String member, String signature, Object... arguments) throws IOException {
        var message = DBusMessage.call(destination, path, interfaceName, member, signature, arguments);
        synchronized (lock) {
            var sent = ++serial;
            var deadline = System.nanoTime() + CALL_TIMEOUT.toNanos();
            var frame = message.encode(sent);
            try {
                send(frame, deadline);
            } finally {
                // A call may carry a secret, encrypted or in the clear
                Arrays.fill(frame, (byte) 0);
                Arrays.fill(message.body(), (byte) 0);
            }
            while (true) {
                var received = receive(deadline);
                if ((received.type() == DBusMessage.METHOD_RETURN || received.type() == DBusMessage.ERROR) && received.replySerial() == sent) {
                    if (received.type() == DBusMessage.ERROR) {
                        var details = received.arguments();
                        throw new DBusErrorException(received.errorName(), details.length > 0 && details[0] instanceof String text ? text : null);
                    }
                    return received;
                }
                keep(received);
            }
        }
    }

    /// Asks the bus to route the signals `rule` matches to this connection.
    public void addMatch(String rule) throws IOException {
        call(BUS, BUS_PATH, BUS, "AddMatch", "s", rule);
    }

    /// Waits for a signal `matcher` accepts, among those kept and those still to come.
    ///
    /// @throws SocketTimeoutException if none comes within `timeout`
    public DBusMessage awaitSignal(Predicate<DBusMessage> matcher, Duration timeout) throws IOException {
        synchronized (lock) {
            for (var iterator = signals.iterator(); iterator.hasNext(); ) {
                var signal = iterator.next();
                if (matcher.test(signal)) {
                    iterator.remove();
                    return signal;
                }
            }
            var deadline = System.nanoTime() + timeout.toNanos();
            while (true) {
                var received = receive(deadline);
                if (received.type() == DBusMessage.SIGNAL && matcher.test(received)) {
                    return received;
                }
                keep(received);
            }
        }
    }

    private void keep(DBusMessage received) {
        // Signals wait for awaitSignal; replies to calls given up on, and calls to this connection, are dropped
        if (received.type() == DBusMessage.SIGNAL) {
            if (signals.size() == MAX_SIGNALS) {
                signals.removeFirst();
            }
            signals.addLast(received);
        }
    }

    private DBusMessage receive(long deadline) throws IOException {
        var start = new byte[16];
        receiveFully(start, 0, start.length, deadline);
        int headerLength;
        int bodyLength;
        try {
            headerLength = DBusMessage.headerLength(start);
            bodyLength = DBusMessage.bodyLength(start);
        } catch (IllegalArgumentException exception) {
            throw new IOException("The D-Bus session bus sent a malformed message", exception);
        }
        if ((long) headerLength + bodyLength > DBusMessage.MAX_LENGTH) {
            throw new IOException("The D-Bus session bus sent a message longer than the specification allows");
        }
        var header = Arrays.copyOf(start, headerLength);
        receiveFully(header, start.length, headerLength - start.length, deadline);
        var body = new byte[bodyLength];
        receiveFully(body, 0, bodyLength, deadline);
        try {
            return DBusMessage.decode(header, body);
        } catch (IllegalArgumentException | ClassCastException exception) {
            throw new IOException("The D-Bus session bus sent a malformed message", exception);
        }
    }

    private void receiveFully(byte[] target, int offset, int length, long deadline) throws IOException {
        transport.readFully(target, offset, length, deadline);
    }

    private void send(byte[] message, long deadline) throws IOException {
        transport.writeFully(message, deadline);
    }

    /// Closes the connection, once the call in progress, if any, has returned.
    @Override
    public void close() throws IOException {
        synchronized (lock) {
            transport.close();
        }
    }
}

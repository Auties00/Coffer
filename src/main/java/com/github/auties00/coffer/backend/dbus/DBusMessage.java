package com.github.auties00.coffer.backend.dbus;

import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

/// A D-Bus message: its type, serial, header fields and body.
///
/// ```text
/// 0   endianness ('l' or 'B'), type, flags, protocol version 1
/// 4   body length, 4 bytes
/// 8   serial, 4 bytes
/// 12  header fields, an a(yv) array
///     padding to 8, then the body
/// ```
///
/// @param type [#METHOD_CALL], [#METHOD_RETURN], [#ERROR] or [#SIGNAL]
/// @param flags the flags
/// @param serial the serial its sender gave it
/// @param fields the header fields by code, their values unwrapped from their variants
/// @param body the marshalled body
/// @param order the byte order of the body
/// @spec https://dbus.freedesktop.org/doc/dbus-specification.html D-Bus Specification
public record DBusMessage(int type, int flags, int serial, Map<Integer, Object> fields, byte[] body, ByteOrder order) {
    public static final int METHOD_CALL = 1;
    public static final int METHOD_RETURN = 2;
    public static final int ERROR = 3;
    public static final int SIGNAL = 4;

    static final int PATH = 1;
    static final int INTERFACE = 2;
    static final int MEMBER = 3;
    static final int ERROR_NAME = 4;
    static final int REPLY_SERIAL = 5;
    static final int DESTINATION = 6;
    static final int SENDER = 7;
    static final int SIGNATURE = 8;

    /// The longest message the specification allows.
    static final int MAX_LENGTH = 1 << 27;

    /// {@return a method call, its body marshalled from `arguments` as `signature`}
    static DBusMessage call(String destination, ObjectPath path, String interfaceName, String member, String signature, Object... arguments) {
        var fields = new TreeMap<Integer, Object>();
        fields.put(PATH, path);
        if (interfaceName != null) {
            fields.put(INTERFACE, interfaceName);
        }
        fields.put(MEMBER, member);
        if (destination != null) {
            fields.put(DESTINATION, destination);
        }
        var body = new DBusWriter();
        try {
            if (!signature.isEmpty()) {
                fields.put(SIGNATURE, signature);
                body.writeAll(signature, arguments);
            }
            return new DBusMessage(METHOD_CALL, 0, 0, fields, body.toByteArray(), ByteOrder.LITTLE_ENDIAN);
        } finally {
            body.erase();
        }
    }

    /// {@return this message, little-endian, under `serial`}
    byte[] encode(int serial) {
        var header = new DBusWriter();
        header.putByte('l');
        header.putByte(type);
        header.putByte(flags);
        header.putByte(1);
        header.putUint32(body.length);
        header.putUint32(serial);
        var entries = new ArrayList<Object[]>();
        for (var field : fields.entrySet()) {
            var signature = switch (field.getKey()) {
                case PATH -> "o";
                case REPLY_SERIAL -> "u";
                case SIGNATURE -> "g";
                default -> "s";
            };
            entries.add(new Object[]{(byte) (int) field.getKey(), new Variant(signature, field.getValue())});
        }
        header.write("a(yv)", entries);
        header.pad(8);
        var head = header.toByteArray();
        var message = new byte[head.length + body.length];
        System.arraycopy(head, 0, message, 0, head.length);
        System.arraycopy(body, 0, message, head.length, body.length);
        return message;
    }

    /// {@return the length of the fixed part of a message plus its header fields and their padding, from its first 16
    /// bytes}
    static int headerLength(byte[] start) {
        var fields = new DBusReader(start, 12, order(start)).getUint32();
        if (fields < 0 || fields > MAX_LENGTH) {
            throw new IllegalArgumentException("A D-Bus message has header fields of " + Integer.toUnsignedString(fields) + " bytes");
        }
        return (16 + fields + 7) / 8 * 8;
    }

    /// {@return the body length of a message, from its first 16 bytes}
    static int bodyLength(byte[] start) {
        var length = new DBusReader(start, 4, order(start)).getUint32();
        if (length < 0 || length > MAX_LENGTH) {
            throw new IllegalArgumentException("A D-Bus message has a body of " + Integer.toUnsignedString(length) + " bytes");
        }
        return length;
    }

    static ByteOrder order(byte[] start) {
        return switch (start[0]) {
            case 'l' -> ByteOrder.LITTLE_ENDIAN;
            case 'B' -> ByteOrder.BIG_ENDIAN;
            default -> throw new IllegalArgumentException("A D-Bus message has an unknown byte order " + start[0]);
        };
    }

    /// {@return the message whose header is `header`, as [#headerLength] measured it, and whose body is `body`}
    static DBusMessage decode(byte[] header, byte[] body) {
        var order = order(header);
        var reader = new DBusReader(header, 4, order);
        reader.getUint32();
        var serial = reader.getUint32();
        var fields = new TreeMap<Integer, Object>();
        @SuppressWarnings("unchecked")
        var entries = (List<Object[]>) reader.read("a(yv)");
        for (var entry : entries) {
            fields.put(((Byte) entry[0]) & 0xFF, ((Variant) entry[1]).value());
        }
        return new DBusMessage(header[1], header[2], serial, fields, body, order);
    }

    /// {@return the arguments of the body, as its signature header field says}
    public Object[] arguments() {
        var signature = (String) fields.getOrDefault(SIGNATURE, "");
        return signature.isEmpty() ? new Object[0] : new DBusReader(body, 0, order).readAll(signature);
    }

    public ObjectPath path() {
        return (ObjectPath) fields.get(PATH);
    }

    public String interfaceName() {
        return (String) fields.get(INTERFACE);
    }

    public String member() {
        return (String) fields.get(MEMBER);
    }

    public String errorName() {
        return (String) fields.get(ERROR_NAME);
    }

    /// {@return the serial of the call this message answers, or -1}
    public int replySerial() {
        var value = fields.get(REPLY_SERIAL);
        return value == null ? -1 : (Integer) value;
    }
}

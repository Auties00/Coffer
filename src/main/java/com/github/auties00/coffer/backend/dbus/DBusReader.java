package com.github.auties00.coffer.backend.dbus;

import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;

/// Unmarshals D-Bus values from a buffer, in either byte order.
///
/// Values come back as [DBusWriter] takes them: `y` as [Byte], `b` as [Boolean], `n` as [Short], `q`, `i` and `u` as
/// [Integer] (`u` keeps its bits), `x` and `t` as [Long], `d` as [Double], `s` and `g` as [String], `o` as
/// [ObjectPath], `v` as [Variant], `ay` as `byte[]`, `a{..}` as a [LinkedHashMap], other arrays as an [ArrayList], and
/// structs as `Object[]`. The buffer must start at an offset of the message that is a multiple of 8.
///
/// @spec https://dbus.freedesktop.org/doc/dbus-specification.html D-Bus Specification
final class DBusReader {
    // The longest array the specification allows
    private static final int MAX_ARRAY = 1 << 26;

    private final byte[] data;
    private final boolean littleEndian;
    private int position;

    DBusReader(byte[] data, int position, ByteOrder order) {
        this.data = data;
        this.position = position;
        this.littleEndian = order == ByteOrder.LITTLE_ENDIAN;
    }

    int position() {
        return position;
    }

    private void align(int alignment) {
        position = (position + alignment - 1) / alignment * alignment;
        check(0);
    }

    private void check(int more) {
        if (position + more > data.length) {
            throw new IllegalArgumentException("A D-Bus value runs past the end of its message");
        }
    }

    private int getByte() {
        check(1);
        return data[position++] & 0xFF;
    }

    int getUint32() {
        align(4);
        check(4);
        var b0 = data[position] & 0xFF;
        var b1 = data[position + 1] & 0xFF;
        var b2 = data[position + 2] & 0xFF;
        var b3 = data[position + 3] & 0xFF;
        position += 4;
        return littleEndian ? b0 | b1 << 8 | b2 << 16 | b3 << 24 : b3 | b2 << 8 | b1 << 16 | b0 << 24;
    }

    private int getUint16() {
        align(2);
        check(2);
        var b0 = data[position] & 0xFF;
        var b1 = data[position + 1] & 0xFF;
        position += 2;
        return littleEndian ? b0 | b1 << 8 : b1 | b0 << 8;
    }

    private long getUint64() {
        align(8);
        check(8);
        var value = 0L;
        for (var i = 0; i < 8; i++) {
            var b = (long) (data[position + i] & 0xFF);
            value |= littleEndian ? b << (8 * i) : b << (8 * (7 - i));
        }
        position += 8;
        return value;
    }

    /// {@return the values of the types of `signature`, in order}
    Object[] readAll(String signature) {
        var types = DBusSignatures.split(signature);
        var values = new Object[types.size()];
        for (var i = 0; i < values.length; i++) {
            values[i] = read(types.get(i));
        }
        return values;
    }

    /// {@return the value of the single complete type `type`}
    Object read(String type) {
        return switch (type.charAt(0)) {
            case 'y' -> (byte) getByte();
            case 'b' -> getUint32() != 0;
            case 'n' -> (short) getUint16();
            case 'q' -> getUint16();
            case 'i', 'u' -> getUint32();
            case 'x', 't' -> getUint64();
            case 'd' -> Double.longBitsToDouble(getUint64());
            case 's' -> getString();
            case 'o' -> new ObjectPath(getString());
            case 'g' -> getSignature();
            case 'v' -> {
                var signature = getSignature();
                yield new Variant(signature, read(signature));
            }
            case 'a' -> getArray(type.substring(1));
            case '(' -> {
                align(8);
                var fields = DBusSignatures.split(type.substring(1, type.length() - 1));
                var values = new Object[fields.size()];
                for (var i = 0; i < values.length; i++) {
                    values[i] = read(fields.get(i));
                }
                yield values;
            }
            default -> throw new IllegalArgumentException("Cannot unmarshal the type " + type);
        };
    }

    private String getString() {
        var length = getUint32();
        if (length < 0) {
            throw new IllegalArgumentException("A D-Bus string is too long");
        }
        check(length + 1);
        var value = new String(data, position, length, StandardCharsets.UTF_8);
        position += length + 1;
        return value;
    }

    private String getSignature() {
        var length = getByte();
        check(length + 1);
        var value = new String(data, position, length, StandardCharsets.US_ASCII);
        position += length + 1;
        return value;
    }

    private Object getArray(String element) {
        var length = getUint32();
        if (length < 0 || length > MAX_ARRAY) {
            throw new IllegalArgumentException("A D-Bus array is too long: " + Integer.toUnsignedString(length));
        }
        align(DBusSignatures.alignment(element.charAt(0)));
        var end = position + length;
        check(length);
        if (element.equals("y")) {
            var bytes = Arrays.copyOfRange(data, position, end);
            position = end;
            return bytes;
        }
        if (element.charAt(0) == '{') {
            var key = element.substring(1, DBusSignatures.end(element, 1));
            var value = element.substring(1 + key.length(), element.length() - 1);
            var map = new LinkedHashMap<Object, Object>();
            while (position < end) {
                align(8);
                map.put(read(key), read(value));
            }
            return map;
        }
        var list = new ArrayList<Object>();
        while (position < end) {
            list.add(read(element));
        }
        return list;
    }
}

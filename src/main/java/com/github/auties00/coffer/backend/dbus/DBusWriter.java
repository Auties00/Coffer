package com.github.auties00.coffer.backend.dbus;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

/// Marshals D-Bus values, little-endian, into a growing buffer.
///
/// The buffer must start at an offset of the message that is a multiple of 8, as the header and the body do, so that
/// alignment within it is alignment within the message.
///
/// | Type | Java value |
/// |---|---|
/// | `y` | a [Number], its low byte |
/// | `b` | [Boolean] |
/// | `n`, `q`, `i`, `u`, `x`, `t` | a [Number] |
/// | `d` | a [Number] |
/// | `s`, `g` | [String] |
/// | `o` | [ObjectPath] |
/// | `v` | [Variant] |
/// | `ay` | `byte[]` |
/// | `a{..}` | [Map] |
/// | `a..` | [List] |
/// | `(..)` | `Object[]` or [List] |
///
/// @spec https://dbus.freedesktop.org/doc/dbus-specification.html D-Bus Specification
final class DBusWriter {
    private byte[] data;
    private int size;

    DBusWriter() {
        this.data = new byte[256];
    }

    int size() {
        return size;
    }

    byte[] toByteArray() {
        return Arrays.copyOf(data, size);
    }

    /// Overwrites what was written, which [#toByteArray()] has copied out.
    void erase() {
        Arrays.fill(data, 0, size, (byte) 0);
    }

    void pad(int alignment) {
        while (size % alignment != 0) {
            putByte(0);
        }
    }

    void putByte(int value) {
        ensure(1);
        data[size++] = (byte) value;
    }

    void putUint32(int value) {
        pad(4);
        ensure(4);
        data[size++] = (byte) value;
        data[size++] = (byte) (value >>> 8);
        data[size++] = (byte) (value >>> 16);
        data[size++] = (byte) (value >>> 24);
    }

    private void putUint16(int value) {
        pad(2);
        ensure(2);
        data[size++] = (byte) value;
        data[size++] = (byte) (value >>> 8);
    }

    private void putUint64(long value) {
        pad(8);
        ensure(8);
        for (var shift = 0; shift < 64; shift += 8) {
            data[size++] = (byte) (value >>> shift);
        }
    }

    private void putBytes(byte[] bytes) {
        ensure(bytes.length);
        System.arraycopy(bytes, 0, data, size, bytes.length);
        size += bytes.length;
    }

    private void setUint32(int at, int value) {
        data[at] = (byte) value;
        data[at + 1] = (byte) (value >>> 8);
        data[at + 2] = (byte) (value >>> 16);
        data[at + 3] = (byte) (value >>> 24);
    }

    private void ensure(int more) {
        if (size + more > data.length) {
            var grown = Arrays.copyOf(data, Math.max(size + more, data.length * 2));
            // A message may carry a secret: the array left behind is erased
            Arrays.fill(data, (byte) 0);
            data = grown;
        }
    }

    /// Marshals each of `values` as the matching type of `signature`.
    ///
    /// @throws IllegalArgumentException if the values do not match the signature
    void writeAll(String signature, Object... values) {
        var types = DBusSignatures.split(signature);
        if (types.size() != values.length) {
            throw new IllegalArgumentException("The signature " + signature + " takes " + types.size() + " values, not " + values.length);
        }
        for (var i = 0; i < values.length; i++) {
            write(types.get(i), values[i]);
        }
    }

    /// Marshals `value` as the single complete type `type`.
    void write(String type, Object value) {
        switch (type.charAt(0)) {
            case 'y' -> putByte(((Number) value).intValue());
            case 'b' -> putUint32((Boolean) value ? 1 : 0);
            case 'n', 'q' -> putUint16(((Number) value).intValue());
            case 'i', 'u' -> putUint32(((Number) value).intValue());
            case 'x', 't' -> putUint64(((Number) value).longValue());
            case 'd' -> putUint64(Double.doubleToRawLongBits(((Number) value).doubleValue()));
            case 's' -> putString((String) value);
            case 'o' -> putString(((ObjectPath) value).value());
            case 'g' -> putSignature((String) value);
            case 'v' -> {
                var variant = (Variant) value;
                putSignature(variant.signature());
                write(variant.signature(), variant.value());
            }
            case 'a' -> putArray(type.substring(1), value);
            case '(' -> {
                pad(8);
                var fields = DBusSignatures.split(type.substring(1, type.length() - 1));
                var values = value instanceof Object[] array ? List.of(array) : (List<?>) value;
                if (values.size() != fields.size()) {
                    throw new IllegalArgumentException("The struct " + type + " has " + fields.size() + " fields, not " + values.size());
                }
                for (var i = 0; i < fields.size(); i++) {
                    write(fields.get(i), values.get(i));
                }
            }
            default -> throw new IllegalArgumentException("Cannot marshal the type " + type);
        }
    }

    private void putString(String value) {
        var bytes = value.getBytes(StandardCharsets.UTF_8);
        putUint32(bytes.length);
        putBytes(bytes);
        putByte(0);
    }

    private void putSignature(String value) {
        var bytes = value.getBytes(StandardCharsets.US_ASCII);
        if (bytes.length > 255) {
            throw new IllegalArgumentException("A signature is at most 255 bytes: " + value);
        }
        putByte(bytes.length);
        putBytes(bytes);
        putByte(0);
    }

    private void putArray(String element, Object value) {
        putUint32(0);
        var lengthAt = size - 4;
        // The length counts the elements, not the padding before the first one
        pad(DBusSignatures.alignment(element.charAt(0)));
        var start = size;
        if (element.equals("y")) {
            putBytes((byte[]) value);
        } else if (element.charAt(0) == '{') {
            var key = element.substring(1, DBusSignatures.end(element, 1));
            var entryValue = element.substring(1 + key.length(), element.length() - 1);
            for (var entry : ((Map<?, ?>) value).entrySet()) {
                pad(8);
                write(key, entry.getKey());
                write(entryValue, entry.getValue());
            }
        } else {
            for (var item : (List<?>) value) {
                write(element, item);
            }
        }
        setUint32(lengthAt, size - start);
    }
}

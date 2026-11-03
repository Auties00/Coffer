package com.github.auties00.coffer.backend.dbus;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/// The D-Bus marshalling: values through the writer and back through the reader, and messages as the bus frames them.
class DBusCodecTest {
    @Test
    @DisplayName("nested values come back as they were written")
    void roundTrip() {
        var properties = new LinkedHashMap<String, Variant>();
        properties.put("org.freedesktop.Secret.Item.Label", new Variant("s", "coffer/test/key"));
        properties.put("org.freedesktop.Secret.Item.Attributes", new Variant("a{ss}", Map.of("name", "key")));
        var secret = new Object[]{new ObjectPath("/org/freedesktop/secrets/session/1"), new byte[]{1, 2, 3}, new byte[]{4, 5}, "application/octet-stream"};
        var writer = new DBusWriter();
        writer.putByte(7);
        writer.writeAll("a{sv}(oayays)btaox", properties, secret, true, 42L, List.of(new ObjectPath("/a"), new ObjectPath("/b")), -5L);
        var values = new DBusReader(writer.toByteArray(), 0, ByteOrder.LITTLE_ENDIAN);
        values.read("y");
        var read = values.readAll("a{sv}(oayays)btaox");
        var map = (Map<?, ?>) read[0];
        assertEquals(new Variant("s", "coffer/test/key"), map.get("org.freedesktop.Secret.Item.Label"));
        assertEquals(Map.of("name", "key"), ((Variant) map.get("org.freedesktop.Secret.Item.Attributes")).value());
        var struct = (Object[]) read[1];
        assertEquals(secret[0], struct[0]);
        assertArrayEquals((byte[]) secret[1], (byte[]) struct[1]);
        assertArrayEquals((byte[]) secret[2], (byte[]) struct[2]);
        assertEquals(secret[3], struct[3]);
        assertEquals(true, read[2]);
        assertEquals(42L, read[3]);
        assertEquals(List.of(new ObjectPath("/a"), new ObjectPath("/b")), read[4]);
        assertEquals(-5L, read[5]);
    }

    @Test
    @DisplayName("an array's length leaves out the padding before its first element")
    void arrayPadding() {
        var writer = new DBusWriter();
        writer.write("at", List.of(1L));
        var bytes = writer.toByteArray();
        // Length 8, four bytes of padding to the 8-byte boundary, then the element
        assertEquals(16, bytes.length);
        assertEquals(8, ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN).getInt(0));
        var empty = new DBusWriter();
        empty.write("at", List.of());
        assertEquals(8, empty.toByteArray().length);
    }

    @Test
    @DisplayName("a call frames its header fields and body, and decodes back")
    void callFrame() {
        var call = DBusMessage.call("org.freedesktop.secrets", new ObjectPath("/org/freedesktop/secrets"),
                "org.freedesktop.Secret.Service", "ReadAlias", "s", "default");
        var encoded = call.encode(9);
        assertEquals('l', encoded[0]);
        var headerLength = DBusMessage.headerLength(encoded);
        assertEquals(0, headerLength % 8);
        var bodyLength = DBusMessage.bodyLength(encoded);
        assertEquals(encoded.length, headerLength + bodyLength);
        var header = java.util.Arrays.copyOf(encoded, headerLength);
        var body = java.util.Arrays.copyOfRange(encoded, headerLength, encoded.length);
        var decoded = DBusMessage.decode(header, body);
        assertEquals(DBusMessage.METHOD_CALL, decoded.type());
        assertEquals(9, decoded.serial());
        assertEquals(new ObjectPath("/org/freedesktop/secrets"), decoded.path());
        assertEquals("ReadAlias", decoded.member());
        assertEquals("org.freedesktop.Secret.Service", decoded.interfaceName());
        assertArrayEquals(new Object[]{"default"}, decoded.arguments());
    }

    @Test
    @DisplayName("a big-endian reply decodes")
    void bigEndian() {
        // A method return to serial 5 carrying the string "hi", framed by hand
        var fields = ByteBuffer.allocate(64).order(ByteOrder.BIG_ENDIAN);
        // REPLY_SERIAL: code, signature "u", padding, value
        fields.put((byte) 5).put((byte) 1).put((byte) 'u').put((byte) 0).putInt(5);
        // SIGNATURE: aligned to 8, code, signature "g", value "s"
        fields.put((byte) 8).put((byte) 1).put((byte) 'g').put((byte) 0).put((byte) 1).put((byte) 's').put((byte) 0);
        var fieldsLength = fields.position();
        var body = ByteBuffer.allocate(7).order(ByteOrder.BIG_ENDIAN).putInt(2).put("hi".getBytes(StandardCharsets.US_ASCII)).put((byte) 0).array();
        var headerLength = (16 + fieldsLength + 7) / 8 * 8;
        var header = ByteBuffer.allocate(headerLength).order(ByteOrder.BIG_ENDIAN);
        header.put((byte) 'B').put((byte) DBusMessage.METHOD_RETURN).put((byte) 0).put((byte) 1).putInt(body.length).putInt(3).putInt(fieldsLength);
        header.put(fields.array(), 0, fieldsLength);
        var bytes = header.array();
        assertEquals(headerLength, DBusMessage.headerLength(bytes));
        var decoded = DBusMessage.decode(bytes, body);
        assertEquals(5, decoded.replySerial());
        assertArrayEquals(new Object[]{"hi"}, decoded.arguments());
    }

    @Test
    @DisplayName("address values lose their escapes")
    void addresses() {
        assertEquals("/run/user/1000/bus", DBusConnection.unescape("%2frun%2Fuser/1000/bus"));
        assertTrue(DBusConnection.unescape("plain").equals("plain"));
    }
}

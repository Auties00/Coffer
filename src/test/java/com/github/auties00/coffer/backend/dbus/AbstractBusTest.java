package com.github.auties00.coffer.backend.dbus;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/// A bus that listens on a Linux abstract socket only, which `COFFER_TEST_ABSTRACT_BUS` names; CI starts one.
@EnabledIfEnvironmentVariable(named = "COFFER_TEST_ABSTRACT_BUS", matches = "unix:abstract=.+")
class AbstractBusTest {
    private static final String BUS = "org.freedesktop.DBus";
    private static final ObjectPath BUS_PATH = new ObjectPath("/org/freedesktop/DBus");

    @Test
    @DisplayName("calls reach a bus on an abstract socket, including ones larger than the staging buffer")
    void calls() throws Exception {
        var address = System.getenv("COFFER_TEST_ABSTRACT_BUS");
        assertInstanceOf(DBusAddress.UnixAbstract.class, DBusAddress.parse(address).getFirst());
        try (var bus = DBusConnection.open(address)) {
            var names = (List<?>) bus.call(BUS, BUS_PATH, BUS, "ListNames", "").arguments()[0];
            assertTrue(names.contains(BUS), names::toString);
            // Not a bus name, so the bus answers with an error, once it has read all 200 KB
            assertThrows(DBusErrorException.class, () -> bus.call(BUS, BUS_PATH, BUS, "GetNameOwner", "s", "x".repeat(200_000)));
            assertTrue(((List<?>) bus.call(BUS, BUS_PATH, BUS, "ListNames", "").arguments()[0]).contains(BUS));
        }
    }
}

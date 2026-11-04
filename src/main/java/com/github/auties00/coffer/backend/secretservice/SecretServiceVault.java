package com.github.auties00.coffer.backend.secretservice;

import com.github.auties00.coffer.CofferException;
import com.github.auties00.coffer.backend.LiveSecret;
import com.github.auties00.coffer.backend.Vault;
import com.github.auties00.coffer.backend.dbus.DBusConnection;
import com.github.auties00.coffer.backend.dbus.DBusErrorException;
import com.github.auties00.coffer.backend.dbus.DBusMessage;
import com.github.auties00.coffer.backend.dbus.ObjectPath;
import com.github.auties00.coffer.backend.dbus.Variant;

import java.io.IOException;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.net.SocketTimeoutException;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.concurrent.locks.ReentrantLock;

/// The [com.github.auties00.coffer.Backend#SECRET_SERVICE] backend: each secret an item of the freedesktop Secret
/// Service, reached over the D-Bus session bus.
///
/// An item belongs to a coffer when its attributes name the coffer's schema and namespace, and holds the secret its
/// `name` attribute names; new items go to the service's default collection. A secret that is already stored is
/// updated in its own collection, so a default that changed leaves it where it is.
///
/// A locked collection or item is unlocked through the service's prompt when the coffer is interactive, and fails the
/// operation otherwise.
///
/// @spec https://specifications.freedesktop.org/secret-service-spec/latest/ Secret Service API
public final class SecretServiceVault implements Vault {
    private static final String SERVICE = "org.freedesktop.secrets";
    private static final ObjectPath SERVICE_PATH = new ObjectPath("/org/freedesktop/secrets");
    private static final String SERVICE_INTERFACE = "org.freedesktop.Secret.Service";
    private static final String COLLECTION_INTERFACE = "org.freedesktop.Secret.Collection";
    private static final String ITEM_INTERFACE = "org.freedesktop.Secret.Item";
    private static final String PROMPT_INTERFACE = "org.freedesktop.Secret.Prompt";
    private static final String PROPERTIES_INTERFACE = "org.freedesktop.DBus.Properties";
    // The libsecret convention for the schema an item follows
    private static final String SCHEMA_ATTRIBUTE = "xdg:schema";
    private static final String SCHEMA = "com.github.auties00.coffer";
    private static final String NAMESPACE_ATTRIBUTE = "namespace";
    private static final String NAME_ATTRIBUTE = "name";

    private final DBusConnection bus;
    private final SecretSession session;
    private final String namespace;
    private final Duration interactive;
    private final ReentrantLock lock;

    private SecretServiceVault(DBusConnection bus, SecretSession session, String namespace, Duration interactive) {
        this.bus = bus;
        this.session = session;
        this.namespace = namespace;
        this.interactive = interactive;
        this.lock = new ReentrantLock();
    }

    /// Connects to the Secret Service of the session and opens an encrypted session with it, or a plain one if the
    /// service offers no other.
    ///
    /// @param interactive the longest wait for the user to unlock the keyring, or `null` to never ask
    /// @throws CofferException with [CofferException.Reason#UNAVAILABLE] if there is no session bus or Secret Service
    public static SecretServiceVault open(String namespace, Duration interactive) {
        DBusConnection bus;
        try {
            bus = DBusConnection.openSessionBus();
        } catch (IOException exception) {
            throw new CofferException(CofferException.Reason.UNAVAILABLE, "The D-Bus session bus cannot be reached", exception);
        }
        try {
            return new SecretServiceVault(bus, openSession(bus), namespace, interactive);
        } catch (IOException | RuntimeException exception) {
            try {
                bus.close();
            } catch (IOException closing) {
                exception.addSuppressed(closing);
            }
            if (exception instanceof CofferException coffer) {
                throw coffer;
            }
            throw new CofferException(CofferException.Reason.UNAVAILABLE, "The Secret Service cannot be reached", exception);
        }
    }

    private static SecretSession openSession(DBusConnection bus) throws IOException {
        var encrypted = SecretSession.encrypted(new SecureRandom());
        try {
            var reply = bus.call(SERVICE, SERVICE_PATH, SERVICE_INTERFACE, "OpenSession", "sv",
                    SecretSession.ENCRYPTED, new Variant("ay", encrypted.publicKey())).arguments();
            encrypted.agree((ObjectPath) reply[1], (byte[]) ((Variant) reply[0]).value());
            return encrypted;
        } catch (DBusErrorException exception) {
            if (!exception.name().equals("org.freedesktop.DBus.Error.NotSupported")) {
                throw exception;
            }
        }
        var reply = bus.call(SERVICE, SERVICE_PATH, SERVICE_INTERFACE, "OpenSession", "sv",
                SecretSession.PLAIN, new Variant("s", "")).arguments();
        return SecretSession.plain((ObjectPath) reply[1]);
    }

    @Override
    public LiveSecret read(String name) {
        lock.lock();
        try {
            var items = search(attributes(name));
            if (items.isEmpty()) {
                return null;
            }
            var item = items.getFirst();
            unlock(List.of(item));
            var reply = bus.call(SERVICE, SERVICE_PATH, SERVICE_INTERFACE, "GetSecrets", "aoo", List.of(item), session.path());
            byte[] value = null;
            try {
                var secrets = (Map<?, ?>) reply.arguments()[0];
                var secret = (Object[]) secrets.get(item);
                if (secret == null) {
                    // Deleted since the search
                    return null;
                }
                value = (byte[]) secret[2];
                // The cipher works on arrays: the plaintext is on the heap until it is copied out
                var plaintext = session.open((byte[]) secret[1], value);
                try {
                    return LiveSecret.copyOf(plaintext);
                } finally {
                    Arrays.fill(plaintext, (byte) 0);
                }
            } finally {
                // The reply carries the secret encrypted, or in the clear in a plain session
                Arrays.fill(reply.body(), (byte) 0);
                if (value != null) {
                    Arrays.fill(value, (byte) 0);
                }
            }
        } catch (IOException exception) {
            throw failure("read the secret " + name, exception);
        } catch (IllegalArgumentException exception) {
            throw new CofferException(CofferException.Reason.CORRUPTED, "The Secret Service sent the secret " + name + " damaged", exception);
        } finally {
            lock.unlock();
        }
    }

    @Override
    public void write(String name, MemorySegment secret) {
        lock.lock();
        // The cipher works on arrays: the plaintext and what carries it are on the heap until the call is sent
        var plaintext = secret.toArray(ValueLayout.JAVA_BYTE);
        Object[] sealed = null;
        try {
            sealed = session.seal(plaintext);
            var items = search(attributes(name));
            if (!items.isEmpty()) {
                var item = items.getFirst();
                unlock(List.of(item));
                bus.call(SERVICE, item, ITEM_INTERFACE, "SetSecret", "(oayays)", (Object) sealed);
                for (var duplicate : items.subList(1, items.size())) {
                    deleteItem(duplicate);
                }
                return;
            }
            var collection = defaultCollection();
            unlock(List.of(collection));
            var properties = new LinkedHashMap<String, Variant>();
            properties.put("org.freedesktop.Secret.Item.Label", new Variant("s", "coffer/" + namespace + "/" + name));
            properties.put("org.freedesktop.Secret.Item.Attributes", new Variant("a{ss}", attributes(name)));
            var reply = bus.call(SERVICE, collection, COLLECTION_INTERFACE, "CreateItem", "a{sv}(oayays)b",
                    properties, sealed, true).arguments();
            prompt((ObjectPath) reply[1]);
        } catch (IOException exception) {
            throw failure("write the secret " + name, exception);
        } finally {
            Arrays.fill(plaintext, (byte) 0);
            if (sealed != null) {
                Arrays.fill((byte[]) sealed[2], (byte) 0);
            }
            lock.unlock();
        }
    }

    @Override
    public boolean delete(String name) {
        lock.lock();
        try {
            var items = search(attributes(name));
            unlock(items);
            for (var item : items) {
                deleteItem(item);
            }
            return !items.isEmpty();
        } catch (IOException exception) {
            throw failure("delete the secret " + name, exception);
        } finally {
            lock.unlock();
        }
    }

    @Override
    public List<String> names() {
        lock.lock();
        try {
            var attributes = new LinkedHashMap<String, String>();
            attributes.put(SCHEMA_ATTRIBUTE, SCHEMA);
            attributes.put(NAMESPACE_ATTRIBUTE, namespace);
            var names = new LinkedHashSet<String>();
            for (var item : search(attributes)) {
                var reply = bus.call(SERVICE, item, PROPERTIES_INTERFACE, "Get", "ss", ITEM_INTERFACE, "Attributes").arguments();
                var values = (Map<?, ?>) ((Variant) reply[0]).value();
                if (values.get(NAME_ATTRIBUTE) instanceof String itemName) {
                    names.add(itemName);
                }
            }
            return List.copyOf(names);
        } catch (IOException exception) {
            throw failure("list the secrets", exception);
        } finally {
            lock.unlock();
        }
    }

    @Override
    public void close() {
        lock.lock();
        try {
            bus.call(SERVICE, session.path(), "org.freedesktop.Secret.Session", "Close", "");
        } catch (IOException _) {
            // The service ends the session with the connection anyway
        } finally {
            try {
                bus.close();
            } catch (IOException _) {
                // Nothing is left to release
            }
            lock.unlock();
        }
    }

    private Map<String, String> attributes(String name) {
        var attributes = new LinkedHashMap<String, String>();
        attributes.put(SCHEMA_ATTRIBUTE, SCHEMA);
        attributes.put(NAMESPACE_ATTRIBUTE, namespace);
        attributes.put(NAME_ATTRIBUTE, name);
        return attributes;
    }

    /// {@return the items whose attributes include `attributes`, unlocked ones first}
    private List<ObjectPath> search(Map<String, String> attributes) throws IOException {
        var reply = bus.call(SERVICE, SERVICE_PATH, SERVICE_INTERFACE, "SearchItems", "a{ss}", attributes).arguments();
        var items = new ArrayList<ObjectPath>();
        for (var list : reply) {
            for (var item : (List<?>) list) {
                items.add((ObjectPath) item);
            }
        }
        return items;
    }

    /// Unlocks `objects`, items or collections, through the service's prompt if it needs one.
    private void unlock(List<ObjectPath> objects) throws IOException {
        if (objects.isEmpty()) {
            return;
        }
        var reply = bus.call(SERVICE, SERVICE_PATH, SERVICE_INTERFACE, "Unlock", "ao", objects).arguments();
        prompt((ObjectPath) reply[1]);
    }

    /// {@return the default collection, created through the service's prompt if there is none}
    private ObjectPath defaultCollection() throws IOException {
        var collection = (ObjectPath) bus.call(SERVICE, SERVICE_PATH, SERVICE_INTERFACE, "ReadAlias", "s", "default").arguments()[0];
        if (!collection.isRoot()) {
            return collection;
        }
        var properties = Map.of("org.freedesktop.Secret.Collection.Label", new Variant("s", "Default keyring"));
        var reply = bus.call(SERVICE, SERVICE_PATH, SERVICE_INTERFACE, "CreateCollection", "a{sv}s", properties, "default").arguments();
        var created = (ObjectPath) reply[0];
        if (!created.isRoot()) {
            return created;
        }
        var result = prompt((ObjectPath) reply[1]);
        if (result != null && result.value() instanceof ObjectPath path && !path.isRoot()) {
            return path;
        }
        throw new CofferException(CofferException.Reason.UNAVAILABLE, "The Secret Service has no default collection", null);
    }

    private void deleteItem(ObjectPath item) throws IOException {
        var reply = bus.call(SERVICE, item, ITEM_INTERFACE, "Delete", "").arguments();
        prompt((ObjectPath) reply[0]);
    }

    /// Shows `prompt` to the user and waits for it, unless it is `/`, the service's way of saying none is needed.
    ///
    /// @return the prompt's result, or `null` if there was no prompt
    /// @throws CofferException with [CofferException.Reason#LOCKED] if the coffer may not prompt, or the user dismissed
    ///                        the prompt or did not answer in time
    private Variant prompt(ObjectPath prompt) throws IOException {
        if (prompt.isRoot()) {
            return null;
        }
        if (interactive == null) {
            throw new CofferException(CofferException.Reason.LOCKED, "The keyring is locked, and the coffer may not ask the user to unlock it", null);
        }
        bus.addMatch("type='signal',interface='" + PROMPT_INTERFACE + "',member='Completed',path='" + prompt.value() + "'");
        bus.call(SERVICE, prompt, PROMPT_INTERFACE, "Prompt", "s", "");
        DBusMessage completed;
        try {
            completed = bus.awaitSignal(signal -> prompt.equals(signal.path()) && "Completed".equals(signal.member()), interactive);
        } catch (SocketTimeoutException exception) {
            try {
                bus.call(SERVICE, prompt, PROMPT_INTERFACE, "Dismiss", "");
            } catch (IOException dismissing) {
                exception.addSuppressed(dismissing);
            }
            throw new CofferException(CofferException.Reason.LOCKED, "The user did not unlock the keyring within " + interactive, exception);
        }
        var arguments = completed.arguments();
        if ((Boolean) arguments[0]) {
            throw new CofferException(CofferException.Reason.LOCKED, "The user dismissed the prompt to unlock the keyring", null);
        }
        return (Variant) arguments[1];
    }

    private static CofferException failure(String operation, IOException exception) {
        var reason = CofferException.Reason.IO;
        if (exception instanceof DBusErrorException error) {
            reason = switch (error.name()) {
                case "org.freedesktop.Secret.Error.IsLocked" -> CofferException.Reason.LOCKED;
                case "org.freedesktop.DBus.Error.AccessDenied" -> CofferException.Reason.DENIED;
                case "org.freedesktop.DBus.Error.ServiceUnknown", "org.freedesktop.DBus.Error.NameHasNoOwner" -> CofferException.Reason.UNAVAILABLE;
                default -> CofferException.Reason.IO;
            };
        }
        return new CofferException(reason, "The Secret Service could not " + operation, exception);
    }
}

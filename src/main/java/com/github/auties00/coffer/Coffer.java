package com.github.auties00.coffer;

import com.github.auties00.coffer.backend.CofferBuilder;
import com.github.auties00.coffer.backend.LiveCoffer;

import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import java.util.Optional;

/// The secrets of one application, kept by the operating system for the user that runs it.
///
/// {@snippet lang = java :
/// try (var coffer = Coffer.open("cobalt")) {
///     if (coffer.protection() != Protection.OPERATING_SYSTEM) {
///         // Only file permissions keep other users out: warn, or refuse to go on
///     }
///     try (var key = coffer.readOrCreate("store-key", 32)) {
///         var mac = Mac.getInstance("HmacSHA256");
///         mac.init(key.asKey("HmacSHA256"));
///     }
/// }
/// }
///
/// Secrets come and go as [Secret]s, which keep their bytes outside the Java heap and erase them when closed.
///
/// # Namespaces and names
/// A coffer belongs to a namespace, the name of the application, and holds secrets by name. Both are 1 to 64 (names
/// 1 to 128) lowercase letters, digits, `.`, `_` or `-`, starting with a letter or a digit. A coffer only ever reads,
/// writes or deletes the secrets its namespace created: secrets other applications keep in the same keyring are never
/// touched, and never listed.
///
/// # Backends
/// A secret lives in one [Backend]: the operating system's keyring, or an owner-only file where none is available.
/// The first time a namespace stores a secret, its backend is recorded in the namespace's directory, and every later
/// coffer of the namespace uses that backend: if it cannot be reached, opening fails rather than start an empty
/// keyring elsewhere, where a secret the application creates anew would replace the one it lost track of.
/// [#moveTo(Backend)] moves the secrets, and the record, to another backend.
///
/// # Threading
/// Every method may be called from any thread, virtual threads included. [#readOrCreate(String, int)] creates a
/// secret once even when threads and processes call it at the same time.
///
/// # Lifecycle
/// A coffer may hold a connection to the keyring's service, which [#close()] releases. A closed coffer refuses every
/// call.
public sealed interface Coffer extends AutoCloseable permits LiveCoffer {
    /// The most bytes a secret holds.
    int MAX_LENGTH = 64 * 1024;

    /// {@return the coffer of `namespace`, in the backend its secrets are in or, for a new namespace, the best one
    /// available}
    ///
    /// It is `builder(namespace).build()`.
    ///
    /// @param namespace the namespace
    /// @throws IllegalArgumentException if `namespace` is not valid
    /// @throws CofferException if the namespace's backend cannot be reached
    static Coffer open(String namespace) {
        return builder(namespace).build();
    }

    /// {@return a builder of the coffer of `namespace`}
    ///
    /// @param namespace the namespace
    /// @throws IllegalArgumentException if `namespace` is not valid
    static Builder builder(String namespace) {
        return new CofferBuilder(namespace);
    }

    /// {@return the namespace}
    String namespace();

    /// {@return the backend the secrets are in}
    Backend backend();

    /// {@return how the secrets are protected}
    default Protection protection() {
        return backend().protection();
    }

    /// {@return the secret stored under `name`, which the caller closes, or an empty optional if there is none}
    ///
    /// @param name the name of the secret
    /// @throws IllegalArgumentException if `name` is not valid
    /// @throws CofferException if the keyring cannot be read
    Optional<Secret> read(String name);

    /// Stores `secret` under `name`, replacing the secret stored under it.
    ///
    /// The coffer reads `secret` and keeps no reference to it; the caller may close it once the method returns.
    ///
    /// @param name the name of the secret
    /// @param secret the secret, at most [#MAX_LENGTH] bytes
    /// @throws IllegalArgumentException if `name` is not valid, `secret` is longer than [#MAX_LENGTH], or `secret`
    ///                                  is destroyed
    /// @throws CofferException if the keyring cannot be written
    void write(String name, Secret secret);

    /// Stores `secret` under `name`, replacing the secret stored under it.
    ///
    /// The coffer copies `secret`; the caller may overwrite it once the method returns.
    ///
    /// @param name the name of the secret
    /// @param secret the secret, at most [#MAX_LENGTH] bytes
    /// @throws IllegalArgumentException if `name` is not valid, or `secret` is longer than [#MAX_LENGTH]
    /// @throws CofferException if the keyring cannot be written
    void write(String name, byte[] secret);

    /// Returns the secret stored under `name`, storing `length` random bytes under it first if there is none.
    ///
    /// Callers that race, in this process or in others, all get the secret the first of them stored.
    ///
    /// @param name the name of the secret
    /// @param length the bytes of a new secret, from 1 to [#MAX_LENGTH]
    /// @return the secret, which the caller closes; a secret stored earlier keeps its own length
    /// @throws IllegalArgumentException if `name` is not valid, or `length` is out of range
    /// @throws CofferException if the keyring cannot be read or written
    Secret readOrCreate(String name, int length);

    /// Deletes the secret stored under `name`.
    ///
    /// @param name the name of the secret
    /// @return whether there was one
    /// @throws IllegalArgumentException if `name` is not valid
    /// @throws CofferException if the keyring cannot be written
    boolean delete(String name);

    /// {@return the names of the secrets stored, in order}
    ///
    /// @throws CofferException if the keyring cannot be read
    List<String> names();

    /// Moves every secret to `backend`, which the namespace uses from then on, and closes this coffer.
    ///
    /// The secrets are copied first, then the namespace's record names `backend`, then the copies left in this
    /// coffer's backend are deleted. A move cut short before the record changes leaves the namespace where it was; one
    /// cut short after leaves copies behind, which the next coffer of the namespace deletes as it opens, once the old
    /// backend can be reached. A coffer of the namespace that another process holds refuses to write after the move.
    ///
    /// @apiNote Moving from [Backend#FILE] to the operating system's keyring, once it becomes available, stops keeping
    /// the secrets in files only file permissions protect.
    /// @param backend the backend to move to
    /// @return the coffer of `backend`, or this coffer if it is already in `backend`
    /// @throws CofferException with [CofferException.Reason#UNAVAILABLE] if `backend` cannot be reached, or another
    ///                        process moved the secrets already; with another reason if a secret cannot be copied,
    ///                        which leaves the namespace where it was
    Coffer moveTo(Backend backend);

    /// Releases the connection to the keyring's service, if there is one; closing a closed coffer does nothing.
    @Override
    void close();

    /// The options of a [Coffer].
    sealed interface Builder permits CofferBuilder {
        /// Considers only `backends`, in this order of preference, for a namespace that has no secret yet.
        ///
        /// A namespace that has secrets keeps their backend, which must be among `backends`. The default is the
        /// operating system's keyring, then [Backend#FILE].
        ///
        /// @param backends the backends, at least one
        /// @return this builder
        /// @throws IllegalArgumentException if `backends` is empty
        Builder backends(Backend... backends);

        /// Keeps the namespace's files in `directory`: the record of its backend, the lock that serializes the
        /// creation of secrets, and the secrets themselves for [Backend#WINDOWS_DATA_PROTECTION] and [Backend#FILE].
        ///
        /// The default is a `coffer` directory in the user's data directory: `%LOCALAPPDATA%` on Windows,
        /// `~/Library/Application Support` on macOS, `$XDG_DATA_HOME` or `~/.local/share` elsewhere, then the
        /// namespace.
        ///
        /// @param directory the directory, created owner-only if missing
        /// @return this builder
        Builder directory(Path directory);

        /// Lets an operation that needs the user, to unlock the keyring or to allow access to a secret, ask them, and
        /// wait at most `timeout` for the answer.
        ///
        /// By default an operation never waits on the user: one that would have to ask throws [CofferException] with
        /// [CofferException.Reason#LOCKED]. The Windows Data Protection API never asks. The macOS Keychain shows its
        /// own dialog, and keeps it open for as long as the user takes: `timeout` bounds the wait on the Secret
        /// Service only.
        ///
        /// @implNote On macOS a coffer that may not ask turns the keychain's user interaction off for each of its
        /// calls, since the file-based keychain obeys no per-call flag. The switch is process-wide: while a call runs,
        /// other code of the process that uses the keychain may see interaction refused too.
        ///
        /// @param timeout the longest wait for the user, positive
        /// @return this builder
        /// @throws IllegalArgumentException if `timeout` is not positive
        Builder interactive(Duration timeout);

        /// Opens the coffer.
        ///
        /// @return the coffer, which the caller closes
        /// @throws CofferException with [CofferException.Reason#UNAVAILABLE] if the namespace's backend, or for a new
        ///                        namespace every backend considered, cannot be reached; with another reason if the
        ///                        namespace's directory cannot be read or created
        Coffer build();
    }
}

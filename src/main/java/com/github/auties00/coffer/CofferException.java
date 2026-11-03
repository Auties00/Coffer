package com.github.auties00.coffer;

import java.util.Objects;

/// Thrown when a [Coffer] cannot reach, read or write its keyring.
public final class CofferException extends RuntimeException {
    private final Reason reason;

    /// Creates an exception.
    ///
    /// @param reason why the operation failed
    /// @param message what failed
    /// @param cause the failure underneath, or `null`
    public CofferException(Reason reason, String message, Throwable cause) {
        super(message, cause);
        this.reason = Objects.requireNonNull(reason, "reason");
    }

    /// {@return why the operation failed}
    public Reason reason() {
        return reason;
    }

    /// Why an operation of a [Coffer] failed.
    public enum Reason {
        /// The backend cannot be reached: it does not exist on this system, its service is not running, or the
        /// namespace's secrets are in a backend the builder does not allow.
        UNAVAILABLE,
        /// The keyring is locked and the coffer may not, or did not manage to, have the user unlock it.
        LOCKED,
        /// The keyring refused the operation.
        DENIED,
        /// A secret is damaged, or was written by another user or on another computer.
        CORRUPTED,
        /// Reading or writing failed.
        IO
    }
}

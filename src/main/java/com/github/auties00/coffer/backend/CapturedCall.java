package com.github.auties00.coffer.backend;

import java.lang.foreign.Arena;
import java.lang.foreign.FunctionDescriptor;
import java.lang.foreign.Linker;
import java.lang.foreign.MemoryLayout;
import java.lang.foreign.MemorySegment;
import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;

/// A downcall to a function jextract bound that also captures the error the operating system recorded for the calling
/// thread: `GetLastError` on Windows, `errno` elsewhere.
///
/// jextract's own handles do not capture it, and reading it with a second call afterwards is unreliable, since the JVM
/// may make system calls in between. This reuses the address and descriptor jextract generated, with
/// [Linker.Option#captureCallState(String...)] added.
public final class CapturedCall {
    private static final MemoryLayout STATE = Linker.Option.captureStateLayout();

    private final MethodHandle handle;
    private final VarHandle error;

    private CapturedCall(MethodHandle handle, VarHandle error) {
        this.handle = handle;
        this.error = error;
    }

    /// {@return the call of the function at `address`, capturing the state named `name`}
    ///
    /// @param name `GetLastError` or `errno`
    public static CapturedCall of(MemorySegment address, FunctionDescriptor descriptor, String name) {
        var handle = Linker.nativeLinker().downcallHandle(address, descriptor, Linker.Option.captureCallState(name));
        return new CapturedCall(handle, STATE.varHandle(MemoryLayout.PathElement.groupElement(name)));
    }

    /// {@return memory that receives the state one call captures}
    public static MemorySegment state(Arena arena) {
        return arena.allocate(STATE);
    }

    /// Calls the function, recording the captured state in `state`.
    ///
    /// @return what the function returns
    public Object invoke(MemorySegment state, Object... arguments) {
        var all = new Object[arguments.length + 1];
        all[0] = state;
        System.arraycopy(arguments, 0, all, 1, arguments.length);
        try {
            return handle.invokeWithArguments(all);
        } catch (RuntimeException | Error exception) {
            throw exception;
        } catch (Throwable exception) {
            throw new IllegalStateException("A native call failed", exception);
        }
    }

    /// {@return the error the last call recording into `state` captured}
    public int error(MemorySegment state) {
        return (int) error.get(state, 0L);
    }
}

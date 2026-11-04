// The Core Foundation and Security framework API jextract binds for the macOS Keychain backend.

// jextract's libclang (13.0) predates the exclavekit environment that newer SDKs test for in TargetConditionals.h: it
// reads the unknown environment as a match, decides the target is not macOS, and Security.h then leaves out the
// macOS-only keychain API (SecKeychain.h). TargetConditionals.h defines TARGET_OS_OSX only where it is not defined yet.
#define TARGET_OS_OSX 1

#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>

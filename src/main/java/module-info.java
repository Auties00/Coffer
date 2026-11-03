/// Coffer, a keyring for the secrets of Java applications: keys, tokens and passwords that the operating system
/// keeps for the user.
///
/// It stores secrets in the Windows Data Protection API, the macOS Keychain or the freedesktop Secret Service, and in
/// an owner-only file where none of them is available. It ships no native library: the Windows and macOS backends
/// call the operating system through the Foreign Function and Memory API, so an application that uses them runs with
/// `--enable-native-access=com.github.auties00.coffer`; the Secret Service backend speaks D-Bus in Java, with no
/// native access.
module com.github.auties00.coffer {
    exports com.github.auties00.coffer;
}

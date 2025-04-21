# boring-flutter

Forked version to support both Android (64-bit) and iOS (64-bit; thin and fat binary). Requires Frida 16.7.0 or later to use `Process.attachModuleObserver()`.
- Android: Hook x509.cc - `ssl_crypto_x509_session_verify_cert_chain()` to force the return value to 1 (`true`).
- iOS: Hook handshake.cc - `ssl_verify_peer_cert()` to force the return value to 0 (`ssl_verify_ok`).

A Python r2pipe script to automatically create a Frida hook and patch the Flutter library to intercept TLS traffic for Flutter based apps.

Inspired by the following blogposts:
- https://blog.nviso.eu/2019/08/13/intercepting-traffic-from-android-flutter-applications/
- https://blog.nviso.eu/2020/05/20/intercepting-flutter-traffic-on-android-x64/

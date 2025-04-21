function log(msg) {
    console.log("[" + new Date().toLocaleString() + "] " + msg);
}

function disablePinning(moduleName) {
    var baseAddress = Module.findBaseAddress(moduleName);
    var hookAddress = baseAddress.add(ptr("0x00000000"));       // for 32-bit ARM, the address must be off by one due to a THUMB function

    Interceptor.attach(hookAddress, {
        onEnter: function(args) {
            log("Enter x509.cc - ssl_crypto_x509_session_verify_cert_chain()");
        },
        onLeave: function(retval) {
            log("Disable certificate validation/pinning");
            retval.replace(0x1);
        }
    });
}

if (Java.available) {
    Java.perform(function() {
        const observer = Process.attachModuleObserver({
            onAdded(module) {
                if (module.name == "libflutter.so") {
                    log(module.name + " is loaded");
                    disablePinning(module.name);
                }
            },
            onRemoved(module) {}
        });
    });
} else {
    log("Error: Java runtime is not available!");
}
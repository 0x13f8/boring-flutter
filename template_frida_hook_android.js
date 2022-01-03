function log(msg) {
    console.log("[" + new Date().toLocaleString() + "] " + msg);
}

var awaitForCondition = function(callback) {
    var int = setInterval(function() {
        if (Module.findBaseAddress("libflutter.so")) {
            clearInterval(int);
            callback();
            log("libflutter.so is loaded");
            return;
        }
    }, 0);
}

function disablePinning() {
    var baseAddress = Module.findBaseAddress("libflutter.so");
    var hookAddress = baseAddress.add(ptr("0x00000000"));       // modify an offset here

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
        awaitForCondition(disablePinning);
    });
} else {
    log("Error: Java runtime is not available!");
}
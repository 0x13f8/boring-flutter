function log(msg) {
    console.log("[" + new Date().toLocaleString() + "] " + msg);
}

var awaitForCondition = function(callback) {
    var int = setInterval(function() {
        if (Module.findBaseAddress("Flutter")) {
            clearInterval(int);
            callback();
            log("Flutter framework is loaded");
            return;
        }
    }, 0);
}

function disablePinning() {
    var baseAddress = Module.findBaseAddress("Flutter");
    var hookAddress = baseAddress.add(ptr("0x00000000"));       // modify an offset here

    Interceptor.attach(hookAddress, {
        onEnter: function(args) {
            log("Enter handshake.cc - ssl_verify_peer_cert()");
        },
        onLeave: function(retval) {
            log("Disable certificate validation/pinning");
            retval.replace(0x0);
        }
    });
}

if (ObjC.available) {
    awaitForCondition(disablePinning);
} else {
    log("Error: Objective-C runtime is not available!");
}
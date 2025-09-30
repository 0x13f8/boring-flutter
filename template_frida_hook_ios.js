function log(msg) {
    console.log("[" + new Date().toLocaleString() + "] " + msg);
}

function disablePinning(moduleName) {
    var baseAddress = Process.getModuleByName(moduleName).base;
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
    const observer = Process.attachModuleObserver({
        onAdded(module) {
            if (module.name == "Flutter") {
                log(module.name + " is loaded");
                disablePinning(module.name);
            }
        },
        onRemoved(module) {}
    });
} else {
    log("Error: Objective-C runtime is not available!");
}
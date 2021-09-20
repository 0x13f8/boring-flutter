function hook_ssl_verify_result(address)
{
    Interceptor.attach(address, {
        onEnter: function(args) {
            console.log("onEnter: Disabling SSL validation");
        },
        onLeave: function(retval)
        {
            console.log("onLeave: Disabling SSL validation");
            retval.replace(0x1);
        }
    });
}

function disablePinning()
{
    console.log("Enter disablePinning()");
    var m = Process.findModuleByName("Flutter");

    hook_ssl_verify_result(m.base.add(0x00000000))
}

if (ObjC.available) {
    disablePinning()
} else {
    send("error: Objective-C Runtime is not available!");
}
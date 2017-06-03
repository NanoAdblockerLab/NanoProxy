"use strict";

//Silimar to "HTTP Proxy.js", but it tries to start the proxy server in HTTPS mode
//Assumes certificates are in "C:/Violentcert"
console.log(`Please make sure certificates are copied to "C:/Violentcert"`);

//Load certificate
const fs = require("fs");
const cert = {
    key: fs.readFileSync("C:/Violentcert/Violentcert.private"),
    cert: fs.readFileSync("C:/Violentcert/Violentcert.crt"),
};
//Start proxy server in https mode
require("../Violentproxy/Violentengine").start({ cert: cert });

console.log("Does it work? Test it out: curl -x localhost:12345 https://example.com");

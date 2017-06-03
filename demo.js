"use strict";

//Start a simple HTTP-only proxy server, it will inject an inline script that write something to the console to all pages that has <head> tag
//Not very useful
require("../Violentproxy/Violentengine").start();

console.log("Does it work? Test it out: curl -x localhost:12345 example.com");
console.log("Keep in mind that HTTPS doesn't work in this demo");

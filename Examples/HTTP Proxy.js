"use strict";

//Simply start a proxy server, it will inject an inline script that write something to the console to all pages that has <head> tag
//Not very useful
require("../Violentproxy/Violentengine").start();

console.log("Does it work? Test it out: curl -x localhost:12345 example.com");

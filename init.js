//Load modules to global scope and start Violentproxy
"use strict";

//I decided to load everything to the global scope so my modules can share them
//I will make sure nothing will write into these global variables

console.log("INFO: Loading modules...");

//Network utilities
global.https = require("https");
global.http = require("http");
global.net = require("net");
global.url = require("url");
global.ws = require("ws");

//Other utilities
global.forge = require("node-forge");
global.zlib = require("zlib");
global.fs = require("fs");

//Custom modules
global.agent = require("./Violentproxy/Violentagent");
global.tls = require("./Violentproxy/Violenttls");

//Load main code
global.engine = require("./Violentproxy/Violentengine");

//Start a simple proxy server
console.log("INFO: Starting Violentproxy...");
//global.engine.start(true);
global.engine.start();

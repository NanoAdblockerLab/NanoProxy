"use strict";

//I will use Forge, as spawning a child process just to sign a certificate might not be faster.
//Calling OpenSSL through Bash on Ubuntu on Windows fells like too big an overhead to me.
//The newest version of OpenSSL in Bash on Ubuntu on Windows also has a few CVE vulnerabilities.
//I have to worry about cross platform compatibility too, if I decide to use OpenSSL.
const forge = require("node-forge");

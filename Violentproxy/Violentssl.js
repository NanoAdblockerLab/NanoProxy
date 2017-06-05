"use strict";

//I will use node-forge, as spawning a child-process just to sign a certificate might not be faster.
//Calling OpenSSL through Bash on Ubuntu on Windows fells like too big an overhead to me.
//The newest version of OpenSSL in Bash on Ubuntu on Windows also has a few CVE vulnerabilities.
//That can be manually resolved, but it's too much work to get too little done, and most people
//won't be confortable working in a terminal.
const {pki, md} = require("node-forge"),
    fs = require("fs");

//The certificate and private key of the certificate authority
let CAcert, CAkey;
//Cache of available 
let certCache = {};

/**
 * Certificate authority attributes.
 * https://stackoverflow.com/questions/6464129/certificate-subject-x-509
 * @const {Object}
 */
const CAattr = [
    {
        shortName: "C", //Country
        value: "World",
    },
    {
        shortName: "O", //Organization, company, etc.
        value: "Violentproxy",
    },
    {
        shortName: "OU", //Organizational Unit, like department
        value: "Violentssl Engine",
    },
    {
        shortName: "ST", //State, province, etc.
        value: "World",
    },
    {
        shortName: "CN", //Domain, IP, etc. For certificate authority, it's different, it can be anything
        value: "ViolentCA",
    },
    //Optional
    {
        shortName: "L", //City, town, etc.
        value: "World",
    },
];
/**
 * Certificate authority extensions.
 * https://access.redhat.com/documentation/en-US/Red_Hat_Certificate_System/8.0/html/Admin_Guide/Standard_X.509_v3_Certificate_Extensions.html
 * @const {Object}
 */
const CAext = [
    {
        name: "basicConstraints", //B.3.3.
        cA: true,
    },
    {

    }
];

/**
 * Initialize certificate authority, calling sign without calling this function first
 * will cause problems. This function will throw if the certificate authority could
 * not be initialized.
 * @function
 */
exports.init = () => {

};

/**
 * Get a certificate for the current domain, do not pass in domain with wildcard.
 * @function
 * @return {Object} An object that can be passed to https.createServer().
 */
exports.sign = (domain) => {

};

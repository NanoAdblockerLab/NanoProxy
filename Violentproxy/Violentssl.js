"use strict";

/**
 * I will use node-forge, as spawning a child-process every time I need to sign a certificate might not be faster.
 * Calling OpenSSL through Bash on Ubuntu on Windows fells like too big an overhead to me.
 * The newest version of OpenSSL in Bash on Ubuntu on Windows also has a few CVE vulnerabilities.
 * That can be manually resolved, but it's too much work to get too little done, and most people
 * won't be confortable working in a terminal.
 * @const {Module}
 */
const {pki, md} = require("node-forge"),
    fs = require("fs");

/**
 * The certificate and its key. Will be initialized later.
 * @const {Certificate}
 */
let CAcert, CAkey;
/**
 * Server certificates cache.
 * Will be a dictionary of domain to certificate. The certificate object can be passed directly to https.createServer().
 * @var {Object.<Certificate>}
 */
let certCache = {};

/**
 * Certificate authority subject.
 * https://stackoverflow.com/questions/6464129/certificate-subject-x-509
 * @const {Object}
 */
const CAsbj = [
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
        name: "basicConstraints",
        cA: true,
    },
    {
        name: "extKeyUsage",
        serverAuth: true,
        clientAuth: true,
        codeSigning: true,
        emailProtection: true,
        timeStamping: true,
    },
    {
        //https://github.com/digitalbazaar/forge/blob/e548bffb2b4e152057adfaf2648c82080b83fdf3/lib/oids.js#L152
        name: "keyUsage",
        digitalSignature: true,
        //nonRepudiation: true, //I'm not sure if browsers will like it if this is missing, need to test it out
        keyEncipherment: true,
        dataEncipherment: true,
        keyCertSign: true,
        cRLSign: true,
    },
    {
        //https://github.com/digitalbazaar/forge/blob/80c7fd4e21ae83fa236ebb6a2f4748d54aa0dec0/lib/x509.js#L1431
        //https://github.com/digitalbazaar/forge/blob/80c7fd4e21ae83fa236ebb6a2f4748d54aa0dec0/lib/x509.js#L1594
        name: "subjectAltName",
        altNames: [
            {
                type: 2, //DNS Name, domain
                value: "localhost",
            },
            {
                type: 7, //IP
                ip: "127.0.0.1",
            },
        ],
    },
    {
        //https://github.com/digitalbazaar/forge/blob/80c7fd4e21ae83fa236ebb6a2f4748d54aa0dec0/lib/x509.js#L1554
        name: "nsCertType",
        client: true,
        server: true,
        email: true,
        objsign: true,
        sslCA: true,
        emailCA: true,
        objCA: true,
    },
];
/**
 * Server subject, same for all servers, refer to certificate authority subject for more information.
 * @const {Object}
 */
const serverSbj = [
    //As browsers don't care about CN anymore, I will drop it and use the same subject for all servers
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
    //Optional
    {
        shortName: "L", //City, town, etc.
        value: "World",
    },
];
/**
 * Get server extension. This cannot be a static global object as I might be signing two certificates at the same
 * time and the extension is slightly different for each server.
 * @const {Object}
 */
const getServerExt = () => {

}

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

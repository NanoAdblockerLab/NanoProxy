"use strict";

/**
 * Load necessary modules.
 * I will use node-forge, as spawning a child-process every time I need to sign a certificate isn't really going
 * to be faster.
 * Also, OpenSSL is a pain to get it to work on Windows.
 * @const {Module}
 */
const forge = require("node-forge"),
    fs = require("fs");

/**
 * The certificate and its key. Will be initialized later.
 * @const {Certificate}
 */
let CAcert, CAprivate, CApublic;
/**
 * Server certificates cache.
 * Will be a dictionary of domain to certificate. The certificate object can be passed directly to https.createServer().
 * @var {Dictionary.<Certificate>}
 */
let certCache = {};

/**
 * Certificate authority subject.
 * https://stackoverflow.com/questions/6464129/certificate-subject-x-509
 * @const {CASubject}
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
 * @const {CAExtensions}
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
 * This can be the same for all servers because browsers don't care abut CN (common name) anymore and only check subjectAltName.
 * @const {ServerSubject}
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
 * Get server extension. This cannot be a single global variable as I might be processing two certificates at the
 * same time and the extension is slightly different for each server. The signing process is synchronous but I don't
 * want to deal with potential race conditions.
 * Refer to certificate authority extensions for more information.
 * @function
 * @param {stirng} domain - The domain, include wildcard as appropriate.
 * @return {ServerExtensions} Server extensions.
 */
const getServerExt = (domain) => {
    return [
        {
            name: "extKeyUsage",
            serverAuth: true,
            clientAuth: true,
        },
        {
            name: "keyUsage",
            digitalSignature: true,
            keyEncipherment: true,
            dataEncipherment: true,
        },
        {
            name: "subjectAltName",
            altNames: [
                {
                    type: 2, //DNS Name, domain
                    value: domain,
                },
            ],
        },
        {
            name: "nsCertType",
            client: true,
            server: true,
        },
    ];
};

/**
 * Generate a certificate authority, data will be written to global variables.
 * Callback will be called when the certificate is ready, saving them to file will be done right after.
 * @function
 * @param {Function} callback - The function to call when the certificate authority is ready.
 */
const genCA = (callback) => {
    //Make the certificate to be valid from yesterday, for a month
    //I might make this longer when I feel it is stable enough
    let startDate = new Date();
    startDate.setDate(startDate.getDate() - 1); //This will work if today is the first day of a month
    let endDate = new Date(); //Need to create a new one
    //The behavior of this is kind of weird when it comes to February, but it's good enough, it's just temporary anyway
    endDate.setMonth(endDate.getMonth() + 1);
    //endDate.setFullYear(endDate.getFullYear() + 1);
    //
    forge.pki.a
};

/**
 * Initialize certificate authority, calling sign() without calling this function first
 * will cause problems. This function will throw if the certificate authority could
 * not be initialized.
 * @function
 * @param {Funciton} callback - The function to call when Violentssl is ready.
 */
exports.init = (callback) => {
    //Check if I already have them

};

/**
 * Get a certificate for the current domain, do not pass in domain with wildcard.
 * @function
 * @param {Function} callback - The function to call when the certificate is ready.
 ** @param {Certificate} - An object that can be passed to https.createServer().
 */
exports.sign = (domain, callback) => {

};

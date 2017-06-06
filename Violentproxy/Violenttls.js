//TLS engine for Violentproxy
//Note that "SSL" often means "SSL/TLS", OpenSSL fully supports TLS related calculations and functions
//As of 2017, SSL is no longer used and its support is dropped by modern browsers
"use strict";

/**
 * Load modules.
 * I will use node-forge, as spawning a child-process every time I need to sign a certificate isn't really going
 * to be faster.
 * Also, it's a pain to get OpenSSL to work on Windows.
 * @const {Module}
 */
const forge = require("node-forge"),
    fs = require("fs");

/**
 * The place where all certificates will be saved.
 * The root certificate will be directly placed under this directory, other certificates will have their own folder.
 * @const {String}
 */
const certFolder = "./Violentproxy/Violentcert";

/**
 * The root certificate and its keys. Will be initialized when init() is called.
 * @const {Certificate}
 */
let CAcert, CAprivate, CApublic;
/**
 * The certificate for the proxy server itself. Will be initialized when init() is called.
 * @const {Certificate}
 */
let proxyCert, proxyPrivate;
/**
 * Server certificates cache.
 * Will be a dictionary of domain to certificate. The certificate object can be passed directly to https.createServer().
 * A domain key must be like "*.example.com", the wildcard is required.
 * TODO: Add a timer that remove certificates when they are not used for extended amount of time.
 * @var {Dictionary.<Cert>}
 */
let certCache = {};
/**
 * Certificate object, this prevents issues that can be caused in race condition.
 * @class
 */
const Cert = class {
    /**
     * Construct the object.
     * Use Cert.value to get the certificate and Cert.busy to check ready state.
     * @constructor
     */
    constructor() {
        this.busy = true;
        this.onReadyCallbacks = [];
    }
    /**
     * Set this certificate, this will also mark it as ready and trigger all callbacks.
     * @method
     * @param {Certificate} val - The certificate
     */
    setVal(val) {
        this.value = val;
        this.busy = false;
        for (let i = 0; i < this.onReadyCallbacks.length; i++) {
            this.onReadyCallbacks[i]();
        }
    }
    /**
     * Schedule a function to call once the certificate is ready
     * @method
     * @param {Function} func - The funtion to call
     */
    onceReady(func) {
        if (this.busy) {
            this.onReadyCallbacks.push(func);
        } else {
            func();
        }
    }
}

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
        value: "Violenttls Engine",
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
        //nonRepudiation: true, //TODO: I'm not sure if browsers will like it if this is missing, need to test it out
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
            //TODO: Dynamically load other IPs and domains
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
 * Server subject, same for all servers, refer to CAsbj for more information.
 * This can be the same for all servers because browsers don't care about CN (common name) anymore and only check
 * subjectAltName extension.
 * @const {ServerSubject}
 */
const serverSbj = [
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
        value: "Violenttls Engine",
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
 * Get server extension. This cannot be a single global variable as I might be generating two certificates at the
 * same time and the extension is slightly different for each server.
 * Refer to CAext for more information.
 * @function
 * @param {stirng} domain - The domain, a version that has wildcard will be included, must be something like "example.com".
 ** It can't have wildcard and can't be a top level domain ("com" is not valid).
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
                {
                    type: 2,
                    value: `*.${domain}`,
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
 * Generate a certificate authority root certificates, data will be written to global variables.
 * The new root certificate will also be saved to a file.
 * @function
 * @param {Array.<string>} - The DNS names of the proxy server.
 * @param {Array.<string>} - The IPs of the proxy server.
 * @param {Function} callback - The function to call when the root certificate is ready.
 */
const genCA = (proxyDNS, proxyIP, callback) => {
    console.log("Generating certificate authority root certificate...");
    //6 months should be long enough, and reminding the user that he is using a self-signed certificate might
    //not be a bad thing
    //I might change this to something longer like one year or two if I think everything is stable enough
    let startDate = new Date();
    //V8 will handle switching to last month
    startDate.setDate(startDate.getDate() - 1);
    let endDate = new Date(); //Need to create a new one
    //V8 will handle switching to next year
    //The certificate is going to work for 6 months, signed for extra 2 months just in case, when checking
    //for validity, a new certificate will be generated if there are less than 2 months validity left
    endDate.setMonth(endDate.getMonth() + 8);
    //Generate key pair
    forge.pki.rsa.generateKeyPair({ bits: 2048 }, (err, keypair) => {
        //Abort on error
        if (err) {
            console.log("ERROR: Could not generate RSA key pair for the certificate authority root certificate.");
            throw err;
        }
        //Save keys
        CAprivate = keypair.privateKey;
        CApublic = keypair.publicKey;
        //Create certificate
        CAcert = forge.pki.createCertificate();
        CAcert.validity.notBefore = startDate;
        CAcert.validity.notAfter = endDate;
        CAcert.setIssuer(CAsbj);
        CAcert.setSubject(CAsbj);
        CAcert.setExtensions(CAext);
        CAcert.publicKey = CApublic;
        //Signing defaults to SHA1, which is not good anymore
        //https://github.com/digitalbazaar/forge/blob/80c7fd4e21ae83fa236ebb6a2f4748d54aa0dec0/lib/x509.js#L1032
        CAcert.sign(CAprivate, forge.md.sha256.create());
        //Save the root certificate to files
        let done = 0;
        const onDone = () => {
            console.log("Certificate authority root certificate generated, don't forget to install it.");
            console.log(`The certificate is located at ${certFolder}/Violentca.crt`);
            //Generate certificate for the proxy server
            console.log("Generating certificate for the proxy server...");
            //TODO: Test out to see if Chrome accepts the root certificate for the proxy server itself
            callback();
        };
        const onTick = (err) => {
            if (err) {
                console.log("ERROR: Could not save certificate authority root certificate.");
                throw err;
            } else {
                (++done === 3) && onDone();
            }
        };
        //I'll write all 3 files in parallel
        fs.writeFile(`${certFolder}/Violentca.crt`, forge.pki.certificateToPem(CAcert), onTick);
        fs.writeFile(`${certFolder}/Violentca.public`, forge.pki.publicKeyToPem(CApublic), onTick);
        fs.writeFile(`${certFolder}/Violentca.private`, forge.pki.privateKeyToPem(CAprivate), onTick);
    });
};
/**
 * Load certificate authority root certificate. This function assumes the files, if found, are properly formatted.
 * Errors could be thrown from node-forge, but I won't handle them here as it does print messages that are easy
 * to understand.
 * @function
 * @param {Function} callback - The function to call when it is done.
 ** @param {boolean} result - True if files are found, false otherwise.
 */
const loadCA = (callback) => {
    //Variable naming is safe since this function will abort on the first error
    fs.readFile(`${certFolder}/Violentca.crt`, (err, data) => {
        if (err) {
            callback(false);
            return;
        }
        CAcert = forge.pki.certificateFromPem(data);
        fs.readFile(`${certFolder}/Violentca.public`, (err, data) => {
            if (err) {
                callback(false);
                return;
            }
            CApublic = forge.pki.publicKeyFromPem(data);
            fs.readFile(`${certFolder}/Violentca.private`, (err, data) => {
                if (err) {
                    callback(false);
                    return;
                }
                CAprivate = forge.pki.privateKeyFromPem(data);
                callback(true);
            });
        });
    });
};

/**
 * Generate a server certificate. Refer to genCA() for more information.
 * The new certificate will be saved to cache as well as to files.
 * @function
 * @param {string} domainKey - The key for the cache dictionary.
 * @param {Function} callback - The function to call when it is done.
 */
const genCert = (domainKey, callback) => {
    const path = `${certFolder}/+${domainKey.substring(1)}`;
    console.log(`Generating server certificate for ${domainKey}...`);
    let startDate = new Date();
    startDate.setDate(startDate.getDate() - 1);
    let endDate = new Date();
    endDate.setDate(endDate.getDate() + 35); //5 weeks
    forge.pki.rsa.generateKeyPair({ bits: 1024 }, (err, keypair) => {
        if (err) {
            console.log(`ERROR: Could not create RSA key pair for server certificate for ${domainKey}.`);
            throw err;
        }
        const privateKey = keypair.privateKey;
        const publucKey = keypair.publicKey;
        let serverCert = forge.pki.rsa.createCertificate();
        serverCert.validity.notBefore = startDate;
        serverCert.validity.notAfter = endDate;
        serverCert.setIssuer(CAcert.issuer.attributes);
        serverCert.setSubject(serverSbj);
        serverCert.setExtensions(getServerExt(domainKey.substring(2))); //Trim off "*."
        serverCert.publicKey = publucKey;
        serverCert.sign(CAprivate, forge.md.sha256.create());
        let done = 0;
        const onDone = () => {
            console.log(`Server certificate for ${domainKey} is generated.`);
            certCache[domainKey].setVal({
                cert: forge.pki.certificateToPem(serverCert),
                key: forge.pki.privateKeyToPem(privateKey),
            });
            callback();
        };
        const onTick = (err) => {
            if (err) {
                console.log(`ERROR: Could not save server certificate for ${domainKey}.`);
                throw err;
            } else {
                (++done === 3) && onDone();
            }
        };
        fs.writeFile(`${path}/Violentcert.crt`, forge.pki.certificateToPem(serverCert), onTick);
        fs.writeFile(`${path}/Violentcert.public`, forge.pki.publicKeyToPem(publucKey), onTick);
        fs.writeFile(`${path}/Violentcert.private`, forge.pki.privateKeyToPem(privateKey), onTick);
    });
};
/**
 * Load certificate. Refer to loadCA() for more information.
 * Loaded certificate will be saved to cache.
 * @function
 * @param {string} domainKey - The key for the cache dictionary.
 * @param {Function} callback - The function to call when it is done.
 ** @param {boolean} result - True if successful, false otherwise.
 */
const loadCert = (domainKey, callback) => {
    //Convert domainKey to file name, the assumption below is safe
    const path = `${certFolder}/+${domainKey.substring(1)}`;
    //As I need to keep the cache entry to be "locked" until I'm ready to update it,
    //I need to construct a temporary object
    let tempCert = {
        cert: null,
        key: null,
    };
    //Read the files, this is different than loading root certificate, since https.createServer expects
    //PEM format and it doesn't need the public key
    fs.readFile(`${path}/Violentcert.crt`, (err, data) => {
        if (err) {
            callback(false);
            return;
        }
        tempCert.cert = data;
        fs.readFile(`${path}/Violentcert.private`, (err, data) => {
            if (err) {
                callback(false);
                return;
            }
            tempCert.private = data;
        });
    });
};

/**
 * Initialize certificate authority, don't call sign() before receiving callback from this function.
 * @function
 * @param {Funciton} callback - The function to call when Violenttls is ready.
 ** @param {Certificate} cert - The certificate for the proxy server itself.
 */
exports.init = (callback) => {
    const onEnd = () => {
        callback({
            cert: forge.pki.certificateFromPem(CAcert),
            key: forge.pki.privateKeyFromPem(CAprivate),
        });
    };
    loadCA((result) => {
        if (result) {
            //Found, but I still need to check if it is going to expire, 2 months is going to be a safe value
            let line = new Date();
            line.setDate(line.getDate() + 14);
            if (line > CAcert.validity.notAfter) {
                console.log("Certificate authority is going to expire soon, generating a new one...");
                console.log("Don't uninstall the old certificate yet, as some server certificates are signed with it " +
                    "and may still be used.");
                //Generate new one
                genCA(onEnd);
            } else {
                console.log("Certificate authority loaded.");
                //All good
                onEnd();
            }
        } else {
            console.log("No certificate authority found, generating a new one...");
            //Generate new one
            genCA(onEnd);
        }
    });
};

/**
 * Get a certificate for the current domain, pass it in directly, don't add wildcard.
 * TODO: Test out if Chrome like our shortcut, we are not checking public suffix.
 * @function
 * @param {Function} callback - The function to call when the certificate is ready.
 ** @param {Certificate} - An object that can be directly passed to https.createServer().
 */
exports.sign = (domain, callback) => {
    let key;
    //I need to count how many dots there are, RegExp would not be faster as it will
    //create an array anyway
    let parts = domain.split(".");
    if (parts.length === 2) {
        //Domain is like "example.com", since I can't sign `*.com`, I will sign "example.com"
        //and "*.example.com"
        key = `*.${domain}`;
    } else {
        //Make the first part to be a wild card
        parts[0] = "*";
        key = parts.join(".");
    }
    //Load certificate from key
    if (!certCache[key]) {
        certCache[key] = new Cert();
        //Try to load certificates from files
        loadCert(key, (result) => {
            if (result) {
                //Found, but I still need to check if it is going to expire, 7 days is going to be a safe value
                let line = new Date();
                line.setDate(line.getDate() + 7);
                if (line > forge.pki.certificateFromPem(certCache[key].value.cert).validity.notAfter) {
                    //Generate a new one
                    certGen(key, () => {
                        callback(certCache[key].value);
                    });
                } else {
                    //Still good, just use it
                    //Schedule for next tick to make it asynchronous
                    process.nextTick(callback(certCache[key].value));
                }
            } else {
                //Generate a new one
                certGen(key, () => {
                    callback(certCache[key].value);
                });
            }
        })
    } else if (certCache[key].busy) {
        //There is probably a better way, but this is nice and easy, and I won't need an extra dependency
        certCache[key].onceReady(() => {
            callback(certCache[key].value);
        });
    } else {
        //Certificate found, as this was verified before, I don't need to check for expiry date
        process.nextTick(callback(certCache[key].value));
    }
};

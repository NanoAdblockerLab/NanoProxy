//TLS engine for Violentproxy
//Note that "SSL" often means "SSL/TLS", OpenSSL fully supports TLS related calculations and functions
//SSL is no longer used and its support is dropped by modern browsers
"use strict";

/**
 * Load modules.
 * I will use node-forge because it's a pain to get OpenSSL working on Windows.
 * @const {Module}
 */
const {forge, fs} = global;

/**
 * The place where all certificates will be saved.
 * The root certificate will be directly placed under this directory, other certificates will have their own folder,
 * which will be like "+.example.com".
 * @const {String}
 */
const certFolder = "./Violentproxy/Violentcert";

/**
 * The certificate authority root certificate. Will be initialized when exports.init() is called.
 * @const {Certificate}
 */
const CAcert = {};
/**
 * The certificate for the proxy server, in the format that https.createServer() expects.
 * Will be initialized when exports.init() is called.
 * @const {Certificate}
 */
global.localCert = {};
/**
 * Server certificates cache.
 * Will be a dictionary of cache key to certificate. The certificate object can be passed directly to https.createServer().
 * A cache key must be like "*.example.com", the wildcard is required.
 * @var {Dictionary.<Cert>}
 */
let certCache = {};
/**
 * Certificate object, this prevents issues that can be caused by race conditions.
 * Use Cert.value to get the certificate and Cert.busy to check ready state.
 * @class
 */
const Cert = class {
    /**
     * Construct the object.
     * @constructor
     */
    constructor() {
        this.value = null;
        this.busy = true;
        this.onceReadyCallbacks = [];
    }
    /**
     * Set this certificate, this will also mark it as ready and trigger callbacks.
     * @method
     * @param {Certificate} val - The certificate.
     */
    setVal(val) {
        this.value = val;
        this.busy = false;
        //Call each callback asynchronously
        let i = 0;
        const call = () => {
            //I don't need to shift the array because I already flipped this.busy flag
            this.onceReadyCallbacks[i++]();
            if (i < this.onceReadyCallbacks.length) {
                process.nextTick(call);
            } else {
                //Free memory
                delete this.onceReadyCallbacks;
            }
        }
        //Check if I have callbacks waiting
        if (this.onceReadyCallbacks.length) {
            process.nextTick(call);
        } else {
            delete this.onceReadyCallbacks;
        }
    }
    /**
     * Schedule a function to call once the certificate is ready.
     * @method
     * @param {Function} func - The funtion to call once the certificate is ready.
     */
    onceReady(func) {
        if (this.busy) {
            this.onReadyCallbacks.push(func);
        } else {
            process.nextTick(func);
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
        shortName: "O", //Organization or company
        value: "Violentproxy",
    },
    {
        shortName: "OU", //Organizational unit or department
        value: "Violenttls Engine",
    },
    {
        shortName: "ST", //State or province
        value: "World",
    },
    {
        shortName: "CN", //Common Name, can be anything
        value: "Violentca",
    },
    { //Optional
        shortName: "L", //City or town
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
        keyEncipherment: true,
        dataEncipherment: true,
        keyCertSign: true,
        cRLSign: true,
    },
    {
        //https://github.com/digitalbazaar/forge/blob/80c7fd4e21ae83fa236ebb6a2f4748d54aa0dec0/lib/x509.js#L1431
        name: "subjectAltName",
        altNames: [
            {
                type: 2, //Domain name or DNS name
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
 * Server subject, same for all servers, refer to CAsbj for more information.
 * This can be the same for all servers because browsers don't care about CN (common name) anymore and only check
 * subjectAltName extension.
 * https://www.chromestatus.com/feature/4981025180483584
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
    {
        shortName: "CN", //Connon Name, can be anything
        value: "Violentserver",
    },
    { //Optional
        shortName: "L", //City, town, etc.
        value: "World",
    },
];
/**
 * Get server extension. This cannot be a single global variable as I might be generating two certificates at the
 * same time and the extension is slightly different for each server. Refer to CAext for more information.
 * @function
 * @param {Array.<stirng>} domain - The domains to sign.
 * @param {Array.<string>} ips - The IPs to sign.
 * @return {ServerExtensions} Server extensions.
 */
const getServerExt = (domains, ips) => {
    let tempExt = [
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
            altNames: [],
        },
        {
            name: "nsCertType",
            client: true,
            server: true,
        },
    ];
    //Add domains
    for (let i = 0; i < domains.length; i++) {
        tempExt[2].altNames.push({
            type: 2,
            value: domains[i],
        });
    }
    //Add IPs
    for (let i = 0; i < domains.length; i++) {
        tempExt[2].altNames.push({
            type: 7,
            ip: ips[i],
        });
    }
    return tempExt;
};

/**
 * Generate a certificate authority root certificates. The new root certificate will be saved to a file automatically.
 * @function
 * @param {Function} callback - The function to call when the root certificate is ready.
 */
const genCA = (callback) => {
    global.log("INFO", "Generating certificate authority root certificate...");
    //Chromium will reject certificate that has validity longer than 39 months (3.25 years)
    //The root certificate will last 20 years, a new one will be generated if there are less than 3 years validity left
    let startDate = new Date();
    //V8 will handle switching to last month
    startDate.setDate(startDate.getDate() - 1);
    let endDate = new Date();
    endDate.setFullYear(endDate.getFullYear() + 20);
    //Generate RSA key pair
    forge.pki.rsa.generateKeyPair({ bits: 2048 }, (err, keypair) => {
        //Abort on error
        if (err) {
            global.log("ERROR", "Could not generate RSA key pair for the certificate authority root certificate.");
            throw err;
        }
        //Save private key
        CAcert.key = keypair.privateKey;
        //Create certificate
        CAcert.cert = forge.pki.createCertificate();
        CAcert.cert.validity.notBefore = startDate;
        CAcert.cert.validity.notAfter = endDate;
        CAcert.cert.setIssuer(CAsbj);
        CAcert.cert.setSubject(CAsbj);
        CAcert.cert.setExtensions(CAext);
        CAcert.cert.publicKey = keypair.publicKey;
        //Signing defaults to SHA1, which is not good anymore
        //https://github.com/digitalbazaar/forge/blob/80c7fd4e21ae83fa236ebb6a2f4748d54aa0dec0/lib/x509.js#L1032
        CAcert.cert.sign(CAcert.key, forge.md.sha256.create());
        //Save the root certificate to files
        let done = 0;
        const onDone = () => {
            global.log("NOTICE", "Certificate authority root certificate generated, don't forget to install it.");
            global.log("NOTICE", `The certificate is located at ${certFolder}/Violentca.crt`);
            callback();
        };
        const onTick = (err) => {
            if (err) {
                global.log("ERROR", "Could not save certificate authority root certificate.");
                throw err;
            } else {
                (++done === 3) && onDone();
            }
        };
        //I'll write all 3 files in parallel
        fs.writeFile(`${certFolder}/Violentca.crt`, forge.pki.certificateToPem(CAcert.cert), onTick);
        fs.writeFile(`${certFolder}/Violentca.public`, forge.pki.publicKeyToPem(keypair.publicKey), onTick);
        fs.writeFile(`${certFolder}/Violentca.private`, forge.pki.privateKeyToPem(CAcert.key), onTick);
    });
};
/**
 * Load certificate authority root certificate. This function assumes the files, if found, are valid.
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
        CAcert.cert = forge.pki.certificateFromPem(data);
        fs.readFile(`${certFolder}/Violentca.private`, (err, data) => {
            if (err) {
                callback(false);
                return;
            }
            CAcert.key = forge.pki.privateKeyFromPem(data);
            callback(true);
        });
    });
};

/**
 * Generate a server certificate. Refer to genCA() for more information.
 * The new certificate will be saved to cache as well as to files.
 * @function
 * @param {Array.<string>} domains - The domains of the certificate.
 * @param {Array.<string>} ips - The ips of the certificate, refer to getServerExt() for more information.
 * @param {string} cacheKey - The key for the certificate cache dictionary.
 * @param {Function} callback - The function to call when it is done.
 */
const genCert = (domains, ips, cacheKey, callback) => {
    const path = `${certFolder}/+${cacheKey.substring(1)}`;
    global.log("INFO", `Generating server certificate for ${cacheKey}...`);
    //Server certificate lasts 2 year, because Chromium will soon start to reject certificates that lasts too long
    let startDate = new Date();
    startDate.setDate(startDate.getDate() - 1);
    let endDate = new Date();
    endDate.setFullYear(endDate.getFullYear() + 2);
    forge.pki.rsa.generateKeyPair({ bits: 2048 }, (err, keypair) => {
        if (err) {
            global.log("ERROR", `Could not create RSA key pair for server certificate for ${cacheKey}.`);
            throw err;
        }
        let serverCert = forge.pki.createCertificate();
        serverCert.validity.notBefore = startDate;
        serverCert.validity.notAfter = endDate;
        serverCert.setIssuer(CAcert.issuer.attributes);
        serverCert.setSubject(serverSbj);
        serverCert.setExtensions(getServerExt(domains, ips));
        serverCert.publicKey = keypair.publicKey;
        serverCert.sign(CAcert.key, forge.md.sha256.create());
        let done = 0;
        const cert = forge.pki.certificateToPem(serverCert);
        const key = forge.pki.privateKeyToPem(keypair.privateKey);
        const onDone = () => {
            global.log("INFO", `Server certificate for ${cacheKey} is generated.`);
            certCache[cacheKey].setVal({
                cert: cert,
                key: key,
            });
            callback();
        };
        const onTick = (err) => {
            if (err) {
                global.log("ERROR", `Could not save server certificate for ${cacheKey}.`);
                throw err;
            } else {
                (++done === 3) && onDone();
            }
        };
        fs.mkdir(path, (err) => {
            if (err) {
                global.log("ERROR", `Could not save server certificate for ${cacheKey}.`);
                throw err;
            } else {
                fs.writeFile(`${path}/Violentcert.crt`, cert, onTick);
                fs.writeFile(`${path}/Violentcert.public`, forge.pki.publicKeyToPem(keypair.publicKey), onTick);
                fs.writeFile(`${path}/Violentcert.private`, key, onTick);
            }
        });
    });
};
/**
 * Load certificate. Refer to loadCA() for more information.
 * Loaded certificate will be saved to cache.
 * @function
 * @param {string} cacheKey - The key for the cache dictionary.
 * @param {Function} callback - The function to call when it is done.
 ** @param {boolean} result - True if successful, false otherwise.
 */
const loadCert = (cacheKey, callback) => {
    //Convert domainKey to file name, the assumption below is safe
    const path = `${certFolder}/+${cacheKey.substring(1)}`;
    //Read the files, this is different than loading root certificate, since https.createServer expects
    //PEM format and it doesn't need the public key
    fs.readFile(`${path}/Violentcert.crt`, (err, cert) => {
        if (err) {
            callback(false);
            return;
        }
        fs.readFile(`${path}/Violentcert.private`, (err, key) => {
            if (err) {
                callback(false);
                return;
            }
            certCache[cacheKey].setVal({
                cert: cert,
                key: key,
            });
            callback(true);
        });
    });
};

/**
 * Initialize certificate authority, don't call sign() before receiving callback from this function.
 * @function
 * @param {Funciton} callback - The function to call when Violenttls is ready.
 */
exports.init = (callback) => {
    const onEnd = () => {
        //Load certificate for the proxy server
        loadCert("localhost", (result) => {
            if (result) {
                //Found, but I still need to check if it is going to expire, 2 months is going to be a safe value
                let line = new Date();
                //V8 will handle switching to next year
                line.setMonth(line.getMonth() + 2);
                if (line > forge.pki.certificateFromPem(certCache["localhost"].value.cert).validity.notAfter) {
                    //Generate a new one
                    genCert(global.proxyDomains, global.proxyIPs, "localhost", () => {
                        global.localCert = certCache["localhost"].value;
                        callback();
                    });
                } else {
                    //Still good, just use it
                    global.localCert = certCache["localhost"].value;
                    callback();
                }
            } else {
                //Generate a new one
                genCert(global.proxyDomains, global.proxyIPs, "localhost", () => {
                    global.localCert = certCache["localhost"].value;
                    callback();
                });
            }
        });
    };
    loadCA((result) => {
        if (result) {
            //Found, but I still need to check if it is going to expire, checking for 3 years because server certificates
            //are valid for 2 years
            let line = new Date();
            line.setFullYear(line.getFullYear() + 3);
            if (line > global.CA.cert.validity.notAfter) {
                global.log("NOTICE", "Certificate authority is going to expire soon, generating a new one...");
                global.log("NOTICE", ": Don't uninstall the old certificate yet, as some server certificates are signed " +
                    "with it and may still be used.");
                //Generate new one
                genCA(onEnd);
            } else {
                global.log("INFO", "Certificate authority root certificate loaded.");
                //All good
                onEnd();
            }
        } else {
            global.log("INFO", "No certificate authority found, generating a new one...");
            //Generate new one
            genCA(onEnd);
        }
    });
};

/**
 * Get a certificate for the current domain, pass it in directly, don't add wildcard.
 * @function
 * @param {string} domain - The domain of the certificate, a wildcard version will be automatically added.
 * @param {Function} callback - The function to call when the certificate is ready.
 ** @param {Certificate} - An object that can be directly passed to https.createServer().
 */
exports.sign = (domain, callback) => {
    let cacheKey;
    let domainsToSign;
    //I need to count how many dots there are, RegExp would not be faster as it will create an array anyway
    let parts = domain.split(".");
    if (parts.length < 2) {
        //Assume local address
        cacheKey = domain;
        domainsToSign = [domain];
    } else if (parts.length === 2) {
        //Domain is like "example.com", since I can't sign `*.com`, I will sign "example.com" and "*.example.com"
        cacheKey = `*.${domain}`;
        domainsToSign = [domain, cacheKey];
    } else {
        //Make the first part to be a wild card
        parts[0] = "*";
        cacheKey = parts.join(".");
        domainsToSign = [domain, cacheKey];
    }
    //Check if I already gave the certificate
    if (!certCache[cacheKey]) {
        certCache[cacheKey] = new Cert();
        //Try to load certificates from files
        loadCert(cacheKey, (result) => {
            if (result) {
                //Found, but I still need to check if it is going to expire, 2 months is going to be a safe value
                let line = new Date();
                //V8 will handle switching to next year
                line.setMonth(line.getMonth() + 2);
                if (line > forge.pki.certificateFromPem(certCache[cacheKey].value.cert).validity.notAfter) {
                    //Generate a new one
                    genCert(domainsToSign, [], cacheKey, () => {
                        callback(certCache[cacheKey].value);
                    });
                } else {
                    //Still good, just use it
                    callback(certCache[cacheKey].value)
                }
            } else {
                //Generate a new one
                genCert(domainsToSign, [], cacheKey, () => {
                    callback(certCache[cacheKey].value);
                });
            }
        });
    } else if (certCache[cacheKey].busy) {
        //There is probably a better way, but this is nice and easy, and I won't need an extra dependency
        certCache[cacheKey].onceReady(() => {
            callback(certCache[cacheKey].value);
        });
    } else {
        //Certificate found, as this was verified before, I don't need to check for expiry date
        process.nextTick(() => {
            callback(certCache[cacheKey].value)
        });
    }
};

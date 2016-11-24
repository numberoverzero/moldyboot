"use strict";

var gaasKeys = (function() {
    var self = {};
    var crypto = window.crypto.subtle;

    // https://gist.github.com/joni/3760795
    function toUTF8Array(str) {
        var utf8 = [];
        for (var i=0; i < str.length; i++) {
            var charcode = str.charCodeAt(i);
            if (charcode < 0x80) utf8.push(charcode);
            else if (charcode < 0x800) {
                utf8.push(0xc0 | (charcode >> 6),
                          0x80 | (charcode & 0x3f));
            }
            else if (charcode < 0xd800 || charcode >= 0xe000) {
                utf8.push(0xe0 | (charcode >> 12),
                          0x80 | ((charcode>>6) & 0x3f),
                          0x80 | (charcode & 0x3f));
            }
            // surrogate pair
            else {
                i++;
                // UTF-16 encodes 0x10000-0x10FFFF by
                // subtracting 0x10000 and splitting the
                // 20 bits of 0x0-0xFFFFF into two halves
                charcode = 0x10000 + (((charcode & 0x3ff)<<10)
                          | (str.charCodeAt(i) & 0x3ff))
                utf8.push(0xf0 | (charcode >>18),
                          0x80 | ((charcode>>12) & 0x3f),
                          0x80 | ((charcode>>6) & 0x3f),
                          0x80 | (charcode & 0x3f));
            }
        }
        return new Uint8Array(utf8);
    }

    // http://stackoverflow.com/a/12713326
    function Uint8ToString(u8a){
        var CHUNK_SZ = 0x8000;
        var c = [];
        for (var i=0; i < u8a.length; i+=CHUNK_SZ) {
            c.push(String.fromCharCode.apply(null, u8a.subarray(i, i+CHUNK_SZ)));
        }
        return c.join("");
    }

    function calculateMaxSaltLength (keyLen, hash) {
        var digestLen;
        if (hash === "SHA-256") digestLen = 32;
        else throw new Error("Unknown hash function '" + hash + "'");
        // RFC 3447
        var emLen = Math.ceil((keyLen-1) / 8);
        return emLen - digestLen - 2;
    }

    self.generate = function (keyLen, hash) {
        var keyLen = (typeof keyLen === 'undefined') ? 2048 : keyLen;
        var hash = (typeof hash === 'undefined') ? "SHA-256" : hash;
        return new Promise(function (resolve, reject) {
            crypto.generateKey(
                {
                    name: "RSA-PSS",
                    modulusLength: keyLen,
                    publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
                    hash: {name: hash}
                },
                true,  // exportable
                ["sign"]  // only used to sign outgoing
            )
            .then(function (keyBlob) {
                keyBlob.saltLen = calculateMaxSaltLength(keyLen, hash);
                resolve(keyBlob);
            })
            .catch(reject)
        });
    };

    self.sign = function(keyBlob, message) {
        return new Promise(function (resolve, reject) {
            crypto.sign(
                {name: "RSA-PSS", saltLength: keyBlob.saltLen},
                keyBlob.privateKey,
                toUTF8Array(message)
            )
            .then(function(signature) {
                // ArrayBuffer -> Uint8Array -> String -> B64Encode
                var b64Str = btoa(Uint8ToString(
                    new Uint8Array(signature)));
                resolve(b64Str);
            })
            .catch(reject);
        });
    };

    self.export = function(keyBlob) {
        return new Promise(function (resolve, reject) {
            Promise.all([
                crypto.exportKey("jwk", keyBlob.publicKey),
                crypto.exportKey("jwk", keyBlob.privateKey)
            ])
            .then(function(jwks) {
                resolve({publicKey: jwks[0], privateKey: jwks[1]});
            })
            .catch(reject);
        });
    };

    return self;
}());

var gaasKeyStore = (function() {
    var self = {};
    var database = null;

    self.open = function() {
        return new Promise(function (resolve, reject) {
            if (database) {
                resolve(self);
            } else {
                var openPromise = indexedDB.open("{{webcrypto.databaseName}}", "{{webcrypto.databaseVersion}}");
                openPromise.onsuccess = function(event) {
                    database = event.target.result;
                    resolve(self);
                };
                openPromise.onupgradeneeded = function (event) {
                    database = event.target.result;
                    if (!database.objectStoreNames.contains("{{webcrypto.objectStoreName}}")) {
                        var objectStore = database.createObjectStore("{{webcrypto.objectStoreName}}", {autoIncrement: false});
                        objectStore.transaction.oncomplete = function(event) {
                            resolve(self);
                        };
                    } else {
                        resolve(self);
                    }
                };
                openPromise.onerror = function(event) {reject(event.error)};
                openPromise.onblocked = function() {
                    reject(new Error("{{webcrypto.databaseName}} is already open."));
                };
            }
        });
    };

    self.close = function() {
        return new Promise(function (resolve, reject) {
            if (!database) {
                resolve(self);
            } else {
                database.close();
                database = null;
                resolve(self);
            }
        });
    };

    self.load = function (username, regenerate, keyLen, hash) {
        var regenerate = (typeof regenerate === 'undefined') ? false : regenerate;
        return new Promise(function (resolve, reject) {
            self.open()
            .then(function() {
                var mode = regenerate ? "readwrite" : "readonly",
                    transaction = database.transaction(["{{webcrypto.objectStoreName}}"], mode),
                    objectStore = transaction.objectStore("{{webcrypto.objectStoreName}}"),
                    request = objectStore.get(username);
                request.onsuccess = function(event) {
                    var keyBlob = event.target.result;
                    if (keyBlob) {
                        resolve(keyBlob);
                    } else if (regenerate) {
                        gaasKeys.generate(keyLen, hash)
                        .then(function (keys) {
                            var keyBlob = {
                                privateKey: keys.privateKey,
                                publicKey: keys.publicKey,
                                saltLen: keys.saltLen
                            };
                            self.save(keyBlob, username)
                            .then(function() {
                                resolve(keyBlob);
                            })
                            .catch(reject);
                        })
                        .catch(reject);
                    } else {
                        reject(new Error("NotFoundError", username));
                    }
                };
                request.onerror = reject;
            })
            .catch(reject);
        });
    };

    self.save = function (keyBlob, username) {
        return new Promise(function (resolve, reject) {
            self.open()
            .then(function() {
                var transaction = database.transaction(["{{webcrypto.objectStoreName}}"], "readwrite");
                transaction.oncomplete = function() {resolve(keyBlob)};
                transaction.onerror = onabort = function(event) {reject(event.error)};
                transaction.objectStore("{{webcrypto.objectStoreName}}").put(keyBlob, username);
            })
            .catch(reject);
        });
    };

    self.delete = function (username) {
        return new Promise(function (resolve, reject) {
            self.open()
            .then(function() {
                var transaction = database.transaction(["{{webcrypto.objectStoreName}}"], "readwrite"),
                    objectStore = transaction.objectStore("{{webcrypto.objectStoreName}}");
                objectStore.delete(username)
                .then(resolve)
                .catch(reject);
            })
            .catch(reject);
        });
    };
    return self;
}());

var api = (function() {
    var self = {};
    self.endpoint = "{{endpoints.api}}";

    /*
     * Can't sign the request, publicKey is part of the request
     */
    self.login = function(username, password) {
        return new Promise(function (resolve, reject) {
            gaasKeyStore.load(username, true)
            .then(function (keyBlob) {
                gaasKeys.export(keyBlob)
                .then(function (jwk) {
                    var credentials = {
                        username: username,
                        password: password,
                        public_key: {
                            e: jwk.publicKey.e,
                            n: jwk.publicKey.n
                        }
                    };
                    return window.superagent
                        .post(self.endpoint + "/keys")
                        .send(credentials);
                })
                .then(function (response) {
                    keyBlob.until = response.body.until;
                    keyBlob.id = response.body.key_id;

                    gaasKeyStore.save(keyBlob, username)
                    .then(function() {
                        resolve(response);
                    })
                    .catch(reject);
                })
                .catch(reject);
            })
            .catch(reject);
        });
    };

    self.call = function(method, path, )

    return self;
}());

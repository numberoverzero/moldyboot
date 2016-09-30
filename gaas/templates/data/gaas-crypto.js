"use strict";

var simpleCrypto = (function() {
    var my = {};
    my.generate = function(keyLen) {
        console.log("Generating new key pair.");
        if (typeof(keyLen) === "undefined") keyLen = 2048;
        return KEYUTIL.generateKeypair("RSA", keyLen);
    };
    my.sign = function(privateKey, message) {
        console.log("Signing message >>>" + message + "<<<");
        return privateKey.signStringPSS(message, "sha256", -2);
    };
    my.toPEM = function(key) {
        var formatType = key.isPrivate ? "PKCS8PRV" : "PKCS8PUB";
        return KEYUTIL.getPEM(key, formatType);
    };
    my.fromPEM = function(pem, isPrivate) {
        return KEYUTIL.getKey(pem, null, isPrivate ? "PKCS8PRV" : "PKCS8PUB");
    };
    my.b64sha256 = function(value, isHex) {
        var md = new KJUR.crypto.MessageDigest({alg: "sha256", prov: "cryptojs"});
        return hex2b64(isHex? md.digestHex(value) : md.digestString(value));
    };
    return my;
}());

var localKeyStorage = (function() {
    var my = {};
    my.set = function(key) {
        console.log("storing apiKey in localStorage.");
        localStorage.setItem("apiKey", JSON.stringify({
            privateKey: simpleCrypto.toPEM(key.privateKey),
            publicKey: simpleCrypto.toPEM(key.publicKey),
            keyId: key.keyId,
            until: key.until ? key.until.toISOString() : undefined
        }));
    };
    my.get = function() {
        var storedKey = localStorage.getItem("apiKey");
        // Not found
        if (storedKey === null) {
            console.log("didn't find apiKey in localStorage.");
            return null;
        }
        storedKey = JSON.parse(storedKey);
        // Has an expiration and passed it
        if (storedKey.until && new Date(storedKey.until) < new Date()) {
            console.log("found EXPIRED apiKey in localStorage.");
            return null;
        }
        console.log("found apiKey in localStorage.");
        return {
            privateKey: simpleCrypto.fromPEM(storedKey.privateKey, true),
            publicKey: simpleCrypto.fromPEM(storedKey.publicKey, false),
            keyId: storedKey.keyId,
            until: storedKey.until ? new Date(storedKey.until) : undefined
        };
    };
    return my;
}());

var signer = (function() {
    var my = {};
    my._key = null;
    my.setKey = function(key) {
        console.log("set signer key.");
        localKeyStorage.set(key);
        my._key = key;
        return key;
    };
    my.loadKey = function() {
        console.log("signer loading key.");
        var key = localKeyStorage.get();
        console.log("signer loaded key.");
        if (key !== null) {
            my._key = key;
        }
        return key;
    };

    my.sign = function(jqXHR, ajaxOptions) {
        if (my._key === null) my.loadKey();
        if (my._key === null){
            console.log("key is missing");
            throw {
                code: "MissingPrivateKey",
                message: "The private key was not found."
            };
        } else if (!my._key.until || !my._key.keyId)  {
            console.log("expiry or key id is missing");
            throw {
                code: "UnknownPublicKey",
                message: "The public key is not registered."
            }
        } else if (my._key.until < new Date()) {
            console.log("expired key");
            throw {
                code: "ExpiredPublicKey",
                message: "The public key has expired."
            }
        }

        var x_date = new Date().toISOString(),

            url = new window.URL(ajaxOptions.url),
            path = url.pathname + url.search,
            method = ajaxOptions.type.toLowerCase(),
            request_target = method + " " + path,

            data = ajaxOptions.data || "",
            content_length = "" + (data ? data.length : 0),
            x_content_sha256 = simpleCrypto.b64sha256(data, false);

        function canonicalize(header) {
            return header.toLowerCase() + ": " + computed_headers[header];
        }

        var computed_headers = {
                "x-date": x_date,
                "content-length": content_length,
                "x-content-sha256": x_content_sha256,
                "(request-target)": request_target
            },
            signed_headers = Object.keys(computed_headers);

        var string_to_sign = signed_headers.map(canonicalize).join("\n"),
            signature_hex_bytes = simpleCrypto.sign(my._key.privateKey, string_to_sign),
            signature_hash = hex2b64(signature_hex_bytes);

        console.log("signature_hex_bytes: " + signature_hex_bytes);

        var authorization_header = [
                'Signature',
                'headers="' + signed_headers.join(" ") + '"',
                'id="' + my._key.keyId + '"',
                'signature="' + signature_hash + '"'
        ].join(" ");

        console.log("created authorization header");
        console.log(authorization_header);

        jqXHR.setRequestHeader("x-date", x_date);
        jqXHR.setRequestHeader("content-length", content_length);
        jqXHR.setRequestHeader("x-content-sha256", x_content_sha256);
        jqXHR.setRequestHeader("authorization", authorization_header);
    };
    my._ajaxSendHandler = null;
    my.attachAjaxSend = function() {
        console.log("attaching signing handler.");
        if (my._ajaxSendHandler !== null) {
            console.log("removing previous signing handler.");
            $(document).off("ajaxSend", null, my._ajaxSendHandler);
        }
        my._ajaxSendHandler = function(event, jqXHR, ajaxOptions){
            // Don't try to sign a login, there's no keyId and the publicKey probably isn't recognized.
            var method = ajaxOptions.type.toLowerCase();
            if (ajaxOptions.url === api.endpoint + "/keys" && method === "post"){
                console.log("not signing post against api login");
                return true;
            }
            console.log("signing handler intercepted " + method + " to " + ajaxOptions.url);
            my.sign(jqXHR, ajaxOptions);
            return true;
        };
        $(document).on("ajaxSend", null, my._ajaxSendHandler);
        console.log("attached signing handler.");
    };
    return my;
}());

var api = (function() {
    var my = {};
    my.endpoint = "{{endpoints.api}}";
    my.login = function(username, password, publicKey) {
        console.log("logging in with credentials: " + username + ", " + password);
        return $.ajax({
            url: my.endpoint + "/keys",
            type: "post",
            data: JSON.stringify({
                username: username,
                password: password,
                public_key: simpleCrypto.toPEM(publicKey)})
        });
    };
    my.getKey = function() {
        console.log("getting current key_id, expiry");
        return $.ajax({
            url: my.endpoint + "/keys",
            type: "get"
        })
    };
    return my;
}());

// One-time setup

// always use json
$.ajaxSetup({
    dataType: "json",
    contentType: "application/json"
});
// install signer
signer.attachAjaxSend();

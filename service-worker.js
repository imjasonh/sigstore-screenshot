// https://stackoverflow.com/questions/38552003/how-to-decode-jwt-token-in-javascript-without-using-a-library
function parseJwt(token) {
    var base64Url = token.split('.')[1];
    var base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
    var jsonPayload = decodeURIComponent(atob(base64).split('').map(function (c) {
        return '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2);
    }).join(''));
    return JSON.parse(jsonPayload);
}

function base64(arrayBuffer) {
    return btoa(String.fromCharCode.apply(null, new Uint8Array(arrayBuffer)));
}

function useKey(key) {
    console.log("pub", key.publicKey);
    console.log("priv", key.privateKey);

    var manifest = chrome.runtime.getManifest();
    var clientId = encodeURIComponent(manifest.oauth2.client_id);
    var scopes = encodeURIComponent(manifest.oauth2.scopes.join(' '));
    var redirectUri = encodeURIComponent('https://' + chrome.runtime.id + '.chromiumapp.org');

    var url = 'https://accounts.google.com/o/oauth2/auth' +
        '?client_id=' + clientId +
        '&response_type=id_token' +
        '&access_type=offline' +
        '&redirect_uri=' + redirectUri +
        '&scope=' + scopes;

    chrome.identity.launchWebAuthFlow({
        'url': url,
        'interactive': true
    }, function (redirectedTo) {
        if (chrome.runtime.lastError) {
            // Example: Authorization page could not be loaded.
            console.error(chrome.runtime.lastError.message);
        }
        else {
            var response = redirectedTo.split('#', 2)[1];

            // Example: id_token=<YOUR_BELOVED_ID_TOKEN>&authuser=0&hd=<SOME.DOMAIN.PL>&session_state=<SESSION_SATE>&prompt=<PROMPT>
            console.log(response);

            // Get id_token
            var idToken = response.split('&', 1)[0].split('=', 2)[1];
            console.log(idToken);
            useToken(key, idToken);
        }
    }
    );
}

function useToken(key, token) {
    console.log("token", token);
    let parsed = parseJwt(token);
    console.log("parsed", parsed);

    crypto.subtle.sign("RSASSA-PKCS1-v1_5", key.privateKey, new TextEncoder().encode(parsed.sub)).then(signature => {
        useSignature(key, token, signature);
    }).catch(console.error);
}

function useSignature(key, token, signature) {
    console.log("signature", signature);
    console.log("signature b64", base64(signature));

    fetch("https://fulcio.sigstore.dev/v2/signingCert", {
        method: "POST",
        headers: {
            "Authorization": `Bearer ${token}`,
        },
        body: JSON.stringify({
            credentials: { oidc_identity_token: token },
            key: {
                public_key: {
                    algorithm: "RSASSA-PKCS1-v1_5",
                    content: key.publicKey
                },
                proof_of_possession: base64(signature),
            }
        }),
    }).then(useResponse).catch(console.error);
}

function useResponse(resp) {
    console.log("resp", resp);
    console.log("resp", resp.json());
}

function capture(tab) {
    console.log("tab", tab);

    crypto.subtle.generateKey({
        name: "RSASSA-PKCS1-v1_5",
        modulusLength: 2048, //can be 1024, 2048, or 4096
        publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
        hash: { name: "SHA-256" }, //can be "SHA-1", "SHA-256", "SHA-384", or "SHA-512"
    }, false, ["sign", "verify"]).then(useKey).catch(console.error);
}

chrome.action.onClicked.addListener((tab) => { chrome.tabs.captureVisibleTab({ format: "png" }, capture); });
chrome.commands.onCommand.addListener((command) => { chrome.tabs.captureVisibleTab({ format: "png" }, capture); });

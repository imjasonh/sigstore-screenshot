// https://stackoverflow.com/questions/38552003/how-to-decode-jwt-token-in-javascript-without-using-a-library
function parseJwt(token) {
    var base64Url = token.split('.')[1];
    var base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
    var jsonPayload = decodeURIComponent(atob(base64).split('').map(function (c) {
        return '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2);
    }).join(''));
    return JSON.parse(jsonPayload);
}

function base64(arrayBuffer) { return btoa(String.fromCharCode.apply(null, new Uint8Array(arrayBuffer))); }

function useKey(key) {
    console.log("pub", key.publicKey);
    console.log("priv", key.privateKey);

    var manifest = chrome.runtime.getManifest();
    var clientId = encodeURIComponent(manifest.oauth2.client_id);
    var scopes = encodeURIComponent(manifest.oauth2.scopes.join(' '));
    var redirectUri = encodeURIComponent(`https://${chrome.runtime.id}.chromiumapp.org`);

    chrome.identity.launchWebAuthFlow({
        url: `https://accounts.google.com/o/oauth2/auth?client_id=${clientId}&response_type=id_token&access_type=offline&redirect_uri=${redirectUri}&scope=${scopes}`,
        interactive: true
    }, function (redirectedTo) {
        if (chrome.runtime.lastError) {
            console.error(chrome.runtime.lastError.message);
        }
        else {
            // Example: id_token=<YOUR_BELOVED_ID_TOKEN>&authuser=0&hd=<SOME.DOMAIN.PL>&session_state=<SESSION_STATE>&prompt=<PROMPT>
            var response = redirectedTo.split('#', 2)[1];
            var idToken = response.split('&', 1)[0].split('=', 2)[1];
            useToken(key, idToken);
        }
    });
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

    fetch("https://fulcio.sigstore.dev/api/v2/signingCert", {
        method: "POST",
        headers: { "Authorization": `Bearer ${token}` },
        body: JSON.stringify({
            credentials: { oidcIdentityToken: token },
            publicKeyRequest: {
                publicKey: {
                    algorithm: "RSASSA-PKCS1-v1_5",
                    content: base64(new TextEncoder().encode(key.publicKey)),
                },
                proofOfPossession: base64(signature),
            }
        }),
    }).then(useResponse).catch(console.error); // TODO: This fails due to CORS
}

function useResponse(resp) {
    console.log("resp", resp);
    console.log("resp", resp.json().then(console.log).catch(console.error));
}

function capture(tab) {
    console.log("tab", tab);

    crypto.subtle.generateKey({
        name: "RSASSA-PKCS1-v1_5",
        modulusLength: 2048,
        publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
        hash: { name: "SHA-256" },
    }, false, ["sign", "verify"]).then(useKey).catch(console.error);
}

chrome.action.onClicked.addListener((tab) => { chrome.tabs.captureVisibleTab({ format: "png" }, capture); });
chrome.commands.onCommand.addListener((command) => { chrome.tabs.captureVisibleTab({ format: "png" }, capture); });

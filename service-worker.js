
// https://stackoverflow.com/questions/38552003/how-to-decode-jwt-token-in-javascript-without-using-a-library
function parseJwt(token) {
    let base64Url = token.split('.')[1];
    let base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
    let jsonPayload = decodeURIComponent(atob(base64).split('').map(function (c) {
        return '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2);
    }).join(''));
    return JSON.parse(jsonPayload);
}

function base64(arrayBuffer) { return btoa(String.fromCharCode.apply(null, new Uint8Array(arrayBuffer))); }

function randString() { return (Math.random() + 1).toString(36).substring(3); }

// https://developers.google.com/identity/openid-connect/openid-connect#exchangecode
function getIDToken() {
    chrome.identity.getProfileUserInfo(info => {
        console.log("info", info);
        let manifest = chrome.runtime.getManifest();
        let state = randString();
        let params = new URLSearchParams();
        params.append("client_id", "344413968647-31l50a3vmasmh1p59rps3fjv2o3ncrae.apps.googleusercontent.com");
        params.append("response_type", "id_token");
        params.append("nonce", randString());
        params.append("redirect_uri", `https://${chrome.runtime.id}.chromiumapp.org`);
        params.append("scope", "https://www.googleapis.com/auth/userinfo.email");
        params.append("state", state);
        params.append("login_hint", info.email);
        let url = `https://accounts.google.com/o/oauth2/v2/auth?` + params

        chrome.identity.launchWebAuthFlow({
            url: url,
            interactive: true
        }, function (redirectedTo) {
            let params = new URLSearchParams(redirectedTo.split('#')[1]);
            console.log("params", Object.fromEntries(params));
            let gotState = params.get('state');
            if (gotState !== state) {
                console.error(`state mismatch ${gotState} !== ${state}`);
                return;
            }

            let idToken = params.get('id_token');
            useToken(idToken);
        });
    });
}

function useToken(idToken) {
    let parsed = parseJwt(idToken);
    console.log("parsed", parsed);

    // Generate an ephemeral key, use it to sign the `sub` so we can prove we own the private key.
    crypto.subtle.generateKey({
        name: "RSASSA-PKCS1-v1_5",
        modulusLength: 2048,
        publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
        hash: { name: "SHA-256" },
    }, false, ["sign", "verify"]).then(key => {
        console.log("pub", key.publicKey);
        console.log("priv", key.privateKey);
        crypto.subtle.sign("RSASSA-PKCS1-v1_5", key.privateKey, new TextEncoder().encode(parsed.sub)).then(signature => {
            getCert(key, idToken, signature);
        }).catch(console.error);
    }).catch(console.error);
}

function getCert(key, idToken, signature) {
    console.log("signature", signature);
    let body = {
        credentials: { oidcIdentityToken: idToken },
        publicKeyRequest: {
            publicKey: {
                algorithm: "RSASSA-PKCS1-v1_5",
                content: base64(new TextEncoder().encode(key.publicKey)),
            },
            proofOfPossession: base64(signature),
        }
    };
    console.log("body", body);

    fetch("https://fulcio.sigstore.dev/api/v2/signingCert", {
        method: "POST",
        body: JSON.stringify(body),
    }).then(resp => {
        console.log("resp", resp);
        resp.json().then(body => {
            if (!resp.ok) {
                console.error("body", body);
                return;
            }
            console.log("body", body);

            // TODO: use ephemeral cert.
        }).catch(console.error);
    }).catch(console.error);
}

function capture(tab) {
    // console.log("tab", tab);

    getIDToken();
}

chrome.action.onClicked.addListener((tab) => { chrome.tabs.captureVisibleTab({ format: "png" }, capture); });
chrome.commands.onCommand.addListener((command) => { chrome.tabs.captureVisibleTab({ format: "png" }, capture); });

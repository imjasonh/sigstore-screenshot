# Verifiable Screenshot Chrome Extension

With this extension, you can take a screenshot of a webpage with Cmd+Shift+6, and then the extension attests a digest of the screenshot to Rekor, using an ephemeral cert from Fulcio, tied to your identity.

This proves that you took the screenshot at a certain time, and that if the image ever changes there's no way to forge the attestation.

_This doesn't currently work_.

-----

Notes for how to get this working:

- get a stable extension ID as documented in https://developer.chrome.com/docs/extensions/how-to/integrate/oauth
- create a GCP project, create OAuth Credentials
  - _not_ a **Chrome Extension** but a regular **Web Application**
  - with redirect URL `https://XXXXXX.chromiumapp.org`

So far this extension:

1. listens for `cmd+shift+6` to take a screenshot of the current tab
1. does Google OAuth to get an ID token
1. generates an ephemeral public/private keypair
1. signs the ID token's `sub` with the private key
1. posts the public key, token and signed `token.sub` to Fulcio
1. 💥 fails with `"There was an error processing the identity token"` presumably because the id token doesn't have audience of `sigstore` -- but setting `audience` in the oauth request gets blocked by Google...

Once I get past that I think the next step is to:

1. get the ephemeral cert returned by Fulcio
1. take the digest of the screenshot data, wrap the digest in the correct envelope(s)
1. post to Rekor
1. get the log ID returned by Rekor, and redirect to search.sigstore.dev, and download the screenshot data.
1. show verification instructions.

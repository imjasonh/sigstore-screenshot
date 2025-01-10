# Work in Progress

Notes for how to get this working:

- get a stable extension ID as documented in https://developer.chrome.com/docs/extensions/how-to/integrate/oauth
- create a GCP project, create OAuth Credentials
  - _not_ a **Chrome Extension** but a regular **Web Application**
  - with redirect URL `https://XXXXXX.chromiumapp.org`

So far this extension:

1. listens for `cmd+shift+6` to take a screenshot of the current tab
1. generates an ephemeral public/private keypair
1. does Google OAuth to get an id token
1. signs the token's `sub` with the private key
1. posts the public key, token and signed `token.sub` to Fulcio
1. 💥 fails because Fulcio doesn't support CORS requests

Once I get past that I think the next step is to:

1. get the ephemeral cert returned by Fulcio
1. take the digest of the screenshot data, wrap the digest in the correct envelope(s)
1. post to Rekor
1. get the log ID returned by Rekor, and redirect to search.sigstore.dev, and download the screenshot data.
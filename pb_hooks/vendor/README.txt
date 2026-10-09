TweetNaCl.js 1.0.3, nacl-fast.js, from the published npm tweetnacl package.
The npm tarball SHA-512 integrity was verified before extraction.
License: tweetnacl-LICENSE (Unlicense).
One adaptation: the Node require('crypto') PRNG initialization is replaced with
null because PocketBase's JS runtime is not Node. This app uses only detached
signature verification. No key generation or signing uses this vendored file.

Upstream: https://github.com/dchest/tweetnacl-js/tree/v1.0.3

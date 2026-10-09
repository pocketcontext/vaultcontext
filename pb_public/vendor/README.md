# PocketBase JavaScript SDK

Vendored official npm package `pocketbase@0.28.1`, `dist/pocketbase.es.mjs`, unchanged.
Source: https://github.com/pocketbase/js-sdk/tree/v0.28.1
Package: https://registry.npmjs.org/pocketbase/-/pocketbase-0.28.1.tgz
Verified package SHA-512 (base64):
`/3ihkq+rvfcs0MQgrK4sEElOg6gfenHW9S/O+3BSO+V1yT+4B10+9aT22uTQUPqze9ItwNtwWyY5ZmdgVCTdVA==`

License is included in LICENSE.md. No external CDN or runtime package lookup.
The demo uses default LocalAuthStore and an isolated BaseAuthStore for guarded
server refresh. Its explicit OAuth popup/SSE wrapper preserves cancellation and
COOP behavior; accepted authentication is published to the SDK store only after
preferences validation. No vault secrets or consent choices are stored there.

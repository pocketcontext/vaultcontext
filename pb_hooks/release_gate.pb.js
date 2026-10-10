// Bearer authentication loads at -1020 and account revocation runs at -1019.
// Gate all application API routes before their individual handlers execute.
routerUse(new Middleware((e) => require(`${__hooks}/release_gate.js`).request(e), -1018));
routerAdd('GET', '/api/vaultcontext/compatibility', (e) => require(`${__hooks}/release_gate.js`).compatibility(e));

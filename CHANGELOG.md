# Changelog

## [0.14.0](https://github.com/c-lgrant/tvault/compare/v0.13.0...v0.14.0) (2026-11-11)


### ⚠ BREAKING CHANGES

* `tvault webhook init`, `up` and `down` are removed, and the tvault-webhook container image is no longer published. Run the reference webhook with `docker compose up -d --build` in examples/webhook, or deploy it to Workers. `tvault webhook bind` now takes --url.

### Features

* **cli:** accept mcp as the access name in grant specs ([f1587cd](https://github.com/c-lgrant/tvault/commit/f1587cd8d3acc25522d15509abfe4d2252b6c7c5))
* **cli:** one-command add for an agent, stdin secrets, and connect ([#40](https://github.com/c-lgrant/tvault/issues/40)) ([227e795](https://github.com/c-lgrant/tvault/commit/227e795846fd55a15149ac64c5a472a4e8ec12c3))
* **cli:** Token Vault sign-in credentials, retired-feature explain codes, no mcpEnabled on agent create ([f611150](https://github.com/c-lgrant/tvault/commit/f61115042d055b1d61198ff99687c1214c8952a4))
* explain policy and access denials in plain words ([045067c](https://github.com/c-lgrant/tvault/commit/045067c6b4e4eeddd01249b92d13d0977d1e1975))
* label, policy attach/detach, credentials and history aliases; repeatable add --for and add --labels ([32e2d00](https://github.com/c-lgrant/tvault/commit/32e2d0096c84c779577862b15270f46be671b300))
* mcp-servers command, tools grants and per-server connect ([#43](https://github.com/c-lgrant/tvault/issues/43)) ([1f2478d](https://github.com/c-lgrant/tvault/commit/1f2478d815efa3b2fe35d76de0d6dedbb6a26c48))
* **mcp-servers:** ls shows the cached tool count ([#45](https://github.com/c-lgrant/tvault/issues/45)) ([7342796](https://github.com/c-lgrant/tvault/commit/7342796cfcce254a3b2f5958837a8127aedca056))
* own-app OAuth refresh, tv-refresh opt-in, Token Vault sign-in in the CLI ([5655860](https://github.com/c-lgrant/tvault/commit/56558604ffdf9f8c0a47ce91f700cf10a6676380))
* webhook limits on the control plane, and CLI exit codes 13 and 14 ([#56](https://github.com/c-lgrant/tvault/issues/56)) ([939739d](https://github.com/c-lgrant/tvault/commit/939739d14967953625b07cdd6223125d88b0791c))
* **webhook:** oauth-callback capability to connect with your own OAuth app ([#42](https://github.com/c-lgrant/tvault/issues/42)) ([e61b58d](https://github.com/c-lgrant/tvault/commit/e61b58d0ce64fa990972a235e0aa3c0bfc13a742))
* **webhook:** refresh own-app OAuth tokens on a schedule and at fetch time ([ae8b4e2](https://github.com/c-lgrant/tvault/commit/ae8b4e237958a5f17a6c535664f4fc768fa149da))


### Bug Fixes

* clean up the CLI and reference webhook before release ([36b1285](https://github.com/c-lgrant/tvault/commit/36b1285a8b0c82d559db7e5b3501d75e86ae86db))
* **cli:** match explain text for sign-in codes to the server ([625c9ca](https://github.com/c-lgrant/tvault/commit/625c9ca030a7d760a79b19cfba5e9a5e3290370b))
* **login:** --ctx names the context and reuses its server ([#44](https://github.com/c-lgrant/tvault/issues/44)) ([496c823](https://github.com/c-lgrant/tvault/commit/496c82350afbd75d3e25a9e0d850b54cedd99319))
* review fixes for the CLI and the reference webhook ([#55](https://github.com/c-lgrant/tvault/issues/55)) ([94b9e5d](https://github.com/c-lgrant/tvault/commit/94b9e5d5e5c29b630d59e41ab834de0908122326))
* **webhook:** bind the request-id header to the signed attemptId ([591e7ea](https://github.com/c-lgrant/tvault/commit/591e7ea54c3940edc7a32664246b45822f70f1af))
* **webhook:** close three gaps in the /v1/proxy upstream checks ([#57](https://github.com/c-lgrant/tvault/issues/57)) ([12ff909](https://github.com/c-lgrant/tvault/commit/12ff909cefd9fb4832a01d1c6e29ab84f020f34e))
* **webhook:** do not give an agent the refresh token on /v1/credential ([8eff1d8](https://github.com/c-lgrant/tvault/commit/8eff1d82b7b0bbe84d212cd940d05caa1c2bd96c))
* **webhook:** fetch-time refresh never serves a credential replaced after the ticket check ([42aaab0](https://github.com/c-lgrant/tvault/commit/42aaab0f2a12b64478288dcd6ed9303a79459738))
* **webhook:** keep credentials out of error responses, gate TOTP heal behind replay checks, bound proxy streams ([88d3330](https://github.com/c-lgrant/tvault/commit/88d3330d91b1763e4922f71a281c2320a69e2582))
* **webhook:** make own-app OAuth refresh keep metadata and fail safely ([c404bba](https://github.com/c-lgrant/tvault/commit/c404bba5ec9961cabdd48889ffc44a0358707c27))
* **webhook:** make the legacy tv-refresh capability opt-in ([bd9c035](https://github.com/c-lgrant/tvault/commit/bd9c03528dead04ce4ececdfdd55612aaf56789b))
* **webhook:** prune used ticket nonces without the cron trigger ([#59](https://github.com/c-lgrant/tvault/issues/59)) ([cf61bc7](https://github.com/c-lgrant/tvault/commit/cf61bc71281599c7cab0f3b2f3773143cd837b27))


### Performance

* **cli:** tvault get skips GET /api/tokens/{name} ([bd1f950](https://github.com/c-lgrant/tvault/commit/bd1f950dadebbca5e946f568364d113865c30adf))
* **webhook,cli:** stream MCP responses, parallel replay checks, bounded audit, Server-Timing ([03fb969](https://github.com/c-lgrant/tvault/commit/03fb969cb640827071a55c431daeb4f15b07c6d0))

## [0.13.0](https://github.com/c-lgrant/tvault/compare/v0.12.0...v0.13.0) (2026-10-31)


### Features

* **explain:** add `WEB_CONSOLE_REQUIRED` ([496fd92](https://github.com/c-lgrant/tvault/commit/496fd929bb562408e2656c4f3ec1c4f0add5e2e7))


### Bug Fixes

* **cli:** `tvault add` and `tvault set` send credential values to your webhook only, with a store ticket. Before, they sent the value to Token Vault first and used the ticket only after Token Vault refused it. Upgrade to stop that. ([8e17aee](https://github.com/c-lgrant/tvault/commit/8e17aee1a014a6382be418c00c085b900f1ce8cf))
* **cli:** `tvault set` keeps the token's type; `--dry-run` works on the ticket path; a refused store ticket exits as a server error, not a login error ([#37](https://github.com/c-lgrant/tvault/issues/37)) ([df6e00d](https://github.com/c-lgrant/tvault/commit/df6e00d94023a7e31f81141dbd4c7b7c40adb1e5))
* **explain:** describe `WEB_CONSOLE_REQUIRED` for any access channel policy ([bb90264](https://github.com/c-lgrant/tvault/commit/bb9026472ed8a7996cb08a4299a3f07a5b3cfe08))
* **deps:** webhook `wrangler` ^4.156.0 and `@hono/node-server` ^2.1.5, clearing the open undici and serveStatic advisories ([#36](https://github.com/c-lgrant/tvault/issues/36)) ([eaff027](https://github.com/c-lgrant/tvault/commit/eaff027))

## [0.12.0](https://github.com/c-lgrant/tvault/compare/v0.11.1...v0.12.0) (2026-10-14)


### Features

* **cli:** `agents list` and `agents show` show when each agent was last active, and `--format wide` adds its access count ([d0f2685](https://github.com/c-lgrant/tvault/commit/d0f268567334334f48ede36d6e432330ad3f45fe))


### Bug Fixes

* **cli:** share the admin ID token across tvault processes, so a burst of parallel `tvault get` calls makes one session refresh instead of one each ([9944bf9](https://github.com/c-lgrant/tvault/commit/9944bf9eac617f347ac03fda4b209bbb04a1f9fa), [7a2e751](https://github.com/c-lgrant/tvault/commit/7a2e7515a8b81042d0e90ec05c144e5b58e8631d))
* **cli:** retry a rate-limited session refresh ([406615d](https://github.com/c-lgrant/tvault/commit/406615d8f9043dcf64d110f3aa6ace2f0a715fc8))
* **webhook:** stop a stalled Cache API lookup hanging requests until the caller times out ([ee29c70](https://github.com/c-lgrant/tvault/commit/ee29c702df7a78207a074a83156b439b80d221e9))

## [0.11.1](https://github.com/c-lgrant/tvault-private/compare/v0.11.0...v0.11.1) (2026-10-13)

**Bug-fix and security release. All webhook operators and CLI users should upgrade.** There are no breaking changes, and no configuration or storage migration is needed.

#### Webhook (`examples/webhook`)

- **Fixed: requests could hang until the client timed out.** About 1 request in 10 hung, on every route. Token Vault's calls failed after 3 s, and `tvault get` failed after 30 s with an empty result. Cause: each Worker instance shared its start-up work across requests. If the first request was cancelled during start-up, every later request to that instance waited forever. Now a request never waits on another request's start-up.
- **Faster cold starts.** Start-up now makes 2 database reads and no writes, down from 4 round trips plus a write on every cold start.
- **Lighter health checks.** `HEAD /v1/health` (Token Vault's warm-up probe) no longer reads every stored credential. `GET /v1/health` counts tokens without loading them.
- **To upgrade:** if you deployed with the Cloudflare button, run the "Update webhook" workflow in your repo and merge its pull request. Workers Builds redeploys automatically. If you run the webhook with Docker or Node, pull this release and rebuild.

#### CLI (`tvault`, npm `@tvault/cli`)

- **Fixed: `tvault tokens edit --notes` did not save the note.** The command reported success, but `tokens show` displayed an empty note.
- **Fixed: `tvault get` could print nothing when the webhook stalled.** Each webhook fetch now stops after 10 s and is retried once with a new ticket. A timeout now says "webhook did not respond within 10s".
- **Security: built with Go 1.27.2.** This fixes 9 Go standard-library vulnerabilities that affected the CLI (net/http, HTTP/2, crypto/tls, net/textproto: GO-2026-6603 to GO-2026-6617). Earlier release binaries were built with Go 1.26.0.
- **To upgrade:** run `npm i -g @tvault/cli@0.11.1`, or download the binary for your platform from this release.

### Bug Fixes

* **cli:** save tokens edit --notes; retry a stalled webhook fetch ([581093f](https://github.com/c-lgrant/tvault-private/commit/581093f9ef58fc891e522bab33894c3d84a78af5))
* **deps:** build with Go 1.27.2; update Go and webhook dependencies ([5c02a71](https://github.com/c-lgrant/tvault-private/commit/5c02a715579c7f990915df7872c7484a04cf6553))
* **webhook:** stop cold-start hangs; cut startup and health D1 work ([49a46ba](https://github.com/c-lgrant/tvault-private/commit/49a46bae808b57e3d572d1fef753c630c1b9a1a5))

## [0.11.0](https://github.com/c-lgrant/tvault-private/compare/v0.10.1...v0.11.0) (2026-10-08)


### Features

* **login:** accept a pasted code while waiting for the browser ([64b15e3](https://github.com/c-lgrant/tvault-private/commit/64b15e3d9e6430d7431f3339301a07f0d505f1f4))

## [0.10.1](https://github.com/c-lgrant/tvault-private/compare/v0.10.0...v0.10.1) (2026-10-08)


### Bug Fixes

* **auth:** validate agent key logins through whoami, so scoped agents without credentials:read can log in ([6584bd5](https://github.com/c-lgrant/tvault-private/commit/6584bd58b21a8f71bcba40867edd02e3c8d714a5)), closes [#15](https://github.com/c-lgrant/tvault-private/issues/15)

## [0.10.0](https://github.com/c-lgrant/tvault-private/compare/v0.9.0...v0.10.0) (2026-10-08)


### Features

* **webhook:** heal legacy plaintext totpUri on read/list, add /v1/admin/migrate ([d9dff13](https://github.com/c-lgrant/tvault-private/commit/d9dff13193b1b6a383e1fccae044b013c43a66d9))
* **webhook:** totpUri as sensitive on store; ticketConstraints (mode, cid) ([bc76b4e](https://github.com/c-lgrant/tvault-private/commit/bc76b4e39e4bc99ff2012595d88c18abdb7df800))

## [0.9.0](https://github.com/c-lgrant/tvault-private/compare/v0.8.2...v0.9.0) (2026-10-08)


### Features

* **cli:** add `login --key-stdin` to keep keys out of shell history ([47e3edd](https://github.com/c-lgrant/tvault-private/commit/47e3edd83cfac4ad122bd3e88ebc3d5b9dbe4ac6))
* **cli:** hints for AUTO_GRANT_IN_PLACE / MANUAL_GRANT_IN_PLACE ([9b6c523](https://github.com/c-lgrant/tvault-private/commit/9b6c523f9b40b79f71f4e936db4f1e15ddc5f072))
* **cli:** rotate --self for keys and agents; SCOPE_NOT_DELEGABLE and ROTATION_CONFLICT hints ([1446a4b](https://github.com/c-lgrant/tvault-private/commit/1446a4b8cff9748e89c8b689d5df038cc4484ef0))
* **cli:** SELF_CHANGE_FORBIDDEN hint and explain entry ([de04604](https://github.com/c-lgrant/tvault-private/commit/de046045268f2832e71e2d68bc36f5bf0a84bf4a))
* map more scoped-key error codes, add keys show/grant/ungrant ([93aef28](https://github.com/c-lgrant/tvault-private/commit/93aef28bb70e0ed451681d33187a4ee1c6fb9a5a))
* scoped-key contexts, scope exit codes, keys command group ([edd9b84](https://github.com/c-lgrant/tvault-private/commit/edd9b84c1778db670fb647ee88787122d8bed258))


### Bug Fixes

* **cli:** "Suspended"/"Resumed agent" (was "Suspendd") ([182362a](https://github.com/c-lgrant/tvault-private/commit/182362af9c8064424d4df4814d987fb236e4c94a))
* **cli:** agents rotate-key --self names the agent, not "agent" ([bf4ceb7](https://github.com/c-lgrant/tvault-private/commit/bf4ceb77ee869c3cb6259cc36ee40c1d480d3050))
* **cli:** clearer errors for old servers, classic agents, expired keys ([2da37ed](https://github.com/c-lgrant/tvault-private/commit/2da37ed99ee55a4d7aa08e047f2d2ef859dbf0e8))
* **cli:** escape control characters in names shown in confirmations ([46a11ff](https://github.com/c-lgrant/tvault-private/commit/46a11ffc5e59c712a7d3392a74cbc416e7dd3636))
* **cli:** no success message under --dry-run for tokens create/set; copy nits ([ff9937d](https://github.com/c-lgrant/tvault-private/commit/ff9937d5a7fa2b70d70560bc7d123ac4fff2a484))
* **cli:** non-zero exit on half-granted agent create; keys revoke --force; agent-friendly NO_GRANT hint ([dd5e24a](https://github.com/c-lgrant/tvault-private/commit/dd5e24a7fe562cbd956f476600b2d780fac9036e))
* **cli:** resolve agent IDs without listing agents ([fc738a0](https://github.com/c-lgrant/tvault-private/commit/fc738a0f37ad53e0c0956643bd578e11a98fdecd))
* **cli:** resolve agent/key refs safely (no name/ID confusion) ([20877f9](https://github.com/c-lgrant/tvault-private/commit/20877f9bca51729c805d76177d864cd17cf30193))
* **cli:** whoami falls back for admin contexts on pre-scoped-key servers ([56de563](https://github.com/c-lgrant/tvault-private/commit/56de5635b920faf8191219be0f1c967bafc60782))
* **deps:** golang.org/x/sys v0.44.0 (GO-2026-5024) and patch updates ([5c5d57c](https://github.com/c-lgrant/tvault-private/commit/5c5d57c6907816b5eaf913c79b4c0272539cf998))
* **login:** derive frontend URL from --api-url instead of falling back to prod ([dc60d44](https://github.com/c-lgrant/tvault-private/commit/dc60d444d7862082d61f6830d60b56d104b7b156))
* parse key grants with grantExpiresAt and the full grant shape ([bd7f750](https://github.com/c-lgrant/tvault-private/commit/bd7f7505e2e83bf3a0fdfd5887c5dae5f69d459d))


### Documentation

* **api:** KeyGrant.Source comment no longer mentions inheritance ([d439727](https://github.com/c-lgrant/tvault-private/commit/d439727994cf484bb10e7c994a10c8ce61e56816))
* document scoped keys, key contexts and exit codes 8-10 ([66cb4c6](https://github.com/c-lgrant/tvault-private/commit/66cb4c65f40ab96ff6b18a4c634bc1278ff19eed))

## [0.8.2](https://github.com/c-lgrant/tvault-private/compare/v0.8.1...v0.8.2) (2026-10-06)


### Bug Fixes

* **deps:** clear all Dependabot alerts in the webhook examples ([5a7b1a6](https://github.com/c-lgrant/tvault-private/commit/5a7b1a62c2f46acf1a22c477bc5607f42d0d1031))

## [0.8.1](https://github.com/c-lgrant/tvault-private/compare/v0.8.0...v0.8.1) (2026-10-06)


### Bug Fixes

* **webhook:** keep createdAt when a token is re-stored ([d4a4d4f](https://github.com/c-lgrant/tvault-private/commit/d4a4d4fe1437e7eb7322d5fa869b987f7ec25e1b))

## [0.8.0](https://github.com/c-lgrant/tvault-private/compare/v0.7.1...v0.8.0) (2026-09-24)


### Features

* **api:** 429 handling with Retry-After honor + exponential GET backoff ([f0dff54](https://github.com/c-lgrant/tvault-private/commit/f0dff543056d6a21da030d260e33212a078b55b9))
* **npm:** publish the CLI as @tvault/cli ([68c33a5](https://github.com/c-lgrant/tvault-private/commit/68c33a532ad18c395e1faad18565e99ebd2e28b6))
* **npm:** publish the CLI as @tvault/cli ([748472a](https://github.com/c-lgrant/tvault-private/commit/748472a840cdc0d4ea2b1a0d519b13e931380765)), closes [#191](https://github.com/c-lgrant/tvault-private/issues/191)
* **webhook:** add a root landing page reporting live worker state ([5197348](https://github.com/c-lgrant/tvault-private/commit/519734839ddfc5a76266b5c91b91e7e2fda5b087))
* **webhook:** ask for the seed in the Deploy-to-Cloudflare dashboard ([354ea5b](https://github.com/c-lgrant/tvault-private/commit/354ea5b58fb24e9d1596c1ba63ba2b8a1d33efa9))
* **webhook:** best-effort per-IP token bucket + CF rate-limit rule guidance ([0f287c9](https://github.com/c-lgrant/tvault-private/commit/0f287c97cb0140851cb376bddadb4464d7da20f1))


### Bug Fixes

* **api:** tolerate fractional grantCount from the backend ([98bcfe2](https://github.com/c-lgrant/tvault-private/commit/98bcfe27020e20d6c75491e3be9071e461ec40cb))
* **webhook:** deploy.sh works in the Workers Builds sandbox ([2b70908](https://github.com/c-lgrant/tvault-private/commit/2b709081c28694fe7318b48358574b4898ad4ba2))
* **webhook:** HTML-escape URLs interpolated into the landing and bind pages ([f9b6d69](https://github.com/c-lgrant/tvault-private/commit/f9b6d6994a9e020ad50ac7877f55028a66166a4c))
* **webhook:** landing Connect link always carries ?tv=&lt;frontend&gt; ([2a98126](https://github.com/c-lgrant/tvault-private/commit/2a98126b9037fc2d74815ca8c664f077bd8d4290))
* **webhook:** never leave the seed unset after a Deploy-button deploy ([3d8c65b](https://github.com/c-lgrant/tvault-private/commit/3d8c65b4161c1160110a9c6a23bafe8ec0e6d768))
* **webhook:** skip .github/workflows in the update overlay ([7fa32a1](https://github.com/c-lgrant/tvault-private/commit/7fa32a16f75480570b131ca1ee0bdfff85f5a1be))
* **webhook:** stage update tarball outside the workspace ([c739f1f](https://github.com/c-lgrant/tvault-private/commit/c739f1fc86c5033e4c7c3edce4f8160a40252918))


### Documentation

* **readme:** say what Token Vault is, not just what the CLI does ([e3e1692](https://github.com/c-lgrant/tvault-private/commit/e3e16922089d72fb74d2a2957467618b8becc40a))
* retire the stale preview-branch install caveat ([b41d0bd](https://github.com/c-lgrant/tvault-private/commit/b41d0bda5b48e7df4bf22d9d8294239ea83586ee))
* retire the stale preview-branch install caveat ([5316e1f](https://github.com/c-lgrant/tvault-private/commit/5316e1f1b6c91b10ece59cc6d6ede935f9cfa78b)), closes [#276](https://github.com/c-lgrant/tvault-private/issues/276)

## [0.7.1](https://github.com/c-lgrant/tvault-private/compare/v0.7.0...v0.7.1) (2026-06-27)


### Bug Fixes

* **webhook:** provision _bind_codes collection on the FS runtime ([e6c74f3](https://github.com/c-lgrant/tvault-private/commit/e6c74f393cd18926ab6f3e508d7089fa06ef567e))
* **webhook:** provision _bind_codes collection on the FS/Node runtime ([63ceddf](https://github.com/c-lgrant/tvault-private/commit/63ceddfadda042ec53304a719e51d18205b000b0))

## [0.7.0](https://github.com/c-lgrant/tvault-private/compare/v0.6.0...v0.7.0) (2026-06-27)


### Features

* **api:** set User-Agent header on all HTTP requests ([a88e3ee](https://github.com/c-lgrant/tvault-private/commit/a88e3eeed6c15a64e6f3b8755989fa3dd0b01996))
* **tokens:** composite token field resolution ([e70a508](https://github.com/c-lgrant/tvault-private/commit/e70a5083a40f5e9490b51b1b3f2e41bb15c8c540))
* **webhook/health:** reflect Origin CORS on GET/HEAD /v1/health ([b966c18](https://github.com/c-lgrant/tvault-private/commit/b966c18e02311fc618884bd3cf342e948775de5c))
* **webhook:** auto-provision seed as a Secret at deploy (build step) ([d46d00b](https://github.com/c-lgrant/tvault-private/commit/d46d00b0a992ca8e7a16cb1356e24a847a923234))
* **webhook:** bind page accepts a tv= target so it isn't pinned to one frontend ([66f027c](https://github.com/c-lgrant/tvault-private/commit/66f027ca0e4ff850cd1e10a428061b50d79d3856))
* **webhook:** boot routine — apply schema migrations + auto-seal in-use webhooks ([f7fcb42](https://github.com/c-lgrant/tvault-private/commit/f7fcb4216857c7f4a50b8e4b7a0172618232c419))
* **webhook:** declare D1 in template so the deploy button provisions it ([1172679](https://github.com/c-lgrant/tvault-private/commit/1172679dfdf50998b9ddbccbeb5965678e172ccd))
* **webhook:** feature modules + credential interceptors ([a713f46](https://github.com/c-lgrant/tvault-private/commit/a713f46ff011b2e8afcd484bc776b27a407553e7))
* **webhook:** Node + Workers runtimes, Docker/tunnels, Workers config ([2fe2de9](https://github.com/c-lgrant/tvault-private/commit/2fe2de9e43b12824055c153ba6b78e4685722d3d))
* **webhook:** one-click seed generate-&-save on /bind + observability ([b442158](https://github.com/c-lgrant/tvault-private/commit/b442158783cf57f2f2ff56a323f8f7e8dfc0d2c2))
* **webhook:** runtime-neutral protocol core ([4a08e72](https://github.com/c-lgrant/tvault-private/commit/4a08e72851da679e11804b692941b208c45e1efe))
* **webhook:** self-update + schema-migration (in-place upgrade) ([74d62cd](https://github.com/c-lgrant/tvault-private/commit/74d62cd03eff32b83fd8b4e9df8a5562327e196f))
* **webhook:** setup page deep-links to CF dashboard + bakes --name into CLI ([b34a473](https://github.com/c-lgrant/tvault-private/commit/b34a4733a6a1c059735d8cc972b1d16a377f78c3))
* **webhook:** ship in-template 'Update webhook' Action (opens upgrade PR) ([673b49a](https://github.com/c-lgrant/tvault-private/commit/673b49a50169fa5ac611e642cd80967956f3e167))
* **webhook:** storage-schema migration mechanism (upconvert on load) ([235bca1](https://github.com/c-lgrant/tvault-private/commit/235bca13f53fcb54b054544d3af41a1ea4729070))
* **webhook:** storage/secret/replay adapters for Node + Workers ([f23eca2](https://github.com/c-lgrant/tvault-private/commit/f23eca29279320dac82d8ddb023b2df777e42652))
* **webhook:** tested upstream-overlay script for the self-update Action ([3002842](https://github.com/c-lgrant/tvault-private/commit/300284271a3f54bc87aaf8a50a14f3c86e31f46d))


### Bug Fixes

* **install:** avoid SIGPIPE on latest-tag lookup ([88171c3](https://github.com/c-lgrant/tvault-private/commit/88171c319beef755b1ebcb196eed63b4b10efff8))
* **webhook/cf:** make canonical deploy script auto-provision the seed ([10fd735](https://github.com/c-lgrant/tvault-private/commit/10fd735b873a46ca716ba33d45e7bd2bd5c92405))
* **webhook/gcp:** drop agent-supplied ?scopes= — always use DEFAULT_SCOPES (FIX 3) ([a3c89ff](https://github.com/c-lgrant/tvault-private/commit/a3c89ffdc1d49d14c7b982283b17b9c20079f6d0))
* **webhook:** accurate fully-sealed 403 message + drop browser_credential from totp allowlist (Copilot review) ([2324ab4](https://github.com/c-lgrant/tvault-private/commit/2324ab4c34602c63ed02fb836dfcd821245604bc))
* **webhook:** address Copilot review — seal ordering, fs internal collection, nonce type ([56f6a91](https://github.com/c-lgrant/tvault-private/commit/56f6a912af87cd9f7c0c9c8aa40804462eb969c6))
* **webhook:** auth hardening — seal bind/exchange, no silent fallback, GCP scope, cleanups ([6e622e8](https://github.com/c-lgrant/tvault-private/commit/6e622e82340327802625b8b854bc82dcdcc3a4e3))
* **webhook:** cleanups — version 2.4.0, nonce/request-id required, drop browser_credential (FIX 4) ([836bf4c](https://github.com/c-lgrant/tvault-private/commit/836bf4cdb8be83083ef40df27f06ea130051e0e0))
* **webhook:** hash admin secret before constant-time compare; deterministic test svc (Copilot review) ([60a0578](https://github.com/c-lgrant/tvault-private/commit/60a05787b12c9bbbc6721fef8a72f6ef58380ff1))
* **webhook:** lstat fallback for unknown-dtype Dirents in overlay walk (Copilot review) ([9458132](https://github.com/c-lgrant/tvault-private/commit/945813280c45e184dd5593cd6fb5bea33d74f4fd))
* **webhook:** migration baseline fallback + non-fatal startup seal (review) ([163fcec](https://github.com/c-lgrant/tvault-private/commit/163fcecd8e954381f0933f49677c22f04ce150aa))
* **webhook:** no schema downgrade + refuse symlink overlay (Copilot review) ([5030af5](https://github.com/c-lgrant/tvault-private/commit/5030af54e16bcaa16f085760c777a5103a014d21))
* **webhook:** persist bind codes in storage (cross-isolate) + setup page ([71937b1](https://github.com/c-lgrant/tvault-private/commit/71937b16250c7117b00fc0b981d34fe9d9363101))
* **webhook:** robust CLI-entrypoint check via pathToFileURL (Copilot review) ([e35fcc3](https://github.com/c-lgrant/tvault-private/commit/e35fcc358f7d77cbef35dbb402e3619a52382e0b))
* **webhook:** run guardBound before config resolution on /v1/register-url + /bind (Copilot review) ([3e46b5e](https://github.com/c-lgrant/tvault-private/commit/3e46b5e68790b7744b012be35f5ccf921c95da61))
* **webhook:** seal /bind+/v1/exchange+/v1/register-url after first bind (FIX 1+2) ([b0979d8](https://github.com/c-lgrant/tvault-private/commit/b0979d8582fab61826775310651f8429d30fcdcd))
* **webhook:** single KV namespace to stop deploy-button collision ([30103e8](https://github.com/c-lgrant/tvault-private/commit/30103e8164ce25e3c2dafea4e0828b65f9d93235))
* **webhook:** skip non-regular files in overlay walk, not just symlinks (Copilot review) ([e6bb91f](https://github.com/c-lgrant/tvault-private/commit/e6bb91fccf12cc5ec84d65dd305c5ed4bb997edf))
* **webhook:** use hex-format KV id placeholders so the deploy button auto-provisions ([c662204](https://github.com/c-lgrant/tvault-private/commit/c6622046753e2fd568e11feed6f5a650cfdf6e5f))
* **webhook:** validate schema stamp is a finite non-negative integer (Copilot review) ([4ec33f7](https://github.com/c-lgrant/tvault-private/commit/4ec33f751ef5808cf39b863cbbf31111faff5ff7))


### Refactoring

* **webhook:** drop KV on Workers — D1-only storage, Cache API replay, Secret-only seed ([1aa6bda](https://github.com/c-lgrant/tvault-private/commit/1aa6bdaaff5f3d44f25e1610f324655eced099a2))


### Documentation

* **webhook:** clearer CF deploy KV setup; drop preview_id; fix stale deploy doc ([a7387c2](https://github.com/c-lgrant/tvault-private/commit/a7387c2b9a1cb881ec8781b5054a6bfbb7a17d9e))
* **webhook:** in-place upgrade guide + README/onboarding links ([e31677d](https://github.com/c-lgrant/tvault-private/commit/e31677d7f12a219ddbfad992c5523fc97d5eaf10))

## [Unreleased]

### Features

* **tokens:** composite token field resolution via `service.field` syntax and `--field`/`--kv` flags ([#pending]())

## [0.6.0](https://github.com/c-lgrant/tvault/compare/v0.5.0...v0.6.0) (2026-05-18)


### Features

* **cli:** top-level shortcuts, --ctx alias, --check probe, webhook-mode auto-route ([8c170a0](https://github.com/c-lgrant/tvault/commit/8c170a0f0d84e90d09ca441395a38d5dce2aa234))
* list_batch operation, background kv saver, tv-mediated refresh ([b8b0267](https://github.com/c-lgrant/tvault/commit/b8b0267f7dbf875c800639e8abbae6cfa2e213f3))
* **webhook:** default --dir to CWD, prompt before overwriting, normalize URL inputs ([207ac83](https://github.com/c-lgrant/tvault/commit/207ac837f5779a58e38b6d394e9c98bca80c1093))
* **webhook:** default --image tracks the running CLI's lineage ([11b4083](https://github.com/c-lgrant/tvault/commit/11b408354fa8c1372956987852aa0a50714a8ee5))


### Bug Fixes

* **auth:** handle CORS preflight on the loopback /callback listener ([9749169](https://github.com/c-lgrant/tvault/commit/97491690adb91b7cc951957a0b56e293657bf5b9))
* **get:** route agent contexts to /api/agents/credentials, fix more stdout leaks ([7e8cb2f](https://github.com/c-lgrant/tvault/commit/7e8cb2f9bb9b79d3c1875ffff2912e5839b87ed8))
* **tokens:** make tokens get/show work in webhook (zero-knowledge) mode ([d4b6e9a](https://github.com/c-lgrant/tvault/commit/d4b6e9ae217078f071c965cf120baf549616acd0))
* **tokens:** stdout for get, distinct exit code for empty, and store-ticket subcommand ([d356b9e](https://github.com/c-lgrant/tvault/commit/d356b9eacd3828d4b67dbe07c8009e13cfc3680b))
* **version:** write to stdout so output is capturable ([be6f4fe](https://github.com/c-lgrant/tvault/commit/be6f4fedd153ade0666a8602e106622ae82d69d4))


### Refactoring

* modularize webhook-ngrok and fix OAuth metadata display ([61b16bb](https://github.com/c-lgrant/tvault/commit/61b16bb4a6caa104df3d1e49f7eeb4542ee235e6))


### Documentation

* **readme:** note install.sh doesn't work on preview branch, document the gh-artifact and go-install alternatives ([f760cf9](https://github.com/c-lgrant/tvault/commit/f760cf955e71fe63832e625e8b6b4a5eba581d16))

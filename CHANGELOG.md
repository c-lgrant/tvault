# Changelog

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

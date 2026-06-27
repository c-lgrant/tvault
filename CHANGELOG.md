# Changelog

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

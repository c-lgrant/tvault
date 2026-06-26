# Changelog

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

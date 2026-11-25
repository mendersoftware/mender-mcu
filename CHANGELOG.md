---
## 1.2.0 - 2026-11-25


### New features

- esp-idf supports backoffs on retries and handles rate-limiting ([MEN-10016](https://northerntech.atlassian.net/browse/MEN-10016)) ([3dccb80](https://github.com/mendersoftware/mender-mcu/commit/3dccb804ff75a8cd73ecbd5813633da02f2f633d)) by @rewanrashid-boop
- *(esp-idf)* Client now handles 429 headers from server. ([MEN-10030](https://northerntech.atlassian.net/browse/MEN-10030)) ([22b8269](https://github.com/mendersoftware/mender-mcu/commit/22b82699f07e5195ae34504bfa7b11291d255720)) by @rewanrashid-boop

### Bug fixes

- *(ci)* Quote the git extraHeader line to avoid YAML colon-space ambiguity ([86e2de2](https://github.com/mendersoftware/mender-mcu/commit/86e2de20d30baafe7eda1335c332e0a95a8b652d)) by @p-targowicz
- *(zephyr)* Ignore artifact size limits for on-prem server. ([MEN-9478](https://northerntech.atlassian.net/browse/MEN-9478)) ([906eee0](https://github.com/mendersoftware/mender-mcu/commit/906eee0fffee63c043f4fa355b75f8e08f8d21d2)) by @rewanrashid-boop
- Fix build errors with glibc >= 2.43 ([3266d79](https://github.com/mendersoftware/mender-mcu/commit/3266d79d5a402995edc8c4c2660d79a00fe26eca)) by @aduskett
- Skip the rollback reboot states for an update without reboot ([a8be24d](https://github.com/mendersoftware/mender-mcu/commit/a8be24dfc91551543a8b394fc10070d0baae3774)) by @hkenken
- Report a failed commit of an update without reboot as failure ([f19e7b5](https://github.com/mendersoftware/mender-mcu/commit/f19e7b50d41f265955be9b87b7c44d74ccf21a59)) by @hkenken
- Store the artifact data after the module has committed ([808ce57](https://github.com/mendersoftware/mender-mcu/commit/808ce57763fce985ff4629eaae1f9de94a2b25d9)) by @hkenken
- *(zephyr)* Erase the Mender NVS area on Zephyr if it was not initialized by Mender instead of reading garbage from it ([MEN-7530](https://northerntech.atlassian.net/browse/MEN-7530)) ([fbc4865](https://github.com/mendersoftware/mender-mcu/commit/fbc4865a5f564f43d211daf86a8b22e513c59964)) by @rewanrashid-boop
- Fix deployments looping forever when the maximum state data
store count is reached right before a reboot. ([MEN-8253](https://northerntech.atlassian.net/browse/MEN-8253)) ([ccdd196](https://github.com/mendersoftware/mender-mcu/commit/ccdd196a530716ab545f40d215e0129d4e323e27)) by @rewanrashid-boop
- Fail the deployment and run Cleanup when the device restarts
while downloading the artifact, like the Mender C++ client. ([MEN-8253](https://northerntech.atlassian.net/browse/MEN-8253)) ([148a2b9](https://github.com/mendersoftware/mender-mcu/commit/148a2b963a715488cea32a5c59dd73a497f8ef9c)) by @rewanrashid-boop

### Dependency updates

- *(deps)* Update dependency mendersoftware/mender-artifact to v4.4.2 ([1dbe291](https://github.com/mendersoftware/mender-mcu/commit/1dbe291b61d99b963e08855583f9bc2fa240a9ff)) by @mender-test-bot

---
### All tickets resolved in this release

| Ticket |
|---|
| [MEN-10016](https://northerntech.atlassian.net/browse/MEN-10016) |
| [MEN-10030](https://northerntech.atlassian.net/browse/MEN-10030) |
| [MEN-9478](https://northerntech.atlassian.net/browse/MEN-9478) |
| [MEN-7530](https://northerntech.atlassian.net/browse/MEN-7530) |
| [MEN-8253](https://northerntech.atlassian.net/browse/MEN-8253) |


## 1.1.0 - 2026-09-01


### New features

- Add support for chunked artifact download ([751274c](https://github.com/mendersoftware/mender-mcu/commit/751274c148dabfa5d751560ceca98bef0fa72370)) by @Dexter9532
- Add support for Mbed TLS 4.x. ([MEN-9810](https://northerntech.atlassian.net/browse/MEN-9810)) ([ea85856](https://github.com/mendersoftware/mender-mcu/commit/ea85856d0c8fac05f49718055a1e7cd0f6715b06)) by @danielskinstad
- Add support for Zephyr 4.4. ([MEN-9810](https://northerntech.atlassian.net/browse/MEN-9810)) ([87c1190](https://github.com/mendersoftware/mender-mcu/commit/87c1190d2caffa2a8efcdc2c0ed2a11f12ce1c0f)) by @danielskinstad
- Add weak mender_http_get_retry_interval fallback ([MEN-9962](https://northerntech.atlassian.net/browse/MEN-9962)) ([db81be4](https://github.com/mendersoftware/mender-mcu/commit/db81be431eb24bf61cdfa5c954bad20ce09e2712)) by @danielskinstad
- Add logging implementation for ESP-IDF. ([MEN-9962](https://northerntech.atlassian.net/browse/MEN-9962)) ([b917554](https://github.com/mendersoftware/mender-mcu/commit/b9175549d7b5792ea051da83a611d495ac6df8f8)) by @danielskinstad
- Build as an ESP-IDF component. ([MEN-9962](https://northerntech.atlassian.net/browse/MEN-9962)) ([b89cae9](https://github.com/mendersoftware/mender-mcu/commit/b89cae96364cfe38de1b81f4289a1ffb24f05335)) by @danielskinstad
- Add FreeRTOS scheduler implementation ([MEN-9961](https://northerntech.atlassian.net/browse/MEN-9961)) ([897f718](https://github.com/mendersoftware/mender-mcu/commit/897f7188210a52e13296f323949883fad92a4aef)) by @danielskinstad
- Add ESP-IDF reboot implementation ([MEN-9961](https://northerntech.atlassian.net/browse/MEN-9961)) ([a025c6c](https://github.com/mendersoftware/mender-mcu/commit/a025c6c176cc2f736df6b2834bd5409a49e61a93)) by @danielskinstad
- A secondary/fallback Mender server URL can now be specified ([MEN-9977](https://northerntech.atlassian.net/browse/MEN-9977)) ([8c9cd3c](https://github.com/mendersoftware/mender-mcu/commit/8c9cd3c11117e5b68fc4f17da3b4637616f0d839)) by @vpodzime

### Bug fixes

- Correctly deref deployment_data double pointer for null check ([0bc6757](https://github.com/mendersoftware/mender-mcu/commit/0bc67571782d19778edf7fe0d8158f29b8dbcf11)) by @danielb-IDG
- Avoid crash when IPv4 info is unavailable in Zephyr inventory ([10cc0ec](https://github.com/mendersoftware/mender-mcu/commit/10cc0ec620da0a6d650af935a05c19c5848160e0)) by @Dexter9532
- *(core)* Use-after-free in mender_filter_provides clears-provides loop ([4407c1b](https://github.com/mendersoftware/mender-mcu/commit/4407c1b67f644489a615db04f30f7dec88e8ef2b)) by @TheYoctoJester

### Dependency updates

- *(deps)* Update dependency mendersoftware/mender-artifact to v4.4.0 ([dd22562](https://github.com/mendersoftware/mender-mcu/commit/dd225627b11b2b099138c49366ed97e56acf2e45)) by @mender-test-bot
- *(deps)* Bump mbedtls to 3.6.6 ([d3228e1](https://github.com/mendersoftware/mender-mcu/commit/d3228e156edcc9d4fd506073a2592026c348a959)) by @aduskett
- *(deps)* Update dependency mendersoftware/mender-artifact to v4.4.1 ([dc9e146](https://github.com/mendersoftware/mender-mcu/commit/dc9e146422dd158a2c39f281bfe904ad14c0e8ab)) by @mender-test-bot

---
### All tickets resolved in this release

| Ticket |
|---|
| [MEN-9810](https://northerntech.atlassian.net/browse/MEN-9810) |
| [MEN-9962](https://northerntech.atlassian.net/browse/MEN-9962) |
| [MEN-9961](https://northerntech.atlassian.net/browse/MEN-9961) |
| [MEN-9977](https://northerntech.atlassian.net/browse/MEN-9977) |


## 1.0.0 - 2026-04-17

* The first stable release


## 0.9.0 - 2025-04-11

* Preview of Mender MCU

---

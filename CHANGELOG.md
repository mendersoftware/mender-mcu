---
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

---
## 1.1.0 - 2026-08-04


### New features

- Add support for chunked artifact download
- Add support for Mbed TLS 4.x. ([MEN-9810](https://northerntech.atlassian.net/browse/MEN-9810))
- Add support for Zephyr 4.4. ([MEN-9810](https://northerntech.atlassian.net/browse/MEN-9810))
- Add weak mender_http_get_retry_interval fallback ([MEN-9962](https://northerntech.atlassian.net/browse/MEN-9962))
- Add logging implementation for ESP-IDF. ([MEN-9962](https://northerntech.atlassian.net/browse/MEN-9962))
- Build as an ESP-IDF component. ([MEN-9962](https://northerntech.atlassian.net/browse/MEN-9962))
- Add FreeRTOS scheduler implementation ([MEN-9961](https://northerntech.atlassian.net/browse/MEN-9961))
- Add ESP-IDF reboot implementation ([MEN-9961](https://northerntech.atlassian.net/browse/MEN-9961))

### Bug fixes

- Correctly deref deployment_data double pointer for null check
- Avoid crash when IPv4 info is unavailable in Zephyr inventory
- *(core)* Use-after-free in mender_filter_provides clears-provides loop

### Dependency updates

- *(deps)* Update dependency mendersoftware/mender-artifact to v4.4.0
- *(deps)* Bump mbedtls to 3.6.6
- *(deps)* Update dependency mendersoftware/mender-artifact to v4.4.1

---
### All tickets resolved in this release

| Ticket |
|---|
| [MEN-9810](https://northerntech.atlassian.net/browse/MEN-9810) |
| [MEN-9962](https://northerntech.atlassian.net/browse/MEN-9962) |
| [MEN-9961](https://northerntech.atlassian.net/browse/MEN-9961) |


## 1.0.0 - 2026-04-17

* The first stable release


## 0.9.0 - 2025-04-11

* Preview of Mender MCU

---
